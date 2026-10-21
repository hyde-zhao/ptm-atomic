"""SSH/Telnet/CLI runner for transport=ssh/telnet/cli atoms.

This module implements shell runners for atoms whose ``transport`` field is
ssh, telnet, or cli. Each operation exposes a single entry point that selects
the underlying transport (SSH via paramiko, or Telnet via telnetlib) based on
the runtime ``transport`` parameter, defaulting to the atom's declared transport.

Security invariants:
- Every {{param}} placeholder MUST be shell-escaped via shlex.quote.
- Credentials come only from the credential env var and the local session file.
- stdout/stderr MUST be written only to diag_snapshot_ref, never to the repo.
- destructive/irreversible commands require gate.required and manual_required rollback.
"""

from __future__ import annotations

import os
import re
import shlex
import socket
import time
import warnings
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from atomic_ops.runner.errors import RunnerError, credential_missing_error
from atomic_ops.runner.session import read_session_file


VERSION_COMMAND = "cat /appdata/etc/version"
VERSION_SUCCESS_PATTERN = r"\S+"

BVI_CONFIG_COMMAND_TEMPLATE = (
    "etcdctl get --print-value-only "
    "/vnf-agent/vpp1/config/vpp/v2/interfaces/bvi{{id}}"
)
BVI_CONFIG_SUCCESS_PATTERN = r"\S+"
BRIDGE_DOMAIN_COMMAND = "/opt/dbappsecurity/bin/vppctl show bridge-domain"
BRIDGE_DOMAIN_SUCCESS_PATTERN = r"\S+"
# 指定 BD 的 scoped 形态（与 mac-age show 同命令形状）：只回该 BD 一个表项
BRIDGE_DOMAIN_SCOPED_COMMAND_TEMPLATE = (
    "/opt/dbappsecurity/bin/vppctl show bridge-domain {{bridge_domain_id}}"
)

NEIGHBOR_PROBE_COMMAND = "/opt/dbappsecurity/bin/vppctl show ip neighbor"
NEIGHBOR_PROBE_SUCCESS_PATTERN = r"Time\s+IP"
BRIDGE_DOMAIN_MAC_AGE_SET_TEMPLATE = (
    "/opt/dbappsecurity/bin/vppctl set bridge-domain mac-age {{bridge_domain_id}} {{age_minutes}}"
)
BRIDGE_DOMAIN_MAC_AGE_SHOW_TEMPLATE = (
    "/opt/dbappsecurity/bin/vppctl show bridge-domain {{bridge_domain_id}}"
)
# show 表头锚点；vppctl set 成功时 stdout 为空、参数错误打到 stderr 且非零退出
BRIDGE_DOMAIN_SHOW_SUCCESS_PATTERN = r"BD-ID"
# show 表头列 → 规范化字段，按表头出现顺序（仿 L2FIB_COLUMNS）
BRIDGE_DOMAIN_COLUMNS = (
    ("bd_id", "BD-ID"),
    ("index", "Index"),
    ("bsn", "BSN"),
    ("age_minutes", "Age(min)"),
    ("learning", "Learning"),
    ("u_forward", "U-Forwrd"),
    ("uu_flood", "UU-Flood"),
    ("flooding", "Flooding"),
    ("arp_term", "ARP-Term"),
    ("arp_ufwd", "arp-ufwd"),
    ("bvi_intf", "BVI-Intf"),
    ("ha_f", "HA-F"),
)
_MAC_AGE_SET_FAILURE_RE = re.compile(r"(?i)expecting|error|invalid|unknown")

# iplink / linkgroup 后端 etcd 校验（链路探测, houjialin 2026-10-19 上游化）
# 全路径 etcdctl + HTTPS endpoint(23790) + 客户端证书；非交互 SSH 的 PATH 不含 /opt/dbappsecurity/bin
_IPLINK_ETCD_PREFIX = (
    "ETCDCTL_API=3 /opt/dbappsecurity/bin/etcdctl --endpoints=https://127.0.0.1:23790 "
    "--cacert=/appdata/etc/etcdcerts/ca.pem --cert=/appdata/etc/etcdcerts/etcd-client.pem "
    "--key=/appdata/etc/etcdcerts/etcd-client-key.pem get --print-value-only "
)
IPLINK_ETCD_COMMAND_TEMPLATE = _IPLINK_ETCD_PREFIX + "/vnf-agent/vpp1/config/vpp/iplink/v1/iplink/{{name}}"
LINKGROUP_ETCD_COMMAND_TEMPLATE = _IPLINK_ETCD_PREFIX + "/vnf-agent/vpp1/config/vpp/iplink/v1/linkgroup/{{name}}"
_IPLINK_STATUS_PREFIX = (
    "ETCDCTL_API=3 /opt/dbappsecurity/bin/etcdctl --endpoints=https://127.0.0.1:23790 "
    "--cacert=/appdata/etc/etcdcerts/ca.pem --cert=/appdata/etc/etcdcerts/etcd-client.pem "
    "--key=/appdata/etc/etcdcerts/etcd-client-key.pem get "
)
IPLINK_STATUS_ETCD_TEMPLATE = _IPLINK_STATUS_PREFIX + "/vnf-agent/vpp1/config/vpp/iplink/v1/status/iplink/{name}/{state}"
LINKGROUP_STATUS_ETCD_TEMPLATE = _IPLINK_STATUS_PREFIX + "/vnf-agent/vpp1/config/vpp/iplink/v1/status/linkgroup/{name}/{state}"
ETCD_CONFIG_SUCCESS_PATTERN = r"\S+"


def _validate_status_args(name: str, state: str) -> None:
    """status key 路径的 name/state 直接拼接(不走 shlex.quote,引号会破坏 etcd key),须白名单校验。"""
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", name):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "name contains characters not allowed in etcd key path.",
            {"name": name},
        )
    if state not in ("up", "down"):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "state must be 'up' or 'down'.",
            {"state": state},
        )


def _render_status_command(name: str, state: str, *, linkgroup: bool = False) -> str:
    """拼接 status key 查询命令(参数经白名单校验后直接拼,不 shell 转义)。"""
    _validate_status_args(name, state)
    if linkgroup:
        return LINKGROUP_STATUS_ETCD_TEMPLATE.format(name=name, state=state)
    return IPLINK_STATUS_ETCD_TEMPLATE.format(name=name, state=state)


SSH_DEFAULT_PORT = 22
TELNET_DEFAULT_PORT = 23


@dataclass
class ShellCommandResult:
    stdout: str
    stderr: str
    exit_code: int


def render_command(template: str, params: dict[str, Any]) -> str:
    """Substitute {{param}} placeholders with shell-escaped values.

    The profile MUST NOT pre-encode metacharacters; the runner owns escaping.
    """
    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        if key not in params:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                f"Missing shell command parameter: {key}",
                {"missing_param": key},
                retryable=False,
            )
        return shlex.quote(str(params[key]))

    return re.sub(r"\{\{([a-z][a-z0-9_]*)\}\}", _replace, template)


def evaluate_success(result: ShellCommandResult, success_pattern: str) -> bool:
    """Return True only when exit_code is 0 AND success_pattern matches stdout.

    Matching against stderr is intentionally avoided so that transport-level
    errors surfaced on stderr (e.g. "Permission denied", "Connection refused")
    cannot accidentally satisfy the success pattern.
    """
    if result.exit_code != 0:
        return False
    pattern = re.compile(success_pattern)
    return bool(pattern.search(result.stdout))


def _shell_output_succeeded(
    result: ShellCommandResult,
    success_pattern: str,
    *,
    acceptable_exit_codes: set[int],
) -> bool:
    """Return True when the exit code is acceptable AND stdout matches the pattern."""
    if result.exit_code not in acceptable_exit_codes:
        return False
    pattern = re.compile(success_pattern)
    return bool(pattern.search(result.stdout))


def _load_dotenv() -> None:
    """Load KEY=VALUE pairs from a .env file in the working directory.

    Mirrors the ptm-te-manaul topology/.env convention so credentials shared
    with web login (FW_WEB_PASSWORD / FW_SSH_PASSWORD / FW_TELNET_PASSWORD)
    are available without an explicit export. Existing environment variables
    take precedence; the file is ignored when absent.
    """
    env_path = Path.cwd() / ".env"
    if not env_path.is_file():
        return
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _read_credential_env(env_name: str) -> str:
    _load_dotenv()
    value = os.environ.get(env_name)
    if value is None or not value:
        # STORY-S6-02：.env 已自动加载仍缺失，属环境变量未注入；与认证失败分层，
        # 消息点名环境变量并附注入指引，不回显凭据值
        raise credential_missing_error(env_name)
    return value


def _host_from_base_url(base_url: str) -> str:
    parsed = urlparse(base_url)
    host = parsed.hostname
    if not host:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "base_url does not contain a usable host.",
            {"base_url": base_url},
        )
    return host


def _resolve_host(*, explicit_host: str | None, base_url: str) -> str:
    """Return explicit_host if provided, otherwise parse host from base_url."""
    if explicit_host:
        return explicit_host
    return _host_from_base_url(base_url)


def _username_from_session(session_payload: dict[str, Any], *, default: str = "admin") -> str:
    username = session_payload.get("username")
    if isinstance(username, str) and username.strip():
        return username
    return default


def _username_preview(session_file: Path, *, default: str = "admin") -> str:
    """Resolve the username for a dry-run request preview without requiring a session file."""
    try:
        session_payload = read_session_file(session_file)
    except RunnerError:
        return default
    return _username_from_session(session_payload)


def _default_port(transport: str) -> int:
    return TELNET_DEFAULT_PORT if transport == "telnet" else SSH_DEFAULT_PORT


# ── Transport primitives ─────────────────────────────────


def _run_ssh_command(
    *,
    host: str,
    port: int,
    username: str,
    credential: str,
    command: str,
    timeout: float,
) -> ShellCommandResult:
    """Execute a remote command over SSH.

    Uses paramiko (pure-Python SSH) as the primary transport so that password
    authentication works cross-platform without sshpass. When the credential is
    empty, key-based auth (SSH agent or default identity files) is attempted.
    """
    try:
        import paramiko  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RunnerError(
            "RUNNER_SHELL_CONNECT_FAILED",
            "paramiko is required for SSH transport but is not installed.",
            {"host": host, "port": port, "missing_dependency": "paramiko"},
            retryable=False,
        ) from exc

    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    connect_kwargs: dict[str, Any] = {
        "hostname": host,
        "port": port,
        "username": username,
        "timeout": timeout,
        "allow_agent": True,
        "look_for_keys": True,
    }
    if credential:
        connect_kwargs["password"] = credential

    try:
        client.connect(**connect_kwargs)
    except paramiko.AuthenticationException as exc:
        raise RunnerError(
            "RUNNER_SHELL_CONNECT_FAILED",
            f"SSH authentication failed for user {username!r}.",
            {"host": host, "port": port, "username": username},
            retryable=False,
        ) from exc
    except (paramiko.SSHException, socket.error, OSError) as exc:
        raise RunnerError(
            "RUNNER_SHELL_CONNECT_FAILED",
            f"SSH connection to {host}:{port} failed.",
            {"host": host, "port": port, "error": str(exc)},
            retryable=True,
        ) from exc

    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        stdin.close()
        stdout_bytes = stdout.read()
        stderr_bytes = stderr.read()
        exit_code = stdout.channel.recv_exit_status()
    except socket.timeout as exc:
        raise RunnerError(
            "RUNNER_SHELL_COMMAND_TIMEOUT",
            "SSH command did not complete within the timeout.",
            {"host": host, "port": port, "timeout_s": timeout, "command": command},
            retryable=True,
        ) from exc
    finally:
        client.close()

    return ShellCommandResult(
        stdout=stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else "",
        stderr=stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else "",
        exit_code=exit_code,
    )


def _run_telnet_command(
    *,
    host: str,
    port: int,
    username: str,
    credential: str,
    command: str,
    timeout: float,
) -> ShellCommandResult:
    """Connect via Telnet, perform login, run command, return output.

    Uses telnetlib (Python stdlib, deprecated in 3.11, removed in 3.13).
    """
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            import telnetlib
    except ImportError as exc:
        raise RunnerError(
            "RUNNER_SHELL_CONNECT_FAILED",
            "telnetlib is not available in this Python version (removed in 3.13+).",
            {"host": host, "port": port, "python_requirement": ">=3.11,<3.13"},
            retryable=False,
        ) from exc

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            tn = telnetlib.Telnet(host, port, timeout=timeout)
    except (OSError, ConnectionRefusedError, socket.timeout) as exc:
        raise RunnerError(
            "RUNNER_SHELL_CONNECT_FAILED",
            f"Telnet connection to {host}:{port} failed.",
            {"host": host, "port": port, "error": str(exc)},
            retryable=True,
        ) from exc

    try:
        tn.read_until(b"ogin:", timeout=timeout)
        tn.write(username.encode("utf-8") + b"\n")

        tn.read_until(b"assword:", timeout=timeout)
        tn.write(credential.encode("utf-8") + b"\n")

        time.sleep(0.5)
        tn.read_very_eager()

        tn.write(command.encode("utf-8") + b"\n")

        raw_output = tn.read_until(b"#", timeout=timeout)
        if not raw_output:
            raw_output = tn.read_until(b"$", timeout=1)
        if not raw_output:
            raw_output = tn.read_until(b">", timeout=1)

        tn.write(b"exit\n")
    except EOFError as exc:
        raise RunnerError(
            "RUNNER_SHELL_CONNECT_FAILED",
            "Telnet session closed unexpectedly during command execution.",
            {"host": host, "port": port},
            retryable=False,
        ) from exc
    except socket.timeout as exc:
        raise RunnerError(
            "RUNNER_SHELL_COMMAND_TIMEOUT",
            "Telnet command did not complete within the timeout.",
            {"host": host, "port": port, "timeout_s": timeout, "command": command},
            retryable=True,
        ) from exc
    finally:
        tn.close()

    text = raw_output.decode("utf-8", errors="replace")
    lines = text.splitlines()
    stdout_lines: list[str] = []
    found_echo = False
    for line in lines:
        if not found_echo and command in line:
            found_echo = True
            continue
        stdout_lines.append(line)
    if stdout_lines and re.search(r"[#>$]\s*$", stdout_lines[-1].strip()):
        stdout_lines.pop()
    stdout = "\n".join(stdout_lines).strip()

    return ShellCommandResult(stdout=stdout, stderr="", exit_code=0)


def _run_shell_command(
    *,
    transport: str,
    host: str,
    port: int,
    username: str,
    credential: str,
    command: str,
    timeout: float,
) -> ShellCommandResult:
    """Route to the transport-specific executor based on the transport value."""
    if transport == "ssh":
        return _run_ssh_command(
            host=host, port=port, username=username, credential=credential,
            command=command, timeout=timeout,
        )
    if transport == "telnet":
        return _run_telnet_command(
            host=host, port=port, username=username, credential=credential,
            command=command, timeout=timeout,
        )
    raise RunnerError(
        "RUNNER_UNSUPPORTED_OP",
        f"Unsupported shell transport: {transport!r}. Supported: ssh, telnet.",
        {"transport": transport, "supported": ["ssh", "telnet"]},
        retryable=False,
    )


# ── Unified query executor ───────────────────────────────


def _execute_shell_op(
    *,
    op_id: str,
    transport: str,
    command: str,
    success_pattern: str,
    result_key: str,
    stdout_ref_label: str,
    base_url: str,
    session_file: Path,
    host: str | None,
    port: int | None,
    credential_env: str,
    timeout: float,
    username: str | None = None,
) -> dict[str, Any]:
    """Shared shell executor for read-only atoms over SSH or Telnet.

    Selects the transport primitive based on ``transport`` (ssh/telnet),
    asserts the success pattern against stdout, and returns the raw output
    under ``result[result_key]`` —— 与 dry-run 构造同形的**顶层**键。
    ``username`` overrides the session-file username (e.g. root for vppctl);
    None falls back to the session file.

    注意：调用方 run_cli 出口 ``_to_run_envelope`` 会把 payload 剩余字段整体
    包进 ``envelope["data"]``，本函数若再自建一层 ``"data"``，对外就变成
    ``envelope.data.data.<key>``，而 atom 的 ``returns`` 声明的是单层
    ``data.<key>`` → ``${STEP.n.<key>}`` 恒解析失败。故此处一律平铺。
    """
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or _username_from_session(session_payload)
    credential = _read_credential_env(credential_env)

    result = _run_shell_command(
        transport=transport,
        host=target_host,
        port=target_port,
        username=effective_username,
        credential=credential,
        command=command,
        timeout=timeout,
    )

    if not evaluate_success(result, success_pattern):
        raise RunnerError(
            "STATE_MISMATCH",
            f"Shell command output did not match the success pattern for {op_id}.",
            {
                "op_id": op_id,
                "transport": transport,
                "exit_code": result.exit_code,
                "stdout_preview": (result.stdout[:200] if result.stdout else ""),
                "stderr_preview": (result.stderr[:200] if result.stderr else ""),
            },
        )

    return {
        "op_id": op_id,
        "status": "success",
        "transport": transport,
        result_key: result.stdout.strip(),
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": effective_username,
        },
        "response": {
            "exit_code": result.exit_code,
            "stdout_ref": stdout_ref_label,
            "stderr_ref": "<diag-snapshot-ref>",
        },
        "diag_snapshot_ref": "<diag-snapshot-ref>",
    }


# ── fw_verify_system_version ──────────────────────────────


def build_verify_system_version_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    expected_version: str | None,
    timeout: float,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    username = _username_from_session(session_payload)
    return {
        "op_id": "fw_verify_system_version",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": VERSION_COMMAND,
            "host": target_host,
            "port": target_port,
            "username": username,
            "success_pattern": VERSION_SUCCESS_PATTERN,
        },
        "expected_version": expected_version,
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_system_version(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    credential_env: str,
    expected_version: str | None,
    timeout: float,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    username = _username_from_session(session_payload)
    credential = _read_credential_env(credential_env)

    result = _run_shell_command(
        transport=transport,
        host=target_host,
        port=target_port,
        username=username,
        credential=credential,
        command=VERSION_COMMAND,
        timeout=timeout,
    )

    if not evaluate_success(result, VERSION_SUCCESS_PATTERN):
        raise RunnerError(
            "STATE_MISMATCH",
            "Version file output did not match the success pattern.",
            {
                "op_id": "fw_verify_system_version",
                "transport": transport,
                "exit_code": result.exit_code,
                "stdout_preview": (result.stdout[:200] if result.stdout else ""),
                "stderr_preview": (result.stderr[:200] if result.stderr else ""),
            },
        )

    version_raw = result.stdout.strip()
    matches_expected = True
    if expected_version:
        matches_expected = expected_version in version_raw

    return {
        "op_id": "fw_verify_system_version",
        "status": "success",
        "transport": transport,
        "version_raw": version_raw,
        "matches_expected": matches_expected,
        "request": {
            "command": VERSION_COMMAND,
            "host": target_host,
            "port": target_port,
            "username": username,
        },
        "response": {
            "exit_code": result.exit_code,
            "stdout_ref": "<version-raw-ref>",
            "stderr_ref": "<diag-snapshot-ref>",
        },
        "diag_snapshot_ref": "<diag-snapshot-ref>",
    }


# ── fw_check_bvi_interface_config ────────────────────────


def build_check_bvi_interface_config_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    bvi_id: str,
    timeout: float,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    username = _username_from_session(session_payload)
    command = render_command(BVI_CONFIG_COMMAND_TEMPLATE, {"id": bvi_id})
    return {
        "op_id": "fw_check_bvi_interface_config",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": username,
            "success_pattern": BVI_CONFIG_SUCCESS_PATTERN,
        },
        "bvi_id": bvi_id,
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_check_bvi_interface_config(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    credential_env: str,
    bvi_id: str,
    timeout: float,
) -> dict[str, Any]:
    command = render_command(BVI_CONFIG_COMMAND_TEMPLATE, {"id": bvi_id})
    return _execute_shell_op(
        op_id="fw_check_bvi_interface_config",
        transport=transport,
        command=command,
        success_pattern=BVI_CONFIG_SUCCESS_PATTERN,
        result_key="config_raw",
        stdout_ref_label="<config-raw-ref>",
        base_url=base_url,
        session_file=session_file,
        host=host,
        port=port,
        credential_env=credential_env,
        timeout=timeout,
    )


# ── fw_check_bridge_domain ────────────────────────────────


def _bridge_domain_query(*, bridge_domain_id: int | None) -> tuple[str, str]:
    """返回 (command, success_pattern)。

    不给 ``bridge_domain_id`` 时查全表，沿用 ``\\S+`` 宽松成功模式；给了则只查该
    BD，并用表头锚点 ``BD-ID`` 判定 —— 目标 BD 不存在时 vppctl 没有表头行，
    判 STATE_MISMATCH 而不是被 ``\\S+`` 放过。
    """
    if bridge_domain_id is None:
        return BRIDGE_DOMAIN_COMMAND, BRIDGE_DOMAIN_SUCCESS_PATTERN
    _validate_bridge_domain_id(bridge_domain_id)
    return (
        render_command(
            BRIDGE_DOMAIN_SCOPED_COMMAND_TEMPLATE,
            {"bridge_domain_id": bridge_domain_id},
        ),
        BRIDGE_DOMAIN_SHOW_SUCCESS_PATTERN,
    )


def build_check_bridge_domain_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    timeout: float,
    bridge_domain_id: int | None = None,
) -> dict[str, Any]:
    command, success_pattern = _bridge_domain_query(bridge_domain_id=bridge_domain_id)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    username = _username_from_session(session_payload)
    return {
        "op_id": "fw_check_bridge_domain",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": username,
            "success_pattern": success_pattern,
        },
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_check_bridge_domain(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    credential_env: str,
    timeout: float,
    bridge_domain_id: int | None = None,
) -> dict[str, Any]:
    command, success_pattern = _bridge_domain_query(bridge_domain_id=bridge_domain_id)
    return _execute_shell_op(
        op_id="fw_check_bridge_domain",
        transport=transport,
        command=command,
        success_pattern=success_pattern,
        result_key="bridge_domain_raw",
        stdout_ref_label="<bridge-domain-raw-ref>",
        base_url=base_url,
        session_file=session_file,
        host=host,
        port=port,
        credential_env=credential_env,
        timeout=timeout,
    )


# ── tgfw-cli interactive session (fw_verify_l2fib) ───────


TGFW_CLI_PROMPT = "DAS-TGFW>"
L2FIB_COMMAND = "show l2fib all"
L2FIB_SUCCESS_PATTERN = r"(L2FIB total/learned entries|no l2fib entries)"

# L2FIB 表头列名到结构化字段名的映射，按表头出现顺序排列。
L2FIB_COLUMNS = (
    ("mac_address", "Mac-Address"),
    ("bd_idx", "BD-Idx"),
    ("if_idx", "If-Idx"),
    ("bsn_isn", "BSN-ISN"),
    ("age", "Age(min)"),
    ("static", "static"),
    ("filter", "filter"),
    ("bvi", "bvi"),
    ("sync", "SYNC"),
    ("interface_name", "Interface-Name"),
)


def _recv_until(
    channel: Any,
    needle: bytes,
    timeout: float,
    *,
    host: str,
    port: int,
) -> bytes:
    """Read from the channel until needle appears; return everything read so far.

    Raises RUNNER_SHELL_COMMAND_TIMEOUT on deadline exhaustion and
    RUNNER_SHELL_CONNECT_FAILED when the remote side closes the session early.
    """
    deadline = time.monotonic() + timeout
    data = b""
    while needle not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RunnerError(
                "RUNNER_SHELL_COMMAND_TIMEOUT",
                "Interactive CLI session did not produce the expected prompt within the timeout.",
                {
                    "host": host,
                    "port": port,
                    "timeout_s": timeout,
                    "collected_tail": repr(data[-200:]),
                },
                retryable=True,
            )
        try:
            chunk = channel.recv(4096)
        except socket.timeout as exc:
            raise RunnerError(
                "RUNNER_SHELL_COMMAND_TIMEOUT",
                "Interactive CLI session did not produce the expected prompt within the timeout.",
                {
                    "host": host,
                    "port": port,
                    "timeout_s": timeout,
                    "collected_tail": repr(data[-200:]),
                },
                retryable=True,
            ) from exc
        if not chunk:
            raise RunnerError(
                "RUNNER_SHELL_CONNECT_FAILED",
                "Interactive CLI session closed before the expected prompt was seen.",
                {"host": host, "port": port},
                retryable=False,
            )
        data += chunk
    return data


_GRAY_SEGMENT_RE = re.compile(r"\x1b\[90m[^\x1b]*\x1b\[0m")


def _cli_output_is_echo(data: bytes, command: str, prompt: str) -> bool:
    """Return True when every non-empty line of the captured block is a command echo frame.

    Interactive shells echo ``DAS-TGFW> show l2fib all`` back before producing
    output; the prompt inside the echo line would otherwise satisfy
    _recv_until early and truncate the real table output. The check is
    all-lines: the block must not contain any real output line (for example
    ``no l2fib entries``), otherwise the trailing prompt frame after the
    command output would keep the caller waiting for data that never arrives.

    The device re-renders the input line on every keystroke; each frame shows
    the typed characters in the default color and the completion candidate in
    gray (``\\x1b[90m``). Gray segments are dropped so that only the typed
    prefix remains, which must be a prefix of the command being echoed.
    """
    lines: list[str] = []
    for line in data.decode("utf-8", errors="replace").splitlines():
        line = _GRAY_SEGMENT_RE.sub("", line)
        line = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", line).strip()
        if line:
            lines.append(line)
    if not lines:
        return False
    for line in lines:
        if not line.startswith(prompt):
            return False
        tail = line[len(prompt) :].lstrip()
        if not tail or not command.startswith(tail):
            return False
    return True


def _run_ssh_cli_session(
    *,
    host: str,
    port: int,
    username: str,
    credential: str,
    command: str,
    prompt: str,
    timeout: float,
) -> ShellCommandResult:
    """Run one command inside an interactive tgfw-cli session over SSH.

    The device lands directly in the tgfw-cli prompt after login (no extra
    entry command). A PTY with a wide terminal is requested so that aligned
    tables are returned without line wrapping.
    """
    try:
        import paramiko  # type: ignore[import-not-found]
    except ImportError as exc:
        raise RunnerError(
            "RUNNER_SHELL_CONNECT_FAILED",
            "paramiko is required for SSH transport but is not installed.",
            {"host": host, "port": port, "missing_dependency": "paramiko"},
            retryable=False,
        ) from exc

    logging.getLogger("paramiko").setLevel(logging.CRITICAL)

    # 用 Transport 层直接认证：auth_password 优先，失败后回退 keyboard-interactive，
    # 兼容只提供 keyboard-interactive 的设备（SSHClient.connect 不暴露该回退）
    def _interactive_handler(title: str, instructions: str, prompt_list: list[Any]) -> list[str]:
        return [credential] * len(prompt_list)

    sock: socket.socket | None = None
    transport: Any = None
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        transport = paramiko.Transport(sock)
        transport.banner_timeout = timeout
        transport.auth_timeout = timeout
        transport.connect()

        try:
            if credential:
                transport.auth_password(username, credential)
            else:
                transport.auth_interactive(username, _interactive_handler)
        except paramiko.AuthenticationException:
            try:
                transport.auth_interactive(username, _interactive_handler)
            except paramiko.AuthenticationException as exc:
                raise RunnerError(
                    "RUNNER_SHELL_CONNECT_FAILED",
                    f"SSH authentication failed for user {username!r}.",
                    {"host": host, "port": port, "username": username},
                    retryable=False,
                ) from exc

        channel = transport.open_session()
        channel.get_pty(width=200, height=50)
        channel.invoke_shell()
        channel.settimeout(timeout)
    except RunnerError:
        raise
    except (paramiko.SSHException, socket.error, OSError) as exc:
        raise RunnerError(
            "RUNNER_SHELL_CONNECT_FAILED",
            f"SSH connection to {host}:{port} failed.",
            {"host": host, "port": port, "error": str(exc)},
            retryable=True,
        ) from exc

    try:
        # SSH 认证已在 transport 层完成（auth_password / keyboard-interactive），
        # invoke_shell 直接进入设备 shell，登录后直接进入 tgfw-cli，等待 CLI 提示符即可
        _recv_until(channel, prompt.encode("utf-8"), timeout, host=host, port=port)

        # 发送查询命令，收集输出直到提示符再次出现；
        # 该 CLI 以 \r 作为行提交符（\n 不会被提交执行）；
        # 跳过命令回显帧（逐字符补全重绘，含 prompt 的回显会使 _recv_until 提前返回）
        channel.send(command.encode("utf-8") + b"\r")
        raw_output = _recv_until(channel, prompt.encode("utf-8"), timeout, host=host, port=port)
        while _cli_output_is_echo(raw_output, command, prompt):
            raw_output += _recv_until(channel, prompt.encode("utf-8"), timeout, host=host, port=port)

        # 退出 tgfw-cli：等待设备关闭会话（EOF）后再断开，避免设备侧残留会话占满并发配额
        channel.send(b"exit\r")
        channel.settimeout(5.0)
        try:
            while channel.recv(4096):
                pass
        except (socket.timeout, EOFError):
            pass
        channel.settimeout(timeout)
    except EOFError as exc:
        raise RunnerError(
            "RUNNER_SHELL_CONNECT_FAILED",
            "SSH CLI session closed unexpectedly during command execution.",
            {"host": host, "port": port},
            retryable=False,
        ) from exc
    except socket.timeout as exc:
        raise RunnerError(
            "RUNNER_SHELL_COMMAND_TIMEOUT",
            "SSH CLI session did not complete within the timeout.",
            {"host": host, "port": port, "timeout_s": timeout, "command": command},
            retryable=True,
        ) from exc
    finally:
        if transport is not None:
            transport.close()
        if sock is not None:
            sock.close()

    stdout = _extract_cli_command_output(raw_output, command, prompt)
    return ShellCommandResult(stdout=stdout, stderr="", exit_code=0)


def _run_telnet_cli_session(
    *,
    host: str,
    port: int,
    username: str,
    credential: str,
    command: str,
    prompt: str,
    timeout: float,
) -> ShellCommandResult:
    """Run one command inside an interactive tgfw-cli session over Telnet."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            import telnetlib
    except ImportError as exc:
        raise RunnerError(
            "RUNNER_SHELL_CONNECT_FAILED",
            "telnetlib is not available in this Python version (removed in 3.13+).",
            {"host": host, "port": port, "python_requirement": ">=3.11,<3.13"},
            retryable=False,
        ) from exc

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            tn = telnetlib.Telnet(host, port, timeout=timeout)
    except (OSError, ConnectionRefusedError, socket.timeout) as exc:
        raise RunnerError(
            "RUNNER_SHELL_CONNECT_FAILED",
            f"Telnet connection to {host}:{port} failed.",
            {"host": host, "port": port, "error": str(exc)},
            retryable=True,
        ) from exc

    try:
        # 累计各阶段返回内容，EOF 时用于诊断登录失败原因
        session_dump = b""
        session_dump += tn.read_until(b"ogin:", timeout=timeout)
        tn.write(username.encode("utf-8") + b"\r")
        session_dump += tn.read_until(b"assword:", timeout=timeout)
        tn.write(credential.encode("utf-8") + b"\r")

        # 登录后直接进入 tgfw-cli，等待 CLI 提示符
        session_dump += tn.read_until(prompt.encode("utf-8"), timeout=timeout)

        tn.write(command.encode("utf-8") + b"\r")
        raw_output = tn.read_until(prompt.encode("utf-8"), timeout=timeout)
        while _cli_output_is_echo(raw_output, command, prompt):
            raw_output += tn.read_until(prompt.encode("utf-8"), timeout=timeout)

        tn.write(b"exit\r")
        time.sleep(1.0)
    except EOFError as exc:
        tail = session_dump.decode("utf-8", errors="replace")[-300:]
        raise RunnerError(
            "RUNNER_SHELL_CONNECT_FAILED",
            "Telnet CLI session closed unexpectedly during command execution.",
            {"host": host, "port": port, "session_tail": tail},
            retryable=False,
        ) from exc
    except socket.timeout as exc:
        raise RunnerError(
            "RUNNER_SHELL_COMMAND_TIMEOUT",
            "Telnet CLI session did not complete within the timeout.",
            {"host": host, "port": port, "timeout_s": timeout, "command": command},
            retryable=True,
        ) from exc
    finally:
        tn.close()

    stdout = _extract_cli_command_output(raw_output, command, prompt)
    return ShellCommandResult(stdout=stdout, stderr="", exit_code=0)


def _extract_cli_command_output(raw_output: bytes, command: str, prompt: str) -> str:
    """Strip ANSI escapes, input redraw frames, and the trailing prompt from CLI output.

    The tgfw-cli re-renders the input line with ANSI control sequences on every
    keystroke (each frame contains the prompt), so any line containing the prompt
    is an input-area frame and is discarded; only the actual command output remains.
    """
    text = raw_output.decode("utf-8", errors="replace")
    text = re.sub(r"\x1b\[[0-9;?]*[A-Za-z]", "", text)  # 剥离 ANSI 转义（颜色/清行/光标）
    lines = text.splitlines()
    stdout_lines: list[str] = []
    for line in lines:
        if prompt in line:
            continue
        stdout_lines.append(line)
    return "\n".join(stdout_lines).strip()


def _run_cli_session_command(
    *,
    transport: str,
    host: str,
    port: int,
    username: str,
    credential: str,
    command: str,
    prompt: str,
    timeout: float,
) -> ShellCommandResult:
    """Route an interactive CLI session command to the transport executor."""
    if transport == "ssh":
        return _run_ssh_cli_session(
            host=host, port=port, username=username, credential=credential,
            command=command, prompt=prompt, timeout=timeout,
        )
    if transport == "telnet":
        return _run_telnet_cli_session(
            host=host, port=port, username=username, credential=credential,
            command=command, prompt=prompt, timeout=timeout,
        )
    raise RunnerError(
        "RUNNER_UNSUPPORTED_OP",
        f"Unsupported shell transport: {transport!r}. Supported: ssh, telnet.",
        {"transport": transport, "supported": ["ssh", "telnet"]},
        retryable=False,
    )


def parse_l2fib_table(raw: str) -> dict[str, Any]:
    """Parse the 'show l2fib all' table into a structured dictionary.

    Data rows are first split on whitespace runs (every column is separated by
    multiple spaces and no field contains an internal space). If a row does not
    yield exactly the expected number of columns, it falls back to fixed-width
    slicing anchored at the header line.
    """
    lines = raw.splitlines()
    # 1. 定位表头行（含 Mac-Address 与 Interface-Name 的列标题行）
    header_index = None
    for i, line in enumerate(lines):
        if "Mac-Address" in line and "Interface-Name" in line:
            header_index = i
            break
    entries: list[dict[str, str]] = []
    if header_index is not None:
        header = lines[header_index]
        # 表头各列起始位置，仅作为列宽兜底
        starts: list[tuple[str, int]] = []
        for field, label in L2FIB_COLUMNS:
            starts.append((field, header.find(label)))
        field_names = [field for field, _ in L2FIB_COLUMNS]
        # 2. 数据行：表头之后直到摘要行
        for line in lines[header_index + 1 :]:
            if not line.strip() or "L2FIB total" in line:
                break
            parts = line.split()
            if len(parts) == len(field_names):
                row = dict(zip(field_names, parts))
            else:
                # 兜底：按表头列边界切分
                row = {}
                for j, (field, start) in enumerate(starts):
                    if start < 0:
                        row[field] = ""
                        continue
                    end = starts[j + 1][1] if j + 1 < len(starts) else len(line)
                    row[field] = line[start:end].strip()
            entries.append(row)
    # 3. 摘要统计
    total = learned = limit = 0
    m = re.search(r"L2FIB total/learned entries:\s*(\d+)/(\d+)", raw)
    if m:
        total, learned = int(m.group(1)), int(m.group(2))
    m = re.search(r"Learn limit:\s*(\d+)", raw)
    if m:
        limit = int(m.group(1))
    return {
        "l2fib_entries": entries,
        "entry_count": len(entries),
        "total_entries": total,
        "learned_entries": learned,
        "learn_limit": limit,
    }


# ── fw_verify_l2fib ───────────────────────────────────────


def build_verify_l2fib_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    timeout: float,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    username = _username_from_session(session_payload)
    return {
        "op_id": "fw_verify_l2fib",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": L2FIB_COMMAND,
            "host": target_host,
            "port": target_port,
            "username": username,
            "prompt": TGFW_CLI_PROMPT,
            "success_pattern": L2FIB_SUCCESS_PATTERN,
            "session_flow": [
                "login as admin",
                "wait for DAS-TGFW> prompt",
                "send 'show l2fib all'",
                "capture output until prompt returns",
                "exit tgfw-cli",
            ],
        },
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_l2fib(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    credential_env: str,
    timeout: float,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    username = _username_from_session(session_payload)
    credential = _read_credential_env(credential_env)

    result = _run_cli_session_command(
        transport=transport,
        host=target_host,
        port=target_port,
        username=username,
        credential=credential,
        command=L2FIB_COMMAND,
        prompt=TGFW_CLI_PROMPT,
        timeout=timeout,
    )

    if not evaluate_success(result, L2FIB_SUCCESS_PATTERN):
        raise RunnerError(
            "STATE_MISMATCH",
            "L2FIB table output did not match the success pattern.",
            {
                "op_id": "fw_verify_l2fib",
                "transport": transport,
                "exit_code": result.exit_code,
                "stdout_preview": repr(result.stdout[:2000]) if result.stdout else "",
                "stderr_preview": (result.stderr[:2000] if result.stderr else ""),
            },
        )

    parsed = parse_l2fib_table(result.stdout)
    return {
        "op_id": "fw_verify_l2fib",
        "status": "success",
        "transport": transport,
        "l2fib_raw": result.stdout,
        "l2fib_entries": parsed["l2fib_entries"],
        "entry_count": parsed["entry_count"],
        "total_entries": parsed["total_entries"],
        "learned_entries": parsed["learned_entries"],
        "learn_limit": parsed["learn_limit"],
        "request": {
            "command": L2FIB_COMMAND,
            "host": target_host,
            "port": target_port,
            "username": username,
            "prompt": TGFW_CLI_PROMPT,
        },
        "response": {
            "exit_code": result.exit_code,
            "stdout_ref": "<l2fib-raw-ref>",
            "stderr_ref": "<diag-snapshot-ref>",
        },
        "diag_snapshot_ref": "<diag-snapshot-ref>",
    }


# ── bridge-domain MAC ageing (fw_config/fw_verify_bridge_domain_mac_age) ──


def parse_bridge_domain_table(raw: str) -> list[dict[str, str]]:
    """Parse the 'vppctl show bridge-domain [id]' table into structured rows.

    表头行定位后按各列起始位置做固定宽度切片（BVI-Intf/HA-F 等列间距不稳定，
    不能按空白切分）；数据行判定：BD-ID 列切片为纯数字（跳过空行与 banner）。
    """
    lines = raw.splitlines()
    header_index = None
    for i, line in enumerate(lines):
        if "BD-ID" in line and "Age(min)" in line:
            header_index = i
            break
    entries: list[dict[str, str]] = []
    if header_index is None:
        return entries
    header = lines[header_index]
    starts: list[tuple[str, int]] = [
        (field, header.find(label)) for field, label in BRIDGE_DOMAIN_COLUMNS
    ]
    for line in lines[header_index + 1 :]:
        if not line.strip():
            continue
        first_start = starts[0][1]
        second_start = starts[1][1]
        first_cell = line[first_start:second_start].strip()
        if not first_cell.isdigit():
            continue
        row: dict[str, str] = {}
        for j, (field, start) in enumerate(starts):
            if start < 0:
                row[field] = ""
                continue
            end = starts[j + 1][1] if j + 1 < len(starts) else len(line)
            row[field] = line[start:end].strip()
        entries.append(row)
    return entries


def _validate_bridge_domain_id(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 4094:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "bridge_domain_id must be an integer in 1..4094.",
            {"field": "bridge_domain_id", "value": value},
            retryable=False,
        )
    return value


def _validate_age_minutes(value: int) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "age_minutes must be a non-negative integer (0 disables ageing).",
            {"field": "age_minutes", "value": value},
            retryable=False,
        )
    return value


def _show_output_valid(result: ShellCommandResult) -> bool:
    """show 输出有效性判定：exit 0 或 -1 且 stdout 含表头。

    设备偶发不返回 exec 通道的 exit status（``recv_exit_status`` 得 -1）但
    命令实际已执行、stdout 已完整捕获；此时以输出内容为准。exit 非 0 或
    stdout 无表头则视为无效。
    """
    if result.exit_code not in (0, -1):
        return False
    return bool(re.search(BRIDGE_DOMAIN_SHOW_SUCCESS_PATTERN, result.stdout))


def build_verify_bridge_domain_mac_age_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str,
    bridge_domain_id: int,
    timeout: float,
) -> dict[str, Any]:
    _validate_bridge_domain_id(bridge_domain_id)
    command = render_command(
        BRIDGE_DOMAIN_MAC_AGE_SHOW_TEMPLATE, {"bridge_domain_id": bridge_domain_id}
    )
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or _username_from_session(session_payload)
    return {
        "op_id": "fw_verify_bridge_domain_mac_age",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": effective_username,
            "success_pattern": BRIDGE_DOMAIN_SHOW_SUCCESS_PATTERN,
        },
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_bridge_domain_mac_age(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str,
    credential_env: str,
    bridge_domain_id: int,
    timeout: float,
) -> dict[str, Any]:
    _validate_bridge_domain_id(bridge_domain_id)
    command = render_command(
        BRIDGE_DOMAIN_MAC_AGE_SHOW_TEMPLATE, {"bridge_domain_id": bridge_domain_id}
    )
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or _username_from_session(session_payload)
    credential = _read_credential_env(credential_env)

    result = _run_shell_command(
        transport=transport,
        host=target_host,
        port=target_port,
        username=effective_username,
        credential=credential,
        command=command,
        timeout=timeout,
    )

    if not _show_output_valid(result):
        raise RunnerError(
            "STATE_MISMATCH",
            "Bridge-domain show output did not match the success pattern.",
            {
                "op_id": "fw_verify_bridge_domain_mac_age",
                "transport": transport,
                "bridge_domain_id": bridge_domain_id,
                "exit_code": result.exit_code,
                "stdout_preview": (result.stdout[:2000] if result.stdout else ""),
                "stderr_preview": (result.stderr[:2000] if result.stderr else ""),
            },
        )

    rows = parse_bridge_domain_table(result.stdout)
    if not rows:
        raise RunnerError(
            "STATE_MISMATCH",
            "Bridge-domain table contained no data row for the requested domain.",
            {
                "op_id": "fw_verify_bridge_domain_mac_age",
                "bridge_domain_id": bridge_domain_id,
                "stdout_preview": (result.stdout[:2000] if result.stdout else ""),
            },
        )
    return {
        "op_id": "fw_verify_bridge_domain_mac_age",
        "status": "success",
        "transport": transport,
        "bridge_domain_id": bridge_domain_id,
        "age_minutes": rows[0].get("age_minutes", ""),
        "bridge_domain_raw": result.stdout,
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": effective_username,
            "success_pattern": BRIDGE_DOMAIN_SHOW_SUCCESS_PATTERN,
        },
        "response": {
            "exit_code": result.exit_code,
            "stdout_ref": "<bridge-domain-raw-ref>",
            "stderr_ref": "<diag-snapshot-ref>",
        },
        "diag_snapshot_ref": "<diag-snapshot-ref>",
    }


def build_config_bridge_domain_mac_age_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str,
    bridge_domain_id: int,
    age_minutes: int,
    timeout: float,
) -> dict[str, Any]:
    _validate_bridge_domain_id(bridge_domain_id)
    _validate_age_minutes(age_minutes)
    set_command = render_command(
        BRIDGE_DOMAIN_MAC_AGE_SET_TEMPLATE,
        {"bridge_domain_id": bridge_domain_id, "age_minutes": age_minutes},
    )
    show_command = render_command(
        BRIDGE_DOMAIN_MAC_AGE_SHOW_TEMPLATE, {"bridge_domain_id": bridge_domain_id}
    )
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or _username_from_session(session_payload)
    return {
        "op_id": "fw_config_bridge_domain_mac_age",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": set_command,
            "verify_command": show_command,
            "host": target_host,
            "port": target_port,
            "username": effective_username,
            "success_pattern": "exit_code==0 and stderr free of expecting/error/invalid",
        },
        "session_file": str(session_file),
        "timeout": timeout,
    }


def _mac_age_set_failed(result: ShellCommandResult) -> bool:
    """vppctl set 明确失败判定：stderr 有报错文本，或退出码非 0 且非 -1。

    vppctl 参数错误（如只传 BD-ID）会把 ``expecting ...`` 打到 stderr 并以非零
    退出；成功时 stdout 为空，不能用 stdout pattern 判定。设备偶发在命令执行
    后不返回 exit status（``recv_exit_status`` 返回 -1 且通道全空），此时以
    回读验证为最终真相，不在此判定失败。
    """
    if result.exit_code not in (0, -1):
        return True
    if _MAC_AGE_SET_FAILURE_RE.search(result.stderr):
        return True
    return False


def execute_config_bridge_domain_mac_age(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str,
    credential_env: str,
    bridge_domain_id: int,
    age_minutes: int,
    timeout: float,
) -> dict[str, Any]:
    _validate_bridge_domain_id(bridge_domain_id)
    _validate_age_minutes(age_minutes)
    set_command = render_command(
        BRIDGE_DOMAIN_MAC_AGE_SET_TEMPLATE,
        {"bridge_domain_id": bridge_domain_id, "age_minutes": age_minutes},
    )
    show_command = render_command(
        BRIDGE_DOMAIN_MAC_AGE_SHOW_TEMPLATE, {"bridge_domain_id": bridge_domain_id}
    )
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or _username_from_session(session_payload)
    credential = _read_credential_env(credential_env)

    set_result = _run_shell_command(
        transport=transport,
        host=target_host,
        port=target_port,
        username=effective_username,
        credential=credential,
        command=set_command,
        timeout=timeout,
    )
    if _mac_age_set_failed(set_result):
        raise RunnerError(
            "STATE_MISMATCH",
            "vppctl set bridge-domain mac-age did not succeed.",
            {
                "op_id": "fw_config_bridge_domain_mac_age",
                "bridge_domain_id": bridge_domain_id,
                "age_minutes": age_minutes,
                "exit_code": set_result.exit_code,
                "stdout_preview": (set_result.stdout[:2000] if set_result.stdout else ""),
                "stderr_preview": (set_result.stderr[:2000] if set_result.stderr else ""),
            },
        )

    # 回读验证：同一凭据再次连接执行 show，解析 Age(min) 确认配置生效。
    # 设备偶发不返回 set 的 exit status（recv_exit_status 得 -1），回读是最终真相。
    show_result = _run_shell_command(
        transport=transport,
        host=target_host,
        port=target_port,
        username=effective_username,
        credential=credential,
        command=show_command,
        timeout=timeout,
    )
    rows = (
        parse_bridge_domain_table(show_result.stdout)
        if _show_output_valid(show_result)
        else []
    )
    age_minutes_actual = rows[0].get("age_minutes", "") if rows else ""
    verify_match = age_minutes_actual == str(age_minutes)
    if not verify_match:
        raise RunnerError(
            "STATE_MISMATCH",
            "Read-back Age(min) does not match the requested value.",
            {
                "op_id": "fw_config_bridge_domain_mac_age",
                "bridge_domain_id": bridge_domain_id,
                "age_minutes": age_minutes,
                "age_minutes_actual": age_minutes_actual,
                "show_exit_code": show_result.exit_code,
                "stdout_preview": (show_result.stdout[:2000] if show_result.stdout else ""),
                "stderr_preview": (show_result.stderr[:2000] if show_result.stderr else ""),
            },
        )
    return {
        "op_id": "fw_config_bridge_domain_mac_age",
        "status": "success",
        "transport": transport,
        "bridge_domain_id": bridge_domain_id,
        "age_minutes": age_minutes,
        "age_minutes_actual": age_minutes_actual,
        "verify_match": verify_match,
        "bridge_domain_raw": show_result.stdout,
        "request": {
            "command": set_command,
            "verify_command": show_command,
            "host": target_host,
            "port": target_port,
            "username": effective_username,
        },
        "response": {
            "exit_code": set_result.exit_code,
            "stdout_ref": "<bridge-domain-raw-ref>",
            "stderr_ref": "<diag-snapshot-ref>",
        },
        "diag_snapshot_ref": "<diag-snapshot-ref>",
    }


# ── ABF policy 生效状态（fw_verify_abf_policy） ───────────


ABF_POLICY_COMMAND = "/opt/dbappsecurity/bin/vppctl show abf policy"
# 表空时输出仅剩计数行（add_counts/del_counts 恒在），有表项时首行是 ``abf:[<i>]: policy-id:<id>``。
ABF_POLICY_SUCCESS_PATTERN = r"add_counts|abf:\["
# 表项行形如 ``abf:[98]: policy-id:10001 acl:10001, action 1, priority:1, sign:...``，
# 其后的缩进行是 path-list / path 明细（不含 policy-id），故按行首锚定。
_ABF_POLICY_ROW_RE = re.compile(r"\s*abf:\[(\d+)\]:\s*policy-id:(\d+)\s*(.*)$")
_ABF_RULES_COUNT_RE = re.compile(r"ip4 rules count:\s*(\d+)\s+ip6 rules count:\s*(\d+)")
ABF_POLICY_TYPES = ("ipv4", "ipv6")
# 用户口径（2026-09-21）：VPP ABF 表里 ipv6 策略路由的 policy-id 是 10000 + 业务 id
# （实测 ``policy-id:10001`` 对应 id=1 的 ipv6 策略路由），ipv4 直用业务 id。
ABF_IPV6_ID_OFFSET = 10000


def parse_abf_policy_table(raw: str) -> dict[str, Any]:
    """解析 ``vppctl show abf policy`` 输出为结构化表项与计数。

    只提取行首表项行的 ``policy-id``（缩进的 path 明细行一律跳过），另抓尾部的
    ``ip4 rules count: N ip6 rules count: M`` 便于诊断。
    """
    policies: list[dict[str, Any]] = []
    for line in raw.splitlines():
        match = _ABF_POLICY_ROW_RE.match(line)
        if not match:
            continue
        entry: dict[str, Any] = {
            "abf_index": int(match.group(1)),
            "policy_id": int(match.group(2)),
        }
        rest = match.group(3)
        acl = re.search(r"acl:(\d+)", rest)
        if acl:
            entry["acl"] = int(acl.group(1))
        priority = re.search(r"priority:(\d+)", rest)
        if priority:
            entry["priority"] = int(priority.group(1))
        policies.append(entry)
    parsed: dict[str, Any] = {
        "policies": policies,
        "policy_ids": [item["policy_id"] for item in policies],
    }
    counts = _ABF_RULES_COUNT_RE.search(raw)
    if counts:
        parsed["ip4_rules_count"] = int(counts.group(1))
        parsed["ip6_rules_count"] = int(counts.group(2))
    return parsed


def resolve_abf_policy_id(policy_route_id: int, policy_type: str) -> int:
    """业务策略路由 id → VPP ABF 表 policy-id。ipv4 直用；ipv6 加 10000。"""
    if policy_type not in ABF_POLICY_TYPES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ABF policy type is unsupported.",
            {"field": "policy_type", "actual": policy_type, "allowed": list(ABF_POLICY_TYPES)},
        )
    if policy_route_id < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ABF policy route id must be a non-negative integer.",
            {"field": "policy_route_id", "actual": policy_route_id},
        )
    return policy_route_id + ABF_IPV6_ID_OFFSET if policy_type == "ipv6" else policy_route_id


def build_verify_abf_policy_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None = None,
    policy_route_id: int,
    policy_type: str,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or "root"
    return {
        "op_id": "fw_verify_abf_policy",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": ABF_POLICY_COMMAND,
            "host": target_host,
            "port": target_port,
            "username": effective_username,
            "success_pattern": ABF_POLICY_SUCCESS_PATTERN,
        },
        "policy_route_id": policy_route_id,
        "policy_type": policy_type,
        "abf_policy_id": resolve_abf_policy_id(policy_route_id, policy_type),
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_abf_policy(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    credential_env: str,
    username: str | None = None,
    policy_route_id: int,
    policy_type: str,
    timeout: float,
) -> dict[str, Any]:
    """查 VPP ABF 表并断言目标 policy-id 在表内。

    判据（用户口径 2026-09-21）：**能查到 policy-id ⇒ 策略路由生效；查不到 ⇒ 不生效**
    （时间对象不在生效范围时设备不下发该 policy）。查不到按 ``STATE_MISMATCH`` 报错，
    负例用例用 ``expected_failure: true`` 表达「预期不生效」。
    """
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    resolved_user = username or "root"
    credential = _read_credential_env(credential_env)
    abf_policy_id = resolve_abf_policy_id(policy_route_id, policy_type)

    result = _run_shell_command(
        transport=transport,
        host=target_host,
        port=target_port,
        username=resolved_user,
        credential=credential,
        command=ABF_POLICY_COMMAND,
        timeout=timeout,
    )
    # 与 fw_verify_neighbor_probe 同一现象：vppctl 在该设备上不经 paramiko exec 通道
    # 回传标准退出码（实测恒 exit_code=-1 而 stdout 完整），故 -1 且带表头/计数行即算命令成功。
    if not _shell_output_succeeded(
        result, ABF_POLICY_SUCCESS_PATTERN, acceptable_exit_codes={0, -1}
    ):
        raise RunnerError(
            "STATE_MISMATCH",
            "Shell command output did not match the ABF policy success pattern.",
            {
                "op_id": "fw_verify_abf_policy",
                "transport": transport,
                "exit_code": result.exit_code,
                "stdout_preview": (result.stdout[:200] if result.stdout else ""),
                "stderr_preview": (result.stderr[:200] if result.stderr else ""),
            },
        )

    parsed = parse_abf_policy_table(result.stdout)
    if abf_policy_id not in parsed["policy_ids"]:
        raise RunnerError(
            "STATE_MISMATCH",
            "ABF policy id is absent from the VPP ABF policy table; the policy route is not in effect.",
            {
                "op_id": "fw_verify_abf_policy",
                "policy_route_id": policy_route_id,
                "abf_policy_id": abf_policy_id,
                "policy_type": policy_type,
                "policy_ids": parsed["policy_ids"],
                "stdout_preview": result.stdout[:2000],
            },
        )
    return {
        "op_id": "fw_verify_abf_policy",
        "status": "success",
        "transport": transport,
        "abf_policy_raw": result.stdout.strip(),
        "policy_route_id": policy_route_id,
        "policy_type": policy_type,
        "abf_policy_id": abf_policy_id,
        "found": True,
        "policy_ids": parsed["policy_ids"],
        "abf_policies": parsed["policies"],
        "request": {
            "command": ABF_POLICY_COMMAND,
            "host": target_host,
            "port": target_port,
            "username": resolved_user,
        },
        "response": {
            "exit_code": result.exit_code,
            "stdout_ref": "<abf-policy-raw-ref>",
            "stderr_ref": "<diag-snapshot-ref>",
        },
        "diag_snapshot_ref": "<diag-snapshot-ref>",
    }


# ── fw_verify_process_state ───────────────────────────────


PROCESS_COMMANDS = {
    "vpp": 'pgrep -f "^/opt/dbappsecurity/bin/vpp -c /appdata/etc/vpp/startup.conf"',
    "dnsmasq": 'pgrep -f "^/opt/dbappsecurity/bin/dnsmasq -k -C /appdata/etc/dns/dnsmasq.conf"',
    "agent": 'pgrep -f "^/opt/dbappsecurity/bin/vpp-agent -config-dir=/appdata/etc/agentcfg"',
}
PROCESS_SUCCESS_PATTERN = r"\d+"


def _process_command(process: str) -> str:
    try:
        return PROCESS_COMMANDS[process]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Unsupported process name for process state verification.",
            {"process": process, "supported": sorted(PROCESS_COMMANDS)},
        ) from exc


def build_verify_process_state_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None = None,
    process: str,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or _username_preview(session_file)
    command = _process_command(process)
    return {
        "op_id": "fw_verify_process_state",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": effective_username,
            "success_pattern": PROCESS_SUCCESS_PATTERN,
        },
        "process": process,
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_process_state(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None = None,
    credential_env: str,
    process: str,
    timeout: float,
) -> dict[str, Any]:
    command = _process_command(process)
    result = _execute_shell_op(
        op_id="fw_verify_process_state",
        transport=transport,
        command=command,
        success_pattern=PROCESS_SUCCESS_PATTERN,
        result_key="pid",
        stdout_ref_label="<process-state-ref>",
        base_url=base_url,
        session_file=session_file,
        host=host,
        port=port,
        credential_env=credential_env,
        timeout=timeout,
        username=username,
    )
    pid = result["pid"]
    result["running"] = bool(re.search(r"\d+", pid))
    result["process"] = process
    return result


# ── fw_kill_process ───────────────────────────────────────


KILL_COMMAND_TEMPLATE = "kill -9 {{pid}}"
# `\z`（串尾）是 PCRE 写法，Python `re` 直到 3.14 才支持，本仓库 requires-python >=3.11，
# 故用 `\A\Z` 表达同一语义：stdout 必须为空串（kill 成功无输出）。
KILL_SUCCESS_PATTERN = r"\A\Z"


def build_kill_process_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None = None,
    process: str,
    pid: str,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or _username_preview(session_file)
    command = render_command(KILL_COMMAND_TEMPLATE, {"pid": pid})
    return {
        "op_id": "fw_kill_process",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": effective_username,
            "success_pattern": KILL_SUCCESS_PATTERN,
        },
        "process": process,
        "pid": pid,
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_kill_process(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None = None,
    credential_env: str,
    process: str,
    pid: str,
    timeout: float,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or _username_from_session(session_payload)
    credential = _read_credential_env(credential_env)
    command = render_command(KILL_COMMAND_TEMPLATE, {"pid": pid})

    result = _run_shell_command(
        transport=transport,
        host=target_host,
        port=target_port,
        username=effective_username,
        credential=credential,
        command=command,
        timeout=timeout,
    )
    if not evaluate_success(result, KILL_SUCCESS_PATTERN):
        raise RunnerError(
            "STATE_MISMATCH",
            "kill command did not complete successfully for the target process.",
            {
                "op_id": "fw_kill_process",
                "process": process,
                "pid": pid,
                "exit_code": result.exit_code,
                "stdout_preview": (result.stdout[:200] if result.stdout else ""),
                "stderr_preview": (result.stderr[:200] if result.stderr else ""),
            },
        )
    return {
        "op_id": "fw_kill_process",
        "status": "success",
        "transport": transport,
        "killed": True,
        "process": process,
        "pid": pid,
        "auto_restart": True,
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": username,
        },
        "response": {
            "exit_code": result.exit_code,
            "stdout_ref": "<kill-result-ref>",
            "stderr_ref": "<diag-snapshot-ref>",
        },
        "diag_snapshot_ref": "<diag-snapshot-ref>",
    }


# ── fw_config_dns_diag ────────────────────────────────────


DNS_DIAG_COMMANDS = {
    "ping": "ping -c 3 {{domain}}",
    "traceroute": "traceroute {{domain}}",
}
DNS_DIAG_SUCCESS_PATTERNS = {
    "ping": r"\d+ bytes from",
    "traceroute": r"\d+ hops max",
}


def _diag_command(mode: str, domain: str) -> str:
    try:
        template = DNS_DIAG_COMMANDS[mode]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Unsupported DNS diagnostic mode.",
            {"mode": mode, "supported": sorted(DNS_DIAG_COMMANDS)},
        ) from exc
    return render_command(template, {"domain": domain})


def build_dns_diag_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    domain: str,
    mode: str,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    username = _username_preview(session_file)
    command = _diag_command(mode, domain)
    return {
        "op_id": "fw_config_dns_diag",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": username,
            "success_pattern": DNS_DIAG_SUCCESS_PATTERNS[mode],
        },
        "mode": mode,
        "domain": domain,
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_dns_diag(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    credential_env: str,
    domain: str,
    mode: str,
    timeout: float,
) -> dict[str, Any]:
    command = _diag_command(mode, domain)
    result = _execute_shell_op(
        op_id="fw_config_dns_diag",
        transport=transport,
        command=command,
        success_pattern=DNS_DIAG_SUCCESS_PATTERNS[mode],
        result_key="diag_output",
        stdout_ref_label="<dns-diag-output-ref>",
        base_url=base_url,
        session_file=session_file,
        host=host,
        port=port,
        credential_env=credential_env,
        timeout=timeout,
    )
    # CR-060/C-1：补齐 atom `returns.data` 声明但 execute 从未产出的三个键
    # （dry-run 只给 mode/domain，diag_output 只在 execute 侧 —— 两半合起来才是
    # 完整契约）。`resolution_ok` 与成功模式同义：`_execute_shell_op` 内已按
    # success_pattern 断言，能走到这里即代表域名解析并拿到回包。
    result["mode"] = mode
    result["domain"] = domain
    result["resolution_ok"] = True
    return result


# ── fw_verify_neighbor_probe ──────────────────────────────


def parse_neighbor_probe_output(stdout: str) -> list[dict[str, Any]]:
    """Parse `vppctl show ip neighbor` stdout into structured neighbor rows.

    Each data row renders the Probes column as two tokens ("0 /3"), so a row is
    10 whitespace-separated tokens:
    Time, IP, Flags, Ethernet, Interface, Phase, ProbesNum, ProbesDen, NextProbe(S), Age(S).
    The header row is skipped because its first token ("Time") is not numeric.
    A 9-token row (Probes rendered as a single token) is accepted for robustness.
    """
    rows: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        tokens = line.split()
        if len(tokens) not in (9, 10):
            continue
        try:
            float(tokens[0])
        except ValueError:
            continue  # header row
        if len(tokens) == 10:
            probes = f"{tokens[6]}/{tokens[7].lstrip('/')}"
            next_probe_s, age_s = tokens[8], tokens[9]
        else:
            probes = tokens[6]
            next_probe_s, age_s = tokens[7], tokens[8]
        rows.append(
            {
                "time": tokens[0],
                "ip": tokens[1],
                "flags": tokens[2],
                "mac": tokens[3],
                "interface": tokens[4],
                "phase": tokens[5],
                "probes": probes,
                "next_probe_s": next_probe_s,
                "age_s": age_s,
            }
        )
    return rows


def build_verify_neighbor_probe_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    expected_ip: str | None,
    expected_interface: str | None,
    expected_phase: str | None,
    timeout: float,
    username: str | None = None,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    resolved_user = username or _username_from_session(session_payload)
    return {
        "op_id": "fw_verify_neighbor_probe",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": NEIGHBOR_PROBE_COMMAND,
            "host": target_host,
            "port": target_port,
            "username": resolved_user,
            "success_pattern": NEIGHBOR_PROBE_SUCCESS_PATTERN,
            "expected_ip": expected_ip or None,
            "expected_interface": expected_interface or None,
            "expected_phase": expected_phase or None,
        },
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_neighbor_probe(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    credential_env: str,
    expected_ip: str | None,
    expected_interface: str | None,
    expected_phase: str | None,
    timeout: float,
    username: str | None = None,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    resolved_user = username or _username_from_session(session_payload)
    credential = _read_credential_env(credential_env)

    result = _run_shell_command(
        transport=transport,
        host=target_host,
        port=target_port,
        username=resolved_user,
        credential=credential,
        command=NEIGHBOR_PROBE_COMMAND,
        timeout=timeout,
    )
    # vppctl does not propagate a standard exit status through the paramiko exec
    # channel on this device (observed exit_code=-1 while stdout is populated).
    # Treat exit_code -1 as success when the neighbor-table header is present.
    if not _shell_output_succeeded(
        result, NEIGHBOR_PROBE_SUCCESS_PATTERN, acceptable_exit_codes={0, -1}
    ):
        raise RunnerError(
            "STATE_MISMATCH",
            "Shell command output did not match the neighbor probe success pattern.",
            {
                "op_id": "fw_verify_neighbor_probe",
                "transport": transport,
                "exit_code": result.exit_code,
                "stdout_preview": (result.stdout[:200] if result.stdout else ""),
                "stderr_preview": (result.stderr[:200] if result.stderr else ""),
            },
        )

    neighbors = parse_neighbor_probe_output(result.stdout)
    matches_expected = _match_neighbor_expectations(neighbors, expected_ip, expected_interface, expected_phase)
    return {
        "op_id": "fw_verify_neighbor_probe",
        "status": "success",
        "transport": transport,
        "neighbor_probe_raw": result.stdout.strip(),
        "neighbors": neighbors,
        "matches_expected": matches_expected,
        "request": {
            "command": NEIGHBOR_PROBE_COMMAND,
            "host": target_host,
            "port": target_port,
            "username": resolved_user,
        },
        "response": {
            "exit_code": result.exit_code,
            "stdout_ref": "<neighbor-probe-raw-ref>",
            "stderr_ref": "<diag-snapshot-ref>",
        },
        "diag_snapshot_ref": "<diag-snapshot-ref>",
    }


def _match_neighbor_expectations(
    neighbors: list[dict[str, Any]],
    expected_ip: str | None,
    expected_interface: str | None,
    expected_phase: str | None,
) -> bool:
    """Return True when every provided expectation is satisfied by some row.

    With no expectations, every query matches (observation only).
    """
    for row in neighbors:
        if expected_ip and row["ip"] != expected_ip:
            continue
        if expected_interface and row["interface"] != expected_interface:
            continue
        if expected_phase and row["phase"].lower() != str(expected_phase).lower():
            continue
        return True
    return False


def build_verify_iplink_etcd_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    name: str,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    resolved_username = username if username else _username_preview(session_file)
    command = render_command(IPLINK_ETCD_COMMAND_TEMPLATE, {"name": name})
    return {
        "op_id": "fw_verify_iplink_etcd",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": resolved_username,
            "success_pattern": ETCD_CONFIG_SUCCESS_PATTERN,
        },
        "name": name,
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_iplink_etcd(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    credential_env: str,
    name: str,
    timeout: float,
) -> dict[str, Any]:
    command = render_command(IPLINK_ETCD_COMMAND_TEMPLATE, {"name": name})
    return _execute_shell_op(
        op_id="fw_verify_iplink_etcd",
        transport=transport,
        command=command,
        success_pattern=ETCD_CONFIG_SUCCESS_PATTERN,
        result_key="config_raw",
        stdout_ref_label="<config-raw-ref>",
        base_url=base_url,
        session_file=session_file,
        host=host,
        port=port,
        username=username,
        credential_env=credential_env,
        timeout=timeout,
    )


# ── fw_verify_iplink_group_etcd ──────────────────────────


def build_verify_iplink_group_etcd_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    name: str,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    resolved_username = username if username else _username_preview(session_file)
    command = render_command(LINKGROUP_ETCD_COMMAND_TEMPLATE, {"name": name})
    return {
        "op_id": "fw_verify_iplink_group_etcd",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": resolved_username,
            "success_pattern": ETCD_CONFIG_SUCCESS_PATTERN,
        },
        "name": name,
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_iplink_group_etcd(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    credential_env: str,
    name: str,
    timeout: float,
) -> dict[str, Any]:
    command = render_command(LINKGROUP_ETCD_COMMAND_TEMPLATE, {"name": name})
    return _execute_shell_op(
        op_id="fw_verify_iplink_group_etcd",
        transport=transport,
        command=command,
        success_pattern=ETCD_CONFIG_SUCCESS_PATTERN,
        result_key="config_raw",
        stdout_ref_label="<config-raw-ref>",
        base_url=base_url,
        session_file=session_file,
        host=host,
        port=port,
        username=username,
        credential_env=credential_env,
        timeout=timeout,
    )


# ── fw_verify_iplink_status_etcd ──────────────────────────


def build_verify_iplink_status_etcd_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    name: str,
    state: str,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    resolved_username = username if username else _username_preview(session_file)
    command = _render_status_command(name, state)
    return {
        "op_id": "fw_verify_iplink_status_etcd",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": resolved_username,
            "success_pattern": ETCD_CONFIG_SUCCESS_PATTERN,
        },
        "name": name,
        "state": state,
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_iplink_status_etcd(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    credential_env: str,
    name: str,
    state: str,
    timeout: float,
) -> dict[str, Any]:
    command = _render_status_command(name, state)
    return _execute_shell_op(
        op_id="fw_verify_iplink_status_etcd",
        transport=transport,
        command=command,
        success_pattern=ETCD_CONFIG_SUCCESS_PATTERN,
        result_key="config_raw",
        stdout_ref_label="<config-raw-ref>",
        base_url=base_url,
        session_file=session_file,
        host=host,
        port=port,
        username=username,
        credential_env=credential_env,
        timeout=timeout,
    )


# ── fw_verify_iplink_group_status_etcd ────────────────────


def build_verify_iplink_group_status_etcd_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    name: str,
    state: str,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    resolved_username = username if username else _username_preview(session_file)
    command = _render_status_command(name, state, linkgroup=True)
    return {
        "op_id": "fw_verify_iplink_group_status_etcd",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": resolved_username,
            "success_pattern": ETCD_CONFIG_SUCCESS_PATTERN,
        },
        "name": name,
        "state": state,
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_iplink_group_status_etcd(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    credential_env: str,
    name: str,
    state: str,
    timeout: float,
) -> dict[str, Any]:
    command = _render_status_command(name, state, linkgroup=True)
    return _execute_shell_op(
        op_id="fw_verify_iplink_group_status_etcd",
        transport=transport,
        command=command,
        success_pattern=ETCD_CONFIG_SUCCESS_PATTERN,
        result_key="config_raw",
        stdout_ref_label="<config-raw-ref>",
        base_url=base_url,
        session_file=session_file,
        host=host,
        port=port,
        username=username,
        credential_env=credential_env,
        timeout=timeout,
    )


# ── 公共进程重启 / 资源 / 存储 / 系统日志检测 ──────────────
# 用户决策：AO-002 进程重启检测、AO-003 资源检查、AO-004 抓包存储检查、
# AO-008 系统日志读取。所有命令均为只读；输出原样写入 data，解析结果
# 作为附加字段返回，解析失败时不臆造值。

# 进程映射表：后续新增进程类型只需扩展此表。
# snort -> 单个进程；vpp -> vpp-agent-init / vpp-agent / vpp 多个进程。
PROCESS_RESTART_MAP: dict[str, dict[str, Any]] = {
    "snort": {
        "patterns": ("snort",),
        "core_patterns": ("snort",),
        "die_log": "/trace/log/snort_die.log",
    },
    "vpp": {
        "patterns": ("vpp-agent-init", "vpp-agent", "vpp"),
        "core_patterns": ("vpp",),
        "die_log": None,
    },
}
PROCESS_RESTART_SUCCESS_PATTERN = r"===PS_BEFORE==="
COREDUMP_DIR = "/trace/coredump"
SNORT_DIE_LOG = "/trace/log/snort_die.log"

SYSTEM_RESOURCE_SUCCESS_PATTERN = r"===MEM==="
CAPTURE_STORAGE_SUCCESS_PATTERN = r"===DF_USERDATA==="
SYSTEM_LOG_SUCCESS_PATTERN = r"===SOURCE:"
IPV4_POLICY_KEYWORD = "后台加载IPv4控制策略成功(system:0)"
IPV6_POLICY_KEYWORD = "后台加载IPv6控制策略成功(system:0)"
SYSTEM_LOG_KEYWORDS = (IPV4_POLICY_KEYWORD, IPV6_POLICY_KEYWORD)


def _validate_process_restart_type(process_type: str) -> dict[str, Any]:
    key = str(process_type).strip().lower()
    if key not in PROCESS_RESTART_MAP:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Unsupported process type for restart detection.",
            {"process_type": process_type, "supported": sorted(PROCESS_RESTART_MAP)},
        )
    return PROCESS_RESTART_MAP[key]


def _process_restart_command(process_type: str, wait_seconds: int) -> str:
    mapping = _validate_process_restart_type(process_type)
    wait_seconds = _validate_wait_seconds(wait_seconds)
    pattern = "|".join(re.escape(item) for item in mapping["patterns"])
    if mapping.get("die_log"):
        die_log = f"ls -l {shlex.quote(str(mapping['die_log']))} 2>/dev/null || true"
    else:
        die_log = "true"
    return (
        "echo '===PS_BEFORE==='; "
        f"ps -ef | grep -E '{pattern}' | grep -v grep || true; "
        f"sleep {wait_seconds}; "
        "echo '===PS_AFTER==='; "
        f"ps -ef | grep -E '{pattern}' | grep -v grep || true; "
        f"echo '===COREDUMP==='; ls -1 {COREDUMP_DIR} 2>/dev/null || true; "
        f"echo '===DIELOG==='; {die_log}"
    )


def build_verify_process_restart_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    process_type: str,
    pid_before: list[int] | None,
    wait_seconds: int,
    timeout: float,
) -> dict[str, Any]:
    mapping = _validate_process_restart_type(process_type)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or _username_preview(session_file)
    return {
        "op_id": "fw_verify_process_restart",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": _process_restart_command(process_type, wait_seconds),
            "host": target_host,
            "port": target_port,
            "username": effective_username,
            "success_pattern": PROCESS_RESTART_SUCCESS_PATTERN,
        },
        "process_type": process_type,
        "process_patterns": list(mapping["patterns"]),
        "pid_before": _normalize_pid_before(pid_before),
        "wait_seconds": wait_seconds,
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_process_restart(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    credential_env: str,
    process_type: str,
    pid_before: list[int] | None,
    wait_seconds: int,
    timeout: float,
) -> dict[str, Any]:
    mapping = _validate_process_restart_type(process_type)
    command = _process_restart_command(process_type, wait_seconds)
    requested_pid_before = _normalize_pid_before(pid_before)
    result = _execute_shell_op(
        op_id="fw_verify_process_restart",
        transport=transport,
        command=command,
        success_pattern=PROCESS_RESTART_SUCCESS_PATTERN,
        result_key="raw_output",
        stdout_ref_label="<process-restart-raw-ref>",
        base_url=base_url,
        session_file=session_file,
        host=host,
        port=port,
        credential_env=credential_env,
        timeout=timeout,
        username=username,
    )
    sections = _parse_sections(result["raw_output"])
    parsed_before = _parse_pids(sections.get("PS_BEFORE", []))
    parsed_after = _parse_pids(sections.get("PS_AFTER", []))
    effective_before = requested_pid_before if requested_pid_before is not None else parsed_before
    core_files = _parse_core_files(
        sections.get("COREDUMP", []), mapping["core_patterns"]
    )
    die_log = _parse_die_log(sections.get("DIELOG", []))
    pid_changed = bool(effective_before) and bool(parsed_after) and set(effective_before) != set(parsed_after)
    evidence: list[str] = []
    if pid_changed:
        evidence.append("pid_changed")
    if core_files:
        evidence.append("core_file")
    if die_log:
        evidence.append("die_log")
    result.update(
        {
            "process_type": process_type,
            "process_patterns": list(mapping["patterns"]),
            "pid_before": effective_before,
            "pid_after": parsed_after,
            "pid_changed": pid_changed,
            "restarted": pid_changed,
            "core_file": core_files[0] if core_files else None,
            "core_files": core_files,
            "die_log": die_log,
            "restart_evidence": evidence,
            "wait_seconds": wait_seconds,
        }
    )
    return result


def _parse_sections(raw_output: str) -> dict[str, list[str]]:
    sections: dict[str, list[str]] = {}
    current: str | None = None
    for line in raw_output.splitlines():
        match = re.fullmatch(r"===(PS_BEFORE|PS_AFTER|COREDUMP|DIELOG|MEM|MEM2|LOAD|CPU|DISK|DISK2|DF_USERDATA|DU_USERDATA|MOUNTS|LS|DF_ALL)===.*", line.strip())
        if match:
            current = match.group(1)
            sections.setdefault(current, [])
            continue
        if current is not None:
            sections[current].append(line)
    return sections


def _parse_pids(lines: list[str]) -> list[int]:
    pids: set[int] = set()
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            pids.add(int(parts[1]))
    return sorted(pids)


def _parse_core_files(lines: list[str], patterns: tuple[str, ...]) -> list[str]:
    files: list[str] = []
    for line in lines:
        name = line.strip()
        if not name:
            continue
        lowered = name.lower()
        if any(pattern.lower() in lowered for pattern in patterns):
            files.append(name)
    return files


def _parse_die_log(lines: list[str]) -> str | None:
    for line in lines:
        text = line.strip()
        if text and "snort_die.log" in text:
            return text
    return None


# ── 系统资源检查 ──────────────────────────────────────────


def _system_resource_command(sample_interval_seconds: int) -> str:
    first = (
        "echo '===MEM==='; free -m 2>/dev/null || cat /proc/meminfo; "
        "echo '===LOAD==='; cat /proc/loadavg 2>/dev/null || true; "
        "echo '===CPU==='; top -bn1 2>/dev/null | grep -E '%Cpu|Cpu\\(s\\)' || true; "
        "echo '===DISK==='; df -P -k 2>/dev/null || true"
    )
    if sample_interval_seconds <= 0:
        return first
    return (
        first
        + f"; sleep {sample_interval_seconds}; "
        + "echo '===MEM2==='; free -m 2>/dev/null || cat /proc/meminfo; "
        + "echo '===DISK2==='; df -P -k 2>/dev/null || true"
    )


def build_verify_system_resource_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    sample_interval_seconds: int,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or _username_preview(session_file)
    return {
        "op_id": "fw_verify_system_resource",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": _system_resource_command(sample_interval_seconds),
            "host": target_host,
            "port": target_port,
            "username": effective_username,
            "success_pattern": SYSTEM_RESOURCE_SUCCESS_PATTERN,
        },
        "sample_interval_seconds": sample_interval_seconds,
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_system_resource(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    credential_env: str,
    sample_interval_seconds: int,
    timeout: float,
) -> dict[str, Any]:
    command = _system_resource_command(sample_interval_seconds)
    result = _execute_shell_op(
        op_id="fw_verify_system_resource",
        transport=transport,
        command=command,
        success_pattern=SYSTEM_RESOURCE_SUCCESS_PATTERN,
        result_key="raw_output",
        stdout_ref_label="<system-resource-raw-ref>",
        base_url=base_url,
        session_file=session_file,
        host=host,
        port=port,
        credential_env=credential_env,
        timeout=timeout,
        username=username,
    )
    sections = _parse_sections(result["raw_output"])
    memory = _parse_memory(sections.get("MEM", []))
    memory2 = _parse_memory(sections.get("MEM2", []))
    disks = _parse_disks(sections.get("DISK", []))
    disks2 = _parse_disks(sections.get("DISK2", []))
    result.update(
        {
            "memory": memory,
            "memory_used_delta_mb": _delta(memory, memory2, "used_mb"),
            "load": _parse_load(sections.get("LOAD", [])),
            "cpu_usage_percent": _parse_cpu_usage(sections.get("CPU", [])),
            "disks": disks,
            "disk_used_delta_kb": _disk_used_delta(disks, disks2),
            "sample_interval_seconds": sample_interval_seconds,
        }
    )
    return result


def _parse_memory(lines: list[str]) -> dict[str, Any]:
    for line in lines:
        text = line.strip()
        if text.startswith("Mem:"):
            parts = text.split()
            if len(parts) >= 4:
                return {
                    "total_mb": _int_or_none(parts[1]),
                    "used_mb": _int_or_none(parts[2]),
                    "free_mb": _int_or_none(parts[3]),
                    "available_mb": _int_or_none(parts[-1]),
                }
    # /proc/meminfo fallback
    values: dict[str, int] = {}
    for line in lines:
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(":"):
            value = _int_or_none(parts[1])
            if value is not None:
                values[parts[0].rstrip(":")] = value
    if "MemTotal" in values:
        total_kb = values["MemTotal"]
        available_kb = values.get("MemAvailable", values.get("MemFree", 0))
        used_kb = max(total_kb - available_kb, 0)
        return {
            "total_mb": round(total_kb / 1024),
            "used_mb": round(used_kb / 1024),
            "free_mb": round(values.get("MemFree", 0) / 1024),
            "available_mb": round(available_kb / 1024),
        }
    return {}


def _parse_load(lines: list[str]) -> dict[str, float]:
    for line in lines:
        parts = line.split()
        if len(parts) >= 3:
            try:
                return {
                    "load_1m": float(parts[0]),
                    "load_5m": float(parts[1]),
                    "load_15m": float(parts[2]),
                }
            except ValueError:
                continue
    return {}


def _parse_cpu_usage(lines: list[str]) -> float | None:
    for line in lines:
        match = re.search(r"(\d+(?:\.\d+)?)\s*id", line)
        if match:
            try:
                return round(max(0.0, 100.0 - float(match.group(1))), 2)
            except ValueError:
                continue
    return None


def _parse_disks(lines: list[str]) -> list[dict[str, Any]]:
    disks: list[dict[str, Any]] = []
    for line in lines:
        parts = line.split(maxsplit=5)
        if len(parts) < 6 or parts[0] == "Filesystem":
            continue
        if not parts[1].isdigit():
            continue
        disks.append(
            {
                "filesystem": parts[0],
                "size_kb": _int_or_none(parts[1]),
                "used_kb": _int_or_none(parts[2]),
                "available_kb": _int_or_none(parts[3]),
                "use_percent": parts[4],
                "mount": parts[5],
            }
        )
    return disks


def _delta(first: dict[str, Any], second: dict[str, Any], key: str) -> int | None:
    a = first.get(key) if isinstance(first, dict) else None
    b = second.get(key) if isinstance(second, dict) else None
    if isinstance(a, int) and isinstance(b, int):
        return b - a
    return None


def _disk_used_delta(first: list[dict[str, Any]], second: list[dict[str, Any]]) -> int | None:
    def root_used(disks: list[dict[str, Any]]) -> int | None:
        for disk in disks:
            if disk.get("mount") == "/":
                value = disk.get("used_kb")
                return value if isinstance(value, int) else None
        return None

    a = root_used(first)
    b = root_used(second)
    if isinstance(a, int) and isinstance(b, int):
        return b - a
    return None


# ── 抓包存储检查 ──────────────────────────────────────────


CAPTURE_STORAGE_COMMAND = (
    "echo '===DF_USERDATA==='; df -P -k /userdata 2>/dev/null || true; "
    "echo '===DU_USERDATA==='; du -sk /userdata 2>/dev/null || true; "
    "echo '===MOUNTS==='; mount 2>/dev/null | grep -E 'userdata|exdisk' || true; "
    "echo '===LS==='; ls -ld /userdata /exdisk 2>/dev/null || true; "
    "echo '===DF_ALL==='; df -P -k 2>/dev/null || true"
)


def build_verify_capture_storage_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or _username_preview(session_file)
    return {
        "op_id": "fw_verify_capture_storage",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": CAPTURE_STORAGE_COMMAND,
            "host": target_host,
            "port": target_port,
            "username": effective_username,
            "success_pattern": CAPTURE_STORAGE_SUCCESS_PATTERN,
        },
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_verify_capture_storage(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    credential_env: str,
    timeout: float,
) -> dict[str, Any]:
    result = _execute_shell_op(
        op_id="fw_verify_capture_storage",
        transport=transport,
        command=CAPTURE_STORAGE_COMMAND,
        success_pattern=CAPTURE_STORAGE_SUCCESS_PATTERN,
        result_key="raw_output",
        stdout_ref_label="<capture-storage-raw-ref>",
        base_url=base_url,
        session_file=session_file,
        host=host,
        port=port,
        credential_env=credential_env,
        timeout=timeout,
        username=username,
    )
    sections = _parse_sections(result["raw_output"])
    userdata_disks = _parse_disks(sections.get("DF_USERDATA", []))
    all_disks = _parse_disks(sections.get("DF_ALL", []))
    userdata_size_kb = _parse_du_size(sections.get("DU_USERDATA", []))
    mount_lines = sections.get("MOUNTS", [])
    ls_lines = sections.get("LS", [])
    mount_text = "\n".join(mount_lines)
    exdisk_present = "/exdisk" in mount_text or any("/exdisk" in line for line in ls_lines)
    mount_source = _userdata_mount_source(mount_lines)
    userdata_disk = userdata_disks[0] if userdata_disks else _find_mount_disk(all_disks, "/userdata")
    device_form = _capture_device_form(
        exdisk_present=exdisk_present,
        mount_source=mount_source,
        userdata_disk=userdata_disk,
        mount_text=mount_text,
    )
    result.update(
        {
            "userdata_size_kb": userdata_size_kb,
            "userdata_disk": userdata_disk,
            "disk_total_kb": userdata_disk.get("size_kb") if userdata_disk else None,
            "disk_used_kb": userdata_disk.get("used_kb") if userdata_disk else None,
            "disk_available_kb": userdata_disk.get("available_kb") if userdata_disk else None,
            "disk_use_percent": userdata_disk.get("use_percent") if userdata_disk else None,
            "device_form": device_form,
            "userdata_mount_source": mount_source,
            "exdisk_present": exdisk_present,
        }
    )
    return result


def _parse_du_size(lines: list[str]) -> int | None:
    for line in lines:
        parts = line.split()
        if parts and parts[0].isdigit():
            return int(parts[0])
    return None


def _userdata_mount_source(lines: list[str]) -> str | None:
    for line in lines:
        if "/userdata" in line:
            parts = line.split()
            if parts:
                return parts[0]
    return None


def _find_mount_disk(disks: list[dict[str, Any]], mount: str) -> dict[str, Any] | None:
    for disk in disks:
        if disk.get("mount") == mount:
            return disk
    return None


def _capture_device_form(
    *,
    exdisk_present: bool,
    mount_source: str | None,
    userdata_disk: dict[str, Any] | None,
    mount_text: str,
) -> str:
    if exdisk_present:
        return "exdisk"
    candidates = [mount_source or "", (userdata_disk or {}).get("filesystem") or ""]
    if any(re.search(r"^(tmpfs|ramfs|rootfs)$", item) for item in candidates):
        return "no_disk"
    if "userdata" in mount_text and re.search(r"\b(tmpfs|ramfs|rootfs)\b", mount_text):
        return "no_disk"
    if userdata_disk is not None:
        return "with_disk"
    return "unknown"


# ── 系统日志读取 ──────────────────────────────────────────


def _system_log_command(lines: int, log_path: str | None) -> str:
    lines = _validate_line_count(lines)
    if log_path:
        if not (log_path.startswith("/var/log/") or log_path.startswith("/trace/log/")):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "System log path must be under /var/log/ or /trace/log/.",
                {"field": "log_path", "value": log_path},
            )
        quoted = shlex.quote(log_path)
        return (
            f"echo '===SOURCE:{log_path}==='; "
            f"tail -n {lines} {quoted} 2>/dev/null || true"
        )
    return (
        "if [ -f /var/log/messages ]; then "
        "echo '===SOURCE:/var/log/messages==='; "
        f"tail -n {lines} /var/log/messages 2>/dev/null; "
        "elif [ -f /var/log/syslog ]; then "
        "echo '===SOURCE:/var/log/syslog==='; "
        f"tail -n {lines} /var/log/syslog 2>/dev/null; "
        "elif command -v journalctl >/dev/null 2>&1; then "
        "echo '===SOURCE:journalctl==='; "
        f"journalctl -n {lines} --no-pager 2>/dev/null; "
        "else echo '===SOURCE:none==='; fi"
    )


def build_capture_system_log_dry_run(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    lines: int,
    log_path: str | None,
    keywords: list[str] | None,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    effective_username = username or _username_preview(session_file)
    return {
        "op_id": "fw_capture_system_log",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": _system_log_command(lines, log_path),
            "host": target_host,
            "port": target_port,
            "username": effective_username,
            "success_pattern": SYSTEM_LOG_SUCCESS_PATTERN,
        },
        "lines": lines,
        "log_path": log_path,
        "keywords": list(keywords) if keywords else list(SYSTEM_LOG_KEYWORDS),
        "session_file": str(session_file),
        "timeout": timeout,
    }


def execute_capture_system_log(
    *,
    base_url: str,
    session_file: Path,
    transport: str,
    host: str | None,
    port: int | None,
    username: str | None,
    credential_env: str,
    lines: int,
    log_path: str | None,
    keywords: list[str] | None,
    timeout: float,
) -> dict[str, Any]:
    result = _execute_shell_op(
        op_id="fw_capture_system_log",
        transport=transport,
        command=_system_log_command(lines, log_path),
        success_pattern=SYSTEM_LOG_SUCCESS_PATTERN,
        result_key="raw_output",
        stdout_ref_label="<system-log-raw-ref>",
        base_url=base_url,
        session_file=session_file,
        host=host,
        port=port,
        credential_env=credential_env,
        timeout=timeout,
        username=username,
    )
    raw_output = result["raw_output"]
    source, raw_log = _split_system_log(raw_output)
    expected = list(keywords) if keywords else list(SYSTEM_LOG_KEYWORDS)
    matched = [keyword for keyword in expected if keyword in raw_log]
    result.update(
        {
            "log_source": source,
            "line_count": len(raw_log.splitlines()),
            "raw_log": raw_log,
            "expected_keywords": expected,
            "matched_keywords": matched,
            "ipv4_policy_loaded": IPV4_POLICY_KEYWORD in raw_log,
            "ipv6_policy_loaded": IPV6_POLICY_KEYWORD in raw_log,
        }
    )
    return result


def _split_system_log(raw_output: str) -> tuple[str | None, str]:
    source: str | None = None
    body: list[str] = []
    for line in raw_output.splitlines():
        match = re.fullmatch(r"===SOURCE:(.*?)===", line.strip())
        if match:
            source = match.group(1)
            continue
        if source is not None:
            body.append(line)
    return source, "\n".join(body)


def _normalize_pid_before(value: list[int] | None) -> list[int] | None:
    if value is None:
        return None
    if isinstance(value, str):
        items: list[Any] = value.replace(",", " ").split()
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "pid_before must be a list of positive integers.",
            {"field": "pid_before", "value": value},
        )
    pids: list[int] = []
    for item in items:
        if isinstance(item, bool):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "pid_before must contain positive integers.",
                {"field": "pid_before", "value": item},
            )
        try:
            pid = int(item)
        except (TypeError, ValueError) as exc:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "pid_before must contain positive integers.",
                {"field": "pid_before", "value": item},
            ) from exc
        if pid < 1:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "pid_before must contain positive integers.",
                {"field": "pid_before", "value": item},
            )
        pids.append(pid)
    unique = sorted(set(pids))
    return unique or None


def _validate_wait_seconds(value: int) -> int:
    if isinstance(value, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "wait_seconds must be an integer from 0 to 300.",
            {"field": "wait_seconds", "value": value},
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "wait_seconds must be an integer from 0 to 300.",
            {"field": "wait_seconds", "value": value},
        ) from exc
    if parsed < 0 or parsed > 300:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "wait_seconds must be an integer from 0 to 300.",
            {"field": "wait_seconds", "value": value},
        )
    return parsed


def _validate_line_count(value: int) -> int:
    if isinstance(value, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "lines must be an integer from 1 to 5000.",
            {"field": "lines", "value": value},
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "lines must be an integer from 1 to 5000.",
            {"field": "lines", "value": value},
        ) from exc
    if parsed < 1 or parsed > 5000:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "lines must be an integer from 1 to 5000.",
            {"field": "lines", "value": value},
        )
    return parsed


def _int_or_none(value: str) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None
