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


def build_check_bridge_domain_dry_run(
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
        "op_id": "fw_check_bridge_domain",
        "status": "dry_run",
        "execute_required": True,
        "transport": transport,
        "request": {
            "command": BRIDGE_DOMAIN_COMMAND,
            "host": target_host,
            "port": target_port,
            "username": username,
            "success_pattern": BRIDGE_DOMAIN_SUCCESS_PATTERN,
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
) -> dict[str, Any]:
    return _execute_shell_op(
        op_id="fw_check_bridge_domain",
        transport=transport,
        command=BRIDGE_DOMAIN_COMMAND,
        success_pattern=BRIDGE_DOMAIN_SUCCESS_PATTERN,
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
KILL_SUCCESS_PATTERN = r"\A\z"


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
