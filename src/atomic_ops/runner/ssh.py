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
import warnings
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from atomic_ops.runner.errors import RunnerError
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


def _read_credential_env(env_name: str) -> str:
    value = os.environ.get(env_name)
    if value is None or not value:
        raise RunnerError(
            "RUNNER_CREDENTIAL_MISSING",
            "Runner credential environment variable is not set or is empty.",
            {"env": env_name},
        )
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

        import time
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
) -> dict[str, Any]:
    """Shared shell executor for read-only atoms over SSH or Telnet.

    Selects the transport primitive based on ``transport`` (ssh/telnet),
    asserts the success pattern against stdout, and returns the raw output
    under ``data[result_key]``.
    """
    session_payload = read_session_file(session_file)
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
        "data": {
            result_key: result.stdout.strip(),
        },
        "request": {
            "command": command,
            "host": target_host,
            "port": target_port,
            "username": username,
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
    session_payload = read_session_file(session_file)
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
    session_payload = read_session_file(session_file)
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
        "data": {
            "version_raw": version_raw,
            "matches_expected": matches_expected,
        },
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
    session_payload = read_session_file(session_file)
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
    session_payload = read_session_file(session_file)
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
    process: str,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    username = _username_preview(session_file)
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
            "username": username,
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
    )
    pid = result["data"]["pid"]
    result["data"]["running"] = bool(re.search(r"\d+", pid))
    result["data"]["process"] = process
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
    process: str,
    pid: str,
    timeout: float,
) -> dict[str, Any]:
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    username = _username_preview(session_file)
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
            "username": username,
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
    credential_env: str,
    process: str,
    pid: str,
    timeout: float,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file)
    target_host = _resolve_host(explicit_host=host, base_url=base_url)
    target_port = port if port is not None else _default_port(transport)
    username = _username_from_session(session_payload)
    credential = _read_credential_env(credential_env)
    command = render_command(KILL_COMMAND_TEMPLATE, {"pid": pid})

    result = _run_shell_command(
        transport=transport,
        host=target_host,
        port=target_port,
        username=username,
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
        "data": {
            "killed": True,
            "process": process,
            "pid": pid,
            "auto_restart": True,
        },
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
    return _execute_shell_op(
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
