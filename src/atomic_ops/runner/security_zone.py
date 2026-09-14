"""NGFW security-zone runner."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
SECURITY_ZONE_ENDPOINTS = {
    "fw_config_security_zone": ("POST", "/api/v1/sfarea"),
    "fw_update_security_zone": ("PUT", "/api/v1/sfarea"),
    "fw_delete_security_zone": ("DELETE", "/api/v1/sfarea"),
    "fw_verify_security_zone": ("GET", "/api/v1/sfarea"),
}
GET_OPS = {"fw_verify_security_zone"}
DELETE_OPS = {"fw_delete_security_zone"}
NO_BODY_OPS = {
    "fw_verify_security_zone",
    "fw_delete_security_zone",
}

# ── payload builders ──────────────────────────────────────────


def build_security_zone_create_payload(
    *,
    name: str,
    desc: str = "",
    interfaces: list[str] | None = None,
) -> dict[str, Any]:
    val: dict[str, Any] = {
        "name": name,
        "desc": desc or "",
        "interfaces": list(interfaces) if interfaces else [],
    }
    return {"val": val}


def build_security_zone_update_payload(
    *,
    name: str,
    desc: str = "",
    interfaces: list[str] | None = None,
    refcnt: int = 0,
) -> dict[str, Any]:
    val: dict[str, Any] = {
        "name": name,
        "desc": desc or "",
        "interfaces": list(interfaces) if interfaces else [],
        "refcnt": refcnt,
    }
    return {"val": val, "id": name}


def build_security_zone_delete_payload(
    *,
    name: str,
) -> dict[str, str]:
    return {"id": name}


def build_security_zone_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    request_payload = None if op_id in NO_BODY_OPS else payload
    return {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(base_url, op_id, payload=payload),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": request_payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_security_zone(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {
        "Content-Type": "application/json",
        auth_header: header_value,
    }
    url = _request_url(base_url, op_id, payload=payload)
    status_code, response_payload, _text = request_json(
        method,
        url,
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise_if_device_session_rejected(status_code, response_payload)
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED" if method != "GET" else "RUNNER_RESPONSE_INVALID",
            "Security-zone device request did not return a success status.",
            {
                "op_id": op_id,
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()) if isinstance(response_payload, dict) else [],
            },
        )
    result: dict[str, Any] = {
        "op_id": op_id,
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": method,
            "path": path,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }
    # Fulfill atom returns.data contract: extract structured zone summary.
    result.update(_extract_security_zone_summary(op_id, response_payload))
    return result


def _extract_security_zone_summary(op_id: str, response_payload: Any) -> dict[str, Any]:
    """Extract structured zone ids from device response per atom returns.data contract."""
    summary: dict[str, Any] = {}
    if op_id == "fw_verify_security_zone":
        vals = response_payload.get("vals") if isinstance(response_payload, dict) else None
        if isinstance(vals, list):
            summary["security_zone_names"] = [
                item.get("name") for item in vals if isinstance(item, dict)
            ]
        if isinstance(response_payload, dict):
            summary["count"] = len(vals) if isinstance(vals, list) else 0
    elif op_id == "fw_config_security_zone":
        # POST response only has {"msg": "success"} — zone name comes from request args
        pass
    elif op_id == "fw_update_security_zone":
        # PUT response only has {"msg": "success"}
        pass
    return summary


def _request_url(
    base_url: str,
    op_id: str,
    *,
    payload: dict[str, Any] | None = None,
) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in DELETE_OPS:
        zone_id = str((payload or {}).get("id") or "")
        url = f"{url}?{urlencode({'id': zone_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return SECURITY_ZONE_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this security-zone operation.",
            {"op_id": op_id},
        ) from exc


# ── VPP data-plane verification via SSH ──────────────────────

VPPCTL_PATH = "/opt/dbappsecurity/bin/vppctl"


def build_vpp_verify_dry_run(
    *,
    ssh_host: str,
    ssh_port: int = 22,
    ssh_user: str = "root",
    zone_name: str | None = None,
    expected_interfaces: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "op_id": "fw_verify_security_zone_vpp",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "SSH",
            "host": ssh_host,
            "port": ssh_port,
            "user": ssh_user,
            "command": f"{VPPCTL_PATH} show zone"
            + (f" name {zone_name}" if zone_name else ""),
        },
    }


def execute_vpp_verify(
    *,
    ssh_host: str,
    ssh_port: int = 22,
    ssh_user: str = "root",
    ssh_password: str,
    zone_name: str | None = None,
    expected_interfaces: list[str] | None = None,
    timeout: float = 30.0,
) -> dict[str, Any]:
    """SSH into the NGFW device and run 'vppctl show zone' to verify VPP data-plane state."""
    import paramiko

    cmd = f"{VPPCTL_PATH} show zone"
    if zone_name:
        cmd += f" name {zone_name}"

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=ssh_host,
            port=ssh_port,
            username=ssh_user,
            password=ssh_password,  # security-gate: ok — 值来自 --credential-env 环境变量，非硬编码
            timeout=timeout,
            look_for_keys=False,
            allow_agent=False,
        )
        _stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        vpp_output = stdout.read().decode("utf-8", errors="replace").strip()
        err_output = stderr.read().decode("utf-8", errors="replace").strip()
        if err_output and not vpp_output:
            vpp_output = err_output
        elif err_output:
            vpp_output = vpp_output + "\n" + err_output
    except Exception as exc:
        raise RunnerError(
            "SSH_CONNECTION_FAILED",
            f"SSH connection to device failed: {exc}",
            {"host": ssh_host, "port": ssh_port},
            suggestion="Verify SSH connectivity and credentials.",
        ) from exc
    finally:
        client.close()

    if not vpp_output:
        raise RunnerError(
            "VPP_COMMAND_FAILED",
            "VPP show zone command returned empty output.",
            {"host": ssh_host, "command": cmd},
        )

    # Parse VPP output to extract zone info
    # VPP output is a table: "Name               Idx     Interface"
    # Lines like: "trust-zone               0       port1 port2"
    interfaces_found: list[str] = []
    zone_found: str | None = None
    for line in vpp_output.split("\n"):
        line_stripped = line.strip()
        if not line_stripped or line_stripped.startswith("Name") or line_stripped.startswith("---"):
            continue
        # Check for "unknown zone" response
        if "unknown zone" in line_stripped.lower():
            zone_found = None
            continue
        # Parse table row: zone_name idx interfaces...
        parts = line_stripped.split()
        if len(parts) >= 1 and zone_name:
            if parts[0] == zone_name:
                zone_found = zone_name
                if len(parts) > 2:
                    interfaces_found = parts[2:]
        elif len(parts) >= 1:
            # List all zones mode
            if not zone_found:
                zone_found = parts[0] if len(parts) >= 1 else None
            if len(parts) > 2:
                if zone_name and parts[0] == zone_name:
                    interfaces_found = parts[2:]

    vpp_api_consistent = True
    if expected_interfaces:
        vpp_api_consistent = set(expected_interfaces) == set(interfaces_found)

    return {
        "op_id": "fw_verify_security_zone_vpp",
        "status": "success",
        # 结果字段平铺到顶层：run_security_zone 出口 `_to_run_envelope` 会把
        # payload 剩余字段整体包进 envelope["data"]，此处若再自建一层 "data"，
        # 对外就是 envelope.data.data.<key>，而 atom 的 returns 声明的是单层
        # data.<key> → ${STEP.n.<key>} 恒解析失败。
        "zone_name": zone_name or zone_found or "<all>",
        "vpp_output": vpp_output[:4096],
        "interfaces_found": interfaces_found,
        "vpp_api_consistent": vpp_api_consistent,
    }
