"""NGFW security-zone runner."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError
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

# ── zone name validation ─────────────────────────────────────

_ZONE_NAME_PATTERN = re.compile(r"^[a-zA-Z0-9一-鿿.\-]{1,31}$")
_FORBIDDEN_NAMES = {".", ".."}
_FORBIDDEN_PREFIX = "IDMC-"


def _validate_zone_name(name: str) -> str:
    """Validate security-zone name per NGFW constraints.

    Returns the trimmed name on success; raises RunnerError on failure.
    """
    if not isinstance(name, str) or not name.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Security-zone name is required and must be a non-empty string.",
            {"field": "name"},
        )
    name = name.strip()
    if not _ZONE_NAME_PATTERN.match(name):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Security-zone name must be 1-31 chars: letters, digits, Chinese, hyphen (-), dot (.).",
            {"field": "name", "name": name},
        )
    if name in _FORBIDDEN_NAMES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Security-zone name cannot be '.' or '..' alone.",
            {"field": "name", "name": name},
        )
    if name.upper().startswith(_FORBIDDEN_PREFIX):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Security-zone name cannot start with 'IDMC-'.",
            {"field": "name", "name": name},
        )
    return name


# ── payload builders ──────────────────────────────────────────


def build_security_zone_create_payload(
    *,
    name: str,
    desc: str = "",
    interfaces: list[str] | None = None,
) -> dict[str, Any]:
    name = _validate_zone_name(name)
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
    name = _validate_zone_name(name)
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
    name = _validate_zone_name(name)
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
    session_payload = read_session_file(session_file)
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
        _validate_zone_name(zone_id)
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
