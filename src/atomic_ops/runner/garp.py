"""NGFW gratuitous ARP runner for /api/v1/neighbor/garplimitrate.

Captured from F12 evidence (arp抓取.txt, 2026-08-26):
- fw_config_garp_rate_limit: PUT /api/v1/neighbor/garplimitrate, id="0"
  body: {"id": "0", "val": {"rate": <pps 1-4096>, "capacity": <burst, observed 16>}}
- GET /api/v1/neighbor/garplimitrate returns {"vals":[{"rate":..., "capacity":...}]}.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file

SUCCESS_STATUS = {200, 201, 202}
GARP_ENDPOINTS = {
    "fw_config_garp_rate_limit": ("PUT", "/api/v1/neighbor/garplimitrate"),
}
CONFIG_OP = "fw_config_garp_rate_limit"
RATE_MIN = 1
RATE_MAX = 4096


def build_garp_rate_limit_payload(*, rate: int, capacity: int) -> dict[str, Any]:
    rate = _validate_range("rate", rate, RATE_MIN, RATE_MAX)
    capacity = _validate_positive_int("capacity", capacity)
    return {"id": "0", "val": {"rate": rate, "capacity": capacity}}


def validate_garp_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RunnerError("RUNNER_VALIDATION_FAILED", "GARP payload must be an object.", {"field": "payload"})
    if op_id not in GARP_ENDPOINTS:
        raise RunnerError("RUNNER_UNSUPPORTED_OP", "Runner does not support this GARP operation.", {"op_id": op_id})
    if str(payload.get("id") or "") != "0":
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "GARP payload id must be 0.",
            {"field": "id", "value": payload.get("id")},
        )
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "GARP payload val object is required.",
            {"field": "val"},
        )
    _validate_range("val.rate", val.get("rate"), RATE_MIN, RATE_MAX)
    _validate_positive_int("val.capacity", val.get("capacity"))
    return payload


def build_garp_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, _path = _method_path(op_id)
    return {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(base_url, op_id),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_garp(
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
    headers = {"Content-Type": "application/json", auth_header: header_value}
    status_code, response_payload, _text = request_json(
        method,
        _request_url(base_url, op_id),
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "GARP device request did not return a success status.",
            {
                "op_id": op_id,
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    return {
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


def _request_url(base_url: str, op_id: str) -> str:
    _method, path = _method_path(op_id)
    return f"{normalize_base_url(base_url)}{path}"


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return GARP_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this GARP operation.",
            {"op_id": op_id},
        ) from exc


def _validate_range(field: str, value: int | str, low: int, high: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "GARP integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < low or parsed > high:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"GARP integer field must be between {low} and {high}.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "GARP integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "GARP integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed
