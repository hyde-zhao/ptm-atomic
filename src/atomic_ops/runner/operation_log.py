"""NGFW operation-log runner for /api/v1/monitor/operationlog."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200}
OPERATION_LOG_ENDPOINT = ("GET", "/api/v1/monitor/operationlog")
TIME_TYPES = {"1h", "24h", "7d", "1m", "custom"}


def build_operation_log_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    page: int,
    size: int,
    timetype: str,
    starttime: int | str | None,
    endtime: int | str | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, _path = OPERATION_LOG_ENDPOINT
    return {
        "op_id": "fw_capture_operation_log",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(
                base_url,
                page=page,
                size=size,
                timetype=timetype,
                starttime=starttime,
                endtime=endtime,
            ),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_operation_log(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    page: int,
    size: int,
    timetype: str,
    starttime: int | str | None,
    endtime: int | str | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = OPERATION_LOG_ENDPOINT
    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    status_code, response_payload, _text = request_json(
        method,
        _request_url(
            base_url,
            page=page,
            size=size,
            timetype=timetype,
            starttime=starttime,
            endtime=endtime,
        ),
        headers=headers,
        json_payload=None,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Operation-log device request did not return a success status.",
            {
                "op_id": "fw_capture_operation_log",
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    return {
        "op_id": "fw_capture_operation_log",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": method,
            "path": path,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }


def _request_url(
    base_url: str,
    *,
    page: int,
    size: int,
    timetype: str,
    starttime: int | str | None,
    endtime: int | str | None,
) -> str:
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)
    if timetype not in TIME_TYPES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Operation-log timetype is unsupported.",
            {"field": "timetype", "timetype": timetype, "allowed": sorted(TIME_TYPES)},
        )
    query: dict[str, Any] = {"page": page, "size": size, "timetype": timetype}
    if timetype == "custom":
        if starttime is None or endtime is None:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Custom timetype requires both starttime and endtime.",
                {"fields": ["starttime", "endtime"]},
            )
        query["starttime"] = _validate_non_negative_int("starttime", starttime)
        query["endtime"] = _validate_non_negative_int("endtime", endtime)
    return f"{normalize_base_url(base_url)}/api/v1/monitor/operationlog?{urlencode(query)}"


def _validate_non_negative_int(field: str, value: int | str | None) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Operation-log integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Operation-log integer field must be non-negative.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_positive_int(field: str, value: int | str) -> int:
    parsed = _validate_non_negative_int(field, value)
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Operation-log integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed
