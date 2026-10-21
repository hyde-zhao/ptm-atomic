"""NGFW system-time reader for GET /api/v1/systime.

The endpoint is read-only by design: this module never issues PUT /api/v1/systime.
It reads ``vals[0]`` and exposes name/enable/date/time/ntp plus optional exact
match flags for ``expected_date`` and ``expected_time``. The result can be used
as a log timestamp baseline or a time-accuracy check.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SYSTEM_TIME_PATH = "/api/v1/systime"
SYSTEM_TIME_ID = "systime"
SUCCESS_STATUS = {200}
SYSTEM_TIME_FIELDS = ("name", "enable", "date", "time", "ntp")


def build_system_time_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    verify_tls: bool,
    timeout: float,
    expected_date: str | None = None,
    expected_time: str | None = None,
) -> dict[str, Any]:
    date_expectation, time_expectation = _validate_expectations(expected_date, expected_time)
    return {
        "op_id": "fw_verify_system_time",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": _request_url(base_url),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "expected_date": date_expectation,
        "expected_time": time_expectation,
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_system_time(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    verify_tls: bool,
    timeout: float,
    expected_date: str | None = None,
    expected_time: str | None = None,
) -> dict[str, Any]:
    date_expectation, time_expectation = _validate_expectations(expected_date, expected_time)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}

    status_code, response_payload, _text = request_json(
        "GET",
        _request_url(base_url),
        headers=headers,
        json_payload=None,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response_payload, op_id="fw_verify_system_time")
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "System-time device request did not return a success status.",
            {
                "op_id": "fw_verify_system_time",
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )

    vals = response_payload.get("vals")
    if not isinstance(vals, list) or not vals:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "System-time response has no vals entry.",
            {
                "op_id": "fw_verify_system_time",
                "response_keys": sorted(response_payload.keys()),
                "vals_type": type(vals).__name__,
            },
        )
    entry = vals[0]
    if not isinstance(entry, dict):
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "System-time vals[0] must be an object.",
            {"op_id": "fw_verify_system_time", "type": type(entry).__name__},
        )

    observed = {field: entry.get(field) for field in SYSTEM_TIME_FIELDS}
    matches_date = date_expectation is None or str(observed["date"]) == date_expectation
    matches_time = time_expectation is None or str(observed["time"]) == time_expectation
    return {
        "op_id": "fw_verify_system_time",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "GET",
            "path": SYSTEM_TIME_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "query": {"id": SYSTEM_TIME_ID},
        },
        **observed,
        "expected_date": date_expectation,
        "expected_time": time_expectation,
        "matches_expected_date": matches_date,
        "matches_expected_time": matches_time,
        "matches_expected": matches_date and matches_time,
        "response": response_payload,
    }


def _validate_expectations(
    expected_date: str | None,
    expected_time: str | None,
) -> tuple[str | None, str | None]:
    date_expectation = _normalize_expectation("expected_date", expected_date)
    time_expectation = _normalize_expectation("expected_time", expected_time)
    return date_expectation, time_expectation


def _normalize_expectation(field: str, value: str | None) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "System-time expectation must not be empty when supplied.",
            {"field": field},
        )
    return text


def _request_url(base_url: str) -> str:
    return f"{normalize_base_url(base_url)}{SYSTEM_TIME_PATH}?id={SYSTEM_TIME_ID}"
