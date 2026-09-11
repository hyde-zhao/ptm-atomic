"""NGFW 时间对象 runner for /api/v1/timeobject.

支持 4 种 scheduletype：
- oneshot: 一次性计划，timequantum，time 格式 ``YYYY-MM-DD HH:MM:SS``
- day:     日计划，timequantum，time 格式 ``HH:MM:SS``
- week:    周计划，timequantum，time 格式 ``HH:MM:SS``，额外 weekday:int
- month:   月计划，timemonquantum（注意容器名不同），time:int + planday:str
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

SCHEDULE_TYPES = {"oneshot", "day", "week", "month"}

TIMEOBJECT_ENDPOINTS = {
    "fw_config_timeobject": ("POST", "/api/v1/timeobject"),
    "fw_update_timeobject": ("PUT", "/api/v1/timeobject"),
    "fw_delete_timeobject": ("DELETE", "/api/v1/timeobject"),
    "fw_delete_batch_timeobject": ("POST", "/api/v1/batch"),
    "fw_verify_timeobject": ("GET", "/api/v1/timeobject"),
}
GET_OPS = {"fw_verify_timeobject"}
DELETE_OPS = {"fw_delete_timeobject"}
BATCH_OPS = {"fw_delete_batch_timeobject"}
NO_BODY_OPS = GET_OPS | DELETE_OPS
PAGINATED_OPS = GET_OPS
TIMEOBJECT_RESOURCE = "/api/v1/timeobject"


def build_timeobject_payload(
    *,
    name: str,
    scheduletype: str,
    start_time: str = "",
    end_time: str = "",
    weekday: int | str | None = None,
    month_time: int | str | None = None,
    planday: str = "",
) -> dict[str, Any]:
    _validate_non_empty("name", name)
    if scheduletype not in SCHEDULE_TYPES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"scheduletype must be one of {sorted(SCHEDULE_TYPES)}.",
            {"field": "scheduletype", "value": scheduletype},
        )
    val: dict[str, Any] = {"name": name, "scheduletype": scheduletype}
    if scheduletype == "month":
        val["timemonquantum"] = _build_timemonquantum(month_time=month_time, planday=planday)
    else:
        val["timequantum"] = _build_timequantum(
            scheduletype=scheduletype, start_time=start_time, end_time=end_time, weekday=weekday
        )
    return {"val": val}


def build_timeobject_update_payload(
    *,
    entry_id: str,
    name: str,
    scheduletype: str,
    start_time: str = "",
    end_time: str = "",
    weekday: int | str | None = None,
    month_time: int | str | None = None,
    planday: str = "",
) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    config_payload = build_timeobject_payload(
        name=name,
        scheduletype=scheduletype,
        start_time=start_time,
        end_time=end_time,
        weekday=weekday,
        month_time=month_time,
        planday=planday,
    )
    return {"id": entry_id, "val": config_payload["val"]}


def build_timeobject_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_non_empty("id", entry_id)
        batch.append({"method": "DELETE", "resource": TIMEOBJECT_RESOURCE, "body": {"id": [entry_id]}})
    return {"batch": batch}


def validate_timeobject_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if op_id in BATCH_OPS:
        return _validate_batch_payload(payload)
    return payload


def _validate_batch_payload(payload: dict[str, Any]) -> dict[str, Any]:
    batch = payload.get("batch")
    if not isinstance(batch, list) or not batch:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Batch delete payload must contain a non-empty batch list.",
            {"field": "batch"},
        )
    for item in batch:
        if not isinstance(item, dict):
            raise RunnerError("RUNNER_VALIDATION_FAILED", "Batch item must be an object.", {"field": "batch"})
        if item.get("method") != "DELETE" or item.get("resource") != TIMEOBJECT_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                f"Batch delete only supports DELETE {TIMEOBJECT_RESOURCE} items.",
                {"method": item.get("method"), "resource": item.get("resource")},
            )
        body = item.get("body")
        ids = body.get("id") if isinstance(body, dict) else None
        if not isinstance(ids, list) or not ids:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch delete item body.id must be a non-empty list.",
                {"field": "batch"},
            )
    return payload


def build_timeobject_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    keywords: str,
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
            "url": _request_url(base_url, op_id, page=page, size=size, keywords=keywords, payload=payload),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in NO_BODY_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_timeobject(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    keywords: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    status_code, response_payload, _text = request_json(
        method,
        _request_url(base_url, op_id, page=page, size=size, keywords=keywords, payload=payload),
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise_if_device_session_rejected(status_code, response_payload)
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "Time-object device request did not return a success status.",
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


def _request_url(
    base_url: str,
    op_id: str,
    *,
    page: int,
    size: int,
    keywords: str,
    payload: dict[str, Any] | None,
) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in PAGINATED_OPS:
        _validate_pagination(page, size)
        query: dict[str, Any] = {"page": page, "size": size}
        if keywords:
            query["keywords"] = keywords
        url = f"{url}?{urlencode(query)}"
    elif op_id in DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return TIMEOBJECT_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this time-object operation.",
            {"op_id": op_id},
        ) from exc


def _build_timequantum(
    *,
    scheduletype: str,
    start_time: str,
    end_time: str,
    weekday: int | str | None,
) -> list[dict[str, Any]]:
    _validate_non_empty("start_time", start_time)
    _validate_non_empty("end_time", end_time)
    if scheduletype == "oneshot":
        _validate_datetime("start_time", start_time)
        _validate_datetime("end_time", end_time)
    else:  # day / week
        _validate_time_only("start_time", start_time)
        _validate_time_only("end_time", end_time)
    entry: dict[str, Any] = {
        "starttime": {"time": start_time},
        "endtime": {"time": end_time},
    }
    if scheduletype == "week":
        if weekday is None:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "weekday is required for week scheduletype.",
                {"field": "weekday"},
            )
        weekday_int = _validate_int_field("weekday", weekday)
        # 结构化入口将同一 weekday 同时设给 starttime 与 endtime；
        # 起止 weekday 不同或多段周计划请走 --payload-json / --payload-file 透传。
        entry["starttime"]["weekday"] = weekday_int
        entry["endtime"]["weekday"] = weekday_int
    return [entry]


def _build_timemonquantum(*, month_time: int | str | None, planday: str) -> list[dict[str, Any]]:
    if month_time is None:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "month_time is required for month scheduletype.",
            {"field": "month_time"},
        )
    _validate_non_empty("planday", planday)
    return [{"time": _validate_int_field("month_time", month_time), "planday": planday}]


def _validate_datetime(field: str, value: str) -> None:
    try:
        datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must match YYYY-MM-DD HH:MM:SS for oneshot scheduletype.",
            {"field": field, "value": value},
        ) from exc


def _validate_time_only(field: str, value: str) -> None:
    try:
        datetime.strptime(value, "%H:%M:%S")
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must match HH:MM:SS for day/week scheduletype.",
            {"field": field, "value": value},
        ) from exc


def _validate_pagination(page: int, size: int) -> None:
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Time-object field is required and must be non-empty.",
            {"field": field},
        )


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Time-object field must be a positive integer.",
            {"field": field},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Time-object field must be a positive integer.",
            {"field": field, "value": value},
        )
    return parsed


def _validate_int_field(field: str, value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must be an integer.",
            {"field": field},
        ) from exc
