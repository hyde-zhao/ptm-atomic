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
from atomic_ops.runner.http import request_json, request_json_with_retries
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.pagination import fetch_all_pages, response_payload_or_raise
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
# P2 delete 未就绪缺口：删除类 op 允许可选内部重试（--retry，默认 0 不重试）。
RETRYABLE_DELETE_OPS = {"fw_delete_timeobject"}


def build_timeobject_payload(
    *,
    name: str,
    scheduletype: str,
    start_time: str = "",
    end_time: str = "",
    weekday: int | str | None = None,
    month_time: int | str | None = None,
    planday: str = "",
    time_ranges: list[str] | None = None,
    month_quanta: list[str] | None = None,
) -> dict[str, Any]:
    _validate_non_empty("name", name)
    if scheduletype not in SCHEDULE_TYPES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"scheduletype must be one of {sorted(SCHEDULE_TYPES)}.",
            {"field": "scheduletype", "value": scheduletype},
        )
    val: dict[str, Any] = {"name": name, "scheduletype": scheduletype}
    # 下游现场（2026-09-08~09-11）：结构化 CLI 此前恒生成单段 timequantum /
    # timemonquantum，跨天/跨周/跨月的双段/多段时间对象表达不了（--payload-json
    # 逃生口未在 atom 文档化，结构化入口也没有多段能力）。
    # --time-range / --month-quantum 提供显式多段入口；未传时保持原单段路径完全不变。
    if time_ranges:
        if scheduletype == "month":
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "--time-range supports oneshot/day/week scheduletype; use --month-quantum for month.",
                {"field": "time_ranges", "scheduletype": scheduletype},
            )
        if start_time or end_time or weekday is not None:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "--time-range must not be combined with --start-time/--end-time/--weekday.",
                {"field": "time_ranges"},
            )
        val["timequantum"] = _parse_time_ranges(scheduletype, time_ranges)
        return {"val": val}
    if month_quanta:
        if scheduletype != "month":
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "--month-quantum supports month scheduletype only; use --time-range for others.",
                {"field": "month_quanta", "scheduletype": scheduletype},
            )
        if month_time is not None or planday:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "--month-quantum must not be combined with --month-time/--planday.",
                {"field": "month_quanta"},
            )
        val["timemonquantum"] = _parse_month_quanta(month_quanta)
        return {"val": val}
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
    time_ranges: list[str] | None = None,
    month_quanta: list[str] | None = None,
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
        time_ranges=time_ranges,
        month_quanta=month_quanta,
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
    aggregate_page_size: int | None = None,
    retries: int = 0,
    retry_backoff_seconds: float = 1.0,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}

    def _fetch_single(page_number: int, page_size: int) -> tuple[int, dict[str, Any], str]:
        return request_json(
            method,
            _request_url(
                base_url, op_id, page=page_number, size=page_size,
                keywords=keywords, payload=payload,
            ),
            headers=headers,
            json_payload=None if op_id in NO_BODY_OPS else payload,
            timeout=timeout,
            verify_tls=verify_tls,
        )

    # P2 大批量 verify 缺口：--page-size 开启内部翻页聚合（默认 None 行为不变）。
    if aggregate_page_size is not None and op_id in GET_OPS:
        response_payload = fetch_all_pages(
            lambda page_number, page_size: response_payload_or_raise(
                op_id, method, _fetch_single(page_number, page_size)
            ),
            page_size=aggregate_page_size,
        )
        status_code = 200
    else:
        # P2 delete 未就绪缺口：删除类 op 支持可选内部重试（默认 retries=0 行为不变）。
        status_code, response_payload, _text = request_json_with_retries(
            lambda: _fetch_single(page, size),
            retries=retries if op_id in RETRYABLE_DELETE_OPS else 0,
            backoff_seconds=retry_backoff_seconds,
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


def _parse_time_ranges(scheduletype: str, time_ranges: list[str]) -> list[dict[str, Any]]:
    """解析可重复 ``--time-range`` 为多段 timequantum（每段一个 entry）。

    段格式（起止用 ``~`` 分隔，时间值本身不含 ``~``）：
    - oneshot: ``YYYY-MM-DD HH:MM:SS~YYYY-MM-DD HH:MM:SS``
    - day:     ``HH:MM:SS~HH:MM:SS``
    - week:    ``N:HH:MM:SS~M:HH:MM:SS``（起止 weekday 可不同，支持跨天段；
               也可 ``N:HH:MM:SS~HH:MM:SS``，end 复用 start 的 weekday）
    解析或校验失败一律 RUNNER_VALIDATION_FAILED，不静默丢弃任何一段。
    """
    entries: list[dict[str, Any]] = []
    for raw in time_ranges:
        text = str(raw).strip()
        if not text:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "--time-range entries must be non-empty.",
                {"field": "time_range"},
            )
        start_text, sep, end_text = text.partition("~")
        if not sep:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "--time-range must contain '~' separating start and end.",
                {"field": "time_range", "value": text},
            )
        start_text = start_text.strip()
        end_text = end_text.strip()
        start_weekday: int | None = None
        end_weekday: int | None = None
        if scheduletype == "week":
            start_weekday, start_text = _split_weekday(start_text)
            end_weekday, end_text = _split_weekday(end_text)
            if end_weekday is None:
                # 端未写 weekday 时复用 start 的 weekday（与单段入口同语义）。
                end_weekday = start_weekday
        elif ":" in start_text and scheduletype == "day":
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "--time-range for day scheduletype must not carry a weekday prefix.",
                {"field": "time_range", "value": text},
            )
        if scheduletype == "oneshot":
            _validate_datetime("time_range start", start_text)
            _validate_datetime("time_range end", end_text)
        else:
            _validate_time_only("time_range start", start_text)
            _validate_time_only("time_range end", end_text)
        entry: dict[str, Any] = {
            "starttime": {"time": start_text},
            "endtime": {"time": end_text},
        }
        if scheduletype == "week":
            # 多段入口允许起止 weekday 不同（跨天段）；单段入口仍把同一 weekday
            # 同时设给两端，行为不变。
            entry["starttime"]["weekday"] = start_weekday
            entry["endtime"]["weekday"] = end_weekday
        entries.append(entry)
    return entries


def _split_weekday(text: str) -> tuple[int | None, str]:
    """拆分 week 段的前缀 weekday（``N:HH:MM:SS``）；无前缀时返回 (None, 原文)。"""
    prefix, sep, rest = text.partition(":")
    if not sep or not prefix.strip().isdigit():
        return None, text
    # 剩余部分必须仍是 HH:MM:SS（含两处冒号），否则该冒号是时间自身的一部分。
    if rest.count(":") != 2:
        return None, text
    return _validate_int_field("weekday", prefix.strip()), rest.strip()


def _parse_month_quanta(month_quanta: list[str]) -> list[dict[str, Any]]:
    """解析可重复 ``--month-quantum`` 为多段 timemonquantum。

    段格式：``time:planday``，如 ``15:1,2,3``（time 为月中第几周的 int，
    planday 为日计划字符串，可含逗号；以第一个 ``:`` 分隔）。
    """
    entries: list[dict[str, Any]] = []
    for raw in month_quanta:
        text = str(raw).strip()
        time_part, sep, planday_part = text.partition(":")
        if not sep or not time_part.strip() or not planday_part.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                '--month-quantum must be "<time>:<planday>", e.g. "15:1,2,3".',
                {"field": "month_quantum", "value": text},
            )
        entries.append(
            {"time": _validate_int_field("month_time", time_part.strip()), "planday": planday_part.strip()}
        )
    return entries


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
