"""NGFW service pool and service group runner for /api/v1/servicepool(+/group)."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

SERVICEPOOL_ENDPOINTS = {
    "fw_config_servicepool": ("POST", "/api/v1/servicepool"),
    "fw_update_servicepool": ("PUT", "/api/v1/servicepool"),
    "fw_delete_servicepool": ("DELETE", "/api/v1/servicepool"),
    "fw_delete_batch_servicepool": ("POST", "/api/v1/batch"),
    "fw_verify_servicepool": ("GET", "/api/v1/servicepool"),
    "fw_verify_servicepool_preset": ("GET", "/api/v1/servicepool"),
    "fw_config_servicepool_group": ("POST", "/api/v1/servicepool/group"),
    "fw_update_servicepool_group": ("PUT", "/api/v1/servicepool/group"),
    "fw_delete_servicepool_group": ("DELETE", "/api/v1/servicepool/group"),
    "fw_delete_batch_servicepool_group": ("POST", "/api/v1/batch"),
    "fw_verify_servicepool_group": ("GET", "/api/v1/servicepool/group"),
}
GET_OPS = {
    "fw_verify_servicepool",
    "fw_verify_servicepool_preset",
    "fw_verify_servicepool_group",
}
BATCH_OPS = {
    "fw_delete_batch_servicepool",
    "fw_delete_batch_servicepool_group",
}
DELETE_OPS = {
    "fw_delete_servicepool",
    "fw_delete_servicepool_group",
}
NO_BODY_OPS = GET_OPS | DELETE_OPS
PAGINATED_OPS = GET_OPS
SERVICEPOOL_RESOURCE = "/api/v1/servicepool"
SERVICEPOOL_GROUP_RESOURCE = "/api/v1/servicepool/group"


def build_servicepool_payload(
    *,
    name: str,
    desc: str = "",
    ranges: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    _validate_non_empty("name", name)
    val: dict[str, Any] = {
        "name": name,
        "desc": desc,
        "type": "CUSTOM",
        "ranges": _validate_ranges(ranges),
    }
    return {"val": val}


def build_servicepool_update_payload(
    *,
    entry_id: str,
    name: str,
    desc: str = "",
    ranges: list[dict[str, Any]] | None = None,
    config_source: int = 0,
) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    config_payload = build_servicepool_payload(name=name, desc=desc, ranges=ranges)
    config_payload["val"]["config_source"] = config_source
    return {"id": entry_id, "val": config_payload["val"]}


def build_servicepool_group_payload(
    *,
    name: str,
    desc: str = "",
    servicepools: list[str] | None = None,
) -> dict[str, Any]:
    _validate_non_empty("name", name)
    val: dict[str, Any] = {
        "name": name,
        "desc": desc,
        "servicepools": _validate_servicepools(servicepools),
    }
    return {"val": val}


def build_servicepool_group_update_payload(
    *,
    entry_id: str,
    name: str,
    desc: str = "",
    servicepools: list[str] | None = None,
) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    config_payload = build_servicepool_group_payload(name=name, desc=desc, servicepools=servicepools)
    return {"id": entry_id, "val": config_payload["val"]}


def build_servicepool_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    return _build_batch_delete_payload(entry_ids=entry_ids, resource=SERVICEPOOL_RESOURCE)


def build_servicepool_group_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    return _build_batch_delete_payload(entry_ids=entry_ids, resource=SERVICEPOOL_GROUP_RESOURCE)


def _build_batch_delete_payload(*, entry_ids: list[str], resource: str) -> dict[str, Any]:
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_non_empty("id", entry_id)
        batch.append({"method": "DELETE", "resource": resource, "body": {"id": [entry_id]}})
    return {"batch": batch}


def validate_servicepool_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if op_id == "fw_delete_batch_servicepool":
        return _validate_batch_payload(payload, resource=SERVICEPOOL_RESOURCE)
    if op_id == "fw_delete_batch_servicepool_group":
        return _validate_batch_payload(payload, resource=SERVICEPOOL_GROUP_RESOURCE)
    return payload


def _validate_batch_payload(payload: dict[str, Any], *, resource: str) -> dict[str, Any]:
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
        if item.get("method") != "DELETE" or item.get("resource") != resource:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                f"Batch delete only supports DELETE {resource} items.",
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


def build_servicepool_dry_run(
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


def execute_servicepool(
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
    session_payload = read_session_file(session_file)
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
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "Service pool device request did not return a success status.",
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
        if op_id == "fw_verify_servicepool":
            query["type"] = "CUSTOM"
            if keywords:
                query["keywords"] = keywords
        elif op_id == "fw_verify_servicepool_preset":
            query["type"] = "PRESET"
        elif op_id == "fw_verify_servicepool_group":
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
        return SERVICEPOOL_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this service pool operation.",
            {"op_id": op_id},
        ) from exc


def _validate_ranges(ranges: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if ranges is None:
        return []
    if not isinstance(ranges, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ranges must be a list of objects.",
            {"field": "ranges"},
        )
    normalized: list[dict[str, Any]] = []
    for item in ranges:
        if not isinstance(item, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each ranges entry must be an object with proto, s_start, s_end, d_start, d_end.",
                {"field": "ranges"},
            )
        normalized.append({
            "proto": _validate_int_field("ranges.proto", item.get("proto")),
            "s_start": _validate_int_field("ranges.s_start", item.get("s_start")),
            "s_end": _validate_int_field("ranges.s_end", item.get("s_end")),
            "d_start": _validate_int_field("ranges.d_start", item.get("d_start")),
            "d_end": _validate_int_field("ranges.d_end", item.get("d_end")),
        })
    return normalized


def _validate_servicepools(servicepools: list[str] | None) -> list[str]:
    if servicepools is None:
        return []
    if not isinstance(servicepools, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "servicepools must be a list of strings.",
            {"field": "servicepools"},
        )
    normalized: list[str] = []
    for item in servicepools:
        if not isinstance(item, str) or not item.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each servicepools entry must be a non-empty string.",
                {"field": "servicepools"},
            )
        normalized.append(item)
    return normalized


def _validate_pagination(page: int, size: int) -> None:
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Service pool field is required and must be non-empty.",
            {"field": field},
        )


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Service pool field must be a positive integer.",
            {"field": field},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Service pool field must be a positive integer.",
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
