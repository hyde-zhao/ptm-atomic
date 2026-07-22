"""NGFW address-object configuration runner."""

from __future__ import annotations

import re
from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

OBJECT_ENDPOINTS = {
    "fw_config_object": ("POST", "/api/v1/ippool"),
    "fw_update_object": ("PUT", "/api/v1/ippool"),
    "fw_delete_object": ("DELETE", "/api/v1/ippool"),
    "fw_verify_object": ("GET", "/api/v1/ippool"),
    "fw_delete_batch_object": ("POST", "/api/v1/batch"),
}
GET_OPS = {"fw_verify_object"}
DELETE_OPS = {"fw_delete_object"}
NO_BODY_OPS = GET_OPS | DELETE_OPS
PAGINATED_OPS = {"fw_verify_object"}
BATCH_OPS = {"fw_delete_batch_object"}
OBJECT_RESOURCE = "/api/v1/ippool"


def build_address_object_payload(
    *,
    object_name: str,
    ipaddr: str,
    mask: str,
    object_desc: str | None,
) -> dict[str, Any]:
    object_name = _validate_object_name(object_name)
    _validate_ipaddr(ipaddr)
    _validate_ipv4_mask(mask)
    return {
        "val": {
            "name": object_name,
            "desc": object_desc if object_desc is not None else object_name,
            "type": 4,
            "ranges": [],
            "networks": [
                {
                    "ipaddr": ipaddr,
                    "mask": str(mask),
                }
            ],
        }
    }


def build_address_object_update_payload(
    *,
    object_name: str,
    ipaddr: str,
    mask: str,
    object_desc: str | None,
) -> dict[str, Any]:
    config_payload = build_address_object_payload(
        object_name=object_name,
        ipaddr=ipaddr,
        mask=mask,
        object_desc=object_desc,
    )
    return {"id": object_name, "val": config_payload["val"]}


def build_address_object_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_config_object",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "POST",
            "url": f"{normalize_base_url(base_url)}/api/v1/ippool",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_address_object(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    normalized = normalize_base_url(base_url)
    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {
        "Content-Type": "application/json",
        auth_header: header_value,
    }
    status_code, response_payload, _text = request_json(
        "POST",
        f"{normalized}/api/v1/ippool",
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "Address-object configuration was rejected by the device.",
            {
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    return {
        "op_id": "fw_config_object",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "POST",
            "path": "/api/v1/ippool",
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }


# 设备对象名规则：1-31 个字符，由大小写字母/数字/中文/连接符(-)/点(.)构成；
# 名称不能是 "." 或 ".." 单独出现；不能以 "IDMC-" 开头。
# 真相源：ptm-te 实测设备规则。原 isalnum() 实现拒绝点(.)、放行 Unicode 非 ASCII、缺长度/前缀校验。
_OBJ_NAME_RE = re.compile(r"^[A-Za-z0-9一-鿿.\-]{1,31}$")


def _validate_object_name(value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object name is required.",
            {"field": "object_name"},
        )
    name = value.strip()
    if name in {".", ".."}:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object name must not be '.' or '..'.",
            {"field": "object_name", "value": value},
        )
    if name.startswith("IDMC-"):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object name must not start with 'IDMC-'.",
            {"field": "object_name", "value": value},
        )
    if not _OBJ_NAME_RE.match(name):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object name must be 1-31 chars of letters, digits, Chinese, hyphen or dot.",
            {"field": "object_name", "value": value},
        )
    return name


def _validate_ipaddr(value: str) -> None:
    try:
        parsed = ip_address(value)
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object ipaddr must be a valid IP address.",
            {"field": "ipaddr"},
        ) from exc
    if parsed.version != 4:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "This runner currently supports IPv4 address objects only.",
            {"field": "ipaddr", "version": parsed.version},
        )


def _validate_ipv4_mask(value: str) -> None:
    try:
        mask = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object mask must be an integer from 0 to 32.",
            {"field": "mask"},
        ) from exc
    if mask < 0 or mask > 32:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object mask must be an integer from 0 to 32.",
            {"field": "mask", "mask": value},
        )


def build_object_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
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
            "url": _request_url(base_url, op_id, page=page, size=size, payload=payload),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in NO_BODY_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_object(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
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
        _request_url(base_url, op_id, page=page, size=size, payload=payload),
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "Address-object device request did not return a success status.",
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
    payload: dict[str, Any] | None,
) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in PAGINATED_OPS:
        _validate_pagination(page, size)
        url = f"{url}?{urlencode({'page': page, 'size': size})}"
    elif op_id in DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return OBJECT_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this address-object operation.",
            {"op_id": op_id},
        ) from exc


def _validate_pagination(page: int, size: int) -> None:
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object field is required and must be non-empty.",
            {"field": field},
        )


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object field must be a positive integer.",
            {"field": field},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object field must be a positive integer.",
            {"field": field, "value": value},
        )
    return parsed


def build_object_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_non_empty("id", entry_id)
        batch.append({"method": "DELETE", "resource": OBJECT_RESOURCE, "body": {"id": [entry_id]}})
    return {"batch": batch}


def validate_object_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if op_id in BATCH_OPS:
        return _validate_object_batch_payload(payload)
    return payload


def _validate_object_batch_payload(payload: dict[str, Any]) -> dict[str, Any]:
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
        if item.get("method") != "DELETE" or item.get("resource") != OBJECT_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch address-object delete only supports DELETE /api/v1/ippool items.",
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
