"""NGFW custom application-object runner for /api/v1/customappobj."""

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

CUSTOMAPPOBJ_ENDPOINTS = {
    "fw_config_customappobj": ("POST", "/api/v1/customappobj"),
    "fw_update_customappobj": ("PUT", "/api/v1/customappobj"),
    "fw_delete_customappobj": ("DELETE", "/api/v1/customappobj"),
    "fw_delete_batch_customappobj": ("POST", "/api/v1/batch"),
    "fw_verify_customappobj": ("GET", "/api/v1/appobjsearch"),
}
GET_OPS = {"fw_verify_customappobj"}
BATCH_OPS = {"fw_delete_batch_customappobj"}
DELETE_OPS = {"fw_delete_customappobj"}
NO_BODY_OPS = GET_OPS | DELETE_OPS
CUSTOMAPPOBJ_RESOURCE = "/api/v1/customappobj"


def build_customappobj_payload(
    *,
    name_cn: str,
    pid: str,
    protocol: str,
    pattern_type: str,
    pattern: str,
    platform: str = "",
    ip: str = "",
    path: str = "",
    desc: str = "",
    customflag: bool = True,
    name_en: str | None = None,
    tcp_offset: str = "0",
    tcp_port: str = "",
    tcp_direct: str = "client",
) -> dict[str, Any]:
    _validate_non_empty("name_cn", name_cn)
    _validate_non_empty("pid", pid)
    _validate_non_empty("protocol", protocol)
    _validate_non_empty("pattern_type", pattern_type)
    _validate_non_empty("pattern", pattern)
    val: dict[str, Any] = {
        "name_cn": name_cn,
        "pid": pid,
        "protocol": protocol,
        "platform": platform,
        "ip": ip,
        "path": path,
        "pattern_type": pattern_type,
        "pattern": pattern,
        "desc": desc,
        "customflag": customflag,
        "name_en": name_en if name_en is not None else name_cn,
        "tcpudpcfg": {
            "offset": tcp_offset,
            "port": tcp_port,
            "direct": tcp_direct,
        },
    }
    return {"val": val}


def build_customappobj_update_payload(
    *,
    name_cn: str,
    appid: str,
    pid: str,
    protocol: str,
    pattern_type: str,
    pattern: str,
    platform: str = "",
    ip: str = "",
    path: str = "",
    desc: str = "",
    customflag: bool = True,
    name_en: str | None = None,
    tcp_offset: str = "0",
    tcp_port: str = "",
    tcp_direct: str = "client",
) -> dict[str, Any]:
    # 设备约定：顶层 id 为 name_cn（应用对象名），val.id 为设备分配的数字 appid。
    _validate_non_empty("name_cn", name_cn)
    _validate_non_empty("appid", appid)
    config_payload = build_customappobj_payload(
        name_cn=name_cn,
        pid=pid,
        protocol=protocol,
        pattern_type=pattern_type,
        pattern=pattern,
        platform=platform,
        ip=ip,
        path=path,
        desc=desc,
        customflag=customflag,
        name_en=name_en,
        tcp_offset=tcp_offset,
        tcp_port=tcp_port,
        tcp_direct=tcp_direct,
    )
    # val 内携带数字 appid（设备 create response 返回的 id）。
    config_payload["val"]["id"] = appid
    return {"id": name_cn, "val": config_payload["val"]}


def build_customappobj_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_non_empty("id", entry_id)
        batch.append({"method": "DELETE", "resource": CUSTOMAPPOBJ_RESOURCE, "body": {"id": [entry_id]}})
    return {"batch": batch}


def validate_customappobj_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
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
        if item.get("method") != "DELETE" or item.get("resource") != CUSTOMAPPOBJ_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch customappobj delete only supports DELETE /api/v1/customappobj items.",
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


def build_customappobj_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    search_keyword: str,
    istagcustom: int,
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
            "url": _request_url(base_url, op_id, search_keyword=search_keyword, istagcustom=istagcustom, payload=payload),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in NO_BODY_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_customappobj(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    search_keyword: str,
    istagcustom: int,
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
        _request_url(base_url, op_id, search_keyword=search_keyword, istagcustom=istagcustom, payload=payload),
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "Custom application-object device request did not return a success status.",
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
    search_keyword: str,
    istagcustom: int,
    payload: dict[str, Any] | None,
) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in GET_OPS:
        query = {"searchkeyword": search_keyword or "", "istagcustom": istagcustom}
        url = f"{url}?{urlencode(query)}"
    elif op_id in DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return CUSTOMAPPOBJ_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this custom application-object operation.",
            {"op_id": op_id},
        ) from exc


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Custom application-object field is required and must be non-empty.",
            {"field": field},
        )
