"""NGFW custom application-tag runner for /api/v1/customappobjtag."""

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

CUSTOMAPPOBJTAG_ENDPOINTS = {
    "fw_config_customappobjtag": ("POST", "/api/v1/customappobjtag"),
    "fw_update_customappobjtag": ("PUT", "/api/v1/customappobjtag"),
    "fw_delete_customappobjtag": ("DELETE", "/api/v1/customappobjtag"),
    "fw_delete_batch_customappobjtag": ("POST", "/api/v1/batch"),
    "fw_verify_customappobjtag": ("GET", "/api/v1/customappobjtag"),
}
GET_OPS = {"fw_verify_customappobjtag"}
BATCH_OPS = {"fw_delete_batch_customappobjtag"}
DELETE_OPS = {"fw_delete_customappobjtag"}
NO_BODY_OPS = GET_OPS | DELETE_OPS
PAGINATED_OPS = {"fw_verify_customappobjtag"}
CUSTOMAPPOBJTAG_RESOURCE = "/api/v1/customappobjtag"


def build_customappobjtag_payload(
    *,
    name_cn: str,
    desc: str = "",
    customflag: bool = True,
    appobjkeys: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    _validate_non_empty("name_cn", name_cn)
    keys = _validate_appobjkeys(appobjkeys)
    val: dict[str, Any] = {
        "name_cn": name_cn,
        "desc": desc,
        "customflag": customflag,
        "appobjkeys": keys,
    }
    return {"val": val}


def build_customappobjtag_update_payload(
    *,
    entry_id: str,
    name_cn: str,
    desc: str = "",
    customflag: bool = True,
    appobjkeys: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    config_payload = build_customappobjtag_payload(
        name_cn=name_cn,
        desc=desc,
        customflag=customflag,
        appobjkeys=appobjkeys,
    )
    return {"id": entry_id, "val": config_payload["val"]}


def build_customappobjtag_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_non_empty("id", entry_id)
        batch.append({"method": "DELETE", "resource": CUSTOMAPPOBJTAG_RESOURCE, "body": {"id": [entry_id]}})
    return {"batch": batch}


def validate_customappobjtag_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
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
        if item.get("method") != "DELETE" or item.get("resource") != CUSTOMAPPOBJTAG_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch customappobjtag delete only supports DELETE /api/v1/customappobjtag items.",
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


def build_customappobjtag_dry_run(
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


def execute_customappobjtag(
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
            "Custom application-tag device request did not return a success status.",
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
        query = {"page": page, "size": size}
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
        return CUSTOMAPPOBJTAG_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this custom application-tag operation.",
            {"op_id": op_id},
        ) from exc


def _validate_appobjkeys(appobjkeys: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if appobjkeys is None:
        return []
    if not isinstance(appobjkeys, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "appobjkeys must be a list of objects.",
            {"field": "appobjkeys"},
        )
    normalized: list[dict[str, Any]] = []
    for item in appobjkeys:
        if not isinstance(item, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each appobjkeys entry must be an object with appname and appid.",
                {"field": "appobjkeys"},
            )
        appname = item.get("appname")
        appid = item.get("appid")
        if not isinstance(appname, str) or not appname.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "appobjkeys entry appname is required.",
                {"field": "appobjkeys"},
            )
        if appid is None or str(appid).strip() == "":
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "appobjkeys entry appid is required.",
                {"field": "appobjkeys"},
            )
        normalized.append({"appname": appname, "appid": str(appid)})
    return normalized


def _validate_pagination(page: int, size: int) -> None:
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Custom application-tag field is required and must be non-empty.",
            {"field": field},
        )


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Custom application-tag field must be a positive integer.",
            {"field": field},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Custom application-tag field must be a positive integer.",
            {"field": field, "value": value},
        )
    return parsed
