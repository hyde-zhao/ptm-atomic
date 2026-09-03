"""NGFW file type object runner for /api/v1/appsec/filetype and /api/v1/appsec/filetypeObj."""

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

FILETYPE_ENDPOINTS = {
    "fw_config_filetype": ("POST", "/api/v1/appsec/filetype"),
    "fw_update_filetype": ("PUT", "/api/v1/appsec/filetype"),
    "fw_delete_filetype": ("DELETE", "/api/v1/appsec/filetype"),
    "fw_verify_filetype": ("GET", "/api/v1/appsec/filetype"),
    "fw_verify_filetype_preset": ("GET", "/api/v1/appsec/filetype"),
    "fw_config_filetypeobj": ("POST", "/api/v1/appsec/filetypeObj"),
    "fw_update_filetypeobj": ("PUT", "/api/v1/appsec/filetypeObj"),
    "fw_verify_filetypeobj": ("GET", "/api/v1/appsec/filetypeObj"),
    "fw_delete_batch_filetypeobj": ("POST", "/api/v1/batch"),
}
GET_OPS = {"fw_verify_filetypeobj", "fw_verify_filetype", "fw_verify_filetype_preset"}
DELETE_OPS = {"fw_delete_filetype"}
BATCH_OPS = {"fw_delete_batch_filetypeobj"}
NO_BODY_OPS = GET_OPS | DELETE_OPS
# Only the file type group query is paginated; the file type object query
# takes a fixed type discriminator (predefine | custom) and ignores page/size.
PAGINATED_OPS = {"fw_verify_filetypeobj"}
FILETYPE_TYPE_QUERIES = {
    "fw_verify_filetype": "custom",
    "fw_verify_filetype_preset": "predefine",
}
FILETYPE_RESOURCE = "/api/v1/appsec/filetype"
FILETYPEOBJ_RESOURCE = "/api/v1/appsec/filetypeObj"


def build_filetype_payload(
    *,
    name: str,
    description: str = "",
    file_type: bool = True,
    classify: list[int] | None = None,
    refcnt: int = 0,
) -> dict[str, Any]:
    _validate_non_empty("name", name)
    val: dict[str, Any] = {
        "name": name,
        "type": file_type,
        "classify": classify if classify is not None else [0],
        "refcnt": refcnt,
        "description": description,
    }
    return {"id": 0, "val": val}


def build_filetype_update_payload(
    *,
    entry_id: str,
    name: str,
    description: str = "",
    file_type: bool = True,
    classify: list[int] | None = None,
    refcnt: int = 0,
) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    config_payload = build_filetype_payload(
        name=name, description=description, file_type=file_type, classify=classify, refcnt=refcnt
    )
    return {"id": entry_id, "val": config_payload["val"]}


def build_filetypeobj_payload(
    *,
    name: str,
    des: str = "",
    filetypes: list[str] | None = None,
) -> dict[str, Any]:
    _validate_non_empty("name", name)
    val: dict[str, Any] = {
        "name": name,
        "des": des,
        "filetype": [{"name": ft, "type": False} for ft in _validate_filetypes(filetypes)],
    }
    return {"id": 0, "val": val}


def build_filetypeobj_update_payload(
    *,
    entry_id: str,
    name: str,
    des: str = "",
    filetypes: list[str] | None = None,
) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    config_payload = build_filetypeobj_payload(name=name, des=des, filetypes=filetypes)
    return {"id": entry_id, "val": config_payload["val"]}


def build_filetype_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_non_empty("id", entry_id)
        batch.append({"method": "DELETE", "resource": FILETYPEOBJ_RESOURCE, "body": {"id": [entry_id]}})
    return {"batch": batch}


def validate_filetype_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
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
        if item.get("method") != "DELETE" or item.get("resource") != FILETYPEOBJ_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                f"Batch delete only supports DELETE {FILETYPEOBJ_RESOURCE} items.",
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


def build_filetype_dry_run(
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
            "url": _request_url(
                base_url, op_id, page=page, size=size, keywords=keywords, payload=payload
            ),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in NO_BODY_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_filetype(
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
            "File type object device request did not return a success status.",
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
    if op_id in FILETYPE_TYPE_QUERIES:
        # File type object query: type is fixed per op (custom / predefine),
        # optional keywords filters by name or description substring.
        query: dict[str, Any] = {"type": FILETYPE_TYPE_QUERIES[op_id]}
        if keywords:
            query["keywords"] = keywords
        url = f"{url}?{urlencode(query, doseq=True)}"
    elif op_id in PAGINATED_OPS:
        _validate_pagination(page, size)
        query: dict[str, Any] = {"page": page, "size": size}
        if keywords:
            query["keywords"] = keywords
        url = f"{url}?{urlencode(query, doseq=True)}"
    elif op_id in DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return FILETYPE_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this file type object operation.",
            {"op_id": op_id},
        ) from exc


def _validate_filetypes(filetypes: list[str] | None) -> list[str]:
    if filetypes is None:
        return []
    if not isinstance(filetypes, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "filetypes must be a list of strings.",
            {"field": "filetypes"},
        )
    normalized: list[str] = []
    for item in filetypes:
        if not isinstance(item, str) or not item.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each filetypes entry must be a non-empty string.",
                {"field": "filetypes"},
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
            "File type object field is required and must be non-empty.",
            {"field": field},
        )


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "File type object field must be a positive integer.",
            {"field": field},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "File type object field must be a positive integer.",
            {"field": field, "value": value},
        )
    return parsed
