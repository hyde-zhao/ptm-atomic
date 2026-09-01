"""NGFW certificate runner for /api/v1/cert/localcert and /api/v1/cert/localcacert."""

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

CERT_ENDPOINTS = {
    "fw_config_localcert": ("POST", "/api/v1/cert/localcert"),
    "fw_update_localcert": ("PUT", "/api/v1/cert/localcert"),
    "fw_delete_localcert": ("DELETE", "/api/v1/cert/localcert"),
    "fw_delete_batch_localcert": ("POST", "/api/v1/batch"),
    "fw_verify_localcert": ("GET", "/api/v1/cert/localcert"),
    "fw_config_localcacert": ("POST", "/api/v1/cert/localcacert"),
    "fw_verify_localcacert": ("GET", "/api/v1/cert/localcacert"),
    "fw_delete_batch_localcacert": ("POST", "/api/v1/batch"),
}
GET_OPS = {"fw_verify_localcert", "fw_verify_localcacert"}
DELETE_OPS = {"fw_delete_localcert"}
BATCH_OPS = {"fw_delete_batch_localcert", "fw_delete_batch_localcacert"}
NO_BODY_OPS = GET_OPS | DELETE_OPS
PAGINATED_OPS = GET_OPS
LOCALCERT_RESOURCE = "/api/v1/cert/localcert"
LOCALCACERT_RESOURCE = "/api/v1/cert/localcacert"
BATCH_RESOURCES = {
    "fw_delete_batch_localcert": LOCALCERT_RESOURCE,
    "fw_delete_batch_localcacert": LOCALCACERT_RESOURCE,
}
SUBJECT_FIELDS = ("country", "state", "location", "organization", "organUnit")
KEY_TYPES = ("RSA", "SM2")


def build_localcert_payload(
    *,
    name: str,
    subject: dict[str, Any] | None = None,
    key_type: str = "RSA",
    key_length: int = 2048,
) -> dict[str, Any]:
    _validate_non_empty("name", name)
    key_type = _validate_key_type(key_type)
    option: dict[str, Any] = {"type": key_type}
    if key_type != "SM2":
        option["keyLenth"] = _validate_positive_int("keyLenth", key_length)
    val: dict[str, Any] = {
        "name": name,
        "subject": _validate_subject(subject),
        "option": option,
    }
    return {"val": val}


def build_localcert_update_payload(
    *,
    entry_id: str,
    name: str,
    subject: dict[str, Any] | None = None,
    key_type: str = "RSA",
    key_length: int = 2048,
) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    config_payload = build_localcert_payload(
        name=name, subject=subject, key_type=key_type, key_length=key_length
    )
    return {"id": entry_id, "val": config_payload["val"]}


def build_localcert_issue_payload(
    *,
    entry_id: str,
    cacert: str = "defaultLocalCA.crt",
    option: str = "1",
    time_length: int = 30,
) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    _validate_non_empty("cacert", cacert)
    val: dict[str, Any] = {
        "option": option,
        "cacert": cacert,
        "timeLenth": _validate_positive_int("timeLenth", time_length),
    }
    return {"id": entry_id, "val": val}


def build_localcacert_payload(
    *,
    name: str,
    subject: dict[str, Any] | None = None,
    key_type: str = "RSA",
    time_length: int = 30,
) -> dict[str, Any]:
    _validate_non_empty("name", name)
    val: dict[str, Any] = {
        "name": name,
        "subject": _validate_subject(subject),
        "type": _validate_key_type(key_type),
        "timeLenth": _validate_positive_int("timeLenth", time_length),
    }
    return {"val": val}


def build_cert_batch_delete_payload(*, entry_ids: list[str], resource: str = LOCALCERT_RESOURCE) -> dict[str, Any]:
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_non_empty("id", entry_id)
        batch.append({"method": "DELETE", "resource": resource, "body": {"id": [str(entry_id)]}})
    return {"batch": batch}


def validate_cert_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if op_id in BATCH_OPS:
        return _validate_batch_payload(payload, op_id)
    return payload


def _validate_batch_payload(payload: dict[str, Any], op_id: str) -> dict[str, Any]:
    resource = BATCH_RESOURCES[op_id]
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


def build_cert_dry_run(
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


def execute_cert(
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
            "Certificate device request did not return a success status.",
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
        url = f"{url}?{urlencode(query, doseq=True)}"
    elif op_id in DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return CERT_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this certificate operation.",
            {"op_id": op_id},
        ) from exc


def _validate_subject(subject: dict[str, Any] | None) -> dict[str, str]:
    if subject is None:
        return {field: "" for field in SUBJECT_FIELDS}
    if not isinstance(subject, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "subject must be an object with country/state/location/organization/organUnit fields.",
            {"field": "subject"},
        )
    return {field: str(subject.get(field, "")) for field in SUBJECT_FIELDS}


def _validate_key_type(key_type: str) -> str:
    if not isinstance(key_type, str) or key_type not in KEY_TYPES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "key_type must be one of RSA or SM2.",
            {"field": "key_type", "value": key_type},
        )
    return key_type


def _validate_pagination(page: int, size: int) -> None:
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Certificate field is required and must be non-empty.",
            {"field": field},
        )


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Certificate field must be a positive integer.",
            {"field": field},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Certificate field must be a positive integer.",
            {"field": field, "value": value},
        )
    return parsed
