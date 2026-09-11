"""NGFW geoip (custom region object) runner.

Custom region objects map an IP range to a geographic location
(country/province/city). Unlike the name-keyed object families, a geoip
object has no name: it is identified by a numeric id returned on create and
queried by IP. Shapes are confirmed against the device (probe17_record.json):

  POST   /api/v1/geoip/custom   {"val":{accuracy,desc,ip,country,province,city}} -> {id,msg}
  PUT    /api/v1/geoip/custom   {"id":N,"val":{...}}
  DELETE /api/v1/geoip/custom?id=<numeric id>
  POST   /api/v1/batch          {"batch":[{"method":"DELETE","resource":"/api/v1/geoip/custom","body":{"id":[<string id>]}}]}
  GET    /api/v1/geoip/custom?page=&size=&keywords= -> {count,page,size,vals}

The verify (list) endpoint is the paginated GET used by the web UI. The
geoip.txt "query" endpoint (/api/v1/geoip/query?ip=) performs an IP-to-region
lookup; it is a functional query, not an object-management listing, so it is
not exposed as a separate atomic op.
"""

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

GEOIP_RESOURCE = "/api/v1/geoip/custom"
GEOIP_ENDPOINTS = {
    "fw_config_geoip": ("POST", GEOIP_RESOURCE),
    "fw_update_geoip": ("PUT", GEOIP_RESOURCE),
    "fw_delete_geoip": ("DELETE", GEOIP_RESOURCE),
    "fw_delete_batch_geoip": ("POST", "/api/v1/batch"),
    "fw_verify_geoip": ("GET", GEOIP_RESOURCE),
}
GET_OPS = {"fw_verify_geoip"}
DELETE_OPS = {"fw_delete_geoip"}
BATCH_OPS = {"fw_delete_batch_geoip"}
NO_BODY_OPS = GET_OPS | DELETE_OPS
PAGINATED_OPS = GET_OPS

# Default geographic precision for a custom region object. accuracy 2 pins the
# mapping to the full country/province/city level (device-confirmed).
DEFAULT_ACCURACY = 2
COUNTRY_FIELDS = ("country", "province", "city")


def build_geoip_payload(
    *,
    ip: str = "",
    country: str = "",
    province: str = "",
    city: str = "",
    accuracy: int = DEFAULT_ACCURACY,
    desc: str = "",
) -> dict[str, Any]:
    _validate_non_empty("ip", ip)
    _validate_non_empty("country", country)
    # The device requires province and city and validates them against its
    # region database; omitting them is rejected with eRequestParam.
    _validate_non_empty("province", province)
    _validate_non_empty("city", city)
    _validate_accuracy(accuracy)
    val: dict[str, Any] = {
        "accuracy": accuracy,
        "desc": desc,
        "ip": ip,
        "country": country,
        "province": province,
        "city": city,
    }
    return {"val": val}


def build_geoip_update_payload(
    *,
    entry_id: str,
    ip: str = "",
    country: str = "",
    province: str = "",
    city: str = "",
    accuracy: int = DEFAULT_ACCURACY,
    desc: str = "",
) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    config_payload = build_geoip_payload(
        ip=ip, country=country, province=province, city=city, accuracy=accuracy, desc=desc
    )
    # The device requires the unique identifier both at the top level and
    # inside val (probe-confirmed: val without id -> "unique identifier"
    # eRequestParam; missing top-level id -> "body has no id field").
    return {"id": entry_id, "val": {**config_payload["val"], "id": entry_id}}


def build_geoip_delete_payload(*, entry_id: str) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    return {"id": entry_id}


def build_geoip_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        if entry_id is None or (isinstance(entry_id, str) and not entry_id.strip()):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Geoip object id is required and must be non-empty.",
                {"field": "id"},
            )
        # The device batch layer accepts geoip ids as strings (probe-confirmed);
        # numeric ids are stringified to match the documented delete body.
        entry_id_str = str(entry_id)
        batch.append(
            {
                "method": "DELETE",
                "resource": GEOIP_RESOURCE,
                "body": {"id": [entry_id_str]},
            }
        )
    return {"batch": batch}


def validate_geoip_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
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
        if item.get("method") != "DELETE" or item.get("resource") != GEOIP_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                f"Batch delete only supports DELETE {GEOIP_RESOURCE} items.",
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


def build_geoip_dry_run(
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


def execute_geoip(
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
            "Geoip object device request did not return a success status.",
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
        return GEOIP_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this geoip object operation.",
            {"op_id": op_id},
        ) from exc


def _validate_pagination(page: int, size: int) -> None:
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Geoip object field is required and must be non-empty.",
            {"field": field},
        )


def _validate_accuracy(accuracy: int) -> int:
    try:
        parsed = int(accuracy)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Geoip object accuracy must be a non-negative integer.",
            {"field": "accuracy"},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Geoip object accuracy must be a non-negative integer.",
            {"field": "accuracy", "value": accuracy},
        )
    return parsed


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Geoip object field must be a positive integer.",
            {"field": field},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Geoip object field must be a positive integer.",
            {"field": field, "value": value},
        )
    return parsed
