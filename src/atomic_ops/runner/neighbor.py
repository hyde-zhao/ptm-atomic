"""NGFW neighbor (ARP) runner for /api/v1/neighbor."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner._payload import load_json_payload
from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
NEIGHBOR_ENDPOINTS = {
    "fw_config_neighbor": ("POST", "/api/v1/neighbor"),
    "fw_update_neighbor": ("PUT", "/api/v1/neighbor"),
    "fw_verify_neighbor": ("GET", "/api/v1/neighbor"),
    "fw_delete_neighbor": ("DELETE", "/api/v1/neighbor"),
    "fw_delete_batch_neighbor": ("POST", "/api/v1/batch"),
}
NO_BODY_OPS = {"fw_verify_neighbor", "fw_delete_neighbor"}
GET_OPS = {"fw_verify_neighbor"}
DELETE_OPS = {"fw_delete_neighbor"}
BATCH_OPS = {"fw_delete_batch_neighbor"}
NEIGHBOR_RESOURCE = "/api/v1/neighbor"

MAC_ADDRESS_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")


def build_neighbor_payload(
    *,
    interface: str,
    ip_address: str,
    phys_address: str,
    op_id: str,
) -> dict[str, Any]:
    _validate_non_empty("interface", interface)
    _validate_non_empty("ip_address", ip_address)
    _validate_mac_address("phys_address", phys_address)
    val = {
        "interface": interface,
        "ipAddress": ip_address,
        "physAddress": phys_address,
    }
    if op_id == "fw_update_neighbor":
        return {"id": "0", "val": val}
    return {"val": val}


def build_neighbor_batch_delete_payload(
    *,
    entries: list[dict[str, str]],
) -> dict[str, Any]:
    if not entries:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one entry is required for batch delete.",
            {"field": "entries"},
        )
    phys_addresses: list[str] = []
    interfaces: list[str] = []
    ip_addresses: list[str] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each batch entry must be an object.",
                {"field": "entries"},
            )
        interface = str(entry.get("interface") or "")
        ip_address = str(entry.get("ip_address") or "")
        phys_address = str(entry.get("phys_address") or "")
        _validate_non_empty("interface", interface)
        _validate_non_empty("ip_address", ip_address)
        _validate_mac_address("phys_address", phys_address)
        interfaces.append(interface)
        ip_addresses.append(ip_address)
        phys_addresses.append(phys_address)
    return {
        "batch": [
            {
                "method": "DELETE",
                "resource": NEIGHBOR_RESOURCE,
                "body": {
                    "physAddress": phys_addresses,
                    "interface": interfaces,
                    "ipAddress": ip_addresses,
                },
            }
        ]
    }


def validate_neighbor_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if op_id in NO_BODY_OPS:
        return payload
    if op_id in BATCH_OPS:
        return _validate_batch_payload(payload)
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Neighbor payload val object is required.",
            {"field": "val"},
        )
    _validate_non_empty("interface", str(val.get("interface") or ""))
    _validate_non_empty("ipAddress", str(val.get("ipAddress") or ""))
    _validate_mac_address("physAddress", str(val.get("physAddress") or ""))
    return payload


def build_neighbor_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    keywords: str,
    is_ip6: int = 0,
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
                base_url, op_id, payload=payload, page=page, size=size, keywords=keywords, is_ip6=is_ip6
            ),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in NO_BODY_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_neighbor(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    keywords: str,
    is_ip6: int = 0,
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
        _request_url(
            base_url, op_id, payload=payload, page=page, size=size, keywords=keywords, is_ip6=is_ip6
        ),
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
            "Neighbor device request did not return a success status.",
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
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    keywords: str,
    is_ip6: int = 0,
) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in GET_OPS:
        _validate_positive_int("page", page)
        _validate_positive_int("size", size)
        _validate_is_ip6(is_ip6)
        query: dict[str, Any] = {
            "page": page,
            "size": size,
            "keywords": keywords or "",
            "is_linux": False,
            "is_ip6": bool(is_ip6),
        }
        url = f"{url}?{urlencode(query)}"
    if op_id in DELETE_OPS:
        val = (payload or {}).get("val") if isinstance(payload, dict) else None
        if isinstance(val, dict):
            interface = str(val.get("interface") or "")
            ip_address = str(val.get("ipAddress") or "")
            phys_address = str(val.get("physAddress") or "")
        else:
            interface = ""
            ip_address = ""
            phys_address = ""
        _validate_non_empty("interface", interface)
        _validate_non_empty("ip_address", ip_address)
        _validate_mac_address("phys_address", phys_address)
        url = f"{url}?{urlencode({'interface': interface, 'ipAddress': ip_address, 'physAddress': phys_address})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return NEIGHBOR_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this neighbor operation.",
            {"op_id": op_id},
        ) from exc


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
        if item.get("method") != "DELETE" or item.get("resource") != NEIGHBOR_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch item only supports DELETE on /api/v1/neighbor.",
                {"method": item.get("method"), "resource": item.get("resource")},
            )
        body = item.get("body")
        if not isinstance(body, dict):
            raise RunnerError("RUNNER_VALIDATION_FAILED", "Batch item body must be an object.", {"field": "body"})
        for key in ("physAddress", "interface", "ipAddress"):
            arr = body.get(key)
            if not isinstance(arr, list) or not arr:
                raise RunnerError(
                    "RUNNER_VALIDATION_FAILED",
                    f"Batch item body.{key} must be a non-empty list.",
                    {"field": f"body.{key}"},
                )
    return payload


def _validate_mac_address(field: str, value: str) -> str:
    _validate_non_empty(field, value)
    if not MAC_ADDRESS_RE.match(value):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Neighbor physAddress must be a valid MAC address.",
            {"field": field, "value": value},
        )
    return value


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required neighbor field is empty.",
            {"field": field},
        )


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Neighbor integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Neighbor integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_is_ip6(value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Neighbor is_ip6 field must be 0 (IPv4 ARP) or 1 (IPv6 ND).",
            {"field": "is_ip6", "value": value},
        ) from exc
    if parsed not in (0, 1):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Neighbor is_ip6 field must be 0 (IPv4 ARP) or 1 (IPv6 ND).",
            {"field": "is_ip6", "value": parsed},
        )
    return parsed
