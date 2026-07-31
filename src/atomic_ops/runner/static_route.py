"""NGFW static-route runner."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
STATIC_ROUTE_ENDPOINTS = {
    "fw_config_static_route": ("POST", "/api/v1/route"),
    "fw_update_static_route": ("PUT", "/api/v1/route"),
    "fw_delete_static_route": ("DELETE", "/api/v1/route"),
    "fw_verify_static_route": ("GET", "/api/v1/route"),
}
GET_OPS = {"fw_verify_static_route"}
NO_BODY_OPS = {"fw_verify_static_route", "fw_delete_static_route"}
ROUTE_TYPES = {"ipv4", "ipv6"}


def build_static_route_payload(
    *,
    dst_network: str,
    next_hop_addr: str,
    enable: bool = True,
    preference: int = 1,
    weight: int = 0,
    outgoing_interface: str = "",
    route_type: str = "ipv4",
    entry_id: int = 0,
) -> dict[str, Any]:
    _validate_route_type(route_type)
    dst_network = (dst_network or "").strip()
    next_hop_addr = (next_hop_addr or "").strip()

    if not dst_network:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static route requires a destination network.",
            {"field": "dst_network"},
        )
    # 校验目的网段格式
    try:
        ip_network(dst_network, strict=False)
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static route dst_network must be a valid CIDR (e.g. 1.1.1.0/24).",
            {"field": "dst_network", "value": dst_network},
        ) from exc

    if not next_hop_addr:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static route requires a next-hop address.",
            {"field": "next_hop_addr"},
        )
    try:
        parsed_next_hop = ip_address(next_hop_addr)
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static route next_hop_addr must be a valid IP address.",
            {"field": "next_hop_addr", "value": next_hop_addr},
        ) from exc
    expected_version = 6 if route_type == "ipv6" else 4
    if parsed_next_hop.version != expected_version:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static route next-hop IP version must match the route type.",
            {"field": "next_hop_addr", "route_type": route_type, "version": parsed_next_hop.version},
        )

    preference = _validate_non_negative_int("preference", preference)
    weight = _validate_non_negative_int("weight", weight)

    val: dict[str, Any] = {
        "dst_network": dst_network,
        "enable": enable,
        "next_hop_addr": next_hop_addr,
        "preference": preference,
        "weight": weight,
        "outgoing_interface": outgoing_interface or "",
    }
    if entry_id > 0:
        val["id"] = entry_id

    payload: dict[str, Any] = {"val": val}
    if entry_id > 0:
        payload["id"] = entry_id
    return payload


def build_static_route_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    route_type: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    request_payload = None if op_id in NO_BODY_OPS else payload
    return {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(base_url, op_id, page=page, size=size, route_type=route_type, payload=payload),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": request_payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_static_route(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    route_type: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {
        "Content-Type": "application/json",
        auth_header: header_value,
    }
    url = _request_url(base_url, op_id, page=page, size=size, route_type=route_type, payload=payload)
    status_code, response_payload, _text = request_json(
        method,
        url,
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED" if method != "GET" else "RUNNER_RESPONSE_INVALID",
            "Static-route device request did not return a success status.",
            {
                "op_id": op_id,
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    result: dict[str, Any] = {
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
    result.update(_extract_static_route_summary(op_id, response_payload))
    return result


def _extract_static_route_summary(op_id: str, response_payload: Any) -> dict[str, Any]:
    summary: dict[str, Any] = {}
    if op_id == "fw_verify_static_route":
        vals = response_payload.get("vals") if isinstance(response_payload, dict) else None
        if isinstance(vals, list):
            summary["static_route_ids"] = [
                item.get("id") for item in vals if isinstance(item, dict)
            ]
        if isinstance(response_payload, dict):
            summary["count"] = response_payload.get("count")
    elif op_id == "fw_config_static_route":
        # POST 不返回 ID，标记 created=True 供上游判断
        summary["created"] = True
    return summary


def _request_url(
    base_url: str,
    op_id: str,
    *,
    page: int,
    size: int,
    route_type: str,
    payload: dict[str, Any] | None = None,
) -> str:
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in GET_OPS:
        url = f"{url}?{urlencode({'page': page, 'size': size, 'is_ip6': str(_route_type_to_is_ip6(route_type)).lower()})}"
    if op_id == "fw_delete_static_route":
        entry_id = str((payload or {}).get("id") or "")
        _validate_positive_int("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return STATIC_ROUTE_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this static-route operation.",
            {"op_id": op_id},
        ) from exc


def _validate_route_type(route_type: str) -> str:
    if route_type not in ROUTE_TYPES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static-route type must be ipv4 or ipv6.",
            {"field": "route_type", "route_type": route_type, "allowed": sorted(ROUTE_TYPES)},
        )
    return route_type


def _route_type_to_is_ip6(route_type: str) -> bool:
    return _validate_route_type(route_type) == "ipv6"


def _validate_non_negative_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static-route integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static-route integer field must be non-negative.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_positive_int(field: str, value: int | str) -> int:
    parsed = _validate_non_negative_int(field, value)
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static-route integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed
