"""NGFW policy-route runner."""

from __future__ import annotations

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
POLICY_ROUTE_ENDPOINTS = {
    "fw_config_policy_route": ("POST", "/api/v1/policyroute"),
    "fw_update_policy_route": ("PUT", "/api/v1/policyroute"),
    "fw_delete_policy_route": ("DELETE", "/api/v1/policyroute"),
    "fw_verify_policy_route": ("GET", "/api/v1/policyroute"),
    "fw_reset_policy_route_hitcount": ("DELETE", "/api/v1/policyroutehitcount"),
    "fw_verify_policy_route_hitcount": ("GET", "/api/v1/policyroute"),
    "fw_update_policy_route_priority": ("POST", "/api/v1/pridpriconf"),
    "fw_delete_batch_policy_route": ("POST", "/api/v1/batch"),
}
POLICY_ROUTE_RESOURCE = "/api/v1/policyroute"
GET_OPS = {"fw_verify_policy_route", "fw_verify_policy_route_hitcount"}
BATCH_OPS = {"fw_delete_batch_policy_route"}
NO_BODY_OPS = {
    "fw_verify_policy_route",
    "fw_delete_policy_route",
    "fw_reset_policy_route_hitcount",
    "fw_verify_policy_route_hitcount",
}
TARGET_SITES = {"before", "after", "first", "last"}
ROUTE_TYPES = {"ipv4", "ipv6"}


def build_policy_route_payload(
    *,
    source_network: str,
    source_network_is_group: bool,
    dst_network: str,
    dst_network_is_group: bool,
    next_hop_ip: str | None,
    in_interface: str,
    outgoing_interface: str | None,
    service: str,
    weight: int,
    time_obj: str,
    route_type: str = "ipv4",
    entry_id: int | str = 0,
    service_is_group: bool = False,
    active: bool = True,
    action: int = 1,
    config_source: int = 0,
) -> dict[str, Any]:
    # source_network 空串/None 归一化为 "any"（全 any 匹配场景）。NGFW 不接受空串
    # source_network（eObjParse "被引用对象不存在"），需显式 "any"（与 dst_network 一致）。
    # 真相源：M4-01-08 全 any 用例实测，default="" 导致 payload source_network="" 被 NGFW 拒绝。
    source_network = (source_network or "").strip() or "any"
    _validate_non_empty("dst_network", dst_network)
    route_type = _validate_route_type(route_type)
    next_hop_ip = (next_hop_ip or "").strip()
    outgoing_interface = (outgoing_interface or "").strip()
    if not next_hop_ip and not outgoing_interface:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Policy-route forwarding path requires next-hop IP or outgoing interface.",
            {"fields": ["next_hop_ip", "outgoing_interface"]},
        )
    if next_hop_ip:
        try:
            parsed_next_hop = ip_address(next_hop_ip)
        except ValueError as exc:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "next-hop IP must be a valid IP address.",
                {"field": "next_hop_ip"},
            ) from exc
        expected_version = 6 if route_type == "ipv6" else 4
        if parsed_next_hop.version != expected_version:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Policy-route next-hop IP version must match the route type.",
                {"field": "next_hop_ip", "route_type": route_type, "version": parsed_next_hop.version},
            )
    if weight < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Policy-route forwarding path weight must be at least 1.",
            {"field": "weight", "weight": weight},
        )
    entry_id = _validate_non_negative_int("id", entry_id)

    val: dict[str, Any] = {
        "type": route_type,
        "in_interface": in_interface,
        "source_network": source_network,
        "source_network_is_group": source_network_is_group,
        "dst_network": dst_network,
        "dst_network_is_group": dst_network_is_group,
        "service": service,
        "service_is_group": service_is_group,
        "active": active,
        "applist": [],
        "app_tag_name": [],
        "forwarding_paths": [
            {
                "next_hop_ip": next_hop_ip,
                "outgoing_interface": outgoing_interface,
                "weight": weight,
                "health_check": {},
            }
        ],
        "time_obj": time_obj,
        "action": action,
        "config_source": config_source,
    }
    if entry_id > 0:
        val["id"] = entry_id

    return {
        "id": entry_id,
        "val": val,
    }


def build_policy_route_delete_payload(*, entry_id: int | str) -> dict[str, int]:
    return {"id": _validate_positive_int("id", entry_id)}


def build_policy_route_batch_delete_payload(
    *,
    entry_ids: list[str],
    route_type: str = "ipv4",
) -> dict[str, Any]:
    is_ip6 = _route_type_to_is_ip6(route_type)
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    is_ip6_str = str(is_ip6).lower()
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_non_empty("id", entry_id)
        batch.append(
            {
                "method": "DELETE",
                "resource": POLICY_ROUTE_RESOURCE,
                "body": {"id": [str(entry_id)], "is_ip6": [is_ip6_str]},
            }
        )
    return {"batch": batch}


def validate_policy_route_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if op_id in BATCH_OPS:
        return _validate_policy_route_batch_payload(payload)
    return payload


def _validate_policy_route_batch_payload(payload: dict[str, Any]) -> dict[str, Any]:
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
        if item.get("method") != "DELETE" or item.get("resource") != POLICY_ROUTE_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch policy-route delete only supports DELETE /api/v1/policyroute items.",
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
        is_ip6 = body.get("is_ip6") if isinstance(body, dict) else None
        if not isinstance(is_ip6, list) or not is_ip6:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch delete item body.is_ip6 must be a non-empty list.",
                {"field": "batch"},
            )
    return payload


def build_policy_route_priority_payload(
    *,
    targetsite: str,
    targetid: int | str,
    moveid: int | str,
    route_type: str = "ipv4",
) -> dict[str, Any]:
    if targetsite not in TARGET_SITES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Policy-route priority target site is unsupported.",
            {"field": "targetsite", "targetsite": targetsite, "allowed": sorted(TARGET_SITES)},
        )
    return {
        "val": {
            "targetsite": targetsite,
            "targetid": _validate_positive_int("targetid", targetid),
            "moveid": _validate_positive_int("moveid", moveid),
            "is_ip6": _route_type_to_is_ip6(route_type),
        }
    }


def build_policy_route_dry_run(
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


def execute_policy_route(
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
            "Policy-route device request did not return a success status.",
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
    # 兑现 atom returns.data 契约：从响应中提取结构化策略路由 id。
    result.update(_extract_policy_route_summary(op_id, response_payload))
    return result


def _extract_policy_route_summary(op_id: str, response_payload: Any) -> dict[str, Any]:
    """从设备响应中提取 atom returns.data 契约声明的结构化策略路由 id。

    verify 返回 policy_route_ids 列表与 count；config/update 返回新策略路由 id。
    其余操作（delete/reset/priority）响应不含策略路由 id，返回空 dict。
    """
    summary: dict[str, Any] = {}
    if op_id == "fw_verify_policy_route":
        vals = response_payload.get("vals") if isinstance(response_payload, dict) else None
        if isinstance(vals, list):
            summary["policy_route_ids"] = [
                item.get("id") for item in vals if isinstance(item, dict)
            ]
        if isinstance(response_payload, dict):
            summary["count"] = response_payload.get("count")
    elif op_id in {"fw_config_policy_route", "fw_update_policy_route"}:
        val = response_payload.get("val") if isinstance(response_payload, dict) else None
        if isinstance(val, dict):
            summary["policy_route_id"] = val.get("id")
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
    if op_id in {"fw_delete_policy_route", "fw_reset_policy_route_hitcount"}:
        entry_id = str((payload or {}).get("id") or "")
        _validate_positive_int("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id, 'is_ip6': str(_route_type_to_is_ip6(route_type)).lower()})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return POLICY_ROUTE_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this policy-route operation.",
            {"op_id": op_id},
        ) from exc


def _validate_route_type(route_type: str) -> str:
    if route_type not in ROUTE_TYPES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Policy-route type must be ipv4 or ipv6.",
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
            "Policy-route integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Policy-route integer field must be non-negative.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_positive_int(field: str, value: int | str) -> int:
    parsed = _validate_non_negative_int(field, value)
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Policy-route integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required policy-route field is empty.",
            {"field": field},
        )
