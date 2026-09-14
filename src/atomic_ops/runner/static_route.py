"""NGFW static-route runner."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
from atomic_ops.runner.http import request_json, request_json_with_retries
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.pagination import fetch_all_pages, response_payload_or_raise
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
# P2 delete 未就绪缺口：删除类 op 允许可选内部重试（--retry，默认 0 不重试）。
RETRYABLE_DELETE_OPS = {"fw_delete_static_route"}
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
    lookup_created_id: bool = True,
    retries: int = 0,
    retry_backoff_seconds: float = 1.0,
    aggregate_page_size: int | None = None,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {
        "Content-Type": "application/json",
        auth_header: header_value,
    }

    def _fetch_single(page_number: int, page_size: int) -> tuple[int, dict[str, Any], str]:
        return request_json(
            method,
            _request_url(
                base_url, op_id, page=page_number, size=page_size,
                route_type=route_type, payload=payload,
            ),
            headers=headers,
            json_payload=None if op_id in NO_BODY_OPS else payload,
            timeout=timeout,
            verify_tls=verify_tls,
        )

    # P2 大批量 verify 缺口：--page-size 开启内部翻页聚合（默认 None 行为不变）。
    if aggregate_page_size is not None and op_id in GET_OPS:
        response_payload = fetch_all_pages(
            lambda page_number, page_size: response_payload_or_raise(
                op_id, method, _fetch_single(page_number, page_size)
            ),
            page_size=aggregate_page_size,
        )
        status_code = 200
    else:
        # P2 delete 未就绪缺口：删除类 op 支持可选内部重试（默认 retries=0 行为不变）。
        status_code, response_payload, _text = request_json_with_retries(
            lambda: _fetch_single(page, size),
            retries=retries if op_id in RETRYABLE_DELETE_OPS else 0,
            backoff_seconds=retry_backoff_seconds,
        )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise_if_device_session_rejected(status_code, response_payload)
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
    # 下游现场（2026-09-08~09-11）：14 条 fw_delete_static_route ERROR 用例各留 1 条
    # 残留——POST /api/v1/route 不返回 id，创建步骤拿不到 id，后续清理/删除步无法引用。
    # 兜底：创建成功后自动按 dst_network（优先 next_hop_addr）回查一次 fw_verify_static_route，
    # 把匹配到的 id 以 machine-readable 键放进 envelope（static_route_ids /
    # created_static_route_id / id_lookup_status）。回查失败不影响创建本身的成功语义
    # （创建已落设备），只标记 id_lookup_status=failed 交由调用方用 verify 逃生口处理。
    if op_id == "fw_config_static_route" and lookup_created_id:
        result.update(
            _lookup_created_static_route_id(
                base_url=base_url,
                session_file=session_file,
                auth_header=auth_header,
                payload=payload,
                route_type=route_type,
                verify_tls=verify_tls,
                timeout=timeout,
            )
        )
    return result


# 创建后自动回查使用的查询页大小与页数上限：单页 500 条（现场反馈 size=5000 之类
# 超大单页查询会让 DUT 长时间无响应），最多 20 页即 1 万条静态路由，足够兜底。
_CREATED_ID_LOOKUP_PAGE_SIZE = 500
_CREATED_ID_LOOKUP_MAX_PAGES = 20


def _lookup_created_static_route_id(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    route_type: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    """按创建 payload 的 dst_network（可选 next_hop_addr）回查新建静态路由的 id。

    route_type 决定 GET 的 is_ip6 查询参数（IPv6 路由必须 is_ip6=true 才查得到）。
    """
    val = (payload or {}).get("val") if isinstance(payload, dict) else None
    dst_network = str((val or {}).get("dst_network") or "")
    next_hop_addr = str((val or {}).get("next_hop_addr") or "")
    summary: dict[str, Any] = {
        "static_route_ids": [],
        "created_static_route_id": None,
        "id_lookup_status": "not_found",
    }
    if not dst_network:
        return summary
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    try:
        matched_ids: list[Any] = []
        for page in range(1, _CREATED_ID_LOOKUP_MAX_PAGES + 1):
            status_code, response_payload, _text = request_json(
                "GET",
                _request_url(
                    base_url, "fw_verify_static_route",
                    page=page, size=_CREATED_ID_LOOKUP_PAGE_SIZE, route_type=route_type,
                ),
                headers=headers,
                json_payload=None,
                timeout=timeout,
                verify_tls=verify_tls,
            )
            if status_code not in GET_SUCCESS_STATUS:
                summary["id_lookup_status"] = "failed"
                summary["id_lookup_status_code"] = status_code
                return summary
            vals = response_payload.get("vals") if isinstance(response_payload, dict) else None
            if not isinstance(vals, list):
                summary["id_lookup_status"] = "failed"
                return summary
            for item in vals:
                if not isinstance(item, dict):
                    continue
                item_val = item.get("val") if isinstance(item.get("val"), dict) else item
                if str(item_val.get("dst_network") or "") != dst_network:
                    continue
                # next_hop_addr 可精确收敛匹配；设备上同网段多路由时用它区分本次新建条目。
                if next_hop_addr and item_val.get("next_hop_addr") not in (None, ""):
                    if str(item_val.get("next_hop_addr")) != next_hop_addr:
                        continue
                matched_ids.append(item.get("id"))
            total = response_payload.get("count")
            if len(vals) < _CREATED_ID_LOOKUP_PAGE_SIZE or (
                isinstance(total, int) and page * _CREATED_ID_LOOKUP_PAGE_SIZE >= total
            ):
                break
        summary["static_route_ids"] = matched_ids
        if len(matched_ids) == 1:
            summary["created_static_route_id"] = matched_ids[0]
            summary["id_lookup_status"] = "matched"
        elif matched_ids:
            # 多条同网段匹配（例如用例重复创建同网段路由）：不猜 id，交调用方用
            # fw_verify_static_route 精确定位。
            summary["id_lookup_status"] = "ambiguous"
    except RunnerError as exc:
        # 回查失败不改变创建 success；标记 failed 让调用方走 verify 逃生口。
        summary["id_lookup_status"] = "failed"
        summary["id_lookup_error"] = exc.error_code
    return summary


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
