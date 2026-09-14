"""NGFW policy-route runner."""

from __future__ import annotations

from ipaddress import ip_address
from pathlib import Path
import re
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
# batch delete（POST /api/v1/batch）部分成功语义复杂，不自动重试。
RETRYABLE_DELETE_OPS = {"fw_delete_policy_route"}
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
    applist: list[dict[str, Any]] | None = None,
    app_tag_name: list[str] | None = None,
    ip_link_name: str | None = None,
) -> dict[str, Any]:
    # 全 any 匹配场景：source_network / in_interface / dst_network 空串/None 统一归一化为 "any"。
    # NGFW 不接受空串（eObjParse "被引用对象不存在"），需显式 "any"。
    # 真相源：M4-01-08 全 any 用例实测，default="" 导致 payload 空串被 NGFW 拒绝。
    # commit 2fd9b04 仅修了 source_network，in_interface/dst_network 漏修，此处补齐对称归一化。
    source_network = _normalize_any("source_network", source_network)
    in_interface = _normalize_any("in_interface", in_interface)
    dst_network = _normalize_any("dst_network", dst_network)
    route_type = _validate_route_type(route_type)
    next_hop_ip = (next_hop_ip or "").strip()
    outgoing_interface = (outgoing_interface or "").strip()
    if not next_hop_ip and not outgoing_interface:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Policy-route forwarding path requires next-hop IP or outgoing interface.",
            {"fields": ["next_hop_ip", "outgoing_interface"]},
        )
    # P2-14（2026-09-14，下游反馈升级项）：两种转发模式**互斥** ——「仅网关」（next_hop_ip）
    # 与「仅出接口」（outgoing_interface）只能二选一，同时提供即前置拒绝，不再下发给设备。
    # 背景：DUT 侧对越界组合只给晦涩错误（「仅出接口」ePolicyRouteOutIfModeError、
    # 「网关+出接口」ePolicyRouteOutIfNextHopError，现场两批次 6+5 次一致），且型号能力
    # 不同（DUT3/DAS-TGFW-290 实测仅支持「仅网关」）→ 工具侧显式声明该限制并前置拒绝，
    # 调用方据 RUNNER_VALIDATION_FAILED.details.fields 可立即定位，无需等设备回错。
    if next_hop_ip and outgoing_interface:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Policy-route forwarding path accepts either next-hop IP or outgoing interface, not both.",
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
    applist = _validate_applist(applist)
    app_tag_name = _validate_app_tag_name(app_tag_name)
    # ip-link 关联：设备通过 forwarding_paths[].health_check={type:"iplink",name:...} 表达
    # 下一跳链路状态探测；省略时 health_check 保持空对象（不关联 ip-link）。
    # 真相源：.input/capacity/特性测试/策略路由.py 的 config_ipv6_policy_route。
    health_check: dict[str, Any] = {}
    if ip_link_name:
        health_check = {"type": "iplink", "name": ip_link_name}

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
        "applist": applist,
        "app_tag_name": app_tag_name,
        "forwarding_paths": [
            {
                "next_hop_ip": next_hop_ip,
                "outgoing_interface": outgoing_interface,
                "weight": weight,
                "health_check": health_check,
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
    aggregate_page_size: int | None = None,
    retries: int = 0,
    retry_backoff_seconds: float = 1.0,
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

    # P2 大批量 verify 缺口：--page-size 开启内部翻页聚合（默认 None 行为不变），
    # 避免 --size 5000 之类的单次超大查询让 DUT 长时间无响应直至连接中断。
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
        # config 是新建语义：到达此处说明 POST 成功（重复创建已被 err_code/err_msg 透传拦截）。
        # 兑现 atom returns.data.created 契约，供外部调用方判断是否需要 rollback。
        # 设备未显式返回 created 时默认 True（成功 POST 即新建）；update 不是新建，不设 created。
        if op_id == "fw_config_policy_route":
            summary["created"] = (
                response_payload.get("created", True)
                if isinstance(response_payload, dict)
                else True
            )
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


def _normalize_any(field: str, value: str | None) -> str:
    """空串/None 归一化为 "any"（全 any 匹配场景）。

    NGFW 不接受空串 source_network/in_interface/dst_network，需显式 "any"。
    CLI default="any" 只覆盖省略参数；显式传空串仍需在此归一化。
    """
    normalized = (value or "").strip()
    return normalized or "any"


def _validate_applist(applist: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    """校验并返回策略路由应用匹配列表（applist）。

    未提供时保持空数组（不匹配应用）；每项必须是对象且 appname 非空。
    appid 不作强制（透传原则：DUT 实测 2026-08-19 接受仅含 appname 的项，
    如 {"appname":"HTTP"}；强制 appid 会拒绝 DUT 合法请求）。
    """
    if not applist:
        return []
    for index, item in enumerate(applist):
        if not isinstance(item, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Policy-route applist items must be objects.",
                {"field": "applist", "index": index},
            )
        appname = item.get("appname")
        if not isinstance(appname, str) or not appname.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Policy-route applist items require non-empty appname.",
                {"field": "applist", "index": index, "missing": "appname"},
            )
    return applist


def _validate_app_tag_name(app_tag_name: list[str] | None) -> list[str]:
    """校验并返回策略路由应用标签名列表（app_tag_name）。

    未提供时保持空数组（不匹配应用标签）；每项必须是非空字符串，
    与界面「应用」标签勾选后保存的请求体格式一致。
    """
    if not app_tag_name:
        return []
    for index, item in enumerate(app_tag_name):
        if not isinstance(item, str) or not item.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Policy-route app_tag_name items must be non-empty strings.",
                {"field": "app_tag_name", "index": index},
            )
    return app_tag_name


# config-batch 递增模式下参与编号的字符串参数键。applist/app_tag_name 引用
# 已存在的应用/标签对象，不参与编号；weight/action/config_source 等数字与
# is_group 布尔标志保持原值。
INCREMENTABLE_KEYS = (
    "source_network",
    "dst_network",
    "in_interface",
    "outgoing_interface",
    "next_hop_ip",
    "service",
    "time_obj",
    "ip_link_name",
)


def increment_value(value: str, index: int) -> str:
    """按批量创建序号递增字符串参数（index 从 1 开始）。

    三种编号规则，按优先级匹配：
    - IPv4 点分地址：主机位递增，超过 254 时向上段进位（1.1.1.254 -> 1.1.2.1）。
    - 末尾含数字（GE0_1、2115:101:2::11）：末尾数字段递增并保留原宽度
      （GE0_1 -> GE0_2；第 1 条保持原始值）。
    - 无末尾数字（test）：追加 4 位补零序号，从 0001 开始（test0001）。
    """
    if _is_ipv4(value):
        return _increment_ipv4(value, index)
    trailing = _trailing_digits(value)
    if trailing is not None:
        prefix, digits = trailing
        offset = index - 1
        return f"{prefix}{int(digits) + offset:0{len(digits)}d}"
    return f"{value}{index:04d}"


def _is_ipv4(value: str) -> bool:
    try:
        return ip_address(value).version == 4
    except ValueError:
        return False


def _increment_ipv4(value: str, index: int) -> str:
    """IPv4 主机位递增，超过 254 时向网段位进位。

    每段有效范围 1..254（0/255 保留）；第 1 条保持原始地址。
    1.1.1.1 index=255 -> 1.1.2.1（主机位回绕、网段位 +1）。
    """
    parts = [int(p) for p in value.split(".")]
    carry = index - 1
    for pos in range(3, 0, -1):
        digit = parts[pos] - 1 + carry
        parts[pos] = (digit % 254) + 1
        carry = digit // 254
    digit = parts[0] - 1 + carry
    parts[0] = (digit % 254) + 1
    return ".".join(str(p) for p in parts)


def _trailing_digits(value: str) -> tuple[str, str] | None:
    match = re.search(r"(\d+)$", value)
    if not match:
        return None
    return value[: match.start()], match.group(1)


def build_policy_route_batch_config_payloads(
    *,
    count: int,
    increment: bool = False,
    **params: Any,
) -> list[dict[str, Any]]:
    """循环构造 count 条策略路由创建 payload（逐条 POST /api/v1/policyroute）。

    increment=False（默认）：所有参数保持不变，生成 count 条相同路由。
    increment=True：对 INCREMENTABLE_KEYS 中的字符串参数按序号递增，
    其余参数保持原值。设备 /api/v1/batch 不支持创建，故只能循环逐条创建。
    """
    _validate_positive_int("count", count)
    payloads: list[dict[str, Any]] = []
    for index in range(1, count + 1):
        entry_params = dict(params)
        if increment:
            for key in INCREMENTABLE_KEYS:
                value = entry_params.get(key)
                # 空串表示"未指定"（如 next_hop_ip 走 outgoing-interface 模式、
                # time_obj/outgoing_interface 默认空），不参与编号，保持空值。
                if isinstance(value, str) and value.strip():
                    entry_params[key] = increment_value(value, index)
        payloads.append(build_policy_route_payload(**entry_params))
    return payloads


def build_policy_route_batch_config_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payloads: list[dict[str, Any]],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    """config-batch dry-run：展示首个请求模板与条数摘要。"""
    first_payload = payloads[0] if payloads else None
    return {
        "op_id": "fw_config_policy_route",
        "status": "dry_run",
        "mode": "config_batch",
        "execute_required": True,
        "count": len(payloads),
        "request": {
            "method": "POST",
            "url": f"{normalize_base_url(base_url)}/api/v1/policyroute",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": first_payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_policy_route_batch_config(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payloads: list[dict[str, Any]],
    page: int,
    size: int,
    route_type: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    """逐条 POST /api/v1/policyroute 创建策略路由，汇总每条结果。

    单条失败不中断：失败条目记录到 failed 列表，其余条目继续执行；
    全部失败时整体状态置为 failed。
    """
    created: list[dict[str, Any]] = []
    failed: list[dict[str, Any]] = []
    for index, payload in enumerate(payloads, start=1):
        try:
            result = execute_policy_route(
                op_id=op_id,
                base_url=base_url,
                session_file=session_file,
                auth_header=auth_header,
                payload=payload,
                page=page,
                size=size,
                route_type=route_type,
                verify_tls=verify_tls,
                timeout=timeout,
            )
            created.append(
                {
                    "index": index,
                    "status": "success",
                    "policy_route_id": result.get("policy_route_id"),
                    "status_code": result.get("status_code"),
                }
            )
        except RunnerError as exc:
            failed.append(
                {
                    "index": index,
                    "status": "failed",
                    "error_code": exc.error_code,
                    "message": exc.message,
                }
            )
    if payloads and len(failed) == len(payloads):
        status = "failed"
    else:
        status = "success"
    return {
        "op_id": "fw_config_policy_route",
        "status": status,
        "mode": "config_batch",
        "count": len(payloads),
        "created_count": len(created),
        "failed_count": len(failed),
        "created": created,
        "failed": failed,
    }
