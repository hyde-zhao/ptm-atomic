"""NGFW UES (unified experience system) runner.

实现 UES 模块 11 个原子操作的请求构造与执行：
- 接入配置: fw_verify_ues_access / fw_config_ues_access / fw_check_ues_connection
- 全局配置: fw_verify_ues_global / fw_config_ues_global
- 推广策略: fw_verify_ues_ip_policy / fw_config_ues_ip_policy /
            fw_update_ues_ip_policy / fw_delete_ues_ip_policy
- 优先级:   fw_verify_ues_ip_policy_order / fw_update_ues_ip_policy_priority

数据来源: UESAPI.txt（2026-08-27 录制，32 次请求 / 13 个接口，全部 2xx）。
与 policy_route runner 的差异：UES 无 ipv4/ipv6 地址族区分、无批量端点；
GET /uesippolicy 的 hitcount 字段为字符串类型。
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
UES_ENDPOINTS = {
    "fw_verify_ues_access": ("GET", "/api/v1/uesaccess"),
    "fw_config_ues_access": ("PUT", "/api/v1/uesaccess"),
    "fw_check_ues_connection": ("POST", "/api/v1/uesaccess/state"),
    "fw_verify_ues_global": ("GET", "/api/v1/uesglobal"),
    "fw_config_ues_global": ("PUT", "/api/v1/uesglobal"),
    "fw_verify_ues_ip_policy": ("GET", "/api/v1/uesippolicy"),
    "fw_config_ues_ip_policy": ("POST", "/api/v1/uesippolicy"),
    "fw_update_ues_ip_policy": ("PUT", "/api/v1/uesippolicy"),
    "fw_delete_ues_ip_policy": ("DELETE", "/api/v1/uesippolicy"),
    "fw_verify_ues_ip_policy_order": ("GET", "/api/v1/uesippolicyorder"),
    "fw_update_ues_ip_policy_priority": ("POST", "/api/v1/uesippolicyorder"),
}
GET_OPS = {
    "fw_verify_ues_access",
    "fw_verify_ues_global",
    "fw_verify_ues_ip_policy",
    "fw_verify_ues_ip_policy_order",
}
NO_BODY_OPS = {
    "fw_verify_ues_access",
    "fw_verify_ues_global",
    "fw_verify_ues_ip_policy",
    "fw_verify_ues_ip_policy_order",
    "fw_delete_ues_ip_policy",
}
QUERY_PAGE_SIZE_OPS = {"fw_verify_ues_ip_policy", "fw_verify_ues_ip_policy_order"}
ORDER_QUERY_OPS = {"fw_verify_ues_ip_policy_order"}
DELETE_OPS = {"fw_delete_ues_ip_policy"}
TARGET_SITES = {"first", "before", "after", "last"}
# action 枚举：0=允许，1=允许并记录，2=允许并推送推广（UES-GAP-03，语义以设备实测为准）
UES_POLICY_ACTION_VALUES = {0, 1, 2}


def build_ues_access_payload(
    *,
    uesswitch: bool,
    uesip: str,
    port: str,
    securitykey: str,
    thirdpartycode: str,
) -> dict[str, Any]:
    """构造 PUT /api/v1/uesaccess 请求体（保存接入配置）。"""
    return {
        "id": "uesaccess",
        "val": {
            "uesswitch": bool(uesswitch),
            "uesip": _validate_non_empty("uesip", uesip),
            "port": _validate_non_empty("port", port),
            "securitykey": (securitykey or "").strip(),
            "thirdpartycode": _validate_non_empty("thirdpartycode", thirdpartycode),
        },
    }


def build_ues_connection_payload(
    *,
    uesip: str,
    port: str,
    securitykey: str,
    thirdpartycode: str,
) -> dict[str, Any]:
    """构造 POST /api/v1/uesaccess/state 请求体（测试连接）。

    录制请求体为 {"id":"ues","val":{...}}，id 固定为 "ues"。
    """
    return {
        "id": "ues",
        "val": {
            "uesip": _validate_non_empty("uesip", uesip),
            "port": _validate_non_empty("port", port),
            "securitykey": (securitykey or "").strip(),
            "thirdpartycode": _validate_non_empty("thirdpartycode", thirdpartycode),
        },
    }


def build_ues_global_payload(
    *,
    httpdstport: list[int],
    httpsdstport: list[int],
    blackadd: bool,
    blocktime: int,
    hashadd: bool,
    uesurl: str,
    notipstate: bool,
    open_service: list[str],
) -> dict[str, Any]:
    """构造 PUT /api/v1/uesglobal 请求体（保存全局配置）。

    uesurl 由 UES 接入端点推导，前端保存时回显 GET /uesglobal 的当前值，
    此处必须显式传入（PUT 整体替换，不合并未传字段）。
    """
    return {
        "id": "uesglobal",
        "val": {
            "httpdstport": _validate_int_list("httpdstport", httpdstport),
            "httpsdstport": _validate_int_list("httpsdstport", httpsdstport),
            "blackadd": bool(blackadd),
            "blocktime": _validate_non_negative_int("blocktime", blocktime),
            "hashadd": bool(hashadd),
            "uesurl": _validate_non_empty("uesurl", uesurl),
            "notipstate": bool(notipstate),
            "open_service": _validate_string_list("open_service", open_service),
        },
    }


def build_ues_ip_policy_payload(
    *,
    entry_id: int | str,
    name: str,
    enable: bool,
    action: int,
    log: bool,
    cycletime: int,
    desc: str,
    srcip: str,
    srcipisgroup: bool,
    dstip: str,
    dstipisgroup: bool,
) -> dict[str, Any]:
    """构造 /api/v1/uesippolicy 请求体（新建 id:0 / 更新 id>0 共用）。

    srcip/dstip 空串/None 归一化为 "any"（NGFW 不接受空串，
    与 policy_route runner 的 _normalize_any 一致）。
    """
    entry_id = _validate_non_negative_int("id", entry_id)
    if action not in UES_POLICY_ACTION_VALUES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "UES promotion-policy action must be 0, 1, or 2.",
            {"field": "action", "action": action, "allowed": sorted(UES_POLICY_ACTION_VALUES)},
        )
    val: dict[str, Any] = {
        "name": _validate_non_empty("name", name),
        "enable": bool(enable),
        "action": action,
        "log": bool(log),
        "cycletime": _validate_non_negative_int("cycletime", cycletime),
        "desc": desc or "",
        "srcip": _normalize_any("srcip", srcip),
        "srcipisgroup": bool(srcipisgroup),
        "dstip": _normalize_any("dstip", dstip),
        "dstipisgroup": bool(dstipisgroup),
    }
    # 更新场景顶层 id 为策略 id；val 允许部分字段（录制确认部分更新可用，val.id 可选）。
    if entry_id > 0:
        val["id"] = entry_id
    return {"id": entry_id, "val": val}


def build_ues_delete_payload(*, entry_id: int | str) -> dict[str, int]:
    """构造 DELETE /api/v1/uesippolicy 查询参数（?id=<id>，无请求体）。"""
    return {"id": _validate_positive_int("id", entry_id)}


def build_ues_priority_payload(
    *,
    targetsite: str,
    moveid: int | str,
    targetid: int | str | None,
) -> dict[str, Any]:
    """构造 POST /api/v1/uesippolicyorder 请求体（调整优先级）。

    录制请求体仅 {"val":{"targetsite":"first","moveid":1}}，无 targetid；
    targetid 仅在前置/后置定位场景（before/after）显式提供时携带
    （UES-GAP-06，设备实测确认前按录制形态构造）。
    """
    if targetsite not in TARGET_SITES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "UES priority target site is unsupported.",
            {"field": "targetsite", "targetsite": targetsite, "allowed": sorted(TARGET_SITES)},
        )
    val: dict[str, Any] = {
        "targetsite": targetsite,
        "moveid": _validate_positive_int("moveid", moveid),
    }
    if targetid not in (None, "", 0):
        val["targetid"] = _validate_positive_int("targetid", targetid)
    return {"val": val}


def build_ues_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    config_source: int,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, _path = _method_path(op_id)
    request_payload = None if op_id in NO_BODY_OPS else payload
    return {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(
                base_url,
                op_id,
                page=page,
                size=size,
                config_source=config_source,
                payload=payload,
            ),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": request_payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_ues(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    config_source: int,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {
        "Content-Type": "application/json",
        auth_header: header_value,
    }
    url = _request_url(
        base_url,
        op_id,
        page=page,
        size=size,
        config_source=config_source,
        payload=payload,
    )
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
        raise_if_device_session_rejected(status_code, response_payload)
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED" if method != "GET" else "RUNNER_RESPONSE_INVALID",
            "UES device request did not return a success status.",
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
    # 兑现 atom returns.data 契约：从响应/请求中提取结构化摘要。
    result.update(_extract_ues_summary(op_id, payload, response_payload))
    return result


def _extract_ues_summary(
    op_id: str,
    payload: dict[str, Any] | None,
    response_payload: Any,
) -> dict[str, Any]:
    """从设备响应（及请求 payload）中提取 atom returns.data 声明的结构化字段。

    - verify 类返回列表 ids 与 count；策略列表额外返回 hitcount 汇总。
    - config/update/delete 依据请求 payload 回填 ip_policy_id；
      config 是新建语义（POST 成功即新建），回填 created=True。
    - 接入/全局配置的 verify 仅回填 existence（响应为扁平对象）。
    """
    summary: dict[str, Any] = {}
    if op_id == "fw_verify_ues_ip_policy":
        vals = response_payload.get("vals") if isinstance(response_payload, dict) else None
        if isinstance(vals, list):
            summary["ip_policy_ids"] = [item.get("id") for item in vals if isinstance(item, dict)]
            hitcounts = [item.get("hitcount") for item in vals if isinstance(item, dict)]
            if hitcounts:
                summary["hitcount"] = hitcounts[0]
        if isinstance(response_payload, dict):
            summary["count"] = response_payload.get("count")
    elif op_id == "fw_verify_ues_ip_policy_order":
        vals = response_payload.get("vals") if isinstance(response_payload, dict) else None
        if isinstance(vals, list):
            summary["policy_order_ids"] = list(vals)
        if isinstance(response_payload, dict):
            summary["count"] = response_payload.get("count")
    elif op_id in {"fw_verify_ues_access", "fw_verify_ues_global"}:
        summary["existence"] = isinstance(response_payload, dict) and bool(response_payload)
    elif op_id in {"fw_config_ues_ip_policy", "fw_update_ues_ip_policy", "fw_delete_ues_ip_policy"}:
        entry_id = (payload or {}).get("id")
        if entry_id not in (None, "", 0):
            summary["ip_policy_id"] = entry_id
        if op_id == "fw_config_ues_ip_policy":
            # 响应仅 {"msg":"success"} 不返回 id；成功 POST 即新建（UES-GAP-04）。
            summary["created"] = True
    return summary


def _request_url(
    base_url: str,
    op_id: str,
    *,
    page: int,
    size: int,
    config_source: int,
    payload: dict[str, Any] | None = None,
) -> str:
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in QUERY_PAGE_SIZE_OPS:
        query: dict[str, Any] = {"page": page, "size": size}
        if op_id in ORDER_QUERY_OPS:
            query["config_source"] = _validate_non_negative_int("config_source", config_source)
        url = f"{url}?{urlencode(query)}"
    if op_id in DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_positive_int("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return UES_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this UES operation.",
            {"op_id": op_id},
        ) from exc


def _validate_non_negative_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "UES integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "UES integer field must be non-negative.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_positive_int(field: str, value: int | str) -> int:
    parsed = _validate_non_negative_int(field, value)
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "UES integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_non_empty(field: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required UES field is empty.",
            {"field": field},
        )
    return value.strip()


def _normalize_any(field: str, value: str | None) -> str:
    """空串/None 归一化为 "any"（全 any 匹配场景，NGFW 不接受空串）。"""
    normalized = (value or "").strip()
    return normalized or "any"


def _validate_int_list(field: str, values: list[int] | None) -> list[int]:
    if not isinstance(values, list) or not values:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "UES port list must be a non-empty integer list.",
            {"field": field, "value": values},
        )
    result: list[int] = []
    for item in values:
        if isinstance(item, bool) or not isinstance(item, int):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "UES port list items must be integers.",
                {"field": field, "value": item},
            )
        if item < 1 or item > 65535:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "UES port list items must be in 1..65535.",
                {"field": field, "value": item},
            )
        result.append(item)
    return result


def _validate_string_list(field: str, values: list[str] | None) -> list[str]:
    if not isinstance(values, list) or not values:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "UES string list must be a non-empty list.",
            {"field": field, "value": values},
        )
    result: list[str] = []
    for item in values:
        if not isinstance(item, str) or not item.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "UES string list items must be non-empty strings.",
                {"field": field, "value": item},
            )
        result.append(item.strip())
    return result
