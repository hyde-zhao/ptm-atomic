"""NGFW session-table runner for /api/v1/monitor/sessioninfo.

Queries the firewall session table (IPv4 or IPv6) and extracts the
per-session security-zone fields (rxzone / txzone) that security-zone
test cases assert on (e.g. "session source zone = zone1").
"""

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
SESSION_ENDPOINTS = {
    "fw_verify_session": ("GET", "/api/v1/monitor/sessioninfo"),
}
GET_OPS = {"fw_verify_session"}
NO_BODY_OPS = GET_OPS

# sessioninfo 支持的过滤参数（值来自 Web 控制台抓包，全部可选）。
FILTER_KEYS = (
    "proto", "src_addr", "dst_addr", "src_port", "dst_port",
    "natsip", "natdip", "natsport", "natdport", "vlanid",
    "rxZone", "txZone", "rxIf", "txIf", "policyId", "appName", "action",
)

# 会话条目中供用例断言的核心字段（含安全域）。
SUMMARY_FIELDS = (
    "sip", "dip", "sport", "dport", "proto", "isip6",
    "rxzone", "txzone", "rxSwIfIndex", "txSwIfIndex",
    "action", "policyid", "appname",
)


def build_session_filters(*, args: dict[str, Any]) -> dict[str, Any]:
    """将过滤参数转换为 sessioninfo query 参数（仅包含显式传入的非空值）。"""
    filters: dict[str, Any] = {}
    for key in FILTER_KEYS:
        value = args.get(key)
        if value is None or value == "":
            continue
        filters[key] = value
    return filters


def build_session_verify_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    page: int,
    size: int,
    is_ip6: bool,
    filters: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = SESSION_ENDPOINTS["fw_verify_session"]
    return {
        "op_id": "fw_verify_session",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(base_url, page=page, size=size, is_ip6=is_ip6, filters=filters),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_session_verify(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    page: int,
    size: int,
    is_ip6: bool,
    filters: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)
    method, path = SESSION_ENDPOINTS["fw_verify_session"]
    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {
        "Content-Type": "application/json",
        auth_header: header_value,
    }
    status_code, response_payload, _text = request_json(
        method,
        _request_url(base_url, page=page, size=size, is_ip6=is_ip6, filters=filters),
        headers=headers,
        json_payload=None,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in GET_SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Session-table device request did not return a success status.",
            {
                "op_id": "fw_verify_session",
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()) if isinstance(response_payload, dict) else [],
            },
        )
    result: dict[str, Any] = {
        "op_id": "fw_verify_session",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": method,
            "path": path,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }
    # 兑现 atom returns.data 契约：提取会话摘要（含 rxzone/txzone 安全域字段）。
    result.update(_extract_session_summary(response_payload))
    return result


def _extract_session_summary(response_payload: Any) -> dict[str, Any]:
    """从 sessioninfo 响应提取 count 与结构化会话摘要。"""
    summary: dict[str, Any] = {}
    if not isinstance(response_payload, dict):
        return summary
    vals = response_payload.get("vals")
    if isinstance(vals, list):
        entries: list[dict[str, Any]] = []
        for item in vals:
            if not isinstance(item, dict):
                continue
            entries.append({field: item.get(field) for field in SUMMARY_FIELDS})
        summary["sessions"] = entries
        # 安全域二元组 (源域, 目的域) 列表，供 zone 断言直接比对。
        summary["session_zones"] = [
            (item.get("rxzone"), item.get("txzone")) for item in entries
        ]
    summary["count"] = response_payload.get("count")
    summary["ipv4_count"] = response_payload.get("ipv4count")
    summary["ipv6_count"] = response_payload.get("ipv6count")
    summary["permit_count"] = response_payload.get("permitcount")
    summary["deny_count"] = response_payload.get("denycount")
    return summary


def _request_url(
    base_url: str,
    *,
    page: int,
    size: int,
    is_ip6: bool,
    filters: dict[str, Any],
) -> str:
    query: dict[str, Any] = {
        "page": page,
        "size": size,
        "isip6": 1 if is_ip6 else 0,
    }
    query.update(filters)
    # 地址/域名/zone 名称保留冒号、点号、连字符与下划线（IPv6/IPv4/zone名），
    # 设备对 %3A / %2D 等编码字符返回空响应。
    return f"{normalize_base_url(base_url)}{SESSION_ENDPOINTS['fw_verify_session'][1]}?{urlencode(query, safe=':.-_')}"


def _validate_positive_int(field: str, value: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Session query integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed <= 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Session query integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed
