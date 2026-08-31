"""NGFW session-table runner for /api/v1/monitor/sessioninfo."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200}
SESSIONINFO_ENDPOINT = ("GET", "/api/v1/monitor/sessioninfo")
OP_ID = "fw_verify_session"

IPV4_ZERO_ADDR = "0.0.0.0"
IPV6_ZERO_ADDR = "0:0::0"
PROTOS = {"ANY", "TCP", "UDP", "ICMP", "ICMPv6", "SCTP", "GRE", "ESP", "AH", "OTHER"}


def _family_zero_addr(isip6: int) -> str:
    return IPV6_ZERO_ADDR if isip6 else IPV4_ZERO_ADDR


def _validate_isip6(value: int) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Session isip6 field must be 0 (IPv4) or 1 (IPv6).",
            {"field": "isip6", "value": value},
        ) from exc
    if parsed not in (0, 1):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Session isip6 field must be 0 (IPv4) or 1 (IPv6).",
            {"field": "isip6", "value": parsed},
        )
    return parsed


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Session integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Session integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_non_negative_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Session integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Session integer field must be non-negative.",
            {"field": field, "value": parsed},
        )
    return parsed


def _request_url(
    base_url: str,
    *,
    isip6: int,
    page: int,
    size: int,
    proto: str,
    src_addr: str,
    dst_addr: str,
    src_port: int,
    dst_port: int,
    natsip: str,
    natdip: str,
    natsport: int,
    natdport: int,
    vlanid: str,
    rx_zone: str,
    tx_zone: str,
    rx_if: str,
    tx_if: str,
    policy_id: str,
    app_name: str,
    action: str,
) -> str:
    isip6 = _validate_isip6(isip6)
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)
    zero = _family_zero_addr(isip6)
    # 地址过滤默认取地址族全零地址；显式传值则使用调用方过滤条件
    src_addr = src_addr if src_addr not in (None, "") else zero
    dst_addr = dst_addr if dst_addr not in (None, "") else zero
    natsip = natsip if natsip not in (None, "") else zero
    natdip = natdip if natdip not in (None, "") else zero
    query: dict[str, Any] = {
        "page": page,
        "size": size,
        "isip6": isip6,
        "proto": proto,
        "src_addr": src_addr,
        "dst_addr": dst_addr,
        "src_port": _validate_non_negative_int("src_port", src_port),
        "dst_port": _validate_non_negative_int("dst_port", dst_port),
        "natsip": natsip,
        "natdip": natdip,
        "natsport": _validate_non_negative_int("natsport", natsport),
        "natdport": _validate_non_negative_int("natdport", natdport),
        "vlanid": vlanid,
        "rxZone": rx_zone,
        "txZone": tx_zone,
        "rxIf": rx_if,
        "txIf": tx_if,
        "policyId": policy_id,
        "appName": app_name,
        "action": action,
    }
    return f"{normalize_base_url(base_url)}/api/v1/monitor/sessioninfo?{urlencode(query)}"


def _extract_session_summary(response_payload: Any) -> dict[str, Any]:
    """提取会话表摘要字段；非 dict 响应按空表处理并保持响应原文可查。"""
    if not isinstance(response_payload, dict):
        return {
            "count": 0,
            "ipv4count": 0,
            "ipv6count": 0,
            "permitcount": 0,
            "denycount": 0,
            "page": 0,
            "size": 0,
            "sessions": [],
        }
    return {
        "count": response_payload.get("count", 0),
        "ipv4count": response_payload.get("ipv4count", 0),
        "ipv6count": response_payload.get("ipv6count", 0),
        "permitcount": response_payload.get("permitcount", 0),
        "denycount": response_payload.get("denycount", 0),
        "page": response_payload.get("page", 0),
        "size": response_payload.get("size", 0),
        "sessions": response_payload.get("vals", []),
    }


def build_verify_session_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    isip6: int = 0,
    page: int = 1,
    size: int = 10,
    proto: str = "ANY",
    src_addr: str | None = None,
    dst_addr: str | None = None,
    src_port: int = 0,
    dst_port: int = 0,
    natsip: str | None = None,
    natdip: str | None = None,
    natsport: int = 0,
    natdport: int = 0,
    vlanid: str = "",
    rx_zone: str = "",
    tx_zone: str = "",
    rx_if: str = "",
    tx_if: str = "",
    policy_id: str = "",
    app_name: str = "",
    action: str = "",
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, _path = SESSIONINFO_ENDPOINT
    return {
        "op_id": OP_ID,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(
                base_url,
                isip6=isip6,
                page=page,
                size=size,
                proto=proto,
                src_addr=src_addr or "",
                dst_addr=dst_addr or "",
                src_port=src_port,
                dst_port=dst_port,
                natsip=natsip or "",
                natdip=natdip or "",
                natsport=natsport,
                natdport=natdport,
                vlanid=vlanid,
                rx_zone=rx_zone,
                tx_zone=tx_zone,
                rx_if=rx_if,
                tx_if=tx_if,
                policy_id=policy_id,
                app_name=app_name,
                action=action,
            ),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_verify_session(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    isip6: int = 0,
    page: int = 1,
    size: int = 10,
    proto: str = "ANY",
    src_addr: str | None = None,
    dst_addr: str | None = None,
    src_port: int = 0,
    dst_port: int = 0,
    natsip: str | None = None,
    natdip: str | None = None,
    natsport: int = 0,
    natdport: int = 0,
    vlanid: str = "",
    rx_zone: str = "",
    tx_zone: str = "",
    rx_if: str = "",
    tx_if: str = "",
    policy_id: str = "",
    app_name: str = "",
    action: str = "",
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = SESSIONINFO_ENDPOINT
    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    status_code, response_payload, _text = request_json(
        method,
        _request_url(
            base_url,
            isip6=isip6,
            page=page,
            size=size,
            proto=proto,
            src_addr=src_addr or "",
            dst_addr=dst_addr or "",
            src_port=src_port,
            dst_port=dst_port,
            natsip=natsip or "",
            natdip=natdip or "",
            natsport=natsport,
            natdport=natdport,
            vlanid=vlanid,
            rx_zone=rx_zone,
            tx_zone=tx_zone,
            rx_if=rx_if,
            tx_if=tx_if,
            policy_id=policy_id,
            app_name=app_name,
            action=action,
        ),
        headers=headers,
        json_payload=None,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Session-table device request did not return a success status.",
            {
                "op_id": OP_ID,
                "status_code": status_code,
                "err_code": response_payload.get("errCode") if isinstance(response_payload, dict) else None,
                "err_msg": (response_payload.get("errMsg") or response_payload.get("message")) if isinstance(response_payload, dict) else None,
                "response_keys": sorted(response_payload.keys()) if isinstance(response_payload, dict) else [],
            },
        )
    return {
        "op_id": OP_ID,
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": method,
            "path": path,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
        "data": _extract_session_summary(response_payload),
    }
