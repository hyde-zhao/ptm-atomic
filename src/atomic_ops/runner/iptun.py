"""NGFW IP tunnel runner for /api/v1/iptun.

IP tunnels come in three variants, distinguished by ``val.type`` and the
tunnel-endpoint subobject:

- 4over6 (type 15): ``val.ipip`` with IPv6 ``src_addr`` / ``dst_addr``
- 6over4 (type 16): ``val.ipip`` with IPv4 ``src_addr`` / ``dst_addr``
- gre   (type 11): ``val.gre``  with ``tunnel_type`` / ``src_addr`` /
  ``dst_addr`` / ``key`` / ``check_sum`` / ``keepalive_enable``

Creating an IP tunnel also brings up an associated tunnel interface on
``/api/v1/intf``; that tunnel interface is configured through the interface
runner with ``--interface-kind tunnel`` and supports PUT and GET only.
"""

from __future__ import annotations

import json
from ipaddress import AddressValueError, IPv4Address, IPv6Address, ip_address, ip_interface
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
IPTUN_ENDPOINTS = {
    "fw_config_iptun": ("POST", "/api/v1/iptun"),
    "fw_update_iptun": ("PUT", "/api/v1/iptun"),
    "fw_delete_iptun": ("DELETE", "/api/v1/iptun"),
    "fw_verify_iptun": ("GET", "/api/v1/iptun"),
    "fw_delete_batch_iptun": ("POST", "/api/v1/batch"),
}
GET_OPS = {"fw_verify_iptun"}
DELETE_OPS = {"fw_delete_iptun"}
NO_BODY_OPS = GET_OPS | DELETE_OPS
BATCH_OPS = {"fw_delete_batch_iptun"}
IPTUN_RESOURCE = "/api/v1/iptun"

# 隧道子类型到 val.type 的映射；4over6 与 6over4 共用 ipip 子对象。
TUNNEL_TYPE_CODES = {"4over6": 15, "6over4": 16, "gre": 11}
IPIP_TUNNEL_TYPES = {"4over6", "6over4"}
TYPE_CODE_TO_KIND = {15: "ipip", 16: "ipip", 11: "gre"}


def load_json_payload(*, payload_file: str | None, payload_json: str | None) -> dict[str, Any] | None:
    if payload_file and payload_json:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "--payload-file and --payload-json cannot be used together.",
            {"fields": ["payload_file", "payload_json"]},
        )
    if not payload_file and not payload_json:
        return None
    try:
        raw = Path(payload_file).read_text(encoding="utf-8") if payload_file else str(payload_json)
        payload = json.loads(raw)
    except OSError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IP tunnel payload file cannot be read.",
            {"path": payload_file, "reason": exc.__class__.__name__},
        ) from exc
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IP tunnel payload must be valid JSON.",
            {"reason": exc.msg},
        ) from exc
    if not isinstance(payload, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IP tunnel payload JSON root must be an object.",
            {"type": type(payload).__name__},
        )
    return payload


def build_iptun_payload(
    *,
    tunnel_type: str,
    entry_id: str,
    ip_addresses: list[str] | None = None,
    enabled: bool = True,
    level: int = 100,
    src_addr: str,
    dst_addr: str,
    gre_tunnel_type: int = 1,
    gre_key: int = 0,
    gre_check_sum: bool = False,
    gre_keepalive_enable: bool = False,
) -> dict[str, Any]:
    type_code = _validate_tunnel_type(tunnel_type)
    _validate_non_empty("id", entry_id)
    _validate_tunnel_endpoints(tunnel_type, src_addr, dst_addr)
    addresses = _validate_ip_addresses(ip_addresses or [])
    _validate_non_negative_int("level", level)

    val: dict[str, Any] = {
        "name": entry_id,
        "type": type_code,
        "enabled": bool(enabled),
        "level": level,
        "ip_addresses": addresses,
    }
    if tunnel_type == "gre":
        val["gre"] = {
            "tunnel_type": _validate_non_negative_int("gre_tunnel_type", gre_tunnel_type),
            "src_addr": src_addr,
            "dst_addr": dst_addr,
            "key": _validate_non_negative_int("gre_key", gre_key),
            "check_sum": bool(gre_check_sum),
            "keepalive_enable": bool(gre_keepalive_enable),
        }
    else:
        val["ipip"] = {"src_addr": src_addr, "dst_addr": dst_addr}

    payload = {"id": entry_id, "val": val}
    validate_iptun_payload(payload, op_id="fw_update_iptun")
    return payload


def build_iptun_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_non_empty("id", entry_id)
        batch.append({"method": "DELETE", "resource": IPTUN_RESOURCE, "body": {"id": [entry_id]}})
    return {"batch": batch}


def validate_iptun_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if op_id in BATCH_OPS:
        return _validate_batch_payload(payload)
    if op_id in NO_BODY_OPS:
        if op_id in DELETE_OPS:
            entry_id = str((payload or {}).get("id") or "")
            _validate_non_empty("id", entry_id)
        return payload

    entry_id = payload.get("id")
    val = payload.get("val")
    if not isinstance(entry_id, str) or not entry_id.strip():
        raise RunnerError("RUNNER_VALIDATION_FAILED", "IP tunnel payload id is required.", {"field": "id"})
    if not isinstance(val, dict):
        raise RunnerError("RUNNER_VALIDATION_FAILED", "IP tunnel payload val object is required.", {"field": "val"})
    name = val.get("name")
    if name != entry_id:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IP tunnel payload id and val.name must match.",
            {"id": entry_id, "name": name},
        )

    type_code = val.get("type")
    kind = TYPE_CODE_TO_KIND.get(type_code)
    if kind is None:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IP tunnel val.type must be 15 (4over6), 16 (6over4), or 11 (gre).",
            {"field": "type", "actual": type_code},
        )

    ipip = val.get("ipip")
    gre = val.get("gre")
    if kind == "gre":
        if not isinstance(gre, dict) or ipip is not None:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "GRE IP tunnel (type 11) requires a gre subobject and must not carry ipip.",
                {"field": "gre"},
            )
        _validate_tunnel_endpoints("gre", str(gre.get("src_addr") or ""), str(gre.get("dst_addr") or ""))
    else:
        if not isinstance(ipip, dict) or gre is not None:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "IP-in-IP tunnel (type 15/16) requires an ipip subobject and must not carry gre.",
                {"field": "ipip"},
            )
        tunnel_type = "4over6" if type_code == 15 else "6over4"
        _validate_tunnel_endpoints(tunnel_type, str(ipip.get("src_addr") or ""), str(ipip.get("dst_addr") or ""))

    _validate_ip_addresses(list(val.get("ip_addresses") or []))
    return payload


def build_iptun_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
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
            "url": _request_url(base_url, op_id, payload=payload),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in NO_BODY_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_iptun(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
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
        _request_url(base_url, op_id, payload=payload),
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "IP tunnel device request did not return a success status.",
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


def _request_url(base_url: str, op_id: str, *, payload: dict[str, Any] | None) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return IPTUN_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this IP tunnel operation.",
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
        if item.get("method") != "DELETE" or item.get("resource") != IPTUN_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch IP tunnel delete only supports DELETE /api/v1/iptun items.",
                {"method": item.get("method"), "resource": item.get("resource")},
            )
        body = item.get("body")
        ids = body.get("id") if isinstance(body, dict) else None
        if not isinstance(ids, list) or not ids:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch IP tunnel delete item body.id must be a non-empty list.",
                {"field": "body.id"},
            )
    return payload


def _validate_tunnel_type(tunnel_type: str) -> int:
    if tunnel_type not in TUNNEL_TYPE_CODES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IP tunnel type is unsupported.",
            {"tunnel_type": tunnel_type, "allowed": sorted(TUNNEL_TYPE_CODES)},
        )
    return TUNNEL_TYPE_CODES[tunnel_type]


def _validate_tunnel_endpoints(tunnel_type: str, src_addr: str, dst_addr: str) -> None:
    _validate_non_empty("src_addr", src_addr)
    _validate_non_empty("dst_addr", dst_addr)
    try:
        src_ip = ip_address(src_addr)
        dst_ip = ip_address(dst_addr)
    except AddressValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IP tunnel endpoint address is invalid.",
            {"src_addr": src_addr, "dst_addr": dst_addr},
        ) from exc

    if tunnel_type == "4over6":
        expected = IPv6Address
        if not (isinstance(src_ip, IPv6Address) and isinstance(dst_ip, IPv6Address)):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "4over6 tunnel endpoints must be IPv6 addresses.",
                {"src_addr": src_addr, "dst_addr": dst_addr},
            )
    elif tunnel_type == "6over4":
        if not (isinstance(src_ip, IPv4Address) and isinstance(dst_ip, IPv4Address)):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "6over4 tunnel endpoints must be IPv4 addresses.",
                {"src_addr": src_addr, "dst_addr": dst_addr},
            )
    # gre 不限制 IP 版本，仅校验地址合法。


def _validate_ip_addresses(ip_addresses: list[str]) -> list[str]:
    validated: list[str] = []
    for item in ip_addresses:
        if not isinstance(item, str) or "/" not in item:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "IP tunnel address must be a CIDR string.",
                {"field": "ip_addresses", "value": item},
            )
        try:
            ip_interface(item)
        except ValueError as exc:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "IP tunnel address must be a valid CIDR address.",
                {"field": "ip_addresses", "value": item},
            ) from exc
        validated.append(item)
    return validated


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required IP tunnel field is empty.",
            {"field": field},
        )


def _validate_non_negative_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IP tunnel integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IP tunnel integer field must be non-negative.",
            {"field": field, "value": parsed},
        )
    return parsed
