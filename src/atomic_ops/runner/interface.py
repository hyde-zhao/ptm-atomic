"""NGFW interface runner for /api/v1/intf."""

from __future__ import annotations

import re
from ipaddress import AddressValueError, IPv4Address, IPv6Address, ip_address, ip_interface
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner._payload import load_json_payload
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
INTERFACE_ENDPOINTS = {
    "fw_config_interface": ("POST", "/api/v1/intf"),
    "fw_update_interface": ("PUT", "/api/v1/intf"),
    "fw_verify_interface": ("GET", "/api/v1/intf"),
    "fw_delete_interface": ("DELETE", "/api/v1/intf"),
    "fw_delete_batch_interface": ("POST", "/api/v1/batch"),
}
NO_BODY_OPS = {"fw_verify_interface", "fw_delete_interface"}
INTERFACE_KINDS = {"bvi", "sub", "physical", "bond", "tunnel"}
INTERFACE_MODES = {"Route", "Switch", "Pair", "Monitor"}
ROUTE_ONLY_KINDS = {"bvi", "sub", "tunnel"}
PHYSICAL_ID_RE = re.compile(r"^GE\d+_\d+$")
SUB_ID_RE = re.compile(r"^(?P<parent>GE\d+_\d+)\.(?P<sub_id>\d+)$")
BVI_ID_RE = re.compile(r"^bvi(?P<instance>\d+)$")
BOND_ID_RE = re.compile(r"^bond(?P<bond_id>\d+)$")
TUNNEL_ID_RE = re.compile(r"^tunnel[\w-]*$")
TUNNEL_TYPE_CODES = {"4over6": 15, "6over4": 16, "gre": 11}
TUNNEL_TYPE_BY_CODE = {15: "4over6", 16: "6over4", 11: "gre"}
TUNNEL_TYPE_CODES_SET = set(TUNNEL_TYPE_CODES.values())


def build_interface_payload(
    *,
    interface_kind: str,
    entry_id: str,
    mode: str = "Route",
    ip_addresses: list[str] | None = None,
    name: str | None = None,
    desc: str = "",
    enabled: bool = True,
    level: int = 100,
    parent_name: str | None = None,
    sub_id: int | None = None,
    bvi_instance: int | None = None,
    bond_id: int | None = None,
    bond_members: list[str] | None = None,
    bond_mode: int = 5,
    bond_lb: int = 0,
    link_type: int | None = None,
    pvid: int = 1,
    allow_pass: str | None = None,
    tunnel_type: str | None = None,
    src_addr: str | None = None,
    dst_addr: str | None = None,
    gre_tunnel_type: int = 1,
    gre_key: int = 0,
    gre_check_sum: bool = False,
    gre_keepalive_enable: bool = False,
) -> dict[str, Any]:
    interface_kind = _validate_interface_kind(interface_kind)
    mode = _validate_mode(interface_kind, mode)
    _validate_non_empty("id", entry_id)
    name = name or entry_id
    if name != entry_id:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface id and val.name must match.",
            {"id": entry_id, "name": name},
        )
    addresses = _validate_ip_addresses(ip_addresses or [])
    _validate_non_negative_int("level", level)

    val = _base_val(
        name=name,
        desc=desc,
        enabled=enabled,
        level=level,
        mode=mode,
        ip_addresses=addresses,
        link_type=link_type,
    )
    if interface_kind == "bvi":
        _apply_bvi(val, entry_id, bvi_instance)
    elif interface_kind == "sub":
        _apply_sub(val, entry_id, parent_name, sub_id)
    elif interface_kind == "physical":
        _apply_physical(val, entry_id)
    elif interface_kind == "bond":
        _apply_bond(val, entry_id, bond_id, bond_members or [], bond_mode, bond_lb)
    elif interface_kind == "tunnel":
        _apply_tunnel(
            val, entry_id, tunnel_type, src_addr, dst_addr,
            gre_tunnel_type=gre_tunnel_type, gre_key=gre_key,
            gre_check_sum=gre_check_sum, gre_keepalive_enable=gre_keepalive_enable,
        )

    _apply_mode_fields(val, interface_kind, mode, pvid=pvid, allow_pass=allow_pass, link_type=link_type)
    payload = {"id": entry_id, "val": val}
    validate_interface_payload(payload, op_id="fw_update_interface")
    return payload


def build_interface_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one interface id is required for batch delete.",
            {"field": "id"},
        )
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_deletable_interface_id(entry_id)
        batch.append({"method": "DELETE", "resource": "/api/v1/intf", "body": {"id": [entry_id]}})
    return {"batch": batch}


def validate_interface_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if op_id == "fw_delete_batch_interface":
        return _validate_batch_payload(payload)
    if op_id in NO_BODY_OPS:
        return payload
    entry_id = payload.get("id")
    val = payload.get("val")
    if not isinstance(entry_id, str) or not entry_id.strip():
        raise RunnerError("RUNNER_VALIDATION_FAILED", "Interface payload id is required.", {"field": "id"})
    if not isinstance(val, dict):
        raise RunnerError("RUNNER_VALIDATION_FAILED", "Interface payload val object is required.", {"field": "val"})
    name = val.get("name")
    if name != entry_id:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface payload id and val.name must match.",
            {"id": entry_id, "name": name},
        )

    kind = _kind_from_payload(entry_id, val)
    mode = _validate_mode(kind, str(val.get("mode") or ""))
    if kind == "tunnel":
        _validate_tunnel_val(val)
    else:
        expected_type = {"bvi": 14, "sub": 1, "physical": 3, "bond": 10}[kind]
        if val.get("type") != expected_type:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Interface payload type does not match the interface id style.",
                {"field": "type", "interface_kind": kind, "expected": expected_type, "actual": val.get("type")},
            )
    _validate_ip_addresses(list(val.get("ip_addresses") or []))
    if op_id == "fw_config_interface" and kind in {"physical", "tunnel"}:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Physical and tunnel interfaces support PUT and GET only.",
            {"interface_kind": kind, "op_id": op_id},
        )
    if mode != "Route" and kind in ROUTE_ONLY_KINDS:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "This interface kind supports Route mode only.",
            {"interface_kind": kind, "mode": mode},
        )
    return payload


def validate_delete_payload(payload: dict[str, Any]) -> dict[str, str]:
    entry_id = str(payload.get("id") or "")
    _validate_deletable_interface_id(entry_id)
    return {"id": entry_id}


def build_interface_dry_run(
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


def execute_interface(
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
            "Interface device request did not return a success status.",
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


def _request_url(base_url: str, op_id: str, *, payload: dict[str, Any] | None = None) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id == "fw_delete_interface":
        entry_id = str((payload or {}).get("id") or "")
        _validate_deletable_interface_id(entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return INTERFACE_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this interface operation.",
            {"op_id": op_id},
        ) from exc


def _base_val(
    *,
    name: str,
    desc: str,
    enabled: bool,
    level: int,
    mode: str,
    ip_addresses: list[str],
    link_type: int | None,
) -> dict[str, Any]:
    val: dict[str, Any] = {
        "vltype": "VPP",
        "name": name,
        "desc": desc,
        "enabled": enabled,
        "level": level,
        "ipv4_gateway": "",
        "ipv4_reverse_path": False,
        "ipv6_reverse_path": False,
        "ipv6_gateway": "",
        "mtus": [1500, 0, 0, 0],
        "ipv4_address_mode_config": {"address_mode": 0},
        "ipv6_address_mode_config": {
            "dhcp_client_setting": {},
            "address_mode": 0,
            "install_default_route": False,
        },
        "ip_addresses": ip_addresses,
        "service": {"https": False, "ssh": False, "ping": False},
        "sip": [],
        "smac": [],
        "mode": mode,
    }
    if link_type is not None:
        val["linkType"] = _validate_non_negative_int("link_type", link_type)
    return val


def _apply_bvi(val: dict[str, Any], entry_id: str, bvi_instance: int | None) -> None:
    match = BVI_ID_RE.match(entry_id)
    if not match:
        raise RunnerError("RUNNER_VALIDATION_FAILED", "BVI id must use bvi<number> style.", {"id": entry_id})
    instance = _validate_positive_int("bvi_instance", bvi_instance or match.group("instance"))
    val.update(
        {
            "linkType": val.get("linkType", 0),
            "type": 14,
            "bvi": {
                "instance": instance,
                "bridge": {
                    "name": entry_id,
                    "interfaces": [],
                    "flood": True,
                    "unknown_unicast_flood": True,
                    "forward": True,
                    "learn": True,
                    "arp_termination": False,
                    "arp_termination_table": [],
                },
            },
            "ip6_nd": {"ip_prefix": []},
            "ip6_racfg": {"suppress": 0},
        }
    )


def _apply_sub(val: dict[str, Any], entry_id: str, parent_name: str | None, sub_id: int | None) -> None:
    match = SUB_ID_RE.match(entry_id)
    if not match:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Subinterface id must use <parent>.<sub-id> style.",
            {"id": entry_id},
        )
    parent = parent_name or match.group("parent")
    parsed_sub_id = _validate_positive_int("sub_id", sub_id or match.group("sub_id"))
    if parent != match.group("parent") or parsed_sub_id != int(match.group("sub_id")):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Subinterface parent and sub_id must match the interface id.",
            {"id": entry_id, "parent_name": parent, "sub_id": parsed_sub_id},
        )
    val.update(
        {
            "linkType": val.get("linkType", 0),
            "type": 1,
            "sub": {"parent_name": parent, "sub_id": parsed_sub_id},
            "ip6_nd": {"ip_prefix": []},
            "ip6_racfg": {"suppress": 0},
        }
    )


def _apply_physical(val: dict[str, Any], entry_id: str) -> None:
    if not PHYSICAL_ID_RE.match(entry_id):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Physical interface id must use GE<number>_<number> style.",
            {"id": entry_id},
        )
    val["type"] = 3


def _apply_bond(
    val: dict[str, Any],
    entry_id: str,
    bond_id: int | None,
    bond_members: list[str],
    bond_mode: int,
    bond_lb: int,
) -> None:
    match = BOND_ID_RE.match(entry_id)
    if not match:
        raise RunnerError("RUNNER_VALIDATION_FAILED", "Bond interface id must use bond<number> style.", {"id": entry_id})
    parsed_bond_id = _validate_positive_int("bond_id", bond_id or match.group("bond_id"))
    if parsed_bond_id != int(match.group("bond_id")):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Bond id must match the interface id.",
            {"id": entry_id, "bond_id": parsed_bond_id},
        )
    if not bond_members:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one bond member is required.",
            {"field": "bond_member"},
        )
    bonded_interfaces = []
    for member in bond_members:
        if not PHYSICAL_ID_RE.match(member):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Bond member must use physical interface id style.",
                {"field": "bond_member", "value": member},
            )
        bonded_interfaces.append({"name": member, "is_passive": False, "is_long_timeout": False})
    val.update(
        {
            "type": 10,
            "enable_garp_timed_send": False,
            "bond": {
                "id": parsed_bond_id,
                "mode": _validate_non_negative_int("bond_mode", bond_mode),
                "lb": _validate_non_negative_int("bond_lb", bond_lb),
                "bonded_interfaces": bonded_interfaces,
            },
        }
    )


def _apply_tunnel(
    val: dict[str, Any],
    entry_id: str,
    tunnel_type: str | None,
    src_addr: str | None,
    dst_addr: str | None,
    *,
    gre_tunnel_type: int,
    gre_key: int,
    gre_check_sum: bool,
    gre_keepalive_enable: bool,
) -> None:
    if not TUNNEL_ID_RE.match(entry_id):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Tunnel interface id must use a tunnel-prefixed style.",
            {"id": entry_id},
        )
    if tunnel_type not in TUNNEL_TYPE_CODES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IP tunnel type is unsupported.",
            {"tunnel_type": tunnel_type, "allowed": sorted(TUNNEL_TYPE_CODES)},
        )
    _validate_tunnel_endpoints(tunnel_type, src_addr or "", dst_addr or "")
    val["type"] = TUNNEL_TYPE_CODES[tunnel_type]
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


def _validate_tunnel_val(val: dict[str, Any]) -> None:
    type_code = val.get("type")
    if type_code not in TUNNEL_TYPE_CODES_SET:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Tunnel interface val.type must be 15 (4over6), 16 (6over4), or 11 (gre).",
            {"field": "type", "actual": type_code},
        )
    ipip = val.get("ipip")
    gre = val.get("gre")
    if type_code == 11:
        if not isinstance(gre, dict) or ipip is not None:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "GRE tunnel interface (type 11) requires a gre subobject and must not carry ipip.",
                {"field": "gre"},
            )
        _validate_tunnel_endpoints("gre", str(gre.get("src_addr") or ""), str(gre.get("dst_addr") or ""))
    else:
        if not isinstance(ipip, dict) or gre is not None:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "IP-in-IP tunnel interface (type 15/16) requires an ipip subobject and must not carry gre.",
                {"field": "ipip"},
            )
        tunnel_type = TUNNEL_TYPE_BY_CODE[type_code]
        _validate_tunnel_endpoints(tunnel_type, str(ipip.get("src_addr") or ""), str(ipip.get("dst_addr") or ""))


def _validate_tunnel_endpoints(tunnel_type: str, src_addr: str, dst_addr: str) -> None:
    _validate_non_empty("src_addr", src_addr)
    _validate_non_empty("dst_addr", dst_addr)
    try:
        src_ip = ip_address(src_addr)
        dst_ip = ip_address(dst_addr)
    except AddressValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Tunnel endpoint address is invalid.",
            {"src_addr": src_addr, "dst_addr": dst_addr},
        ) from exc
    if tunnel_type == "4over6":
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


def _apply_mode_fields(
    val: dict[str, Any],
    interface_kind: str,
    mode: str,
    *,
    pvid: int,
    allow_pass: str | None,
    link_type: int | None,
) -> None:
    if mode == "Route":
        return
    val["tag_rw_option"] = 0
    val["pvid"] = _validate_positive_int("pvid", pvid)
    if "linkType" not in val:
        val["linkType"] = 1 if interface_kind == "bond" else 2
    if link_type is not None:
        val["linkType"] = _validate_non_negative_int("link_type", link_type)
    if mode == "Monitor":
        val["allowPass"] = allow_pass if allow_pass is not None else "1-4094"
    elif mode in {"Switch", "Pair"}:
        val["allowPass"] = allow_pass if allow_pass is not None else ""


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
        if item.get("method") != "DELETE" or item.get("resource") != "/api/v1/intf":
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch interface delete only supports DELETE /api/v1/intf items.",
                {"method": item.get("method"), "resource": item.get("resource")},
            )
        body = item.get("body")
        ids = body.get("id") if isinstance(body, dict) else None
        if not isinstance(ids, list) or not ids:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch interface delete item body.id must be a non-empty list.",
                {"field": "body.id"},
            )
        for entry_id in ids:
            _validate_deletable_interface_id(str(entry_id))
    return payload


def _kind_from_payload(entry_id: str, val: dict[str, Any]) -> str:
    type_code = val.get("type")
    if type_code in TUNNEL_TYPE_CODES_SET:
        if not TUNNEL_ID_RE.match(entry_id):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Tunnel interface id must use a tunnel-prefixed style.",
                {"id": entry_id, "type": type_code},
            )
        return "tunnel"
    if BVI_ID_RE.match(entry_id) and "bvi" in val:
        return "bvi"
    if SUB_ID_RE.match(entry_id) and "sub" in val:
        return "sub"
    if PHYSICAL_ID_RE.match(entry_id):
        return "physical"
    if BOND_ID_RE.match(entry_id) and "bond" in val:
        return "bond"
    raise RunnerError(
        "RUNNER_VALIDATION_FAILED",
        "Interface payload id style or type-specific object is unsupported.",
        {"id": entry_id},
    )


def _validate_deletable_interface_id(entry_id: str) -> None:
    _validate_non_empty("id", entry_id)
    if PHYSICAL_ID_RE.match(entry_id):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Physical interfaces cannot be deleted.",
            {"id": entry_id},
        )
    if TUNNEL_ID_RE.match(entry_id):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Tunnel interfaces cannot be deleted; delete the IP tunnel via fw_delete_iptun instead.",
            {"id": entry_id},
        )
    if not (BVI_ID_RE.match(entry_id) or SUB_ID_RE.match(entry_id) or BOND_ID_RE.match(entry_id)):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface delete id must be bvi<number>, <parent>.<sub-id>, or bond<number>.",
            {"id": entry_id},
        )


def _validate_interface_kind(interface_kind: str) -> str:
    if interface_kind not in INTERFACE_KINDS:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface kind is unsupported.",
            {"interface_kind": interface_kind, "allowed": sorted(INTERFACE_KINDS)},
        )
    return interface_kind


def _validate_mode(interface_kind: str, mode: str) -> str:
    if mode not in INTERFACE_MODES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface mode is unsupported.",
            {"mode": mode, "allowed": sorted(INTERFACE_MODES)},
        )
    if interface_kind in ROUTE_ONLY_KINDS and mode != "Route":
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "This interface kind supports Route mode only.",
            {"interface_kind": interface_kind, "mode": mode},
        )
    return mode


def _validate_ip_addresses(ip_addresses: list[str]) -> list[str]:
    validated: list[str] = []
    for item in ip_addresses:
        if not isinstance(item, str) or "/" not in item:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Interface IP address must be a CIDR string.",
                {"field": "ip_addresses", "value": item},
            )
        try:
            ip_interface(item)
        except ValueError as exc:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Interface IP address must be a valid CIDR address.",
                {"field": "ip_addresses", "value": item},
            ) from exc
        validated.append(item)
    return validated


def _validate_positive_int(field: str, value: int | str) -> int:
    parsed = _validate_non_negative_int(field, value)
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_non_negative_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface integer field must be non-negative.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required interface field is empty.",
            {"field": field},
        )

