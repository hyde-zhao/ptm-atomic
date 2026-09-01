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
INTERFACE_KINDS = {"bvi", "sub", "physical", "bond", "tunnel", "pppoe"}
INTERFACE_MODES = {"Route", "Switch", "Pair", "Monitor"}
ROUTE_ONLY_KINDS = {"bvi", "sub", "tunnel", "pppoe"}
# ---------------------------------------------------------------------------
# 接口 ID 识别正则（仅用于从 id 中提取构造 val 所需的字段，NOT 格式强校验）。
#
# 按决策点3：接口 id 透传，不因格式不符而拒绝（配置用例需要把无效值发给 DUT，
# 由 DUT 校验并返回错误）。这些正则只作为"提取工具"：能匹配就提取出 instance/
# parent/sub_id/bond_id 供 val 构造；匹配不上则回退到显式参数或 0，绝不 raise。
#
# 有效值结构（供用例编写参考，DUT 型号相关）：
#   - 物理口:    GE<slot>_<port>，如 GE0_0 / GE0_1；不同型号前缀不同（TE0_9 / TTE0_1 / GE0_5）
#   - 子接口:    <父接口>.<子ID>，如 GE0_0.100 / TE0_1.100
#   - BVI:       bvi<编号>，如 bvi1 / bvi2
#   - 聚合口:    bond<编号>，如 bond1
#   - 隧道口:    tunnel<名称>，如 tunnel0 / tunnel-ipip1
# ---------------------------------------------------------------------------
PHYSICAL_ID_RE = re.compile(r"^GE\d+_\d+$")
SUB_ID_RE = re.compile(r"^(?P<parent>[^.]+)\.(?P<sub_id>\d+)$")
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
    pppoe_username: str | None = None,
    pppoe_password: str | None = None,
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
    elif interface_kind == "pppoe":
        _apply_pppoe(val, entry_id, pppoe_username, pppoe_password)
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
    elif kind == "pppoe":
        _validate_pppoe_val(val)
    elif kind != "unknown":
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
    # 透传：id 格式不做强校验（DUT 校验无效值），正则仅用于提取 instance。
    # 提取不到且未显式传 bvi_instance 时回退 0，不拒绝。
    match = BVI_ID_RE.match(entry_id)
    if match is not None and bvi_instance is None:
        instance = int(match.group("instance"))
    elif bvi_instance is not None:
        instance = _validate_non_negative_int("bvi_instance", bvi_instance)
    else:
        digits = re.search(r"(\d+)", entry_id)
        instance = int(digits.group(1)) if digits else 0
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
    # 透传：id 格式不做强校验（DUT 校验无效值），正则仅用于提取 parent/sub_id。
    # 提取不到时从 id 按 '.' 拆分，仍拆分不出则回退参数或 0，不拒绝。
    match = SUB_ID_RE.match(entry_id)
    if match is not None:
        parent = parent_name or match.group("parent")
        parsed_sub_id = int(sub_id) if sub_id is not None else int(match.group("sub_id"))
    elif "." in entry_id:
        parent_part, _, sub_part = entry_id.rpartition(".")
        parent = parent_name or parent_part or entry_id
        parsed_sub_id = int(sub_id) if sub_id is not None else (int(sub_part) if sub_part.isdigit() else 0)
    else:
        parent = parent_name or entry_id
        parsed_sub_id = int(sub_id) if sub_id is not None else 0
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
    # 接口 ID 不做格式校验，直接透传；ID 不存在时由防火墙返回错误。
    # 不同型号防火墙物理口命名不同（如 GE0_5 / TE0_9 / TTE0_1），不能在此限定前缀。
    val["type"] = 3


def _apply_pppoe(
    val: dict[str, Any],
    entry_id: str,
    pppoe_username: str | None,
    pppoe_password: str | None,
) -> None:
    # PPPoE 叠加在物理接口上（type=3），另设 pppoe 子对象（username/password）
    # 并将 IPv4 地址模式置为 2（PPPoE 动态获取，对齐 DUT2 TE0_8 已调通配置）。
    # 接口 ID 沿用物理口命名（如 TE0_8），不做格式校验，直接透传。
    _validate_non_empty("pppoe_username", pppoe_username or "")
    _validate_non_empty("pppoe_password", pppoe_password or "")
    val["type"] = 3
    val["pppoe"] = {"username": pppoe_username, "password": pppoe_password}
    val["ipv4_address_mode_config"]["address_mode"] = 2


def _apply_bond(
    val: dict[str, Any],
    entry_id: str,
    bond_id: int | None,
    bond_members: list[str],
    bond_mode: int,
    bond_lb: int,
) -> None:
    match = BOND_ID_RE.match(entry_id)
    # 透传：id 格式不做强校验（DUT 校验无效值），正则仅用于提取 bond_id。
    # 提取不到时回退显式参数或 id 内数字，再回退 0。
    if match is not None and bond_id is None:
        parsed_bond_id = int(match.group("bond_id"))
    elif bond_id is not None:
        parsed_bond_id = _validate_non_negative_int("bond_id", bond_id)
    else:
        digits = re.search(r"(\d+)", entry_id)
        parsed_bond_id = int(digits.group(1)) if digits else 0
    if not bond_members:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one bond member is required.",
            {"field": "bond_member"},
        )
    # bond 成员名透传不校验格式（不同型号物理口命名不同，GE0_5 / TE0_9 / TTE0_1）。
    bonded_interfaces = [
        {"name": member, "is_passive": False, "is_long_timeout": False} for member in bond_members
    ]
    val.update(
        {
            "type": 10,
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
    # 透传：tunnel id 格式不做强校验（DUT 校验无效值），仅保留业务约束。
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


def _validate_pppoe_val(val: dict[str, Any]) -> None:
    if val.get("type") != 3:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "PPPoE interface must use physical type (3).",
            {"field": "type", "actual": val.get("type")},
        )
    pppoe = val.get("pppoe")
    if not isinstance(pppoe, dict) or not pppoe.get("username") or not pppoe.get("password"):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "PPPoE interface requires a pppoe object with username and password.",
            {"field": "pppoe"},
        )
    address_mode = (val.get("ipv4_address_mode_config") or {}).get("address_mode")
    if address_mode != 2:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "PPPoE interface requires ipv4 address_mode=2.",
            {"field": "ipv4_address_mode_config.address_mode", "actual": address_mode},
        )


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
        return "tunnel"
    if BVI_ID_RE.match(entry_id) and "bvi" in val:
        return "bvi"
    if SUB_ID_RE.match(entry_id) and "sub" in val:
        return "sub"
    if "pppoe" in val:
        # PPPoE 叠加在物理口上（type=3），先于 physical 判定
        return "pppoe"
    if type_code == 3:
        # 物理口按 type 代码判定，不校验 ID 前缀（不同型号防火墙命名不同：GE0_5 / TE0_9 / TTE0_1）
        return "physical"
    if BOND_ID_RE.match(entry_id) and "bond" in val:
        return "bond"
    # 透传兜底：id 风格识别不出时不拒绝，返回 unknown，由调用方跳过 type 强校验、
    # 把 payload 原样发给 DUT（配置用例需验证无效值）。
    return "unknown"


def _validate_deletable_interface_id(entry_id: str) -> None:
    # 透传：delete 的 id 不做格式/类别强校验（DUT 校验无效 id），仅要求非空。
    # 物理口/tunnel 是否可删由 DUT 决定，runner 不再拦截。
    _validate_non_empty("id", entry_id)


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

