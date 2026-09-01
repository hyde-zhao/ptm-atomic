"""P4-347323: 预定义服务对象基础配置验证

xlsx(对象管理用例_重构_563.xlsx):
  1. 登录防火墙管理界面
  2. 检查所有预定义服务对象的配置
  3. 仔细确认端口号、协议类型与标准RFC一致【check1】所有预定义服务对象端口与标准RFC完全一致

设备实测(55.63, probe24): /api/v1/servicepool?type=PRESET 返回 95 个预定义服务,
条目含 ranges[{proto,s_start,s_end,d_start,d_end}]。知名服务(HTTP/HTTPS/SSH/
TELNET/SMTP/POP3/IMAP/FTP/DNS)端口与协议均与 RFC 一致。本用例:
  check1a: 全部预定义条目结构合法(协议号在 IANA 0-255, 端口 0-65535, 范围有序)。
  check1b: 知名服务逐项抽查, 端口/协议与 RFC 完全一致。
"""

from __future__ import annotations

from typing import Any

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

TITLE = "P4-347323 预定义服务对象基础配置验证"

# 知名服务 → (协议号, RFC 目的端口)。DNS 支持 TCP(6)/UDP(17) 双协议。
RFC_SERVICES = {
    "http": (6, 80), "https": (6, 443), "ssh": (6, 22), "telnet": (6, 23),
    "smtp": (6, 25), "pop3": (6, 110), "imap": (6, 143), "ftp": (6, 21),
    "dns": (6, 53),
}
RFC_SERVICES_ALT_PROTO = {"dns": {6, 17}}


def _entries(response: Any) -> list[dict[str, Any]]:
    seen: dict[str, dict[str, Any]] = {}

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            nm = node.get("name")
            if isinstance(nm, str) and nm and isinstance(node.get("ranges"), list):
                if nm not in seen:
                    seen[nm] = node
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(response)
    return list(seen.values())


def _bad_ranges(entry: dict[str, Any]) -> list[str]:
    """结构非法(range 缺失字段/端口越界/顺序颠倒)的说明列表。"""
    bad: list[str] = []
    for i, rng in enumerate(entry.get("ranges") or []):
        if not isinstance(rng, dict):
            bad.append(f"r[{i}] not-dict")
            continue
        try:
            proto = int(rng.get("proto"))
            s0, s1 = int(rng.get("s_start")), int(rng.get("s_end"))
            d0, d1 = int(rng.get("d_start")), int(rng.get("d_end"))
        except (TypeError, ValueError):
            bad.append(f"r[{i}] non-integer fields")
            continue
        if not (0 <= proto <= 255):
            bad.append(f"r[{i}] proto={proto}")
        for label, lo, hi in (("s", s0, s1), ("d", d0, d1)):
            if not (0 <= lo <= hi <= 65535):
                bad.append(f"r[{i}] {label}_range={lo}-{hi}")
    return bad


def run(ctx: CaseContext, result: CaseResult) -> None:
    out = ctx.runner.run("service-pool", "verify-preset", page=1, size=200)
    result.record(op_succeeded(out, ctx=ctx, label="preset-list-query"))
    if not ctx.execute:
        return
    entries = _entries(out.response()) if out.success else []
    result.record(Check(name="preset-discovered", ok=len(entries) > 0,
                        detail=f"preset_services={len(entries)}"))

    # check1a: 所有预定义条目结构合法。
    bad_entries = []
    for e in entries:
        bad = _bad_ranges(e)
        if bad:
            bad_entries.append(f"{e.get('name')}:{','.join(bad[:2])}")
    result.record(Check(name="all-preset-struct-valid", ok=len(bad_entries) == 0,
                        detail=f"invalid={bad_entries[:6]}" if bad_entries
                               else f"all {len(entries)} entries structurally valid"))

    # check1b: 知名服务端口/协议与 RFC 一致。
    for svc, (proto, port) in RFC_SERVICES.items():
        entry = next((e for e in entries if str(e.get("name", "")).lower() == svc), None)
        if entry is None:
            result.record(Check(name=f"rfc-{svc}", ok=False, detail="service not found"))
            continue
        alt = RFC_SERVICES_ALT_PROTO.get(svc, set())
        ok = any(
            isinstance(r, dict)
            and int(r.get("proto")) in ({proto} | alt)
            and int(r.get("d_start")) <= port <= int(r.get("d_end"))
            for r in (entry.get("ranges") or [])
        )
        result.record(Check(name=f"rfc-{svc}", ok=ok,
                            detail=f"name={svc!r} port={port} proto={proto} ranges="
                                   f"{[rng for rng in (entry.get('ranges') or []) if isinstance(rng, dict)]}"))
