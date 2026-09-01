"""Shared helpers for the address-object/group capacity cases
(129003/129004/129011/129013/129022/129023).

Probe-confirmed device limits (55.63, 2026-09-01):
  * IPv4/IPv6 address OBJECT max networks = 1024 entries.  1024→ok, 1025→reject
    「{ipv4,ipv6}地址对象单个容量超过限制,当前配置数量 {n}」. (xlsx 写 2048 字符,
    divergence: 实际按网络条目数计,上限 1024。)
  * IPv4/IPv6 address GROUP max members = 256.  256→ok, 257→reject
    「{ipv4,ipv6}地址组容量超过限制,当前配置数量 257」. (与 xlsx 一致。)
  * IPv4/IPv6 address GROUP 对象数量上限 > 1050 (探针创建 1050 无上限) →
    数量容量用例走「有界高水位」+ documented-divergence。

REST 资源:
  IPv4 对象 /api/v1/ippool        IPv6 对象 /api/v1/ip6pool
  IPv4 组   /api/v1/ippool/group  IPv6 组   /api/v1/ip6pool/group
  payload: 对象 {"val":{name,desc,type:4,ranges:[],networks:[{ipaddr,mask}],exclranges:[],exclnetworks:[]}}
           组   {"val":{name,desc,ippools:[names]}} / {"val":{name,desc,ip6pools:[names]}}
  update:   PUT <res>?id=<name> body {"id":name,"val":{...}}
  delete:   DELETE <res>?id=<name>
"""

from __future__ import annotations

import json
from typing import Any

import requests
import urllib3

from framework.checks import Check
from framework.context import CaseContext
from framework.results import CaseResult

urllib3.disable_warnings()

V4_OBJ = "/api/v1/ippool"
V6_OBJ = "/api/v1/ip6pool"
V4_GRP = "/api/v1/ippool/group"
V6_GRP = "/api/v1/ip6pool/group"

OBJ_MAX_NETWORKS = 1024
GRP_MAX_MEMBERS = 256
# 组对象数量实测 > 1050; 有界高水位(快速、不洪泛操作日志)。
GRP_COUNT_FILL = 60


def raw_headers(ctx: CaseContext) -> dict[str, str]:
    data = json.loads(ctx.session_file.read_text(encoding="utf-8"))
    return {"Authorization": f"Bearer {data['session_value']}", "Content-Type": "application/json"}


def raw_req(ctx: CaseContext, method: str, resource: str, *, val: dict[str, Any] | None = None,
            ident: str | None = None) -> tuple[int, str]:
    """raw REST call.  PUT 更新按设备实证走 body 携带 id(`{"id":name,"val":...}`);
    DELETE 用 `?id=` 查询参数;POST 直接 body `{"val":...}`。"""
    url = f"{ctx.base_url}{resource}"
    if ident is not None:
        url += f"?id={ident}"
    body = None
    if val is not None:
        body = {"val": val}
        if method.upper() == "PUT":
            body = {"id": ident, "val": val}
    r = requests.request(method, url, headers=raw_headers(ctx), verify=bool(ctx.verify_tls),
                         json=body, timeout=60)
    msg = ""
    try:
        body = r.json()
        msg = str(body.get("errMsg") or body.get("errCode") or "")[:140]
    except Exception:  # noqa: BLE001
        msg = r.text[:80]
    return r.status_code, msg


def raw_delete(ctx: CaseContext, resource: str, name: str) -> None:
    requests.delete(f"{ctx.base_url}{resource}?id={name}", headers=raw_headers(ctx),
                    verify=bool(ctx.verify_tls), timeout=20)


def group_find(ctx: CaseContext, resource: str, name: str) -> dict[str, Any] | None:
    r = requests.get(f"{ctx.base_url}{resource}?page=1&size=1&keywords={name}",
                     headers=raw_headers(ctx), verify=bool(ctx.verify_tls), timeout=20)
    try:
        vals = r.json().get("vals") or []
    except Exception:  # noqa: BLE001
        vals = []
    return next((e for e in vals if isinstance(e, dict) and e.get("name") == name), None)


# ── bulk helpers (raw REST, 秒级, 不洪泛操作日志) ───────────────────────────


def bulk_create_objects(ctx: CaseContext, names: list[str], *, v6: bool,
                        desc: str = "cap-mem") -> tuple[int, list[str]]:
    res = obj_resource(v6)
    ok = 0
    fails: list[str] = []
    for nm in names:
        st, _ = raw_req(ctx, "POST", res, val=obj_val(nm, 1, v6=v6, desc=desc))
        if st in (200, 201, 202):
            ok += 1
        else:
            fails.append(f"{nm}:{st}")
    return ok, fails


def bulk_create_groups(ctx: CaseContext, names: list[str], member: str, *, v6: bool,
                       desc: str = "cap-grp") -> tuple[int, list[str]]:
    res = grp_resource(v6)
    ok = 0
    fails: list[str] = []
    for nm in names:
        st, _ = raw_req(ctx, "POST", res, val=grp_val(nm, [member], v6=v6, desc=desc))
        if st in (200, 201, 202):
            ok += 1
        else:
            fails.append(f"{nm}:{st}")
    return ok, fails


# ── payload builders ───────────────────────────────────────────────────────


def v4_net(i: int) -> dict[str, str]:
    # 250 进制分解 → (a,b) 对唯一, 保证 1024 条不重复。
    return {"ipaddr": f"10.90.{i // 250}.{i % 250}", "mask": "32"}


def v6_net(i: int) -> dict[str, str]:
    return {"ipaddr": f"2001:db8:{i & 0xffff:04x}::", "mask": "64"}


def make_nets(n: int, v6: bool) -> list[dict[str, str]]:
    return [v6_net(i) if v6 else v4_net(i) for i in range(n)]


def obj_val(name: str, n: int, *, v6: bool, desc: str = "cap") -> dict[str, Any]:
    return {"name": name, "desc": desc, "type": 4, "ranges": [],
            "networks": make_nets(n, v6), "exclranges": [], "exclnetworks": []}


def grp_val(name: str, members: list[str], *, v6: bool, desc: str = "cap") -> dict[str, Any]:
    key = "ip6pools" if v6 else "ippools"
    return {"name": name, "desc": desc, key: members}


def obj_resource(v6: bool) -> str:
    return V6_OBJ if v6 else V4_OBJ


def grp_resource(v6: bool) -> str:
    return V6_GRP if v6 else V4_GRP


# ── standard checks ────────────────────────────────────────────────────────


def record_cap(ctx: CaseContext, result: CaseResult, *, label: str, status: int,
               expect_ok: bool, want: int, msg: str = "",
               err_needle: str | list[str] | None = None) -> None:
    """Record a create/update attempt at a capacity boundary as a check.

    err_needle: 拒绝路径若给出, 额外断言响应 errMsg 含任一关键词
      (设备实测: 「...容量超过限制,当前配置数量 {n}」, 关键词取「容量超过限制」)。
    """
    ok = (status in (200, 201, 202)) == expect_ok
    got = "ok" if status in (200, 201, 202) else f"rejected({status})"
    want_s = f"{want}+" if not expect_ok else f"<= {want}"
    detail = f"entries={want} → {got} (want {'ok' if expect_ok else 'reject'})"
    if not expect_ok and err_needle:
        needles = [err_needle] if isinstance(err_needle, str) else err_needle
        hit = any(n in msg for n in needles)
        ok = ok and hit
        detail += f" errmsg[{('hit' if hit else 'miss:' + repr(msg[:60]))}]"
    result.record(Check(name=label, ok=ok, detail=detail))


def verify_network_count(ctx: CaseContext, result: CaseResult, *, resource: str,
                         name: str, expect: int, label: str) -> None:
    r = requests.get(f"{ctx.base_url}{resource}?page=1&size=1&keywords={name}",
                     headers=raw_headers(ctx), verify=bool(ctx.verify_tls), timeout=20)
    try:
        vals = r.json().get("vals") or []
    except Exception:  # noqa: BLE001
        vals = []
    entry = next((e for e in vals if isinstance(e, dict) and e.get("name") == name), None)
    if entry is None:
        result.record(Check(name=label, ok=False, detail="object not found in verify"))
        return
    count = len(entry.get("networks") or [])
    result.record(Check(name=label, ok=count == expect, detail=f"networks={count} want {expect}"))


def verify_member_count(ctx: CaseContext, result: CaseResult, *, resource: str,
                        name: str, expect: int, label: str) -> None:
    """Verify a group's stored member count. v6 组读成员字段 ip6pools, v4 读 ippools。"""
    entry = group_find(ctx, resource, name)
    if entry is None:
        result.record(Check(name=label, ok=False, detail="group not found in verify"))
        return
    key = "ip6pools" if resource == V6_GRP else "ippools"
    count = len(entry.get(key) or [])
    result.record(Check(name=label, ok=count == expect, detail=f"members={count} want {expect}"))
