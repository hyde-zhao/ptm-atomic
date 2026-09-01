"""Shared helpers for the address-object exclude matrix cases
(263447-263513, 332064-332181, 900001-900027, 347295/347311).

Probe-confirmed device semantics (55.63, probe21):
  * partial-overlap / disjoint / subnet-partial excludes → ACCEPT (200).
  * full-overlap exclude(排除地址覆盖全部基础地址)→ 400 eNoUsableNetworks
    「无可用地址」(v4/v6 均如此)。
  * IP 范围字段用 {"start":ip,"end":ip}, round-trip 正常。
  * 对象 val 必须含 ranges/exclranges 键(空数组 ok)。

REST 资源(同 addr_cap_support):
  IPv4 对象 /api/v1/ippool        IPv6 对象 /api/v1/ip6pool
  IPv4 组   /api/v1/ippool/group  IPv6 组   /api/v1/ip6pool/group
"""

from __future__ import annotations

from typing import Any

from framework.checks import Check
from framework.context import CaseContext
from framework.results import CaseResult

from cases.addr_cap_support import grp_resource, grp_val, group_find, raw_req

OK = (200, 201, 202)


def n(ip: str, mask: int) -> list[dict[str, str]]:
    """单条网络条目(networks / exclnetworks 的元素)。"""
    return [{"ipaddr": ip, "mask": str(mask)}]


def rng(start: str, end: str) -> list[dict[str, str]]:
    """单条范围条目(ranges / exclranges 的元素)。"""
    return [{"start": start, "end": end}]


def obj_resource(v6: bool) -> str:
    return "/api/v1/ip6pool" if v6 else "/api/v1/ippool"


def obj_val(name: str, *, networks: list | None = None, ranges: list | None = None,
            exclnetworks: list | None = None, exclranges: list | None = None,
            desc: str = "atc-excl") -> dict[str, Any]:
    return {"name": name, "desc": desc, "type": 4,
            "ranges": ranges or [], "networks": networks or [],
            "exclranges": exclranges or [], "exclnetworks": exclnetworks or []}


def _rec(ctx: CaseContext, result: CaseResult, *, label: str, status: int,
         expect_ok: bool, msg: str, err_needle: str | list[str] | None = None) -> None:
    """Record a create/update attempt as a check.

    err_needle: 拒绝路径若给出, 额外断言响应 errMsg 含任一关键词
      (设备实测完全重叠排除 → 「无可用地址」)。"""
    ok = (status in OK) == expect_ok
    got = "ok" if status in OK else f"rejected({status})"
    detail = f"→ {got} (want {'ok' if expect_ok else 'reject'})"
    if not expect_ok and err_needle:
        needles = [err_needle] if isinstance(err_needle, str) else err_needle
        hit = any(x in msg for x in needles)
        ok = ok and hit
        detail += f" errmsg[{'hit' if hit else 'miss:' + repr(msg[:60])}]"
    result.record(Check(name=label, ok=ok, detail=detail))


def excl_create(ctx: CaseContext, result: CaseResult, *, label: str, v6: bool, name: str,
                networks: list | None = None, ranges: list | None = None,
                exclnetworks: list | None = None, exclranges: list | None = None,
                desc: str = "atc-excl", expect_ok: bool = True,
                err_needle: str | list[str] | None = None) -> bool:
    """POST 地址对象(含排除)并断言创建/拒绝。返回是否创建成功。"""
    st, msg = raw_req(ctx, "POST", obj_resource(v6),
                      val=obj_val(name, networks=networks, ranges=ranges,
                                  exclnetworks=exclnetworks, exclranges=exclranges,
                                  desc=desc))
    _rec(ctx, result, label=label, status=st, expect_ok=expect_ok, msg=msg,
         err_needle=err_needle)
    return st in OK


def excl_update(ctx: CaseContext, result: CaseResult, *, label: str, v6: bool, name: str,
                newname: str | None = None, networks: list | None = None,
                ranges: list | None = None, exclnetworks: list | None = None,
                exclranges: list | None = None, desc: str = "atc-excl",
                expect_ok: bool = True,
                err_needle: str | list[str] | None = None) -> bool:
    """PUT ?id=<name> 更新地址对象。newname 非空时尝试原地改名。"""
    st, msg = raw_req(ctx, "PUT", obj_resource(v6), ident=name,
                      val=obj_val(newname or name, networks=networks, ranges=ranges,
                                  exclnetworks=exclnetworks, exclranges=exclranges,
                                  desc=desc))
    _rec(ctx, result, label=label, status=st, expect_ok=expect_ok, msg=msg,
         err_needle=err_needle)
    return st in OK


def excl_stored(ctx: CaseContext, result: CaseResult, *, label: str, v6: bool, name: str,
                networks: list | None = None, ranges: list | None = None,
                exclnetworks: list | None = None, exclranges: list | None = None) -> None:
    """GET 校验对象落库的基础/排除字段(按条目数比较)。"""
    entry = group_find(ctx, obj_resource(v6), name)
    if entry is None:
        result.record(Check(name=label, ok=False, detail="object not found in verify"))
        return
    want = {"networks": networks, "ranges": ranges,
            "exclnetworks": exclnetworks, "exclranges": exclranges}
    got, bad = [], []
    for key, w in want.items():
        if w is None:
            continue
        count = len(entry.get(key) or [])
        got.append(f"{key}={count}")
        if count != len(w):
            bad.append(f"{key}={count}!={len(w)}")
    detail = " ".join(got) + f" name={name!r}"
    if bad:
        detail += " BAD:" + ",".join(bad)
    result.record(Check(name=label, ok=not bad, detail=detail))


def grp_create(ctx: CaseContext, result: CaseResult, *, label: str, v6: bool,
               name: str, members: list[str], expect_ok: bool = True) -> bool:
    st, msg = raw_req(ctx, "POST", grp_resource(v6),
                      val=grp_val(name, members, v6=v6, desc="atc-excl"))
    _rec(ctx, result, label=label, status=st, expect_ok=expect_ok, msg=msg)
    return st in OK


def grp_members(ctx: CaseContext, v6: bool, name: str) -> list[str] | None:
    entry = group_find(ctx, grp_resource(v6), name)
    if entry is None:
        return None
    key = "ip6pools" if v6 else "ippools"
    return list(entry.get(key) or [])
