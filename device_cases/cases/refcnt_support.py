"""Shared helpers for the group-reference REFCNT cases (18147/18148/18161/18162).

Probe-confirmed device semantics (probe31/probe32 on 55.63, 2026-09-02):
  * An ipv4/ipv6 single address object referenced by an address GROUP is a real
    reference: its ``refcnt`` field (visible in the /api/v1/{ippool,ip6pool}
    list entry) increments 0 -> 1 (one group) -> 2 (two groups) and back to 0
    once the groups are removed / the member is replaced.
  * Deleting a referenced object -> 400 「{name}被引用无法被删除」; a failed
    delete leaves refcnt unchanged.
  * Dereference = PUT the group with a different member set (groups reject an
    empty member list, mirroring the service group). After the reference is
    gone the object deletes (200).
  * xlsx check2 references via 地址组/策略/NAT/带宽/策略路由; the address
    GROUP is the object-level reference vehicle, so these cases exercise it
    exactly as xlsx lists first. Policy/bandwidth/policy-route references stay
    in the data-plane domain (documented-skip).

Helpers mirror c_256060 (service ref/unref) so each case is a thin shell.
"""
from __future__ import annotations

from typing import Any

import requests

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.addr_cap_support import (
    V4_GRP,
    V4_OBJ,
    V6_GRP,
    V6_OBJ,
    grp_val,
    obj_resource,
    grp_resource,
    obj_val,
    raw_headers,
    raw_req,
)

_OK = (200, 201, 202)
_ERR_REFERENCED = "被引用无法被删除"


def _entry(ctx: CaseContext, resource: str, name: str) -> dict[str, Any] | None:
    r = requests.get(f"https://{ctx.device}{resource}?page=1&size=200&keywords={name}",
                     headers=raw_headers(ctx), verify=bool(ctx.verify_tls), timeout=20)
    try:
        vals = r.json().get("vals") or []
    except Exception:  # noqa: BLE001
        vals = []
    return next((e for e in vals if isinstance(e, dict) and e.get("name") == name), None)


def _refcnt(ctx: CaseContext, resource: str, name: str) -> int | None:
    e = _entry(ctx, resource, name)
    if e is None:
        return None
    try:
        return int(e.get("refcnt", e.get("refCnt", -1)))
    except (TypeError, ValueError):
        return None


def addr_unref(ctx: CaseContext, result: CaseResult, *, case_id: int, v6: bool) -> None:
    """Create A/B, reference A from a group, delete A -> blocked, deref, delete A -> ok."""
    obj = obj_resource(v6)
    grp = grp_resource(v6)
    base = unique_random(case_id, "u")
    a = f"{base}-a"
    b = f"{base}-b"
    g = unique_random(case_id, "g")

    def _create(name: str, label: str) -> bool:
        st, msg = raw_req(ctx, "POST", obj, val=obj_val(name, 1, v6=v6, desc="ref"))
        result.record(Check(name=label, ok=st in _OK, detail=f"create {name} → {st} ({msg or 'ok'})"))
        return st in _OK

    try:
        if not _create(a, "create-object-a"):
            return
        if not _create(b, "create-helper-object-b"):
            return

        # reference A from a group
        st, msg = raw_req(ctx, "POST", grp, val=grp_val(g, [a], v6=v6, desc="ref"))
        result.record(Check(name="create-group-ref", ok=st in _OK,
                            detail=f"group {g}=[{a}] → {st} ({msg or 'ok'})"))
        entry = _entry(ctx, grp, g)
        key = "ip6pools" if v6 else "ippools"
        members = entry.get(key) or [] if entry else []
        result.record(Check(name="group-member-stored", ok=entry is not None and a in members,
                            detail=f"{key} contains {a}: {members}"))

        # delete referenced A -> rejected
        st, msg = raw_req(ctx, "DELETE", obj, ident=a)
        hit = _ERR_REFERENCED in msg
        result.record(Check(name="delete-referenced-reject",
                            ok=st not in _OK and hit,
                            detail=f"delete referenced {a} → {st} ({msg or ''})"
                                   + ("" if hit else " errmsg-miss")))
        result.record(Check(name="still-present-after-reject",
                            ok=_entry(ctx, obj, a) is not None,
                            detail="object still present after rejected delete"))

        # deref: PUT group to [b]
        st, msg = raw_req(ctx, "PUT", grp, ident=g, val=grp_val(g, [b], v6=v6, desc="unref"))
        result.record(Check(name="unref-update-group", ok=st in _OK,
                            detail=f"update {g}=[{b}] → {st} ({msg or 'ok'})"))
        if st in _OK:
            st, msg = raw_req(ctx, "DELETE", obj, ident=a)
            result.record(Check(name="delete-after-unref-ok", ok=st in _OK,
                                detail=f"delete {a} after unref → {st} ({msg or 'ok'})"))
            result.record(Check(name="gone-after-delete", ok=_entry(ctx, obj, a) is None,
                                detail=f"{a} gone from query"))
    finally:
        raw_req(ctx, "DELETE", grp, ident=g)
        raw_req(ctx, "DELETE", obj, ident=a)
        raw_req(ctx, "DELETE", obj, ident=b)


def addr_count(ctx: CaseContext, result: CaseResult, *, case_id: int, v6: bool) -> None:
    """Numeric refcnt consistency: 0 -> 1 (one group) -> 2 (two groups), delete
    blocked while referenced (refcnt unchanged), cleanup back to 0."""
    obj = obj_resource(v6)
    grp = grp_resource(v6)
    base = unique_random(case_id, "c")
    a = f"{base}-a"
    g1 = unique_random(case_id, "g1")
    g2 = unique_random(case_id, "g2")

    def rec_refcnt(label: str, want: int | None) -> None:
        got = _refcnt(ctx, obj, a)
        result.record(Check(name=label, ok=got == want,
                            detail=f"{a} refcnt={got} want={want}"))

    try:
        st, msg = raw_req(ctx, "POST", obj, val=obj_val(a, 1, v6=v6, desc="refcnt"))
        result.record(Check(name="create-object", ok=st in _OK,
                            detail=f"create {a} → {st} ({msg or 'ok'})"))
        if st not in _OK:
            return
        rec_refcnt("refcnt-baseline", 0)

        # reference from one group -> refcnt 1
        st, msg = raw_req(ctx, "POST", grp, val=grp_val(g1, [a], v6=v6, desc="ref"))
        result.record(Check(name="group1-ref", ok=st in _OK,
                            detail=f"group {g1}=[{a}] → {st} ({msg or 'ok'})"))
        rec_refcnt("refcnt-one-group", 1)

        # second group -> refcnt 2
        st, msg = raw_req(ctx, "POST", grp, val=grp_val(g2, [a], v6=v6, desc="ref"))
        result.record(Check(name="group2-ref", ok=st in _OK,
                            detail=f"group {g2}=[{a}] → {st} ({msg or 'ok'})"))
        rec_refcnt("refcnt-two-groups", 2)

        # delete while double-referenced -> rejected, refcnt unchanged
        st, msg = raw_req(ctx, "DELETE", obj, ident=a)
        hit = _ERR_REFERENCED in msg
        result.record(Check(name="delete-double-referenced",
                            ok=st not in _OK and hit,
                            detail=f"delete referenced {a} → {st} ({msg or ''})"))
        rec_refcnt("refcnt-unchanged-after-fail", 2)

        # release both references -> refcnt 0
        for g in (g1, g2):
            raw_req(ctx, "DELETE", grp, ident=g)
        rec_refcnt("refcnt-after-unref", 0)

        # now deletable
        st, msg = raw_req(ctx, "DELETE", obj, ident=a)
        result.record(Check(name="delete-after-full-unref", ok=st in _OK,
                            detail=f"delete {a} after all refs released → {st} ({msg or 'ok'})"))
    finally:
        raw_req(ctx, "DELETE", grp, ident=g1)
        raw_req(ctx, "DELETE", grp, ident=g2)
        raw_req(ctx, "DELETE", obj, ident=a)
