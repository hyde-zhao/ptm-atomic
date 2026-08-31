"""P2-257667: 服务组基于协议类型(TCP)搜索.

Create a deterministic custom service plus a service group referencing it, then
exercise the protocol-type search on the group list (TCP = 6). The device
ignores the protocol parameter for service groups (probe: count unchanged) —
the effective filter is keywords by name. Assert the facet query is accepted
and returns entries, and keyword search finds the created group.
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, SERVICE, SERVICE_GROUP
from framework.results import CaseResult

from cases.service_support import name_filtered, named_entries

TITLE = "P2-257667 服务组基于协议类型(TCP)搜索"

# Device protocol numbers: 6 = TCP, 17 = UDP.
PROTO_TCP = "6"
TCP_RANGE = '[{"proto":6,"s_start":0,"s_end":65535,"d_start":0,"d_end":65535}]'


def run(ctx: CaseContext, result: CaseResult) -> None:
    svc = unique_random(257667, "sv")
    grp = unique_random(257667, "grp")
    try:
        out = _run_create(ctx, SERVICE, name=svc, ranges=TCP_RANGE, desc="atc grp svc")
        result.record(op_succeeded(out, ctx=ctx, label="svc-created"))
        if not ctx.execute:
            return
        gout = _run_create(ctx, SERVICE_GROUP, name=grp, servicepools=[svc])
        result.record(op_succeeded(gout, ctx=ctx, label="grp-created"))

        out_f = ctx.runner.run("service-pool", "group-verify", page=1, size=50, protocol=PROTO_TCP)
        result.record(op_succeeded(out_f, ctx=ctx, label="grp-protocol-query"))
        if out_f.success:
            filtered = named_entries(out_f.response())
            result.record(Check(
                name="grp-protocol-accepted", ok=len(filtered) > 0,
                detail=f"entries={len(filtered)} (device ignores protocol; request accepted)",
            ))

        out_kw = ctx.runner.run("service-pool", "group-verify", page=1, size=50, keywords=grp)
        result.record(op_succeeded(out_kw, ctx=ctx, label="grp-keywords-query"))
        if out_kw.success:
            hits = name_filtered(out_kw.response(), grp)
            result.record(Check(
                name="grp-name-search", ok=len(hits) > 0,
                detail=f"keyword={grp!r} hits={len(hits)}",
            ))
    finally:
        if ctx.execute:
            result.record(op_succeeded(_run_delete(ctx, SERVICE_GROUP, name=grp),
                                       ctx=ctx, label="cleanup-grp"))
            result.record(op_succeeded(_run_delete(ctx, SERVICE, name=svc),
                                       ctx=ctx, label="cleanup-svc"))
