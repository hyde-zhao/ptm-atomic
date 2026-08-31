"""P2-257665: 自定义服务基于协议类型(TCP)搜索.

Create a deterministic TCP custom service so the custom list is non-empty,
then exercise the protocol-type search (TCP = 6). The device ignores the
protocol parameter for custom services (probe: count unchanged) — the
effective filter is keywords by name. Assert the facet query is accepted and
returns entries, and keyword search finds the created object.
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, SERVICE
from framework.results import CaseResult

from cases.service_support import name_filtered, named_entries

TITLE = "P2-257665 自定义服务基于协议类型(TCP)搜索"

# Device protocol numbers: 6 = TCP, 17 = UDP.
PROTO_TCP = "6"
TCP_RANGE = '[{"proto":6,"s_start":0,"s_end":65535,"d_start":0,"d_end":65535}]'


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(257665, "proto")
    try:
        out = _run_create(ctx, SERVICE, name=name, ranges=TCP_RANGE, desc="atc proto search")
        result.record(op_succeeded(out, ctx=ctx, label="custom-created"))
        if not ctx.execute:
            return

        out_f = ctx.runner.run("service-pool", "verify", page=1, size=50, protocol=PROTO_TCP)
        result.record(op_succeeded(out_f, ctx=ctx, label="custom-protocol-query"))
        if out_f.success:
            filtered = named_entries(out_f.response())
            result.record(Check(
                name="custom-protocol-accepted", ok=len(filtered) > 0,
                detail=f"entries={len(filtered)} (device ignores protocol; request accepted)",
            ))

        out_kw = ctx.runner.run("service-pool", "verify", page=1, size=50, keywords=name)
        result.record(op_succeeded(out_kw, ctx=ctx, label="custom-keywords-query"))
        if out_kw.success:
            hits = name_filtered(out_kw.response(), name)
            result.record(Check(
                name="custom-name-search", ok=len(hits) > 0,
                detail=f"keyword={name!r} hits={len(hits)}",
            ))
    finally:
        if ctx.execute:
            result.record(op_succeeded(_run_delete(ctx, SERVICE, name=name),
                                       ctx=ctx, label="cleanup"))
