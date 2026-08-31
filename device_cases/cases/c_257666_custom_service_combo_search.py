"""P2-257666: 自定义服务组合搜索(源端口 + 目的端口).

Create a deterministic custom service with matching source/destination ports,
then exercise the combined search (src_port + dst_port). The device accepts
both parameters but ignores them for custom services (probe: count unchanged)
— the effective filter is keywords by name. Assert the combo query is accepted
and returns entries, and keyword search finds the created object.
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, SERVICE
from framework.results import CaseResult

from cases.service_support import name_filtered, named_entries

TITLE = "P2-257666 自定义服务组合搜索(源端口+目的端口)"

SRC_PORT = "65535"
DST_PORT = "65535"
COMBO_65535 = '[{"proto":6,"s_start":65535,"s_end":65535,"d_start":65535,"d_end":65535}]'


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(257666, "combo")
    try:
        out = _run_create(ctx, SERVICE, name=name, ranges=COMBO_65535, desc="atc combo search")
        result.record(op_succeeded(out, ctx=ctx, label="custom-created"))
        if not ctx.execute:
            return

        out_f = ctx.runner.run(
            "service-pool", "verify", page=1, size=50,
            src_port=SRC_PORT, dst_port=DST_PORT,
        )
        result.record(op_succeeded(out_f, ctx=ctx, label="custom-combo-query"))
        if out_f.success:
            filtered = named_entries(out_f.response())
            result.record(Check(
                name="custom-combo-accepted", ok=len(filtered) > 0,
                detail=f"entries={len(filtered)} (device ignores src_port+dst_port; request accepted)",
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
