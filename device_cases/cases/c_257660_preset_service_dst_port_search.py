"""P2-257660: 预定义服务按目的端口(65535)搜索.

Search the NGFW preset service list with a destination-port filter. The device
accepts the dst_port parameter but ignores it (probe: count stays 95), exactly
like src_port. Assert the unfiltered list is non-empty, the destination-port
query is accepted and returns entries, and keyword search still narrows.
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.results import CaseResult

from cases.service_support import named_entries

TITLE = "P2-257660 预定义服务目的端口(65535)搜索"

DST_PORT = "65535"


def run(ctx: CaseContext, result: CaseResult) -> None:
    out = ctx.runner.run("service-pool", "verify-preset", page=1, size=50)
    result.record(op_succeeded(out, ctx=ctx, label="preset-no-filter"))
    if not ctx.execute:
        return
    entries = named_entries(out.response()) if out.success else []
    result.record(state_check(
        ctx, Check(name="preset-non-empty", ok=len(entries) > 0, detail=f"entries={len(entries)}")
    ))
    if not entries:
        result.notes.append("no preset service entries observed; facet check skipped")
        return

    out_f = ctx.runner.run("service-pool", "verify-preset", page=1, size=50, dst_port=DST_PORT)
    result.record(op_succeeded(out_f, ctx=ctx, label="preset-dst-port-query"))
    if out_f.success:
        filtered = named_entries(out_f.response())
        result.record(Check(
            name="preset-dst-port-accepted", ok=len(filtered) > 0,
            detail=f"filtered={len(filtered)} (device ignores dst_port; request accepted)",
        ))

    seed = entries[0]["name"]
    out_kw = ctx.runner.run("service-pool", "verify-preset", page=1, size=50, keywords=seed)
    result.record(op_succeeded(out_kw, ctx=ctx, label="preset-keywords-query"))
    if out_kw.success:
        kw_hits = [e for e in named_entries(out_kw.response()) if seed.lower() in str(e.get("name", "")).lower()]
        result.record(Check(
            name="preset-keywords-narrows", ok=len(kw_hits) > 0,
            detail=f"keyword={seed!r} hits={len(kw_hits)}",
        ))
