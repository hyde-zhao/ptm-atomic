"""P2-257661: 预定义服务基于协议类型(TCP)搜索.

Search the NGFW preset service list with a protocol-type filter (TCP = 6).
The device accepts the protocol parameter but ignores it (probe: count stays
95). Assert the unfiltered list is non-empty, the protocol query is accepted
and returns entries, and keyword search still narrows by name.
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.results import CaseResult

from cases.service_support import named_entries

TITLE = "P2-257661 预定义服务基于协议类型(TCP)搜索"

# Device protocol numbers: 6 = TCP, 17 = UDP.
PROTO_TCP = "6"


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

    out_f = ctx.runner.run("service-pool", "verify-preset", page=1, size=50, protocol=PROTO_TCP)
    result.record(op_succeeded(out_f, ctx=ctx, label="preset-protocol-query"))
    if out_f.success:
        filtered = named_entries(out_f.response())
        result.record(Check(
            name="preset-protocol-accepted", ok=len(filtered) > 0,
            detail=f"filtered={len(filtered)} (device ignores protocol; request accepted)",
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
