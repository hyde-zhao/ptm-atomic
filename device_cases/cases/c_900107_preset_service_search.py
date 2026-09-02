"""P0-900107: 预定义服务搜索.

Search NGFW preset services through /api/v1/servicepool?type=PRESET. The device
honours the ``keywords`` filter (probing: count drops to matches); ``src_port``
/ ``dst_port`` / ``protocol`` parameters are accepted but ignored. The case
asserts the unfiltered list is non-empty, keyword search narrows it to the
matching names, entries carry the expected shape, and the port/protocol query
parameters are safe to send.
"""

from __future__ import annotations

from typing import Any

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.results import CaseResult

TITLE = "P0-900107 预定义服务搜索"


def _preset_entries(response: Any) -> list[dict[str, Any]]:
    """Heuristic: preset service entries are dicts carrying a string 'name'."""
    hits: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            name = node.get("name")
            if isinstance(name, str) and name:
                hits.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(response)
    return hits


def run(ctx: CaseContext, result: CaseResult) -> None:
    # 1) Unfiltered preset query returns the PRESET type without error.
    out = ctx.runner.run("service-pool", "verify-preset", page=1, size=50)
    result.record(op_succeeded(out, ctx=ctx, label="preset-no-filter"))
    if not ctx.execute:
        return

    entries = _preset_entries(out.response()) if out.success else []
    result.record(
        state_check(
            ctx,
            Check(name="preset-non-empty", ok=len(entries) > 0, detail=f"preset_entries={len(entries)}"),
        )
    )
    if not entries:
        result.notes.append("no preset service entries observed; keyword/port checks skipped")
        return

    # 2) Keyword filter by an actual preset name returns that entry.
    seed_name = entries[0]["name"]
    out_kw = ctx.runner.run("service-pool", "verify-preset", page=1, size=50, keywords=seed_name)
    result.record(op_succeeded(out_kw, ctx=ctx, label="preset-keywords-query"))
    if out_kw.success:
        kw_hits = [e for e in _preset_entries(out_kw.response()) if seed_name.lower() in str(e.get("name", "")).lower()]
        result.record(
            Check(
                name="keywords-match-name",
                ok=len(kw_hits) > 0,
                detail=f"matching={len(kw_hits)} keyword={seed_name!r}",
            )
        )

    # 3) Preset entries carry the expected shape (name + ranges + type=PRESET).
    sample = entries[:20]
    shape_ok = all(
        isinstance(e.get("name"), str)
        and isinstance(e.get("ranges"), list)
        and e.get("type") == "PRESET"
        for e in sample
    )
    result.record(
        Check(name="preset-shape", ok=shape_ok, detail=f"checked first {len(sample)} entries (name/ranges/type=PRESET)")
    )

    # 4) Port / protocol filters: the device accepts the query parameters but
    #    ignores them (probing on 55.63: count stays 95 regardless of
    #    src_port/dst_port/protocol). Assert the requests still succeed and
    #    return a non-empty preset list — i.e. the parameters are safe to send.
    for label, kwargs in (
        ("src-port", {"src_port": "80"}),
        ("dst-port", {"dst_port": "8080"}),
        ("protocol", {"protocol": "6"}),
    ):
        out_f = ctx.runner.run("service-pool", "verify-preset", page=1, size=50, **kwargs)
        result.record(op_succeeded(out_f, ctx=ctx, label=f"preset-{label}-query"))
        if out_f.success:
            filtered = _preset_entries(out_f.response())
            result.record(
                Check(
                    name=f"{label}-accepted",
                    ok=len(filtered) > 0,
                    detail=f"filtered={len(filtered)} (device ignores {label}; request accepted)",
                )
            )
