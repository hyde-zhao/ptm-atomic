"""P1-900102: 自定义服务起始与结束端口配置测试.

A single destination port is stored as an N-N range and a real start/end
range is stored as-is. Both must be delivered successfully and visible in the
REST entry (ranges[0].d_start / d_end).
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, _run_verify, SERVICE
from framework.results import CaseResult

TITLE = "P1-900102 自定义服务起始与结束端口配置"


def _dest_range(d_start: int, d_end: int) -> str:
    return f'[{{"proto":6,"s_start":0,"s_end":65535,"d_start":{d_start},"d_end":{d_end}}}]'


def run(ctx: CaseContext, result: CaseResult) -> None:
    # check1: start=80, end left empty -> stored as 80-80.
    n1 = unique_random(900102, "single")
    try:
        out = _run_create(ctx, SERVICE, name=n1, ranges=_dest_range(80, 80), desc="atc port single")
        result.record(op_succeeded(out, ctx=ctx, label="start-80-end-empty"))
        if ctx.execute and out.success:
            result.record(_verify_dports(ctx, n1, label="start-80-end-empty-verify", expected=("80", "80")))
    finally:
        if ctx.execute:
            result.record(op_succeeded(_run_delete(ctx, SERVICE, name=n1), ctx=ctx, label=f"cleanup:{n1}"))

    # check2: start=1000, end=2000 -> stored as 1000-2000.
    n2 = unique_random(900102, "range")
    try:
        out = _run_create(ctx, SERVICE, name=n2, ranges=_dest_range(1000, 2000), desc="atc port range")
        result.record(op_succeeded(out, ctx=ctx, label="start-1000-end-2000"))
        if ctx.execute and out.success:
            result.record(_verify_dports(ctx, n2, label="start-1000-end-2000-verify", expected=("1000", "2000")))
    finally:
        if ctx.execute:
            result.record(op_succeeded(_run_delete(ctx, SERVICE, name=n2), ctx=ctx, label=f"cleanup:{n2}"))


def _verify_dports(ctx: CaseContext, name: str, *, label: str, expected: tuple[str, str]) -> Check:
    vout = _run_verify(ctx, SERVICE, name=name)
    if not vout.success:
        return Check(name=f"{label}-query", ok=False, detail=f"verify failed: {vout.err_msg()}")
    hits = [e for e in _walk_dicts(vout.response()) if isinstance(e, dict) and str(e.get("name", "")) == name]
    if not hits:
        return Check(name=label, ok=False, detail="object not found in REST verify")
    ranges = hits[0].get("ranges")
    if not isinstance(ranges, list) or not ranges:
        return Check(name=label, ok=False, detail=f"no ranges in entry: {hits[0]}")
    first = ranges[0]
    got = (str(first.get("d_start")), str(first.get("d_end")))
    ok = got == expected
    return Check(name=label, ok=ok, detail=f"d_start/d_end={got} expected={expected}")


def _walk_dicts(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)
