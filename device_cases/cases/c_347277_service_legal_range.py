"""P2-347277: 自定义服务合法范围填写(1000-2000).

A service with both start and end ports filled within the valid range stores
as-is. Assert create success and that the REST verify reflects 1000-2000.
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, _run_verify, SERVICE
from framework.results import CaseResult

TITLE = "P2-347277 自定义服务合法范围(1000-2000)"

RANGE_1000_2000 = '[{"proto":6,"s_start":1000,"s_end":2000,"d_start":0,"d_end":65535}]'


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(347277, "svc")
    try:
        out = _run_create(ctx, SERVICE, name=name, ranges=RANGE_1000_2000, desc="atc legal range")
        result.record(op_succeeded(out, ctx=ctx, label="legal-range-created"))
        if ctx.execute and out.success:
            result.record(_verify_range(ctx, name, label="legal-range-verify", expected=("1000", "2000")))
    finally:
        if ctx.execute:
            result.record(op_succeeded(_run_delete(ctx, SERVICE, name=name), ctx=ctx, label="cleanup"))


def _verify_range(ctx: CaseContext, name: str, *, label: str, expected: tuple[str, str]) -> Check:
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
    got = (str(first.get("s_start")), str(first.get("s_end")))
    ok = got == expected
    return state_check(ctx, Check(name=label, ok=ok, detail=f"s_start/s_end={got} expected={expected}"))


def _walk_dicts(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)
