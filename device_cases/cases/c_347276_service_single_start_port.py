"""P2-347276: 自定义服务仅配置起始端口,结束端口留空.

Web UI lets the operator set only a start port and leave the end port empty;
the device normalises that to a single-port range "80-80". At the REST layer
there is no "empty end port" concept — sending a null s_end is rejected — so
the single-port intent is expressed as s_start == s_end == 80, and the case
asserts the stored range normalises to 80-80.
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, _run_verify, SERVICE
from framework.results import CaseResult

TITLE = "P2-347276 自定义服务仅起始端口(80-80 归一)"

SINGLE_80 = '[{"proto":6,"s_start":80,"s_end":80,"d_start":0,"d_end":65535}]'
EMPTY_END = '[{"proto":6,"s_start":80,"d_start":0,"d_end":65535}]'


def run(ctx: CaseContext, result: CaseResult) -> None:
    # check1: a null end port is not a REST concept -> rejected.
    n0 = unique_random(347276, "nullend")
    out = _run_create(ctx, SERVICE, name=n0, ranges=EMPTY_END, desc="atc nullend")
    result.record(op_rejected(out, ctx=ctx, label="null-end-rejected"))

    # check2: single port expressed as s_start==s_end==80 stores 80-80.
    n1 = unique_random(347276, "one")
    out = _run_create(ctx, SERVICE, name=n1, ranges=SINGLE_80, desc="atc oneport")
    result.record(op_succeeded(out, ctx=ctx, label="single-port-80-created"))
    if ctx.execute and out.success:
        result.record(_verify_range(ctx, n1, label="single-port-80-verify", expected=("80", "80")))
        result.record(op_succeeded(_run_delete(ctx, SERVICE, name=n1), ctx=ctx, label="cleanup:one"))


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
