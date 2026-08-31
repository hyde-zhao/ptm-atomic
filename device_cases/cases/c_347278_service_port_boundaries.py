"""P1-347278: 自定义服务端口边界值.

The device must accept and store every valid edge combination: full range
0-65535, single-port 0-0, single-port 65535-65535. Each is created, verified,
then cleaned up. (Empty-end-port intent is expressed as start == end at the
REST layer, mirroring 347276.)
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, _run_verify, SERVICE
from framework.results import CaseResult

TITLE = "P1-347278 自定义服务端口边界值"

EDGES = (
    ("full", 0, 65535, "0", "65535"),
    ("zero", 0, 0, "0", "0"),
    ("max", 65535, 65535, "65535", "65535"),
)


def run(ctx: CaseContext, result: CaseResult) -> None:
    for tag, s, e, expect_s, expect_e in EDGES:
        name = unique_random(347278, tag)
        try:
            rng = f'[{{"proto":6,"s_start":{s},"s_end":{e},"d_start":0,"d_end":65535}}]'
            out = _run_create(ctx, SERVICE, name=name, ranges=rng, desc=f"atc {tag}")
            result.record(op_succeeded(out, ctx=ctx, label=f"edge-{tag}-created"))
            if ctx.execute and out.success:
                result.record(_verify_range(ctx, name, label=f"edge-{tag}-verify",
                                            expected=(expect_s, expect_e)))
        finally:
            if ctx.execute:
                result.record(op_succeeded(_run_delete(ctx, SERVICE, name=name),
                                           ctx=ctx, label=f"edge-{tag}-cleanup"))


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
