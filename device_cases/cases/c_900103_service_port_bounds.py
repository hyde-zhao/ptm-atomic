"""P1-900103: 自定义服务端口边界值与逻辑校验.

Service ranges accept 0-65535 and 0-0; reject start > end; reject values out
of range. Each attempt uses its own object name and is cleaned up afterwards.
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, _run_verify, SERVICE
from framework.results import CaseResult

TITLE = "P1-900103 自定义服务端口边界与逻辑校验"


def _range(proto: int, s_start: int, s_end: int) -> str:
    return f'[{{"proto":{proto},"s_start":{s_start},"s_end":{s_end},"d_start":0,"d_end":65535}}]'


def run(ctx: CaseContext, result: CaseResult) -> None:
    # check1: 0-65535 is a valid full range.
    n1 = unique_random(900103, "full")
    created = []
    try:
        out = _run_create(ctx, SERVICE, name=n1, ranges=_range(6, 0, 65535), desc="atc full")
        result.record(op_succeeded(out, ctx=ctx, label="range-0-65535"))
        if ctx.execute and out.success:
            created.append(n1)
            result.record(_verify_ranges(ctx, n1, label="range-0-65535-verify", expected=("0", "65535")))

        # check2: 0-0 (single port 0) is valid.
        n2 = unique_random(900103, "zero")
        out = _run_create(ctx, SERVICE, name=n2, ranges=_range(6, 0, 0), desc="atc zero")
        result.record(op_succeeded(out, ctx=ctx, label="range-0-0"))
        if ctx.execute and out.success:
            created.append(n2)
            result.record(_verify_ranges(ctx, n2, label="range-0-0-verify", expected=("0", "0")))
    finally:
        for name in created:
            result.record(op_succeeded(_run_delete(ctx, SERVICE, name=name), ctx=ctx, label=f"cleanup:{name}"))

    # check3: start > end is rejected.
    n3 = unique_random(900103, "inverted")
    out = _run_create(ctx, SERVICE, name=n3, ranges=_range(6, 3000, 2000), desc="atc inverted")
    result.record(op_rejected(out, ctx=ctx, label="range-start-gt-end"))

    # check4: out-of-range port and non-numeric protocol are rejected.
    n4 = unique_random(900103, "oob")
    out = _run_create(ctx, SERVICE, name=n4, ranges=_range(6, 70000, 70001), desc="atc oob")
    result.record(op_rejected(out, ctx=ctx, label="range-out-of-bounds"))

    n5 = unique_random(900103, "badproto")
    out = _run_create(ctx, SERVICE, name=n5, ranges='[{"proto":"TCP","s_start":0,"s_end":80,"d_start":0,"d_end":80}]', desc="atc badproto")
    result.record(op_rejected(out, ctx=ctx, label="range-non-numeric-proto"))


def _verify_ranges(ctx: CaseContext, name: str, *, label: str, expected: tuple[str, str]) -> Check:
    """Fetch the object and check the s_start/s_end of its first range."""
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
    return Check(name=label, ok=ok, detail=f"s_start/s_end={got} expected={expected}")


def _walk_dicts(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)
