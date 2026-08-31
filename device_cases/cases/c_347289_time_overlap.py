"""P2-347289: 单对象内时间段重叠的处理逻辑.

A oneshot time object carrying two overlapping ranges (09:00-11:00 and
10:00-12:00) must be accepted and stored as-is — the device unions the two
segments at match time. The CLI builder emits a single quantum, so the two
overlapping segments are passed through --payload-json (the escape hatch
documented for multi-segment time objects). The case asserts the create
succeeds and the verify response reflects both segments.

The clock-walk steps (策略持续生效 at 10:30 / 11:30 / 12:01) are data-plane
coupling and are not asserted here.
"""

from __future__ import annotations

import json

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, _run_verify, TIME
from framework.results import CaseResult

TITLE = "P2-347289 单对象内时间段重叠处理"

# Two overlapping one-shot ranges; a single timequantum start/end cannot
# express both, so the complete payload is passed through --payload-json.
def _overlap_payload(name: str) -> str:
    return json.dumps(
        {
            "val": {
                "name": name,
                "scheduletype": "oneshot",
                "timequantum": [
                    {"starttime": {"time": "2026-08-31 09:00:00"},
                     "endtime": {"time": "2026-08-31 11:00:00"}},
                    {"starttime": {"time": "2026-08-31 10:00:00"},
                     "endtime": {"time": "2026-08-31 12:00:00"}},
                ],
            }
        }
    )


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(347289, "to")
    try:
        out = _run_create(ctx, TIME, name=name, payload_json=_overlap_payload(name))
        result.record(op_succeeded(out, ctx=ctx, label="overlap-created"))
        if ctx.execute and out.success:
            result.record(_verify_overlap(ctx, name))
    finally:
        if ctx.execute:
            result.record(op_succeeded(_run_delete(ctx, TIME, name=name), ctx=ctx, label="cleanup"))


def _verify_overlap(ctx: CaseContext, name: str) -> Check:
    """Both overlapping segments must be present in the stored timequantum."""
    vout = _run_verify(ctx, TIME, name=name)
    if not vout.success:
        return Check(name="overlap-verify-query", ok=False, detail=f"verify failed: {vout.err_msg()}")
    hits = [e for e in _walk_dicts(vout.response()) if isinstance(e, dict) and str(e.get("name", "")) == name]
    if not hits:
        return Check(name="overlap-verify-entry", ok=False, detail="object not found in REST verify")
    quantum = hits[0].get("timequantum")
    if not isinstance(quantum, list):
        return Check(name="overlap-verify-quantum", ok=False,
                     detail=f"no timequantum list in entry: {hits[0]}")
    starts = [q.get("starttime", {}).get("time", "") for q in quantum if isinstance(q, dict)]
    expect = {"2026-08-31 09:00:00", "2026-08-31 10:00:00"}
    ok = expect.issubset(set(starts))
    return state_check(
        ctx,
        Check(name="overlap-both-segments", ok=ok,
              detail=f"segments={starts} expect both 09:00:00 and 10:00:00 starts"),
    )


def _walk_dicts(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)
