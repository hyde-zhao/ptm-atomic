"""P1-347279: 自定义服务逻辑及错误校验.

The device rejects invalid port ranges: start > end, ports above 65535, and
negative ports. Each rejection must leave no trace in REST. (Empty-end-port
and non-numeric-protocol edge cases are covered by 900103/347276.)
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, _run_verify, SERVICE
from framework.results import CaseResult

TITLE = "P1-347279 自定义服务逻辑及错误校验"

BAD_RANGES = (
    ("start-gt-end", 3000, 2000),
    ("over-65535", 65536, 65535),
    ("negative", 1000, -1),
)


def run(ctx: CaseContext, result: CaseResult) -> None:
    for tag, s, e in BAD_RANGES:
        name = unique_random(347279, tag)
        rng = f'[{{"proto":6,"s_start":{s},"s_end":{e},"d_start":0,"d_end":65535}}]'
        out = _run_create(ctx, SERVICE, name=name, ranges=rng, desc=f"atc {tag}")
        result.record(op_rejected(out, ctx=ctx, label=f"{tag}-rejected"))
        if ctx.execute:
            # No trace: the rejected object must not be queryable.
            vout = _run_verify(ctx, SERVICE, name=name)
            hits = [x for x in _walk_dicts(vout.response()) if isinstance(x, dict) and str(x.get("name", "")) == name]
            result.record(
                Check(name=f"{tag}-absent", ok=len(hits) == 0,
                      detail=f"entries={len(hits)} (want 0)")
            )


def _walk_dicts(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)
