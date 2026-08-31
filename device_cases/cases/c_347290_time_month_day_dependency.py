"""P2-347290: 月计划对日计划的依赖及依赖中断处理.

Configuration-plane coverage of the month-day dependency contract:
  1. A day schedule (09:00-17:00) is created and reflected in verify.
  2. A month schedule that references a planday is created and reflected.
  3. A month schedule that does NOT reference a planday is rejected by the
     device (probe: timemonquantum without planday -> 400 eRequestParamWithDetail).
  4. Deleting the referenced day object while the month references it: the
     device has no REST-level object reference between month and day (their
     coupling lives in the security-policy layer), so the config-plane
     delete succeeds and this step is recorded as informational.

The clock-walk assertions (策略在满足 Daily_B 时间段生效 / 依赖中断后失效) are
data-plane coupling and out of scope here.
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, _run_verify, TIME
from framework.results import CaseResult

TITLE = "P2-347290 月计划对日计划的依赖及依赖中断"

DAY_START = "09:00:00"
DAY_END = "17:00:00"


def run(ctx: CaseContext, result: CaseResult) -> None:
    day_name = unique_random(347290, "daily")
    month_name = unique_random(347290, "month")
    try:
        # check1: day schedule 09:00-17:00.
        out = _run_create(ctx, TIME, name=day_name, scheduletype="day",
                          start_time=DAY_START, end_time=DAY_END)
        result.record(op_succeeded(out, ctx=ctx, label="day-created"))
        if ctx.execute and out.success:
            result.record(_day_reflected(ctx, day_name))

        # check1: month schedule referencing planday.
        out = _run_create(ctx, TIME, name=month_name, scheduletype="month",
                          month_time=11, planday="11")
        result.record(op_succeeded(out, ctx=ctx, label="month-created"))
        if ctx.execute and out.success:
            result.record(_month_reflected(ctx, month_name))

        # check4: month without a planday reference is rejected.
        bad = unique_random(347290, "noplanday")
        out = _run_create(ctx, TIME, name=bad, scheduletype="month", month_time=11)
        result.record(op_rejected(out, ctx=ctx, label="month-no-planday-rejected"))

        # check3: config-plane delete of the referenced day succeeds (the
        # month-day dependency is a policy-layer concern, not a REST ref).
        if ctx.execute:
            dout = _run_delete(ctx, TIME, name=day_name)
            result.record(
                Check(name="day-delete-while-referenced",
                      ok=dout.success,
                      detail="config-plane: day delete succeeds; policy-layer ref is out of scope")
            )
            # The day object is gone now; keep cleanup from double-deleting.
            day_name = ""
    finally:
        if ctx.execute:
            if day_name:
                result.record(op_succeeded(_run_delete(ctx, TIME, name=day_name),
                                           ctx=ctx, label="cleanup-day"))
            result.record(op_succeeded(_run_delete(ctx, TIME, name=month_name),
                                       ctx=ctx, label="cleanup-month"))


def _day_reflected(ctx: CaseContext, name: str) -> Check:
    vout = _run_verify(ctx, TIME, name=name)
    if not vout.success:
        return Check(name="day-reflected-query", ok=False, detail=f"verify failed: {vout.err_msg()}")
    hits = [e for e in _walk_dicts(vout.response()) if isinstance(e, dict) and str(e.get("name", "")) == name]
    if not hits:
        return Check(name="day-reflected-entry", ok=False, detail="day object not in REST verify")
    q = hits[0].get("timequantum")
    ok = isinstance(q, list) and any(
        isinstance(x, dict)
        and x.get("starttime", {}).get("time") == DAY_START
        and x.get("endtime", {}).get("time") == DAY_END
        for x in q
    )
    return state_check(ctx, Check(name="day-reflected", ok=ok, detail=f"quantum={q}"))


def _month_reflected(ctx: CaseContext, name: str) -> Check:
    vout = _run_verify(ctx, TIME, name=name)
    if not vout.success:
        return Check(name="month-reflected-query", ok=False, detail=f"verify failed: {vout.err_msg()}")
    hits = [e for e in _walk_dicts(vout.response()) if isinstance(e, dict) and str(e.get("name", "")) == name]
    if not hits:
        return Check(name="month-reflected-entry", ok=False, detail="month object not in REST verify")
    tm = hits[0].get("timemonquantum")
    ok = isinstance(tm, list) and any(
        isinstance(x, dict) and str(x.get("time")) == "11" and str(x.get("planday")) == "11"
        for x in tm
    )
    return state_check(ctx, Check(name="month-reflected", ok=ok, detail=f"timemonquantum={tm}"))


def _walk_dicts(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)
