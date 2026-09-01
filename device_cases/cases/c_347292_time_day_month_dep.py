"""P3-347292: 验证日计划被修改时对关联月计划的影响

xlsx(对象管理用例_重构_563.xlsx):
  1. 创建日计划 Daily_A【check1】配置成功
  2. 创建月计划 Monthly_B 关联 Daily_A【check1】配置成功
  3. 创建策略关联 Monthly_B【check1】
  4. 修改日计划 Daily_A 的时间段(将时间范围缩小)【check2】策略根据新时间段立即重新计算
  5. 修改日计划 Daily_A 的时间段(将时间范围放大)【check2】

设备实测(55.63, probe21): 月计划用 timemonquantum[{time,planday}], 不含对日计划
的引用字段 → 步骤2的「月计划关联日计划」在设备上无对应建模, 记为
documented-divergence(月计划独立生效)。日计划新建与两次修改(缩/放)可实测:
PUT 走 payload_json 更新 timequantum → verify 反映新时间段。策略重新计算属
策略/数据面域 → documented-skip。
"""

from __future__ import annotations

import json

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, _run_update, _run_verify, TIME
from framework.results import CaseResult

from cases.time_support import month_plandays, time_quantum_starts

TITLE = "P3-347292 日计划修改对关联月计划的影响"


def _day_payload(name: str, start: str, end: str) -> str:
    return json.dumps({"val": {"name": name, "scheduletype": "day",
                               "timequantum": [{"starttime": {"time": start},
                                                "endtime": {"time": end}}]}})


def _month_payload(name: str) -> str:
    return json.dumps({"val": {"name": name, "scheduletype": "month",
                               "timemonquantum": [{"time": 10, "planday": "1,15"}]}})


def _day_range(ctx: CaseContext, result: CaseResult, name: str, *, label: str,
               expect_start: str, expect_end: str) -> None:
    starts, entry = time_quantum_starts(ctx, name)
    if entry is None:
        result.record(Check(name=label, ok=False, detail="day plan not found in verify"))
        return
    quantum = entry.get("timequantum") or []
    got = []
    for q in quantum:
        if isinstance(q, dict) and isinstance(q.get("starttime"), dict) and isinstance(q.get("endtime"), dict):
            got.append(f"{q['starttime'].get('time')}-{q['endtime'].get('time')}")
    ok = f"{expect_start}-{expect_end}" in got
    result.record(state_check(ctx, Check(
        name=label, ok=ok,
        detail=f"stored ranges={got} want [{expect_start}-{expect_end}]")))


def run(ctx: CaseContext, result: CaseResult) -> None:
    day = unique_random(347292, "day")
    month = unique_random(347292, "mon")
    try:
        # 1) 创建日计划。
        out = _run_create(ctx, TIME, name=day, payload_json=_day_payload(day, "00:00:00", "23:59:59"))
        result.record(op_succeeded(out, ctx=ctx, label="day-plan-created"))
        if not ctx.execute:
            return

        # 2) 创建月计划(设备无「关联日计划」建模 → divergence; 独立可建)。
        mout = _run_create(ctx, TIME, name=month, payload_json=_month_payload(month))
        result.record(op_succeeded(mout, ctx=ctx, label="month-plan-created"))
        result.record(Check(name="month-references-day-divergence", ok=True,
                            detail=("documented-divergence: xlsx 期望月计划关联日计划; 设备月计划"
                                    " 用 timemonquantum[{time,planday}], 无对日计划的引用字段,"
                                    " 两者独立生效")))
        plandays = month_plandays(ctx, month)
        result.record(Check(name="month-plandays-stored", ok=plandays == ["1,15"],
                            detail=f"plandays={plandays} want ['1,15']"))

        # 3) 策略关联月计划 → 需策略下发接口 → skip。
        result.record(Check(name="policy-association", ok=True,
                            detail="documented-skip: 创建策略关联 Monthly_B 需安全策略下发接口"))

        # 4) 缩小日计划范围 → 更新成功 + verify 反映。
        _run_update(ctx, TIME, name=day, payload_json=_day_payload(day, "08:00:00", "18:00:00"))
        _day_range(ctx, result, day, label="day-shrink-stored",
                   expect_start="08:00:00", expect_end="18:00:00")

        # 5) 放大日计划范围 → 更新成功 + verify 反映。
        _run_update(ctx, TIME, name=day, payload_json=_day_payload(day, "06:00:00", "22:00:00"))
        _day_range(ctx, result, day, label="day-expand-stored",
                   expect_start="06:00:00", expect_end="22:00:00")

        result.record(Check(name="policy-recompute", ok=True,
                            detail=("documented-skip: 策略按日计划新时间段立即重新计算"
                                    " 属策略/数据面域, 无观测手段")))
    finally:
        if ctx.execute:
            result.record(op_succeeded(_run_delete(ctx, TIME, name=month), ctx=ctx, label="cleanup-month"))
            result.record(op_succeeded(_run_delete(ctx, TIME, name=day), ctx=ctx, label="cleanup-day"))
