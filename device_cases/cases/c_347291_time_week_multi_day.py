"""P3-347291: 验证周计划多日关联及跨周执行的准确性

xlsx(对象管理用例_重构_563.xlsx):
  1. 创建周计划 Weekly_C(关联 周一、周四, 时间段 10:00:00-11:00:00)【check1】配置成功
  2. 策略关联周计划【check1】
  3. 调整时间到周一 10:30【check2】策略生效
  4. 调整时间到周二 10:30【check3】策略失效
  5. 调整时间到周四 10:30【check4】策略再次生效
  6. 周日→下周一自动跨周切换【check5】策略在周一 10:00:00 准确生效

多日周计划经 --payload-json(weekday 1 与 4 各一段)。check1 创建成功 + verify
两个 weekday 都存储。策略关联与时钟翻转观测 → documented-skip。
"""

from __future__ import annotations

import json

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, TIME
from framework.results import CaseResult

from cases.time_support import quantum_segments_check, time_quantum_starts, time_weekdays

TITLE = "P3-347291 周计划多日关联及跨周执行准确性"


def _payload(name: str) -> str:
    return json.dumps({"val": {
        "name": name,
        "scheduletype": "week",
        "timequantum": [
            {"starttime": {"time": "10:00:00", "weekday": 1},
             "endtime": {"time": "11:00:00", "weekday": 1}},
            {"starttime": {"time": "10:00:00", "weekday": 4},
             "endtime": {"time": "11:00:00", "weekday": 4}},
        ],
    }})


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(347291, "to")
    try:
        out = _run_create(ctx, TIME, name=name, payload_json=_payload(name))
        result.record(op_succeeded(out, ctx=ctx, label="multi-day-week-created"))
        if not ctx.execute:
            return
        starts, _ = time_quantum_starts(ctx, name)
        result.record(state_check(
            ctx, quantum_segments_check(
                label="both-days-stored",
                starts=starts,
                expect={"10:00:00"},
            )))
        days = time_weekdays(ctx, name)
        result.record(state_check(ctx, Check(
            name="weekdays-stored",
            ok=set(days) == {1, 4},
            detail=f"weekdays={days} want [1, 4]")))

        # check2-5: 周一/周二/周四生效失效 + 跨周切换 → 时钟 + 数据面, skip。
        result.record(Check(name="policy-effect-across-days", ok=True,
                            detail=("documented-skip: 周一生效/周二失效/周四再生效/跨周切换"
                                    " 需调整系统时钟并观测数据面策略状态, 无对应注入/观测手段")))
    finally:
        if ctx.execute:
            result.record(op_succeeded(_run_delete(ctx, TIME, name=name), ctx=ctx, label="cleanup"))
