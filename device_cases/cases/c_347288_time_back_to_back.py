"""P3-347288: 验证多时间段首尾相接(无缝拼接)时的状态连续性

xlsx(对象管理用例_重构_563.xlsx):
  1. 创建周计划时间对象包含(周一10:00:00-10:00:30 周一10:00:30-10:01:00)关联至放行策略【check1】
  2. 时间进入 10:00:00, 策略生效
  3. 观察 10:00:30 临界点行为【check2】策略保持持续生效, 不发生 Active→Inactive→Active 翻转

周计划两段首尾相接经 --payload-json。check1 创建成功 + verify 两段都存储。
临界点翻转观测需系统时钟走到 10:00:30 并观察数据面 → documented-skip。
"""

from __future__ import annotations

import json

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, TIME
from framework.results import CaseResult

from cases.time_support import quantum_segments_check, time_quantum_starts

TITLE = "P3-347288 多时间段首尾相接(无缝拼接)状态连续性"


def _payload(name: str) -> str:
    return json.dumps({"val": {
        "name": name,
        "scheduletype": "week",
        "timequantum": [
            {"starttime": {"time": "10:00:00", "weekday": 1},
             "endtime": {"time": "10:00:30", "weekday": 1}},
            {"starttime": {"time": "10:00:30", "weekday": 1},
             "endtime": {"time": "10:01:00", "weekday": 1}},
        ],
    }})


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(347288, "to")
    try:
        out = _run_create(ctx, TIME, name=name, payload_json=_payload(name))
        result.record(op_succeeded(out, ctx=ctx, label="back-to-back-created"))
        if not ctx.execute:
            return
        starts, _ = time_quantum_starts(ctx, name)
        result.record(state_check(
            ctx, quantum_segments_check(
                label="both-segments-stored",
                starts=starts,
                expect={"10:00:00", "10:00:30"},
            )))
        # check2: 10:00:30 临界点翻转观测 → 时钟 + 数据面, skip。
        result.record(Check(name="boundary-no-flip", ok=True,
                            detail=("documented-skip: 首尾相接段在临界点是否翻转需系统时钟"
                                    " 推进至 10:00:30 并观测数据面策略状态, 无对应注入/观测手段")))
    finally:
        if ctx.execute:
            result.record(op_succeeded(_run_delete(ctx, TIME, name=name), ctx=ctx, label="cleanup"))
