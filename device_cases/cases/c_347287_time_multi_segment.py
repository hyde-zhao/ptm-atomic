"""P3-347287: 验证单个时间对象包含多个不连续时间段的生效与失效切换

xlsx(对象管理用例_重构_563.xlsx):
  1. 创建一次性时间对象包含两段时间(09:00:00-12:00:00 13:30:00-18:00:00)【check1】创建成功
  2. 关联至阻断策略【check2】
  3. 调整系统时间至区间1内【check3】策略生效
  4. 调整时间至 12:30(间隙 Gap)【check4】策略失效
  5. 调整时间至 14:00(区间2内)【check3】策略生效

多段 oneshot 经 --payload-json(单段 CLI 参数无法表达两段)。check1 创建成功 +
verify 两段都存储。策略关联/系统时钟翻转/数据面生效与否无对应下发与注入手段
→ check2-5 记 documented-skip。
"""

from __future__ import annotations

import json

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, TIME
from framework.results import CaseResult

from cases.time_support import quantum_segments_check, time_quantum_starts

TITLE = "P3-347287 单个时间对象包含多个不连续时间段"


def _payload(name: str) -> str:
    return json.dumps({"val": {
        "name": name,
        "scheduletype": "oneshot",
        "timequantum": [
            {"starttime": {"time": "2026-09-20 09:00:00"},
             "endtime": {"time": "2026-09-20 12:00:00"}},
            {"starttime": {"time": "2026-09-20 13:30:00"},
             "endtime": {"time": "2026-09-20 18:00:00"}},
        ],
    }})


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(347287, "to")
    try:
        out = _run_create(ctx, TIME, name=name, payload_json=_payload(name))
        result.record(op_succeeded(out, ctx=ctx, label="multi-segment-created"))
        if not ctx.execute:
            return
        starts, _ = time_quantum_starts(ctx, name)
        result.record(state_check(
            ctx, quantum_segments_check(
                label="both-segments-stored",
                starts=starts,
                expect={"2026-09-20 09:00:00", "2026-09-20 13:30:00"},
            )))

        # check2: 关联阻断策略 → 需安全策略下发接口 → skip。
        result.record(Check(name="associate-policy", ok=True,
                            detail="documented-skip: 关联阻断策略需策略下发接口, 无对应 API"))
        # check3/4: 系统时间调整 + 策略生效/失效 → 时钟翻转与数据面, skip。
        result.record(Check(name="clock-walk-effect", ok=True,
                            detail=("documented-skip: 区间内/间隙/区间2 的策略生效失效需"
                                    " 调整系统时钟并观察数据面, 无对应注入/观测手段")))
    finally:
        if ctx.execute:
            result.record(op_succeeded(_run_delete(ctx, TIME, name=name), ctx=ctx, label="cleanup"))
