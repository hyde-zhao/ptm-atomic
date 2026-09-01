"""P1-168977: MAC地址对象配置下发失败测试

xlsx(对象管理用例_重构_563.xlsx): 下发错误对象→400; 查询无此对象; etcd 与下发前相同
设备实测: 无效 mac 格式→设备拒(400 类); verify 查不到该对象; etcd 需 SSH(不可达→skip,
REST 侧已验证对象不存在)。
"""

from __future__ import annotations

from framework.checks import Check, op_rejected
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import absent_check, entry_by_name

TITLE = "P1-168977 MAC地址对象配置下发失败测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    try:
        name = unique_random(168977, "bad")
        out = ctx.runner.run("mac-pool", "config", name=name, mac=["00:11:22:33:44"])
        result.record(op_rejected(out, ctx=ctx, label="config-invalid-rejected"))
        if not ctx.execute:
            return
        absent_check(ctx, result, name=name, label="bad-object-absent")
    except Exception as exc:  # noqa: BLE001
        result.record(Check(name="push-fail", ok=False, detail=f"{type(exc).__name__}: {exc}"))
