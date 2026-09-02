"""P2-18147: 某个ipv4地址的引用次数与实际引用一致.

xlsx(对象管理用例_重构_563.xlsx): 新建 ipv4 地址 → 在 ipv4 地址组/策略/NAT/带宽/
策略路由引用【check2】→ 查看引用次数与实际引用一致【check3】→ 解除引用后再查【check3】。

设备实测(55.63, probe31/32): 以「ipv4 地址组」为对象级引用载体(xlsx check2 所列第一项),
单对象 refcnt 字段 0→1(一组)→2(两组),删除被引用对象被拒 400「被引用无法被删除」且
refcnt 不变,解除全部引用后 refcnt 归零、对象可删。策略/NAT/带宽/策略路由引用属数据面域
→ documented-skip。
"""
from __future__ import annotations

from framework.context import CaseContext
from framework.results import CaseResult

from cases.refcnt_support import addr_count

TITLE = "P2-18147 某个ipv4地址的引用次数与实际引用一致"


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        from framework.checks import Check
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    addr_count(ctx, result, case_id=18147, v6=False)
