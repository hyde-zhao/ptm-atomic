"""P2-18161: 某个ipv6地址的引用次数与实际引用一致.

xlsx: 新建 ipv6 地址 → 在 ipv6 地址组/策略/NAT/带宽/策略路由引用【check2】→ 引用次数与
实际一致【check3】→ 解除引用后再查【check3】。

设备实测(55.63, probe31/32): 以 ipv6 地址组为对象级引用载体,单对象 refcnt 0→1(一组)→
2(两组),删除被引用被拒 400 且 refcnt 不变,解除后归零可删。策略/NAT/带宽/策略路由引用属
数据面域 → documented-skip。
"""
from __future__ import annotations

from framework.context import CaseContext
from framework.results import CaseResult

from cases.refcnt_support import addr_count

TITLE = "P2-18161 某个ipv6地址的引用次数与实际引用一致"


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        from framework.checks import Check
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    addr_count(ctx, result, case_id=18161, v6=True)
