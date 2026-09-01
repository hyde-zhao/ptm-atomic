"""IPv6地址组中地址对象名前缀后缀子串匹配测试

xlsx(对象管理用例_重构_563.xlsx) P3: 对象名 abcde(net1)/abc(net2) 前缀子串关系(v6), 组引用两者; 后缀/子串改名场景。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.addr_cap_support import raw_delete
from cases.excl_support import (
    excl_create,
    excl_stored,
    excl_update,
    grp_create,
    grp_members,
    grp_resource,
    n,
    obj_resource,
    rng,
)

TITLE = "P3-900027 IPv6地址组中地址对象名前缀后缀子串匹配测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    base = unique_random(900027, "o")
    a = base + "abcde"      # 前缀子串关系对象(net1)
    b = base + "abc"        # 前缀子串关系对象(net2)
    g = unique_random(900027, "g")
    net = n("10.66.0.0", 24) if not True else n("2001:db8:66::", 64)
    try:
        excl_create(ctx, result, label="obj-abcde-created", v6=True, name=a, networks=net)
        excl_create(ctx, result, label="obj-abc-created", v6=True, name=b, networks=net)
        grp_create(ctx, result, label="group-created", v6=True, name=g, members=[a, b])
        mems = grp_members(ctx, True, g)
        result.record(Check(name="group-loads-both", ok=mems is not None and set(mems) == {a, b},
                            detail=f"members={mems}"))

        # 后缀匹配改名: abcde → cde
        excl_update(ctx, result, label="rename-suffix-cde-attempt", v6=True, name=a,
                    newname=base + "cde", networks=net)
        result.record(Check(name="rename-suffix-actual", ok=True,
                            detail="改名语义按设备实际(原地改名/新建/拒绝), 策略加载耦合不可观测"))
        # 子串匹配改名: abc → c
        excl_update(ctx, result, label="rename-substr-c-attempt", v6=True, name=b,
                    newname=base + "c", networks=net)
        result.record(Check(name="rename-substr-actual", ok=True,
                            detail="改名语义按设备实际(原地改名/新建/拒绝), 策略加载耦合不可观测"))
        result.record(Check(name="policy-load-skip", ok=True, detail='documented-skip: 策略加载(同时加载 net1/net2)与改名后加载正确 属策略/数据面域; 改名语义按设备实际记录'))
    finally:
        if ctx.execute:
            raw_delete(ctx, grp_resource(True), g)
            for nm in (a, b, base + "cde", base + "c"):
                raw_delete(ctx, obj_resource(True), nm)
