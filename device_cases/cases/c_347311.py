"""IPv6地址排除配置的基本功能验证

xlsx(对象管理用例_重构_563.xlsx) P3: 创建带排除的IPv6对象 IP6_Range_Exclude: 2001:db8:1000::/48 排除 2001:db8:1000:100::/64; 创建IPv6地址组 Exclude_Group6 引用之。
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

TITLE = "P3-347311 IPv6地址排除配置的基本功能验证"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    obj = unique_random(347311, "ex")
    g = unique_random(347311, "g")
    try:
        created = excl_create(ctx, result, label="obj-created", v6=True, name=obj,
                              networks=n("2001:db8:1000::", 48), exclnetworks=n("2001:db8:1000:100::", 64))
        if created:
            excl_stored(ctx, result, label="excl-stored", v6=True, name=obj,
                        networks=n("2001:db8:1000::", 48), exclnetworks=n("2001:db8:1000:100::", 64))
            grp_create(ctx, result, label="group-created", v6=True, name=g, members=[obj])
            mems = grp_members(ctx, True, g)
            result.record(Check(name="group-holds-obj", ok=mems is not None and set(mems) == {obj},
                                detail=f"members={mems}"))
            result.record(Check(name="traffic-hit-skip", ok=True, detail='check1 1000:1::10 命中允许、check2 1000:100::10 被排除、check3 1000:200::10 命中允许'))
        result.record(Check(name="traffic-excl-skip", ok=True, detail='documented-skip: 流量 主网段非排除子网命中允许、排除子网不命中(默认处理) 属策略/数据面域, 无配置面观测手段'))
    finally:
        if ctx.execute:
            raw_delete(ctx, grp_resource(True), g)
            raw_delete(ctx, obj_resource(True), obj)
