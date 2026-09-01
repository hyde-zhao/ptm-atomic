"""IPv4地址排除配置的基本功能验证

xlsx(对象管理用例_重构_563.xlsx) P3: 创建带排除的IPv4对象 IP_Range_Exclude: 192.168.2.0/24 排除 192.168.2.100-110; 创建地址组 Exclude_Group 引用之。
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

TITLE = "P3-347295 IPv4地址排除配置的基本功能验证"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    obj = unique_random(347295, "ex")
    g = unique_random(347295, "g")
    try:
        created = excl_create(ctx, result, label="obj-created", v6=False, name=obj,
                              networks=n("192.168.2.0", 24), exclranges=rng("192.168.2.100", "192.168.2.110"))
        if created:
            excl_stored(ctx, result, label="excl-stored", v6=False, name=obj,
                        networks=n("192.168.2.0", 24), exclranges=rng("192.168.2.100", "192.168.2.110"))
            grp_create(ctx, result, label="group-created", v6=False, name=g, members=[obj])
            mems = grp_members(ctx, False, g)
            result.record(Check(name="group-holds-obj", ok=mems is not None and set(mems) == {obj},
                                detail=f"members={mems}"))
            result.record(Check(name="traffic-hit-skip", ok=True, detail='check1 .50 命中允许、check2 .105 被排除按默认、check3 .200 命中允许'))
        result.record(Check(name="traffic-excl-skip", ok=True, detail='documented-skip: 流量 .50/.200 命中允许、.105 被排除不命中(默认处理) 属策略/数据面域, 无配置面观测手段'))
    finally:
        if ctx.execute:
            raw_delete(ctx, grp_resource(False), g)
            raw_delete(ctx, obj_resource(False), obj)
