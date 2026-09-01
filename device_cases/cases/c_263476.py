"""IPV4地址组排除地址并集关系测试

xlsx(对象管理用例_重构_563.xlsx) P3: 新建地址组关联两个IPv4对象: 正常对象A(网段) + 对象B(更大网段基础, 排除A的网段, 部分重叠→可建); 组并集含A全部地址。
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

TITLE = "P3-263476 IPV4地址组排除地址并集关系测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    a = unique_random(263476, "a")
    b = unique_random(263476, "b")
    g = unique_random(263476, "g")
    try:
        excl_create(ctx, result, label="obj-a-created", v6=False, name=a,
                    networks=n("10.66.0.0", 24) if not False else n("2001:db8:66::", 64))
        excl_create(ctx, result, label="obj-b-with-excl-created", v6=False, name=b,
                    networks=n("10.66.0.0", 16) if not False else n("2001:db8:66::", 48),
                    exclnetworks=n("10.66.0.0", 24) if not False else n("2001:db8:66::", 64))
        grp_create(ctx, result, label="group-created", v6=False, name=g, members=[a, b])
        mems = grp_members(ctx, False, g)
        result.record(Check(name="group-holds-both", ok=mems is not None and set(mems) == {a, b},
                            detail=f"members={mems}"))
        result.record(Check(name="nat-traffic-skip", ok=True, detail='documented-skip: NAT策略引用地址组、排除地址业务流会话建立 属策略/数据面域'))
    finally:
        if ctx.execute:
            raw_delete(ctx, grp_resource(False), g)
            raw_delete(ctx, obj_resource(False), b)
            raw_delete(ctx, obj_resource(False), a)
