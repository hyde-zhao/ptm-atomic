"""IPV6地址,验证多个IP地址的多行CIDR地址排除，完全不重叠测试

xlsx(对象管理用例_重构_563.xlsx) P3: 多个IP地址基础 + 多行CIDR地址排除(完全不重叠); 步骤4修改排除为部分重合。
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

TITLE = "P3-263504 IPV6地址,验证多个IP地址的多行CIDR地址排除，完全不重叠测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    name = unique_random(263504, "ex")
    try:
        created = excl_create(ctx, result, label="create-ok", v6=True, name=name,
                              networks=n("2001:db8:66::10", 128) + n("2001:db8:66::11", 128), exclnetworks=n("2001:db8:66:2::", 64) + n("2001:db8:66:3::", 64))
        if created:
            excl_stored(ctx, result, label="stored-after-create", v6=True, name=name,
                        networks=n("2001:db8:66::10", 128) + n("2001:db8:66::11", 128), exclnetworks=n("2001:db8:66:2::", 64) + n("2001:db8:66:3::", 64))
            excl_update(ctx, result, label="update-partial-ok", v6=True, name=name,
                        networks=n("2001:db8:66::10", 128) + n("2001:db8:66::11", 128), exclnetworks=n("2001:db8:66::", 123))
            excl_stored(ctx, result, label="stored-after-update", v6=True, name=name,
                        networks=n("2001:db8:66::10", 128) + n("2001:db8:66::11", 128), exclnetworks=n("2001:db8:66::", 123))
            result.record(Check(name="policy-traffic-skip", ok=True, detail='documented-skip: 建后修改排除为部分重合, 会话减少数与重合处一致 属策略/数据面域, 无配置面观测手段'))
    finally:
        if ctx.execute:
            raw_delete(ctx, obj_resource(True), name)
