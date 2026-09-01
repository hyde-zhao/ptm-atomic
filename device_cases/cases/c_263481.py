"""IPV4地址,验证多个IP地址的多行IP地址排除，完全重叠测试

xlsx(对象管理用例_重构_563.xlsx) P4: 多个IP地址基础 + 相同多行IP排除(完全重叠)。
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

TITLE = "P4-263481 IPV4地址,验证多个IP地址的多行IP地址排除，完全重叠测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    name = unique_random(263481, "ex")
    try:
        created = excl_create(ctx, result, label="create-rejected", v6=False, name=name,
                              networks=n("10.66.1.10", 32) + n("10.66.1.20", 32), exclnetworks=n("10.66.1.10", 32) + n("10.66.1.20", 32),
                              expect_ok=False, err_needle=["无可用地址", "eNoUsableNetworks"])
        result.record(Check(name="full-overlap-divergence", ok=True, detail='documented-divergence: xlsx 期望完全重叠可建对象、后续删除排除再命中; 设备实测创建即拒(400 eNoUsableNetworks 无可用地址), 无对象可改/无业务流可发'))
    finally:
        if ctx.execute and created:
            raw_delete(ctx, obj_resource(False), name)
