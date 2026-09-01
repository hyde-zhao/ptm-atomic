"""IPV6地址,验证单行IP地址与单行地址排除，部分重叠测试

xlsx(对象管理用例_重构_563.xlsx) P2: 新建IPv6地址对象A, 排除地址与基础地址部分重合(基础网段/64 内排除单IP)。
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

TITLE = "P2-263448 IPV6地址,验证单行IP地址与单行地址排除，部分重叠测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    name = unique_random(263448, "ex")
    try:
        created = excl_create(ctx, result, label="create-ok", v6=True, name=name,
                              networks=n("2001:db8:66::", 64), exclnetworks=n("2001:db8:66::10", 128))
        if created:
            excl_stored(ctx, result, label="excl-stored", v6=True, name=name,
                        networks=n("2001:db8:66::", 64), exclnetworks=n("2001:db8:66::10", 128))
            result.record(Check(name="policy-traffic-skip", ok=True, detail='documented-skip: 控制策略引用地址对象后, 基础地址(排除外)命中会话建立、排除地址不命中 属策略/数据面域, 无配置面观测手段'))
    finally:
        if ctx.execute:
            raw_delete(ctx, obj_resource(True), name)
