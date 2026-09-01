"""IPV4地址,验证单行IP地址与单行地址排除，部分重叠测试

xlsx(对象管理用例_重构_563.xlsx) P2: 新建IPv4地址对象A, 排除地址与基础地址部分重合(基础网段/24 内排除单IP)。设备实测部分重叠接受。
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

TITLE = "P2-263447 IPV4地址,验证单行IP地址与单行地址排除，部分重叠测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    name = unique_random(263447, "ex")
    try:
        created = excl_create(ctx, result, label="create-ok", v6=False, name=name,
                              networks=n("10.66.0.0", 24), exclnetworks=n("10.66.0.10", 32))
        if created:
            excl_stored(ctx, result, label="excl-stored", v6=False, name=name,
                        networks=n("10.66.0.0", 24), exclnetworks=n("10.66.0.10", 32))
            result.record(Check(name="policy-traffic-skip", ok=True, detail='documented-skip: 控制策略引用地址对象后, 基础地址(排除外)命中会话建立、排除地址不命中 属策略/数据面域, 无配置面观测手段'))
    finally:
        if ctx.execute:
            raw_delete(ctx, obj_resource(False), name)
