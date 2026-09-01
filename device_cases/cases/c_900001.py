"""IPV4地址单类型排除地址部分重叠组合测试

xlsx(对象管理用例_重构_563.xlsx) P3: 单类型组合 sweep: 每变体 create/update 带排除对象, 断言落库; 各组合命中/排除一致属数据面。
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

TITLE = "P3-900001 IPV4地址单类型排除地址部分重叠组合测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    name = unique_random(900001, "ex")
    variants = [
        ("v1-ip-ip", {**dict(networks=n("10.66.1.10", 32) + n("10.66.1.20", 32), exclnetworks=n("10.66.1.10", 32) + n("10.66.1.30", 32))}),
        ("v2-range-range", {**dict(ranges=rng("10.66.2.10", "10.66.2.20"), exclranges=rng("10.66.2.15", "10.66.2.25"))}),
        ("v3-cidr-cidr", {**dict(networks=n("10.66.3.0", 24), exclnetworks=n("10.66.3.128", 25))}),
        ("v4-ip-cidr", {**dict(networks=n("10.66.1.10", 32) + n("10.66.1.20", 32), exclnetworks=n("10.66.1.0", 25))}),
        ("v5-range-cidr", {**dict(ranges=rng("10.66.4.10", "10.66.4.20"), exclnetworks=n("10.66.4.16", 28))}),
        ("v6-cidr-iprange", {**dict(networks=n("10.66.5.0", 24), exclnetworks=n("10.66.5.10", 32), exclranges=rng("10.66.5.100", "10.66.5.110"))}),
    ]
    try:
        for i, (label, fields) in enumerate(variants):
            if i == 0:
                excl_create(ctx, result, label=f"{label}-created", v6=False, name=name, **fields)
            else:
                excl_update(ctx, result, label=f"{label}-updated", v6=False, name=name, **fields)
            excl_stored(ctx, result, label=f"{label}-stored", v6=False, name=name, **fields)
            result.record(Check(name=f"{label}-traffic-skip", ok=True, detail='documented-skip: 各组合命中/排除行为一致 属数据面域'))
    finally:
        if ctx.execute:
            raw_delete(ctx, obj_resource(False), name)
