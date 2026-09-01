"""IPV4地址混合类型排除地址部分重叠组合测试

xlsx(对象管理用例_重构_563.xlsx) P3: 混合类型 sweep: 固定多IP/范围/CIDR基础, 排除地址依次改为 多CIDR→多IP→多范围→混合。
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

TITLE = "P3-900003 IPV4地址混合类型排除地址部分重叠组合测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    name = unique_random(900003, "ex")
    variants = [
        ("v1-excl-cidr", {**dict(networks=n("10.66.1.10", 32) + n("10.66.3.0", 24), ranges=rng("10.66.2.10", "10.66.2.20"), exclnetworks=n("10.66.1.0", 25) + n("10.66.2.16", 28) + n("10.66.3.0", 25))}),
        ("v2-excl-ip", {**dict(networks=n("10.66.1.10", 32) + n("10.66.3.0", 24), ranges=rng("10.66.2.10", "10.66.2.20"), exclnetworks=n("10.66.1.10", 32) + n("10.66.2.10", 32) + n("10.66.3.10", 32))}),
        ("v3-excl-range", {**dict(networks=n("10.66.1.10", 32) + n("10.66.3.0", 24), ranges=rng("10.66.2.10", "10.66.2.20"), exclranges=rng("10.66.1.10", "10.66.1.11") + rng("10.66.2.10", "10.66.2.12") + rng("10.66.3.10", "10.66.3.12"))}),
        ("v4-excl-mixed", {**dict(networks=n("10.66.1.10", 32) + n("10.66.3.0", 24), ranges=rng("10.66.2.10", "10.66.2.20"), exclnetworks=n("10.66.1.10", 32) + n("10.66.3.0", 25), exclranges=rng("10.66.2.10", "10.66.2.12"))}),
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
