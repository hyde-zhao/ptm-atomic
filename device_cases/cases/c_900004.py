"""IPV6地址单类型排除地址部分重叠组合测试

xlsx(对象管理用例_重构_563.xlsx) P3: 单类型组合 sweep(v6): IP/IP → 范围/范围 → CIDR/CIDR → IP/CIDR。
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

TITLE = "P3-900004 IPV6地址单类型排除地址部分重叠组合测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    name = unique_random(900004, "ex")
    variants = [
        ("v1-ip-ip", {**dict(networks=n("2001:db8:66::10", 128) + n("2001:db8:66::11", 128), exclnetworks=n("2001:db8:66::10", 128) + n("2001:db8:66::20", 128))}),
        ("v2-range-range", {**dict(ranges=rng("2001:db8:66:1::10", "2001:db8:66:1::20"), exclranges=rng("2001:db8:66:1::15", "2001:db8:66:1::25"))}),
        ("v3-cidr-cidr", {**dict(networks=n("2001:db8:66:2::", 64), exclnetworks=n("2001:db8:66:2:80::", 65))}),
        ("v4-ip-cidr", {**dict(networks=n("2001:db8:66::10", 128) + n("2001:db8:66::2000", 128), exclnetworks=n("2001:db8:66::", 123))}),
    ]
    try:
        for i, (label, fields) in enumerate(variants):
            if i == 0:
                excl_create(ctx, result, label=f"{label}-created", v6=True, name=name, **fields)
            else:
                excl_update(ctx, result, label=f"{label}-updated", v6=True, name=name, **fields)
            excl_stored(ctx, result, label=f"{label}-stored", v6=True, name=name, **fields)
            result.record(Check(name=f"{label}-traffic-skip", ok=True, detail='documented-skip: 各组合命中/排除行为一致 属数据面域'))
    finally:
        if ctx.execute:
            raw_delete(ctx, obj_resource(True), name)
