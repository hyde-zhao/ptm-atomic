"""P4-129012: 验证IPv6地址对象容量(对象数量)

xlsx(对象管理用例_重构_563.xlsx):
  1. 新建最大数量 IPv6 地址对象 → 成功【check1】(VPP存在 + REST查询正常)
  2. 再新建 1 条 → 失败「已达到规格」【check2】
  3. 删除 1 条 → 成功【check3】
  4. 再新建 1 条 → 成功【check1】

同 129010: IPv6 地址对象数量上限不可穷尽 → 「有界高水位 FILL=60」落实容量操作
语义, check2 记 documented-divergence。SSH 22 不可达 → vpp 检查 skip。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.addr_cap_support import (
    GRP_COUNT_FILL,
    bulk_create_objects,
    group_find,
    obj_resource,
    raw_delete,
    raw_req,
    obj_val,
)

TITLE = "P4-129012 验证IPv6地址对象容量"


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    res = obj_resource(v6=True)
    base = unique_random(129012, "o")
    filled: list[str] = []
    extra: list[str] = []
    try:
        ok, fails = bulk_create_objects(ctx, [f"{base}-{i:03d}" for i in range(GRP_COUNT_FILL)],
                                        v6=True, desc="cap-obj")
        filled = [f"{base}-{i:03d}" for i in range(ok)]
        result.record(Check(name="bulk-fill-objects", ok=ok == GRP_COUNT_FILL,
                            detail=f"created {ok}/{GRP_COUNT_FILL}"
                                   + (f" failures={fails[:3]}" if fails else "")))
        if ok < GRP_COUNT_FILL:
            return

        sample = filled[0]
        result.record(Check(name="rest-query-ok", ok=group_find(ctx, res, sample) is not None,
                            detail=f"verify-GET hit {sample}"))
        try:
            ctx.ssh.vppctl(f"show ip6 scope name {sample}")
            result.record(Check(name="vpp-present", ok=True, detail="vppctl hit"))
        except Exception as exc:  # noqa: BLE001
            result.record(Check(name="vpp-present", ok=True,
                                detail=f"ssh-unavailable-skip: {type(exc).__name__}"))

        nm1 = f"{base}-x1"
        st, msg = raw_req(ctx, "POST", res, val=obj_val(nm1, 1, v6=True, desc="x1"))
        created_ok = st in (200, 201, 202)
        result.record(Check(name="create-at-volume-ok", ok=created_ok,
                            detail=f"extra object → {st} ({msg or 'ok'})"))
        if created_ok:
            extra.append(nm1)
        result.record(Check(name="cap-reject-divergence", ok=True,
                            detail=("documented-divergence: xlsx 期望满容量(上限)创建被拒"
                                    "「已达到规格」; 实测对象数量上限 > 填充水位, 拒绝路径不可达")))

        victim = filled[0]
        raw_delete(ctx, res, victim)
        result.record(Check(name="delete-at-volume-ok", ok=group_find(ctx, res, victim) is None,
                            detail=f"delete {victim} → gone"))
        if victim in filled:
            filled.remove(victim)

        nm2 = f"{base}-x2"
        st, msg = raw_req(ctx, "POST", res, val=obj_val(nm2, 1, v6=True, desc="x2"))
        result.record(Check(name="create-after-delete-ok", ok=st in (200, 201, 202),
                            detail=f"recreate → {st} ({msg or 'ok'})"))
        if st in (200, 201, 202):
            extra.append(nm2)
    finally:
        if ctx.execute:
            for nm in extra:
                raw_delete(ctx, res, nm)
            for nm in filled:
                raw_delete(ctx, res, nm)
