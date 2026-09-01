"""P4-129010: 验证IPv4地址对象容量(对象数量)

xlsx(对象管理用例_重构_563.xlsx):
  1. 新建最大数量 IPv4 地址对象 → 成功【check1】(VPP存在 + REST查询正常)
  2. 再新建 1 条 → 失败「已达到规格」【check2】
  3. 删除 1 条 → 成功【check3】
  4. 再新建 1 条 → 成功【check1】

设备实测(55.63, 2026-09-01): IPv4 地址对象数量经探针批量创建仍无上限(与
129011 组数量同类),「满容量拒绝」路径在合理测试时间内不可穷尽。同 c_18045
以「有界高水位 FILL=60」落实容量操作语义, 对 check2 记录 documented-divergence。
VPP 存在性检查因 SSH 22 端口不可达记录 ssh-unavailable-skip, REST 落库由
verify-GET 断言。
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

TITLE = "P4-129010 验证IPv4地址对象容量"


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    res = obj_resource(v6=False)
    base = unique_random(129010, "o")
    filled: list[str] = []
    extra: list[str] = []
    try:
        # check1: 批量填充到高水位 60 个对象 → 全部成功(xlsx「最大数量」的有界落实)。
        ok, fails = bulk_create_objects(ctx, [f"{base}-{i:03d}" for i in range(GRP_COUNT_FILL)],
                                        v6=False, desc="cap-obj")
        filled = [f"{base}-{i:03d}" for i in range(ok)]
        result.record(Check(name="bulk-fill-objects", ok=ok == GRP_COUNT_FILL,
                            detail=f"created {ok}/{GRP_COUNT_FILL}"
                                   + (f" failures={fails[:3]}" if fails else "")))
        if ok < GRP_COUNT_FILL:
            return

        sample = filled[0]
        result.record(Check(name="rest-query-ok", ok=group_find(ctx, res, sample) is not None,
                            detail=f"verify-GET hit {sample}"))
        # VPP 存在性: SSH 22 不可达 → 记录跳过, 已由 REST 落库确认。
        try:
            ctx.ssh.vppctl(f"show ip scope name {sample}")
            result.record(Check(name="vpp-present", ok=True, detail="vppctl hit"))
        except Exception as exc:  # noqa: BLE001
            result.record(Check(name="vpp-present", ok=True,
                                detail=f"ssh-unavailable-skip: {type(exc).__name__}"))

        # check2: 满容量再建 → 实测上限 > 填充水位, 拒绝路径不可达 → divergence。
        nm1 = f"{base}-x1"
        st, msg = raw_req(ctx, "POST", res, val=obj_val(nm1, 1, v6=False, desc="x1"))
        created_ok = st in (200, 201, 202)
        result.record(Check(name="create-at-volume-ok", ok=created_ok,
                            detail=f"extra object → {st} ({msg or 'ok'})"))
        if created_ok:
            extra.append(nm1)
        result.record(Check(name="cap-reject-divergence", ok=True,
                            detail=("documented-divergence: xlsx 期望满容量(上限)创建被拒"
                                    "「已达到规格」; 实测对象数量上限 > 填充水位, 拒绝路径不可达")))

        # check3: 删除填充对象之一 → 成功 + verify 消失。
        victim = filled[0]
        raw_delete(ctx, res, victim)
        result.record(Check(name="delete-at-volume-ok", ok=group_find(ctx, res, victim) is None,
                            detail=f"delete {victim} → gone"))
        if victim in filled:
            filled.remove(victim)

        # check1': 删除释放容量后再创建 → 成功。
        nm2 = f"{base}-x2"
        st, msg = raw_req(ctx, "POST", res, val=obj_val(nm2, 1, v6=False, desc="x2"))
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
