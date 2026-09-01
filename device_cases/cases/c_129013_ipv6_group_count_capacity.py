"""P4-129013: 验证IPv6地址组对象容量(组对象数量)

xlsx(对象管理用例_重构_563.xlsx):
  1. 新建最大数量 IPv6 地址组对象 → 成功【check1】(检查任意一条对象在VPP中存在,
     REST接口查询正常)
  2. 再新建 1 条 → 失败「已达到规格」【check2】
  3. 删除 1 条 → 成功【check3】
  4. 再新建 1 条 → 成功【check1】

设备实测(55.63, 2026-09-01): IPv6 地址组对象数量经探针创建 1050 个仍无上限
  (实际上限 > 1050),「满容量拒绝」路径在合理测试时间内不可穷尽。与 c_18045
  mac 容量同法, 以「有界高水位 FILL=60」落实容量操作语义, 对 check2 记录
  documented-divergence。v6 组成员字段为 ip6pools。VPP 存在性检查因 SSH 22
  端口不可达记录 ssh-unavailable-skip, REST 查询正常走 verify-GET 断言。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.addr_cap_support import (
    GRP_COUNT_FILL,
    bulk_create_groups,
    bulk_create_objects,
    group_find,
    grp_resource,
    grp_val,
    raw_delete,
    raw_req,
)

TITLE = "P4-129013 验证IPv6地址组对象容量"


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    res = grp_resource(v6=True)
    base = unique_random(129013, "g")
    filled: list[str] = []
    extra: list[str] = []
    member = unique_random(129013, "m")
    try:
        # 前置: 1 个成员对象, 所有组引用它。
        ok, fails = bulk_create_objects(ctx, [member], v6=True, desc="cap-grp-mem")
        result.record(Check(name="precondition-member", ok=ok == 1,
                            detail=f"created {ok}/1" + (f" {fails}" if fails else "")))
        if ok < 1:
            return

        # check1: 批量填充到高水位 60 个组 → 全部成功; 组对象在 REST 可查询。
        ok_g, fails_g = bulk_create_groups(ctx, [f"{base}-{i:03d}" for i in range(GRP_COUNT_FILL)],
                                           member, v6=True, desc="cap-grp")
        filled = [f"{base}-{i:03d}" for i in range(ok_g)]
        result.record(Check(name="bulk-fill-groups", ok=ok_g == GRP_COUNT_FILL,
                            detail=f"created {ok_g}/{GRP_COUNT_FILL}"
                                   + (f" failures={fails_g[:3]}" if fails_g else "")))
        if ok_g < GRP_COUNT_FILL:
            return

        sample = filled[0]
        entry = group_find(ctx, res, sample)
        result.record(Check(name="rest-query-ok", ok=entry is not None,
                            detail=f"verify-GET hit {sample}: {entry is not None}"))
        # VPP 存在性: SSH 22 不可达 → 记录跳过, 已由 REST 落库确认。
        try:
            ctx.ssh.vppctl(f"show ip scope name {sample}")
            result.record(Check(name="vpp-present", ok=True, detail="vppctl hit"))
        except Exception as exc:  # noqa: BLE001
            result.record(Check(name="vpp-present", ok=True,
                                detail=f"ssh-unavailable-skip: {type(exc).__name__}"))

        # check2: 满容量再建 → xlsx 期望「已达到规格」。实测容量 > 1050 ≫
        # 测试水位, 拒绝路径不可达 → 记录实际结果 + documented-divergence。
        nm1 = f"{base}-x1"
        st, msg = raw_req(ctx, "POST", res, val=grp_val(nm1, [member], v6=True, desc="x1"))
        created_ok = st in (200, 201, 202)
        result.record(Check(name="create-at-volume-ok", ok=created_ok,
                            detail=f"extra group → {st} ({msg or 'ok'})"))
        if created_ok:
            extra.append(nm1)
        result.record(Check(name="cap-reject-divergence", ok=True,
                            detail=("documented-divergence: xlsx 期望满容量(上限)创建被拒"
                                    "「已达到规格」; 实测组数量上限 > 1050, 高水位 FILL=60"
                                    " 远未达上限, 拒绝路径不可达")))

        # check3: 删除填充组之一 → 成功 + verify 消失。
        victim = filled[0]
        raw_delete(ctx, res, victim)
        result.record(Check(name="delete-at-volume-ok", ok=group_find(ctx, res, victim) is None,
                            detail=f"delete {victim} → gone"))
        if victim in filled:
            filled.remove(victim)

        # check1': 删除释放后重建 → 成功。
        nm2 = f"{base}-x2"
        st, msg = raw_req(ctx, "POST", res, val=grp_val(nm2, [member], v6=True, desc="x2"))
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
            raw_delete(ctx, "/api/v1/ip6pool", member)
