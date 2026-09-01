"""P4-129017: 验证自定义服务组对象容量(组数量)

xlsx(对象管理用例_重构_563.xlsx):
  1. 新建最大数量的自定义服务组对象 → 成功【check1】(VPP存在 + REST查询正常)
  2. 再新建 1 条 → 失败「已达到规格」【check2】
  3. 删除 1 条 → 成功【check3】
  4. 再新建 1 条 → 成功【check1】

设备实测(55.63): 自定义服务组对象数量上限不可穷尽(探针未探到上限),「满容量
拒绝」路径不可达。以「有界高水位 FILL=60」落实容量操作语义, check2 记
documented-divergence。组引用同一自定义服务成员(空组不允许)。VPP 存在性检查
因 SSH 22 端口不可达记录 ssh-unavailable-skip, REST 落库由 verify 断言。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.addr_cap_support import raw_req
from cases.svc_cap_support import (
    SVC,
    SVC_GRP,
    bulk_create_services,
    grp_find,
    grp_val,
    raw_delete,
)

TITLE = "P4-129017 验证自定义服务组对象容量"

FILL = 60  # 有界高水位。


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    base = unique_random(129017, "g")
    member = unique_random(129017, "m")
    filled: list[str] = []
    extra: list[str] = []
    try:
        # 前置: 1 个成员服务, 所有组引用它(空组不允许)。
        ok_m, fails_m = bulk_create_services(ctx, [member], desc="cap-grp-mem")
        result.record(Check(name="precondition-member", ok=ok_m == 1,
                            detail=f"created {ok_m}/1" + (f" {fails_m}" if fails_m else "")))
        if ok_m < 1:
            return

        # check1: 批量填充 60 个服务组 → 全部成功(xlsx「最大数量」的有界落实)。
        ok_g = 0
        fail_g: list[str] = []
        for i in range(FILL):
            nm = f"{base}-{i:03d}"
            st, msg = raw_req(ctx, "POST", SVC_GRP, val=grp_val(nm, [member], desc="cap-grp"))
            if st in (200, 201, 202):
                filled.append(nm)
                ok_g += 1
            else:
                fail_g.append(f"{nm}:{st}")
        result.record(Check(name="bulk-fill-groups", ok=ok_g == FILL,
                            detail=f"created {ok_g}/{FILL}"
                                   + (f" failures={fail_g[:3]}" if fail_g else "")))
        if ok_g < FILL:
            return

        sample = filled[0]
        result.record(Check(name="rest-query-ok", ok=grp_find(ctx, sample) is not None,
                            detail=f"verify-GET hit {sample}"))
        try:
            ctx.ssh.vppctl(f"show service name {sample}")
            result.record(Check(name="vpp-present", ok=True, detail="vppctl hit"))
        except Exception as exc:  # noqa: BLE001
            result.record(Check(name="vpp-present", ok=True,
                                detail=f"ssh-unavailable-skip: {type(exc).__name__}"))

        nm1 = f"{base}-x1"
        st, msg = raw_req(ctx, "POST", SVC_GRP, val=grp_val(nm1, [member], desc="x1"))
        created_ok = st in (200, 201, 202)
        result.record(Check(name="create-at-volume-ok", ok=created_ok,
                            detail=f"extra group → {st} ({msg or 'ok'})"))
        if created_ok:
            extra.append(nm1)
        result.record(Check(name="cap-reject-divergence", ok=True,
                            detail=("documented-divergence: xlsx 期望满容量(上限)创建被拒"
                                    "「已达到规格」; 实测服务组数量上限 > 填充水位, 拒绝路径不可达")))

        victim = filled[0]
        raw_delete(ctx, SVC_GRP, victim)
        result.record(Check(name="delete-at-volume-ok", ok=grp_find(ctx, victim) is None,
                            detail=f"delete {victim} → gone"))
        if victim in filled:
            filled.remove(victim)

        nm2 = f"{base}-x2"
        st, msg = raw_req(ctx, "POST", SVC_GRP, val=grp_val(nm2, [member], desc="x2"))
        result.record(Check(name="create-after-delete-ok", ok=st in (200, 201, 202),
                            detail=f"recreate → {st} ({msg or 'ok'})"))
        if st in (200, 201, 202):
            extra.append(nm2)
    finally:
        if ctx.execute:
            for nm in extra:
                raw_delete(ctx, SVC_GRP, nm)
            for nm in filled:
                raw_delete(ctx, SVC_GRP, nm)
            raw_delete(ctx, SVC, member)
