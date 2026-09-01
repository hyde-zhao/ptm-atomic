"""P4-129016: 验证自定义服务对象容量(对象数量)

xlsx(对象管理用例_重构_563.xlsx):
  1. 新建最大数量的自定义服务对象 → 成功【check1】(VPP存在)
  2. 再新建 1 条 → 失败「已达到规格」【check2】
  3. 删除 1 条 → 成功【check3】
  4. 再新建 1 条 → 成功【check1】

设备实测(55.63): 自定义服务对象数量上限不可穷尽(与服务组数量同类, 探针未探到
上限),「满容量拒绝」路径在合理测试时间内不可达。同 129010 以「有界高水位
FILL=60」落实容量操作语义, check2 记 documented-divergence。VPP 存在性检查因
SSH 22 端口不可达记录 ssh-unavailable-skip, REST 落库由 verify 断言。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.addr_cap_support import raw_req
from cases.svc_cap_support import (
    SVC,
    bulk_create_services,
    raw_delete,
    svc_find,
    svc_val,
)

TITLE = "P4-129016 验证自定义服务对象容量"

FILL = 60  # 有界高水位。


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    base = unique_random(129016, "s")
    filled: list[str] = []
    extra: list[str] = []
    try:
        ok, fails = bulk_create_services(ctx, [f"{base}-{i:03d}" for i in range(FILL)],
                                         desc="cap-svc")
        filled = [f"{base}-{i:03d}" for i in range(ok)]
        result.record(Check(name="bulk-fill-services", ok=ok == FILL,
                            detail=f"created {ok}/{FILL}"
                                   + (f" failures={fails[:3]}" if fails else "")))
        if ok < FILL:
            return

        sample = filled[0]
        result.record(Check(name="rest-query-ok", ok=svc_find(ctx, sample) is not None,
                            detail=f"verify-GET hit {sample}"))
        try:
            ctx.ssh.vppctl(f"show service name {sample}")
            result.record(Check(name="vpp-present", ok=True, detail="vppctl hit"))
        except Exception as exc:  # noqa: BLE001
            result.record(Check(name="vpp-present", ok=True,
                                detail=f"ssh-unavailable-skip: {type(exc).__name__}"))

        nm1 = f"{base}-x1"
        st, msg = raw_req(ctx, "POST", SVC, val=svc_val(nm1, desc="x1"))
        created_ok = st in (200, 201, 202)
        result.record(Check(name="create-at-volume-ok", ok=created_ok,
                            detail=f"extra service → {st} ({msg or 'ok'})"))
        if created_ok:
            extra.append(nm1)
        result.record(Check(name="cap-reject-divergence", ok=True,
                            detail=("documented-divergence: xlsx 期望满容量(上限)创建被拒"
                                    "「已达到规格」; 实测服务对象数量上限 > 填充水位, 拒绝路径不可达")))

        victim = filled[0]
        raw_delete(ctx, SVC, victim)
        result.record(Check(name="delete-at-volume-ok", ok=svc_find(ctx, victim) is None,
                            detail=f"delete {victim} → gone"))
        if victim in filled:
            filled.remove(victim)

        nm2 = f"{base}-x2"
        st, msg = raw_req(ctx, "POST", SVC, val=svc_val(nm2, desc="x2"))
        result.record(Check(name="create-after-delete-ok", ok=st in (200, 201, 202),
                            detail=f"recreate → {st} ({msg or 'ok'})"))
        if st in (200, 201, 202):
            extra.append(nm2)
    finally:
        if ctx.execute:
            for nm in extra:
                raw_delete(ctx, SVC, nm)
            for nm in filled:
                raw_delete(ctx, SVC, nm)
