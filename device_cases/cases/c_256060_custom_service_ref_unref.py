"""P2-256060: 自定义服务的引用与解引用测试

xlsx(对象管理用例_重构_563.xlsx):
  1. 新建自定义服务【check1】
  2. 新建服务组, 引用自定义服务【check2】
  3. 尝试删除被引用的自定义服务【check3】→ 无法删除
  4. 解除服务组占用的自定义服务, 再删除【check4】→ 可以删除

设备实测(55.63, 2026-09-01): 删除被组引用的服务 → 400「{name}被引用无法被删除」。
  解引用方式: 服务组不允许空成员列表(PUT 空列表 → 400「服务对象列表为空」), 因此
  「解除占用」落实为把组成员从 [S1] 更新为 [S2], 之后 S1 可正常删除。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.svc_cap_support import (
    SVC,
    SVC_GRP,
    grp_find,
    grp_val,
    raw_delete,
    raw_req,
    svc_find,
    svc_val,
)

TITLE = "P2-256060 自定义服务的引用与解引用测试"

_ERR_REFERENCED = "被引用无法被删除"


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    base = unique_random(256060, "s")
    s1 = f"{base}-s1"
    s2 = f"{base}-s2"
    g = unique_random(256060, "g")
    try:
        # check1: 新建自定义服务 → 成功 + 落库可查。
        st, msg = raw_req(ctx, "POST", SVC, val=svc_val(s1, desc="ref-test"))
        result.record(Check(name="create-custom-service", ok=st in (200, 201, 202),
                            detail=f"create {s1} → {st} ({msg or 'ok'})"))
        st, msg = raw_req(ctx, "POST", SVC, val=svc_val(s2, desc="ref-test"))
        result.record(Check(name="create-helper-service", ok=st in (200, 201, 202),
                            detail=f"create helper {s2} → {st} ({msg or 'ok'})"))
        if svc_find(ctx, s1) is None:
            return

        # check2: 新建服务组, 引用 s1 → 成功 + 组成员校验。
        st, msg = raw_req(ctx, "POST", SVC_GRP, val=grp_val(g, [s1], desc="ref-test"))
        result.record(Check(name="create-group-ref", ok=st in (200, 201, 202),
                            detail=f"group {g}=[{s1}] → {st} ({msg or 'ok'})"))
        entry = grp_find(ctx, g)
        result.record(Check(name="group-member-stored", ok=entry is not None
                            and s1 in (entry.get("servicepools") or []),
                            detail=f"servicepools contains {s1}: {entry is not None}"))
        if entry is None or s1 not in (entry.get("servicepools") or []):
            return

        # check3: 删除被引用的 s1 → 失败「被引用无法被删除」。
        st, msg = raw_req(ctx, "DELETE", SVC, ident=s1)
        rejected = st not in (200, 201, 202)
        hit = _ERR_REFERENCED in msg
        result.record(Check(name="delete-referenced-reject", ok=rejected and hit,
                            detail=f"delete referenced {s1} → {st} ({msg or ''})"
                                   + ("" if hit else " errmsg-miss")))
        result.record(Check(name="still-present-after-reject", ok=svc_find(ctx, s1) is not None,
                            detail="s1 still present after rejected delete"))

        # check4: 解除占用(组 [s1]→[s2]) → 再删除 s1 成功。
        st, msg = raw_req(ctx, "PUT", SVC_GRP, ident=g, val=grp_val(g, [s2], desc="unref"))
        result.record(Check(name="unref-update-group", ok=st in (200, 201, 202),
                            detail=f"update {g}=[{s2}] → {st} ({msg or 'ok'})"))
        if st in (200, 201, 202):
            st, msg = raw_req(ctx, "DELETE", SVC, ident=s1)
            result.record(Check(name="delete-after-unref-ok", ok=st in (200, 201, 202),
                                detail=f"delete {s1} after unref → {st} ({msg or 'ok'})"))
            result.record(Check(name="gone-after-delete", ok=svc_find(ctx, s1) is None,
                                detail=f"{s1} gone from query"))
    finally:
        if ctx.execute:
            raw_delete(ctx, SVC_GRP, g)
            raw_delete(ctx, SVC, s1)
            raw_delete(ctx, SVC, s2)
