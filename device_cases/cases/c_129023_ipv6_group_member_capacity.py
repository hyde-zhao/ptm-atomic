"""P4-129023: 单个IPv6地址组对象最大容量测试

xlsx(对象管理用例_重构_563.xlsx): 预建 257 个 IPv6 地址对象 →
  1. 建组含 256 个 → 成功【check1】
  2. 建组含 257 个 → 失败「IPv6地址组对象单个容量超过限制,当前配置数量257」【check2】
  3. 编辑组含 256 个 → 成功【check3】
  4. 编辑组含 257 个 → 失败【check4】

设备实测(55.63, 2026-09-01): IPv6 地址组最大成员 256(256→成功, 257→拒绝),
  与 xlsx 一致。v6 组成员字段为 ip6pools。257 个成员对象为前置条件, 走
  raw REST 批量创建(秒级)。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.addr_cap_support import (
    GRP_MAX_MEMBERS,
    bulk_create_objects,
    grp_resource,
    grp_val,
    raw_delete,
    raw_req,
    record_cap,
    verify_member_count,
)

TITLE = "P4-129023 单个IPv6地址对象，最大容量测试"

_ERR_NEEDLE = "容量超过限制"
_N_MEMBERS = GRP_MAX_MEMBERS + 1  # 257


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    res = grp_resource(v6=True)
    base = unique_random(129023, "m")
    members = [f"{base}-{i:03d}" for i in range(_N_MEMBERS)]
    g_ok = unique_random(129023, "g")
    try:
        # 前置: 批量创建 257 个成员对象。
        ok, fails = bulk_create_objects(ctx, members, v6=True, desc="cap-mem")
        result.record(Check(name="precondition-257-members", ok=ok == _N_MEMBERS,
                            detail=f"created {ok}/{_N_MEMBERS}"
                                   + (f" failures={fails[:3]}" if fails else "")))
        if ok < _N_MEMBERS:
            return

        # check1: 建组含 256 个 → 成功 + 落库成员数校验。
        st, _ = raw_req(ctx, "POST", res, val=grp_val(g_ok, members[:GRP_MAX_MEMBERS], v6=True))
        record_cap(ctx, result, label="create-256-ok", status=st, expect_ok=True,
                   want=GRP_MAX_MEMBERS)
        if st in (200, 201, 202):
            verify_member_count(ctx, result, resource=res, name=g_ok,
                                expect=GRP_MAX_MEMBERS, label="stored-members-256")

        # check2: 建组含 257 个 → 失败(容量超限)。
        g_bad = unique_random(129023, "gb")
        st, msg = raw_req(ctx, "POST", res, val=grp_val(g_bad, members, v6=True))
        record_cap(ctx, result, label="create-257-reject", status=st, expect_ok=False,
                   want=_N_MEMBERS, msg=msg, err_needle=_ERR_NEEDLE)

        # check3: 编辑已有组 → 256 个(不同成员集合)成功 + 落库校验。
        st, _ = raw_req(ctx, "PUT", res, ident=g_ok,
                        val=grp_val(g_ok, members[1:GRP_MAX_MEMBERS + 1], v6=True, desc="cap-edited"))
        record_cap(ctx, result, label="update-256-ok", status=st, expect_ok=True,
                   want=GRP_MAX_MEMBERS)
        if st in (200, 201, 202):
            verify_member_count(ctx, result, resource=res, name=g_ok,
                                expect=GRP_MAX_MEMBERS, label="stored-members-after-update-256")

        # check4: 编辑 → 257 个失败; 组保持 256。
        st, msg = raw_req(ctx, "PUT", res, ident=g_ok,
                          val=grp_val(g_ok, members, v6=True, desc="bad"))
        record_cap(ctx, result, label="update-257-reject", status=st, expect_ok=False,
                   want=_N_MEMBERS, msg=msg, err_needle=_ERR_NEEDLE)
    finally:
        if ctx.execute:
            raw_delete(ctx, res, g_ok)
            for nm in members:
                raw_delete(ctx, "/api/v1/ip6pool", nm)
