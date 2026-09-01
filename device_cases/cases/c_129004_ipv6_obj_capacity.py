"""P4-129004: 单个IPv6地址对象最大容量测试

xlsx(对象管理用例_重构_563.xlsx): IP 地址含掩码共 2048 个字符 → 新建成功;
  2049 字符 → 新建失败「ipv6地址对象单个容量超过限制,当前配置数量2049」;
  编辑 2048/2049 字符同理。

设备实测(55.63, 2026-09-01): 设备按「网络条目数」计容量而非字符数,
  IPv6 地址对象上限 1024 条(1024→成功, 1025→拒绝「当前配置数量 1025」)。
  xlsx 的 2048 字符近似于此上限(按 v6 条目平均字符换算), 本用例以条目数
  落实容量边界, 记录 documented-divergence。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.addr_cap_support import (
    OBJ_MAX_NETWORKS,
    obj_resource,
    obj_val,
    raw_delete,
    raw_req,
    record_cap,
    verify_network_count,
)

TITLE = "P4-129004 单个IPv6地址对象，最大容量测试"

_ERR_NEEDLE = "容量超过限制"


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    res = obj_resource(v6=True)
    a = unique_random(129004, "a")
    try:
        # check1: 1024 条 → 新建成功 + 落库条数校验。
        st, _ = raw_req(ctx, "POST", res, val=obj_val(a, OBJ_MAX_NETWORKS, v6=True))
        record_cap(ctx, result, label="create-1024-ok", status=st, expect_ok=True,
                   want=OBJ_MAX_NETWORKS)
        if st in (200, 201, 202):
            verify_network_count(ctx, result, resource=res, name=a,
                                 expect=OBJ_MAX_NETWORKS, label="stored-count-1024")

        # check2: 1025 条 → 新建失败(容量超限)。
        b = unique_random(129004, "b")
        st, msg = raw_req(ctx, "POST", res, val=obj_val(b, OBJ_MAX_NETWORKS + 1, v6=True))
        record_cap(ctx, result, label="create-1025-reject", status=st, expect_ok=False,
                   want=OBJ_MAX_NETWORKS + 1, msg=msg, err_needle=_ERR_NEEDLE)

        # check3: 编辑已有对象 → 1024 条成功 + 落库校验。
        st, _ = raw_req(ctx, "PUT", res, ident=a,
                        val=obj_val(a, OBJ_MAX_NETWORKS, v6=True, desc="cap-edited"))
        record_cap(ctx, result, label="update-1024-ok", status=st, expect_ok=True,
                   want=OBJ_MAX_NETWORKS)
        if st in (200, 201, 202):
            verify_network_count(ctx, result, resource=res, name=a,
                                 expect=OBJ_MAX_NETWORKS, label="stored-count-after-update-1024")

        # check4: 编辑 → 1025 条失败; 对象保持 1024。
        st, msg = raw_req(ctx, "PUT", res, ident=a,
                          val=obj_val(a, OBJ_MAX_NETWORKS + 1, v6=True, desc="bad"))
        record_cap(ctx, result, label="update-1025-reject", status=st, expect_ok=False,
                   want=OBJ_MAX_NETWORKS + 1, msg=msg, err_needle=_ERR_NEEDLE)
    finally:
        if ctx.execute:
            raw_delete(ctx, res, a)
