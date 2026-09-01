"""P1-168961: MAC地址对象配置下发成功测试

xlsx(对象管理用例_重构_563.xlsx): 新建/编辑 成功; 查询字段一致; etcd/vppctl 下发一致
设备实测: REST verify 返回 name/macaddrs/desc/type 与下发一致; etcd/vppctl 需 SSH(当前通道
不可达→记录 skip,对象已由 verify-GET 值比对确认)。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import (
    MAC_OK, cleanup_names, create_ok, update_ok,
)

TITLE = "P1-168961 MAC地址对象配置下发成功测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        created.append(unique_random(168961, "ok"))
        entry = create_ok(ctx, result, name=created[-1], label="create",
                          desc="下发成功", macs=[MAC_OK])
        if entry is not None:
            result.record(Check(name="create-fields", ok=(
                entry.get("name") == created[-1]
                and entry.get("type") in (2, "2")
                and entry.get("desc") == "下发成功"
                and [e.get("mac") for e in entry.get("macaddrs") or []] == [MAC_OK]),
                detail=f"fields name={entry.get('name')} type={entry.get('type')} desc={entry.get('desc')}"))
        update_ok(ctx, result, name=created[-1], label="edit", desc="下发成功2",
                  macs=["66:55:44:33:22:11"])
    finally:
        cleanup_names(ctx, created)
