"""P0-18040: 删除单个mac地址有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 删除存在→成功; 空/不存在/超长 id→失败
设备实测: 单删 DELETE ?id=<name>; 不存在/超长→can't delete macpool(拒); 空 id→客户端必填
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_OK, absent_check, cleanup_names, create_ok

TITLE = "P0-18040 删除单个mac地址有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        created.append(unique_random(18040, "del"))
        create_ok(ctx, result, name=created[-1], label="seed", macs=[MAC_OK])
        out = ctx.runner.run("mac-pool", "delete", id=created[-1])
        result.record(op_succeeded(out, ctx=ctx, label="delete-exist-ok"))
        if ctx.execute and out.success:
            absent_check(ctx, result, name=created[-1], label="delete-exist-absent")
            created.pop()
        # 空 id → 客户端必填。
        out = ctx.runner.run("mac-pool", "delete", id="")
        result.record(op_rejected(out, ctx=ctx, label="delete-empty-rejected"))
        # 不存在的 id → 拒。
        out = ctx.runner.run("mac-pool", "delete", id=unique_random(18040, "nosuch"))
        result.record(op_rejected(out, ctx=ctx, label="delete-nonexistent-rejected"))
        # 超长字符串 id → 拒。
        out = ctx.runner.run("mac-pool", "delete", id="M" * 100)
        result.record(op_rejected(out, ctx=ctx, label="delete-overlong-rejected"))
    finally:
        cleanup_names(ctx, created)
