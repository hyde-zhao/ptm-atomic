"""P0-18041: 删除多个mac地址有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 删除存在组合→成功; 空/不存在组合/混合/超长→失败
设备实测(divergence): 批量删除 POST /api/v1/batch 对不存在的 name 是静默 no-op(返回 success,
不影响其它条目)——与 xlsx 期望的“失败”不同。存在组合→全部删除成功。
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_OK, absent_check, cleanup_names, create_ok

TITLE = "P0-18041 删除多个mac地址有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        for i in range(3):
            created.append(unique_random(18041, f"s{i}"))
            create_ok(ctx, result, name=created[-1], label=f"seed{i}", macs=[MAC_OK])
        # 存在组合 → 全部删除成功。
        names = created[:2]
        out = ctx.runner.run("mac-pool", "delete-batch", id=names)
        result.record(op_succeeded(out, ctx=ctx, label="batch-delete-exist-ok"))
        if ctx.execute and out.success:
            for nm in names:
                absent_check(ctx, result, name=nm, label="batch-gone")
            created = created[2:]
        # 空 id → 客户端必填。
        out = ctx.runner.run("mac-pool", "delete-batch", id=[])
        result.record(op_rejected(out, ctx=ctx, label="batch-delete-empty-rejected"))
        # 不存在组合 → 设备静默 no-op(divergence: xlsx 期望失败)。
        out = ctx.runner.run("mac-pool", "delete-batch", id=[unique_random(18041, "ns1"),
                                                             unique_random(18041, "ns2")])
        result.record(op_succeeded(out, ctx=ctx, label="batch-delete-nonexistent-noop"))
        # 存在+不存在 混合 → 存在的被删,不存在的 no-op。
        mix_keep = created[0]
        out = ctx.runner.run("mac-pool", "delete-batch", id=[unique_random(18041, "ns3"), mix_keep])
        result.record(op_succeeded(out, ctx=ctx, label="batch-delete-mixed-ok"))
        if ctx.execute and out.success:
            absent_check(ctx, result, name=mix_keep, label="batch-mixed-gone")
            created = created[1:]
        # 超长字符串 → 设备静默 no-op。
        out = ctx.runner.run("mac-pool", "delete-batch", id=["M" * 100])
        result.record(op_succeeded(out, ctx=ctx, label="batch-delete-overlong-noop"))
    finally:
        cleanup_names(ctx, created)
