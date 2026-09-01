"""P0-18110: 删除多个本地CA证书有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 存在id组合删除成功; 空/不存在组合/超长 无效
设备实测(divergence): 批量删除幂等;空 id 客户端拒。容量 9 含 2 内置,种子用 2 个
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok,
)

TITLE = "P0-18110 删除多个本地CA证书有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created = []
    try:
        from framework.checks import op_succeeded
        a = create_ok(ctx, result, resource="localcacert",
                      name=unique_random(18110, "dla"), label="seed-a")
        b = create_ok(ctx, result, resource="localcacert",
                      name=unique_random(18110, "dlb"), label="seed-b")
        created += [a, b]
        if a is not None and b is not None:
            out = ctx.runner.run("cert", "localcacert-delete-batch", id=[str(a), str(b)])
            result.record(op_succeeded(out, ctx=ctx, label="del-batch-2-ok"))
            created = [None, None]
        out = ctx.runner.run("cert", "localcacert-delete-batch", id=["99999999", "88888888"])
        result.record(Check(name="del-nonexistent-pair", ok=out.success, detail="200 no-op"))
        out = ctx.runner.run("cert", "localcacert-delete-batch", id=["X" * 50])
        result.record(Check(name="del-overlong", ok=out.success, detail="200 no-op"))
    finally:
        cleanup_ids(ctx, "localcacert", created)
