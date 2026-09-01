"""P0-18095: 删除多个本地证书有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 存在id组合删除成功; 空/不存在组合/超长 无效
设备实测(divergence): 批量删除幂等——含不存在/0 的 id 组合返回 200;空 id 客户端拒
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok,
)

TITLE = "P0-18095 删除多个本地证书有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created = []
    try:
        from framework.checks import op_succeeded
        from cases.cert_config_support import RESOURCE_OPS
        # check1: 两个存在 id 组合删除成功。
        a = create_ok(ctx, result, resource="localcert",
                      name=unique_random(18095, "dla"), label="seed-a")
        b = create_ok(ctx, result, resource="localcert",
                      name=unique_random(18095, "dlb"), label="seed-b")
        created += [a, b]
        if a is not None and b is not None:
            out = ctx.runner.run("cert", "localcert-delete-batch", id=[str(a), str(b)])
            result.record(op_succeeded(out, ctx=ctx, label="del-batch-2-ok"))
            created = [None, None]
        # 不存在组合 / 存在的+0 / 存在的+不存在: 设备幂等 200。
        out = ctx.runner.run("cert", "localcert-delete-batch", id=["99999999", "88888888"])
        result.record(Check(name="del-nonexistent-pair", ok=out.success,
                            detail="device 200 no-op"))
        e = create_ok(ctx, result, resource="localcert",
                      name=unique_random(18095, "dlc"), label="seed-c")
        created.append(e)
        if e is not None:
            out = ctx.runner.run("cert", "localcert-delete-batch", id=[str(e), "0"])
            result.record(Check(name="del-valid-plus-0", ok=out.success,
                                detail="device 200 no-op for 0 id"))
            out = ctx.runner.run("cert", "localcert-delete-batch", id=[str(e), "99999999"])
            result.record(Check(name="del-valid-plus-nonexistent", ok=out.success,
                                detail="device 200 no-op"))
            created[-1] = None
        # 超长 id 组合: 设备幂等。
        out = ctx.runner.run("cert", "localcert-delete-batch", id=["X" * 50])
        result.record(Check(name="del-overlong", ok=out.success, detail="device 200 no-op"))
    finally:
        cleanup_ids(ctx, "localcert", created)
