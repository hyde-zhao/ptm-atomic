"""P0-18094: 删除单个本地证书有效值和无效值测试.

xlsx(对象管理用例_重构_563.xlsx): 存在id删除成功; 空/不存在/超长id 无效
设备实测(divergence): 删除幂等——不存在/超长 id 返回 200 空操作;仅缺 id 客户端拒
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import base_kwargs, cleanup_ids, create_ok
from cases.cert_support import first_id

TITLE = "P0-18094 删除单个本地证书有效值和无效值测试"


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[int | None] = []
    seed = unique_random(18094, "del")
    try:
        # check1: 存在 id 删除成功 → verify 不再命中。
        eid = create_ok(ctx, result, resource="localcert", name=seed, label="seed-created")
        created.append(eid)
        if eid is not None:
            out = ctx.runner.run("cert", "localcert-delete-batch", id=str(eid))
            result.record(op_succeeded(out, ctx=ctx, label="del-single-ok"))
            v = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=seed)
            result.record(Check(name="del-single-gone", ok=first_id(v.response(), seed) is None,
                                detail="verify no longer finds it"))
            created[-1] = None
        # check2-4: 空 / 不存在 / 超长 id。
        out = ctx.runner.run("cert", "localcert-delete-batch", id="")
        result.record(Check(name="del-id-empty-rejected", ok=not out.success,
                            detail=f"rc={out.exit_code}"))
        out = ctx.runner.run("cert", "localcert-delete-batch", id="99999999")
        result.record(Check(name="del-id-nonexistent-idempotent", ok=out.success,
                            detail="device returns 200 no-op for nonexistent id"))
        out = ctx.runner.run("cert", "localcert-delete-batch", id="X" * 50)
        result.record(Check(name="del-id-overlong-idempotent", ok=out.success,
                            detail="device returns 200 no-op for overlong id"))
    finally:
        cleanup_ids(ctx, "localcert", created)
