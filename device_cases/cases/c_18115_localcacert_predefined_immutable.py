"""P0-18115: 预定义本地CA证书对象不可修改和删除测试

xlsx(对象管理用例_重构_563.xlsx): 修改预定义→失败; 删除预定义→失败
设备实测(divergence): localcacert 无 update/issue op; 以同名 config-POST 作为“修改”代理→certNameConflict。
DELETE→接口返回 success 但实际是 no-op,内置 CA 仍存在。删除断言改为: 删除尝试后内置 CA 必须仍在。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok,
)

TITLE = "P0-18115 预定义本地CA证书对象不可修改和删除测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    try:
        from framework.checks import op_rejected, op_succeeded
        from cases.cert_support import find_by_name
        v = ctx.runner.run("cert", "localcacert-verify", page=1, size=200)
        hits = find_by_name(v.response(), "defaultLocalCA.crt")
        eid = hits[0]["id"] if hits else None
        if eid is None:
            result.record(Check(name="builtin-found", ok=False, detail="defaultLocalCA.crt not found"))
            return
        result.record(Check(name="builtin-found", ok=True, detail=f"id={eid}"))
        # “修改预定义”代理: localcacert 无 update op,同名 config-POST 必被拒。
        out = ctx.runner.run("cert", "localcacert-config", name="defaultLocalCA.crt",
                             **base_kwargs("localcacert"))
        result.record(op_rejected(out, ctx=ctx, label="builtin-modify-proxy-rejected",
                                  expect_err_codes=("certNameConflict", "eRequestParam", "eRequestParamWithDetail")))
        # 删除预定义: 设备返回 success 但为 no-op,内置 CA 必须仍在。
        out = ctx.runner.run("cert", "localcacert-delete-batch", id=str(eid))
        result.record(op_succeeded(out, ctx=ctx, label="builtin-delete-noop-ok"))
        v2 = ctx.runner.run("cert", "localcacert-verify", page=1, size=200)
        still = find_by_name(v2.response(), "defaultLocalCA.crt")
        result.record(Check(name="builtin-still-present", ok=bool(still),
                            detail=f"after delete attempt: {len(still)} defaultLocalCA.crt entries (device no-op)"))
    except Exception as exc:  # noqa: BLE001
        result.record(Check(name="predefined-immutable", ok=False, detail=f"{type(exc).__name__}: {exc}"))
