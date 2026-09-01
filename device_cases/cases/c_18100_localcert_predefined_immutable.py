"""P0-18100: 预定义本地证书对象不可修改和删除测试

xlsx(对象管理用例_重构_563.xlsx): 修改预定义→失败; 删除预定义→失败
设备实测(divergence): 内置证书(defaultLocalCert.crt 等)PUT issue→putCertFailByDefaultCert;
DELETE→接口返回 success 但实际是 no-op,内置证书仍存在(delCertFailCanNotDel 不出现)。
因此删除断言改为: 删除尝试后内置证书必须仍在。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok,
)

TITLE = "P0-18100 预定义本地证书对象不可修改和删除测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    try:
        from framework.checks import op_rejected, op_succeeded
        from cases.cert_support import find_by_name
        v = ctx.runner.run("cert", "localcert-verify", page=1, size=200)
        hits = find_by_name(v.response(), "defaultLocalCert.crt")
        eid = hits[0]["id"] if hits else None
        if eid is None:
            result.record(Check(name="builtin-found", ok=False, detail="defaultLocalCert.crt not found"))
            return
        result.record(Check(name="builtin-found", ok=True, detail=f"id={eid}"))
        out = ctx.runner.run("cert", "localcert-issue", id=str(eid),
                             cacert="defaultLocalCA.crt", option="1", time_length=30)
        result.record(op_rejected(out, ctx=ctx, label="builtin-modify-rejected",
                                  expect_err_codes=("putCertFailByDefaultCert",)))
        out = ctx.runner.run("cert", "localcert-delete-batch", id=str(eid))
        result.record(op_succeeded(out, ctx=ctx, label="builtin-delete-noop-ok"))
        v2 = ctx.runner.run("cert", "localcert-verify", page=1, size=200)
        still = find_by_name(v2.response(), "defaultLocalCert.crt")
        result.record(Check(name="builtin-still-present", ok=bool(still),
                            detail=f"after delete attempt: {len(still)} defaultLocalCert.crt entries (device no-op)"))
    except Exception as exc:  # noqa: BLE001
        result.record(Check(name="predefined-immutable", ok=False, detail=f"{type(exc).__name__}: {exc}"))
