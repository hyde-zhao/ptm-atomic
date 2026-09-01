"""P1-197295: 新建本地证书失败测试

xlsx(对象管理用例_重构_563.xlsx): 无效值→失败; 修改不存在证书→失败; etcd 无 key
设备实测: 无效参数→eRequestParam; 不存在的 id update→拒
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok,
)

TITLE = "P1-197295 新建本地证书失败测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    try:
        from framework.checks import op_rejected
        out = ctx.runner.run("cert", "localcert-config", name="X" * 32, **base_kwargs("localcert"))
        result.record(op_rejected(out, ctx=ctx, label="invalid-value-rejected",
                                  expect_err_codes=("eRequestParamWithDetail",)))
        # check2: 修改不存在证书 → 失败。
        out = ctx.runner.run("cert", "localcert-issue", id="99999999",
                             cacert="defaultLocalCA.crt", option="1", time_length=30)
        result.record(op_rejected(out, ctx=ctx, label="update-nonexistent-rejected",
                                  expect_err_codes=("eRequestParam", "eObjParse", "putCertFailByIsNotCsr")))
    except Exception as exc:  # noqa: BLE001
        result.record(Check(name="create-fail", ok=False, detail=f"{type(exc).__name__}: {exc}"))
