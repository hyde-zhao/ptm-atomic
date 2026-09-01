"""P1-197294: 新建本地证书成功测试

xlsx(对象管理用例_重构_563.xlsx): 新建成功→etcd key 存在; 修改成功
设备实测: config→verify 命中→etcd /vnf-agent/vpp1/config/cert/v1/localcert/<id> 存在
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok,
)

TITLE = "P1-197294 新建本地证书成功测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created = []
    try:
        from framework.checks import op_succeeded
        name = unique_random(197294, "ok")
        eid = create_ok(ctx, result, resource="localcert", name=name, label="create-success")
        created.append(eid)
        if eid is not None:
            # check2: 修改(issue 自签)→ 成功。
            out = ctx.runner.run("cert", "localcert-issue", id=str(eid),
                                 cacert="defaultLocalCA.crt", option="1", time_length=30)
            result.record(op_succeeded(out, ctx=ctx, label="update-success"))
    finally:
        cleanup_ids(ctx, "localcert", created)
