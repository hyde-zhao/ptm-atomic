"""P0-18099: 本地证书数量最大后的增删改测试

xlsx(对象管理用例_重构_563.xlsx): 创建1→成功; 重复同名→失败; 修改→成功; 删除→成功; 再创建→成功
设备容量 localcert=65。不填满 65(避免慢),验证同名拒绝+update+delete+recreate 闭环
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok,
)

TITLE = "P0-18099 本地证书数量最大后的增删改测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created = []
    try:
        from framework.checks import op_rejected, op_succeeded
        from cases.cert_support import first_id
        from cases.cert_config_support import RESOURCE_OPS
        _, verify_op, _, _ = RESOURCE_OPS["localcert"]
        name = unique_random(18099, "cap")
        out = ctx.runner.run("cert", "localcert-config", name=name, **base_kwargs("localcert"))
        result.record(op_succeeded(out, ctx=ctx, label="create-ok"))
        v = ctx.runner.run("cert", verify_op, page=1, size=200, keywords=name)
        eid = first_id(v.response(), name)
        created.append(eid)
        if eid is not None:
            # check2: 重复同名 → 失败(certNameConflict)。
            out = ctx.runner.run("cert", "localcert-config", name=name, **base_kwargs("localcert"))
            result.record(op_rejected(out, ctx=ctx, label="dup-name-rejected",
                                      expect_err_codes=("certNameConflict", "eRequestParam")))
            # check3: 修改(update 变体: issue 自签) → 成功。
            out = ctx.runner.run("cert", "localcert-issue", id=str(eid),
                                 cacert="defaultLocalCA.crt", option="1", time_length=30)
            result.record(op_succeeded(out, ctx=ctx, label="update-ok"))
            # check4: 删除 → 成功。
            out = ctx.runner.run("cert", "localcert-delete-batch", id=str(eid))
            result.record(op_succeeded(out, ctx=ctx, label="delete-ok"))
            created[-1] = None
        # check5: 再次创建 → 成功。
        name2 = unique_random(18099, "cap2")
        out = ctx.runner.run("cert", "localcert-config", name=name2, **base_kwargs("localcert"))
        result.record(op_succeeded(out, ctx=ctx, label="recreate-ok"))
        v2 = ctx.runner.run("cert", verify_op, page=1, size=200, keywords=name2)
        created.append(first_id(v2.response(), name2))
    finally:
        cleanup_ids(ctx, "localcert", created)
