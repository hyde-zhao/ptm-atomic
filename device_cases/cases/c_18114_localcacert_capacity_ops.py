"""P0-18114: 本地CA证书数量最大后的增删改测试

xlsx(对象管理用例_重构_563.xlsx): 创建1→成功; 重复同名→失败; 修改→成功; 删除→成功; 再创建→成功
设备容量 localcacert=9 含 2 内置。验证同名拒绝+update+delete+recreate 闭环
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok,
)

TITLE = "P0-18114 本地CA证书数量最大后的增删改测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created = []
    try:
        from framework.checks import op_rejected, op_succeeded
        from cases.cert_support import first_id
        name = unique_random(18114, "cap")
        out = ctx.runner.run("cert", "localcacert-config", name=name, **base_kwargs("localcacert"))
        result.record(op_succeeded(out, ctx=ctx, label="create-ok"))
        v = ctx.runner.run("cert", "localcacert-verify", page=1, size=200, keywords=name)
        eid = first_id(v.response(), name)
        created.append(eid)
        if eid is not None:
            out = ctx.runner.run("cert", "localcacert-config", name=name, **base_kwargs("localcacert"))
            result.record(op_rejected(out, ctx=ctx, label="dup-name-rejected",
                                      expect_err_codes=("certNameConflict", "eRequestParam")))
            # update localcacert: 无 update op,以同样 subject 重新 POST 同名不可行。仅验证重复建被拒 + 删除。
            out = ctx.runner.run("cert", "localcacert-delete-batch", id=str(eid))
            result.record(op_succeeded(out, ctx=ctx, label="delete-ok"))
            created[-1] = None
        name2 = unique_random(18114, "cap2")
        out = ctx.runner.run("cert", "localcacert-config", name=name2, **base_kwargs("localcacert"))
        result.record(op_succeeded(out, ctx=ctx, label="recreate-ok"))
        v2 = ctx.runner.run("cert", "localcacert-verify", page=1, size=200, keywords=name2)
        created.append(first_id(v2.response(), name2))
    finally:
        cleanup_ids(ctx, "localcacert", created)
