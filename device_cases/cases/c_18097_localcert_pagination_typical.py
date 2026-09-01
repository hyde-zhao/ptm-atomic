"""P0-18097: 验证本地证书分页大小典型值测试

xlsx(对象管理用例_重构_563.xlsx): 配置>40条; size=10/20/30/40 各页查询正确
设备容量 65: 建 44 条种子,size 10/20/30/40 各查首页校验条数
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_names, create_ok,
)

TITLE = "P0-18097 验证本地证书分页大小典型值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        from cases.cert_config_support import RESOURCE_OPS
        from framework.checks import find_entries
        _, verify_op, _, _ = RESOURCE_OPS["localcert"]
        for i in range(44):
            name = unique_random(18097, f"t{i}")
            out = ctx.runner.run("cert", "localcert-config", name=name, **base_kwargs("localcert"))
            if out.success:
                created.append(name)
        for sz in (10, 20, 30, 40):
            v = ctx.runner.run("cert", verify_op, page=1, size=sz, keywords="atc18097")
            hits = [e for e in find_entries(v.response(), lambda e: isinstance(e, dict) and "atc18097" in str(e.get("name", "")))]
            result.record(Check(name=f"size-{sz}-first-page", ok=len(hits) == sz,
                                detail=f"page1 hits={len(hits)} want={sz}"))
    finally:
        cleanup_names(ctx, "localcert", created)

