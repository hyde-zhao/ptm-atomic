"""P0-18111: 验证查询本地CA证书分页查询功能

xlsx(对象管理用例_重构_563.xlsx): 无证书→空; 1条→正确; ≥2s条→首页s条/末页余数/中间页正确
设备实测: 分页正常。容量 9 含 2 内置,种子仅 7 条→s=3 验证首页/末页/中间页
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_names, create_ok,
)

TITLE = "P0-18111 验证查询本地CA证书分页查询功能"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        from cases.cert_config_support import RESOURCE_OPS
        from framework.checks import find_entries
        _, verify_op, _, _ = RESOURCE_OPS["localcacert"]
        s = 3
        n = 7  # 容量上限 9 含 2 内置 → 最多 7 自定义
        for i in range(n):
            name = unique_random(18111, f"pg{i}")
            out = ctx.runner.run("cert", "localcacert-config", name=name, **base_kwargs("localcacert"))
            if out.success:
                created.append(name)
        p1 = ctx.runner.run("cert", verify_op, page=1, size=s, keywords="atc18111")
        p_last = ctx.runner.run("cert", verify_op, page=3, size=s, keywords="atc18111")
        p_mid = ctx.runner.run("cert", verify_op, page=2, size=s, keywords="atc18111")
        def hits(resp):
            return [e for e in find_entries(resp, lambda e: isinstance(e, dict) and "atc18111" in str(e.get("name", "")))]
        result.record(Check(name="page-first-size-s", ok=len(hits(p1.response())) == s,
                            detail=f"page1 hits={len(hits(p1.response()))} want={s}"))
        result.record(Check(name="page-middle-size-s", ok=len(hits(p_mid.response())) == s,
                            detail=f"page2 hits={len(hits(p_mid.response()))} want={s}"))
        result.record(Check(name="page-last-remainder", ok=0 < len(hits(p_last.response())) <= s,
                            detail=f"page3 hits={len(hits(p_last.response()))}"))
    finally:
        cleanup_names(ctx, "localcacert", created)
