"""P0-18096: 验证查询本地证书分页查询功能.

xlsx(对象管理用例_重构_563.xlsx): 无证书→空; 1条→正确; ≥2s条→首页s条/末页余数/中间页正确
设备实测: verify 分页正常;本地证书容量 65。用 2*s 条种子(s=10)验证首页/末页/中间页
"""

from __future__ import annotations

from framework.checks import Check, find_entries
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import base_kwargs, cleanup_names

TITLE = "P0-18096 验证查询本地证书分页查询功能"

S = 10
PREFIX = "atc18096"


def _hits(resp) -> list:
    return [e for e in find_entries(resp, lambda e: isinstance(e, dict)
                                    and PREFIX in str(e.get("name", "")))]


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        # check1: 无本地证书时首页为空(用不存在前缀隔离)。
        v = ctx.runner.run("cert", "localcert-verify", page=1, size=S, keywords="atc-zzz-no-such")
        result.record(Check(name="page-empty-when-none", ok=len(_hits(v.response())) == 0,
                            detail="isolated by nonexistent keywords"))
        # 建 2*s 条种子(localcert 容量 65, 20 条安全)。
        for i in range(2 * S):
            name = unique_random(18096, f"pg{i}")
            out = ctx.runner.run("cert", "localcert-config", name=name, **base_kwargs("localcert"))
            if out.success:
                created.append(name)
        n = len(created)
        # 首页 / 中间页 / 末页。
        p1 = ctx.runner.run("cert", "localcert-verify", page=1, size=S, keywords=PREFIX)
        p_mid = ctx.runner.run("cert", "localcert-verify", page=2, size=S, keywords=PREFIX)
        last_page = (n + S - 1) // S
        p_last = ctx.runner.run("cert", "localcert-verify", page=last_page, size=S, keywords=PREFIX)
        h1, hm, hl = len(_hits(p1.response())), len(_hits(p_mid.response())), len(_hits(p_last.response()))
        result.record(Check(name="page-first-size-s", ok=h1 == S, detail=f"page1 hits={h1} want={S}"))
        result.record(Check(name="page-middle-size-s", ok=hm == S, detail=f"page{2} hits={hm} want={S}"))
        expect_last = n - S * (last_page - 1)
        result.record(Check(name="page-last-remainder", ok=hl == expect_last,
                            detail=f"page{last_page} hits={hl} want={expect_last} (remainder)"))
    finally:
        cleanup_names(ctx, "localcert", created)
