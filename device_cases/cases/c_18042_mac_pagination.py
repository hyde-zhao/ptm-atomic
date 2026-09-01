"""P0-18042: 验证查询mac地址分页查询功能

xlsx(对象管理用例_重构_563.xlsx): 无对象→空; 1条→正确; ≥2s条→首页s条/末页余数/中间页正确
设备实测: verify 分页正常。用 2*s 条种子(s=3)验证首页/末页/中间页
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_OK, cleanup_names, create_ok, entry_by_name

TITLE = "P0-18042 验证查询mac地址分页查询功能"

S = 3
PREFIX = "atc18042"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        v = ctx.runner.run("mac-pool", "verify", page=1, size=S, keywords="atc-zzz-no-such")
        result.record(Check(name="page-empty-when-none",
                            ok=len(entry_by_name(v.response(), "atc-zzz-no-such")) == 0,
                            detail="isolated by nonexistent keywords"))
        for i in range(2 * S):
            name = unique_random(18042, f"pg{i}")
            if create_ok(ctx, result, name=name, label=f"seed{i}", macs=[MAC_OK], want_etcd=False):
                created.append(name)
        n = len(created)
        def hits(resp) -> int:
            return len([e for e in (resp.get('vals') or [])
                        if isinstance(e, dict) and str(e.get('name', '')).startswith(PREFIX)])
        p1 = ctx.runner.run("mac-pool", "verify", page=1, size=S, keywords=PREFIX)
        p_mid = ctx.runner.run("mac-pool", "verify", page=2, size=S, keywords=PREFIX)
        last_page = (n + S - 1) // S
        p_last = ctx.runner.run("mac-pool", "verify", page=last_page, size=S, keywords=PREFIX)
        h1, hm, hl = hits(p1.response()), hits(p_mid.response()), hits(p_last.response())
        result.record(Check(name="page-first-size-s", ok=h1 == S, detail=f"page1 hits={h1} want={S}"))
        result.record(Check(name="page-middle-size-s", ok=hm == S, detail=f"page2 hits={hm} want={S}"))
        expect_last = n - S * (last_page - 1)
        result.record(Check(name="page-last-remainder", ok=hl == expect_last,
                            detail=f"page{last_page} hits={hl} want={expect_last} (remainder)"))
    finally:
        cleanup_names(ctx, created)
