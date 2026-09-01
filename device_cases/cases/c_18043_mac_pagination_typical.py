"""P0-18043: 验证mac地址对象分页大小典型值测试

xlsx(对象管理用例_重构_563.xlsx): 配置>40条; size=10/20/30/40 各页查询正确
设备实测: macpool 容量 >1200,建 44 条种子,size 10/20/30/40 各查首页校验条数
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_OK, cleanup_names, create_ok

TITLE = "P0-18043 验证mac地址对象分页大小典型值测试"

PREFIX = "atc18043"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        for i in range(44):
            name = unique_random(18043, f"t{i}")
            if create_ok(ctx, result, name=name, label=f"seed{i}", macs=[MAC_OK], want_etcd=False):
                created.append(name)
        for sz in (10, 20, 30, 40):
            v = ctx.runner.run("mac-pool", "verify", page=1, size=sz, keywords=PREFIX)
            hits = [e for e in (v.response().get('vals') or [])
                    if isinstance(e, dict) and str(e.get('name', '')).startswith(PREFIX)]
            want = min(sz, len(created))
            result.record(Check(name=f"size-{sz}-first-page", ok=len(hits) == want,
                                detail=f"page1 hits={len(hits)} want={want}"))
    finally:
        cleanup_names(ctx, created)
