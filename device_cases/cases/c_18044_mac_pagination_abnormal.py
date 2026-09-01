"""P0-18044: 验证查询mac地址对象页数和分页大小异常值

xlsx(对象管理用例_重构_563.xlsx): page=0&size=0→返回全部; 超大page/size→返回当前条数; 字符串→返回首页
设备实测(divergence): CLI 客户端校验 page/size 必须为正整数——page=0/size=0 与字符串被客户端拒绝,
无法到达设备。设备侧: 超大 page→空; 超大 size→返回全部(被钳制到可用条数)。
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_OK, cleanup_names, create_ok

TITLE = "P0-18044 验证查询mac地址对象页数和分页大小异常值"

PREFIX = "atc18044"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        for i in range(5):
            name = unique_random(18044, f"s{i}")
            if create_ok(ctx, result, name=name, label=f"seed{i}", macs=[MAC_OK], want_etcd=False):
                created.append(name)
        n = len(created)
        # page=0 size=0: 客户端校验正整数 → 拒(divergence: xlsx 期望返回全部)。
        out = ctx.runner.run("mac-pool", "verify", page=0, size=0)
        result.record(op_rejected(out, ctx=ctx, label="page0-size0-client-rejected"))
        # 超大 page → 设备返回空。
        out = ctx.runner.run("mac-pool", "verify", page=999999, size=1)
        result.record(op_succeeded(out, ctx=ctx, label="huge-page-ok"))
        if ctx.execute and out.success:
            nv = len([e for e in (out.response().get('vals') or [])
                      if isinstance(e, dict) and str(e.get('name', '')).startswith(PREFIX)])
            result.record(Check(name="huge-page-empty", ok=nv == 0,
                                detail=f"huge-page returned {nv} (want 0)"))
        # 超大 size → 设备返回全部。
        out = ctx.runner.run("mac-pool", "verify", page=1, size=999999)
        result.record(op_succeeded(out, ctx=ctx, label="huge-size-ok"))
        if ctx.execute and out.success:
            nv = len([e for e in (out.response().get('vals') or [])
                      if isinstance(e, dict) and str(e.get('name', '')).startswith(PREFIX)])
            result.record(Check(name="huge-size-all", ok=nv == n,
                                detail=f"huge-size returned {nv} want {n}"))
    finally:
        cleanup_names(ctx, created)
