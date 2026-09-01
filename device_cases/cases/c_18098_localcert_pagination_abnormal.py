"""P0-18098: 验证查询本地证书页数和分页大小异常值

xlsx(对象管理用例_重构_563.xlsx): page0/size0; page最大/size最大; 超最大值; 异常字符串
设备实测: page0/size0→客户端拒(正整型); 超大 page/size→200 返回全部/空; 字符串→拒
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok,
)

TITLE = "P0-18098 验证查询本地证书页数和分页大小异常值"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    try:
        from cases.cert_config_support import RESOURCE_OPS
        _, verify_op, _, _ = RESOURCE_OPS["localcert"]
        out = ctx.runner.run("cert", verify_op, page=0, size=0)
        result.record(Check(name="page0-size0-rejected", ok=not out.success,
                            detail="runner rejects non-positive page/size"))
        out = ctx.runner.run("cert", verify_op, page=2147483647, size=2147483647)
        result.record(Check(name="page-size-max", ok=out.success,
                            detail="device returns 200 for max page/size"))
        out = ctx.runner.run("cert", verify_op, page=99999999, size=10)
        result.record(Check(name="page-over-max", ok=out.success, detail="200 for page > max"))
        out = ctx.runner.run("cert", verify_op, page=1, size=99999999)
        result.record(Check(name="size-over-max", ok=out.success, detail="200 for size > max"))
    except Exception as exc:  # noqa: BLE001
        result.record(Check(name="abnormal-pagination", ok=False, detail=f"{type(exc).__name__}: {exc}"))
