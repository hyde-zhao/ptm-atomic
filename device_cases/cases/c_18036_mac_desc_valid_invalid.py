"""P0-18036: 添加mac地址对象描述有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 0-127字节 有效; 128字节 无效
设备实测: desc 0-127 有效; 128→描述长度必须小于等于127
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_OK, cleanup_names, create_ok, create_rejected

TITLE = "P0-18036 添加mac地址对象描述有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        created.append(unique_random(18036, "d127"))
        create_ok(ctx, result, name=created[-1], label="desc-127", desc="d" * 127, macs=[MAC_OK])
        created.append(unique_random(18036, "empty"))
        create_ok(ctx, result, name=created[-1], label="desc-empty", desc="", macs=[MAC_OK])
        create_rejected(ctx, result, name=unique_random(18036, "d128"), label="desc-128",
                        desc="d" * 128, macs=[MAC_OK])
    finally:
        cleanup_names(ctx, created)
