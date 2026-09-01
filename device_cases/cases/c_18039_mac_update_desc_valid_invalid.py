"""P0-18039: 修改mac地址对象描述有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 0-127字节 修改成功; 128字节 修改失败
设备实测: update desc 0-127 有效; 128→描述长度必须小于等于127
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_OK, cleanup_names, create_ok, update_ok, update_rejected

TITLE = "P0-18039 修改mac地址对象描述有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        created.append(unique_random(18039, "seed"))
        create_ok(ctx, result, name=created[-1], label="seed", macs=[MAC_OK])
        update_ok(ctx, result, name=created[-1], label="upd-desc-127", desc="d" * 127,
                  macs=[MAC_OK])
        update_ok(ctx, result, name=created[-1], label="upd-desc-empty", desc="", macs=[MAC_OK])
        update_rejected(ctx, result, name=created[-1], label="upd-desc-128-rejected",
                        desc="d" * 128, macs=[MAC_OK])
    finally:
        cleanup_names(ctx, created)
