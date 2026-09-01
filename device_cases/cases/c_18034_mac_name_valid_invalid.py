"""P0-18034: 添加mac地址对象名称有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 1-31字节 字母数字中文连接符点 有效; 空/32字节 无效
设备实测: name 1-31 允许 中文/英文/数字/点号/短横线; 空→客户端必填; 32字节/含 `!`→拒
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_OK, cleanup_names, create_ok, create_rejected

TITLE = "P0-18034 添加mac地址对象名称有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        created.append(unique_random(18034, "nm"))
        create_ok(ctx, result, name=created[-1], label="name-valid", macs=[MAC_OK])
        exact31 = (unique_random(18034, "nm31")[:20].replace("-", "a") + "b" * 11)[:31]
        created.append(exact31)
        create_ok(ctx, result, name=exact31, label="name-31-exact", macs=[MAC_OK])
        created.append("中文mac对象名")
        create_ok(ctx, result, name=created[-1], label="name-cn", macs=[MAC_OK])
        created.append("atc.dot.name")
        create_ok(ctx, result, name=created[-1], label="name-dot", macs=[MAC_OK])
        create_rejected(ctx, result, name="", label="name-empty", macs=[MAC_OK])
        create_rejected(ctx, result, name="Y" * 32, label="name-32", macs=[MAC_OK])
        create_rejected(ctx, result, name=unique_random(18034, "sp") + "!", label="name-special",
                        macs=[MAC_OK])
    finally:
        cleanup_names(ctx, created)
