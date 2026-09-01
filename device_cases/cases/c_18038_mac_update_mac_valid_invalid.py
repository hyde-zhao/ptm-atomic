"""P0-18038: 修改mac地址对象mac地址有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 全0/全f/任意值 修改成功; 空/超长/分隔符不合法/5段/7段/特殊字符 修改失败
设备实测: update 身份=name, mac 格式校验同 config(update 侧返回 schema pattern error)
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import (
    MAC_ALL, MAC_OK, MAC_ZERO, cleanup_names, create_ok, update_ok, update_rejected,
)

TITLE = "P0-18038 修改mac地址对象mac地址有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        created.append(unique_random(18038, "seed"))
        create_ok(ctx, result, name=created[-1], label="seed", macs=[MAC_OK])
        update_ok(ctx, result, name=created[-1], label="upd-zero", macs=[MAC_ZERO])
        update_ok(ctx, result, name=created[-1], label="upd-all", macs=[MAC_ALL])
        update_ok(ctx, result, name=created[-1], label="upd-mixed", macs=["Aa:Bb:Cc:Dd:Ee:Ff"])
        update_ok(ctx, result, name=created[-1], label="upd-arbitrary", macs=["02:03:0a:00:53:0c"])
        update_rejected(ctx, result, name=created[-1], label="upd-empty-macs-rejected")
        update_rejected(ctx, result, name=created[-1], label="upd-no-colon-rejected",
                        macs=["001122334455"])
        update_rejected(ctx, result, name=created[-1], label="upd-5seg-rejected",
                        macs=["00:11:22:33:44"])
        update_rejected(ctx, result, name=created[-1], label="upd-7seg-rejected",
                        macs=["00:11:22:33:44:55:66"])
        update_rejected(ctx, result, name=created[-1], label="upd-dash-rejected",
                        macs=["00-11-22-33-44-55"])
        update_rejected(ctx, result, name=created[-1], label="upd-badhex-rejected",
                        macs=["aa:bb:cc:dd:ee:gg"])
    finally:
        cleanup_names(ctx, created)
