"""P0-18035: 添加mac地址对象mac地址有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 全0/全f/任意值 有效; 空/超长(2049)/分隔符不合法/5段/7段/特殊字符 无效
设备实测: 格式 ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$; macaddrs 1-2048 条;
空列表→macaddrs列表必须至少有1个条目; 2049→最多只能有2048个条目
"""

from __future__ import annotations

import json
import os
import tempfile

from framework.checks import Check, op_rejected
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_ALL, MAC_OK, MAC_ZERO, cleanup_names, create_ok, create_rejected

TITLE = "P0-18035 添加mac地址对象mac地址有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        created.append(unique_random(18035, "z"))
        create_ok(ctx, result, name=created[-1], label="mac-zero", macs=[MAC_ZERO])
        created.append(unique_random(18035, "f"))
        create_ok(ctx, result, name=created[-1], label="mac-all", macs=[MAC_ALL])
        created.append(unique_random(18035, "mx"))
        create_ok(ctx, result, name=created[-1], label="mac-mixed", macs=["Aa:Bb:Cc:Dd:Ee:Ff"])
        created.append(unique_random(18035, "arb"))
        create_ok(ctx, result, name=created[-1], label="mac-arbitrary", macs=["02:03:0a:00:53:0c"])
        # 无效分支
        create_rejected(ctx, result, name=unique_random(18035, "empty"), label="mac-empty-list")
        create_rejected(ctx, result, name=unique_random(18035, "nc"), label="mac-no-colon",
                        macs=["001122334455"])
        create_rejected(ctx, result, name=unique_random(18035, "5"), label="mac-5seg",
                        macs=["00:11:22:33:44"])
        create_rejected(ctx, result, name=unique_random(18035, "7"), label="mac-7seg",
                        macs=["00:11:22:33:44:55:66"])
        create_rejected(ctx, result, name=unique_random(18035, "dash"), label="mac-dash",
                        macs=["00-11-22-33-44-55"])
        create_rejected(ctx, result, name=unique_random(18035, "sp"), label="mac-badhex",
                        macs=["aa:bb:cc:dd:ee:gg"])
        # 超长 2049 条走 payload-file(CLI 参数超 Windows cmdline 上限)。
        name = unique_random(18035, "many")
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False,
                                         encoding="utf-8") as f:
            json.dump({"val": {"name": name, "desc": "", "type": 2,
                               "macaddrs": [{"mac": MAC_OK}] * 2049}}, f, ensure_ascii=False)
            path = f.name
        try:
            out = ctx.runner.run("mac-pool", "config", payload_file=path)
            result.record(op_rejected(out, ctx=ctx, label="mac-2049-rejected"))
        finally:
            os.unlink(path)
    finally:
        cleanup_names(ctx, created)
