"""P0-18046: 预定义mac地址对象不可修改和删除测试

xlsx(对象管理用例_重构_563.xlsx): 修改预定义→失败; 删除预定义→失败
设备实测: 内置 "any" (type ANY, desc 任何地址, mac "") 不可修改/删除——
update→any不可被修改; config 同名→存在同名的对象; delete→预定义地址对象不能被删除
"""

from __future__ import annotations

from framework.checks import Check, op_rejected
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_OK, entry_by_name

TITLE = "P0-18046 预定义mac地址对象不可修改和删除测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    try:
        v = ctx.runner.run("mac-pool", "verify", page=1, size=300, keywords="any")
        hits = entry_by_name(v.response(), "any")
        if not hits:
            result.record(Check(name="builtin-any-found", ok=False, detail="predefined 'any' not found"))
            return
        result.record(Check(name="builtin-any-found", ok=True,
                            detail=f"type={hits[0].get('type')} desc={hits[0].get('desc')!r}"))
        # 修改预定义(改 desc+mac)→ 失败。
        out = ctx.runner.run("mac-pool", "update", id="any", name="any",
                             desc="CHANGED", mac=[MAC_OK])
        result.record(op_rejected(out, ctx=ctx, label="builtin-update-rejected"))
        # config 同名(重建/覆盖)→ 失败。
        out = ctx.runner.run("mac-pool", "config", name="any", mac=[MAC_OK])
        result.record(op_rejected(out, ctx=ctx, label="builtin-config-rejected"))
        # 删除预定义 → 失败。
        out = ctx.runner.run("mac-pool", "delete", id="any")
        result.record(op_rejected(out, ctx=ctx, label="builtin-delete-rejected"))
        # 删除尝试后内置仍在。
        v2 = ctx.runner.run("mac-pool", "verify", page=1, size=300, keywords="any")
        still = entry_by_name(v2.response(), "any")
        result.record(Check(name="builtin-still-present", ok=bool(still),
                            detail=f"after delete attempt: {len(still)} 'any' entries"))
    except Exception as exc:  # noqa: BLE001
        result.record(Check(name="predefined-immutable", ok=False,
                            detail=f"{type(exc).__name__}: {exc}"))
