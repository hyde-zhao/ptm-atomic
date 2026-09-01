"""P0-18037: 修改mac地址对象名称有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 三种名称修改均期望 修改失败。
设备实测(55.63):
  * 有效值改名 → 「name不可被修改」(eRequestParam), 修改失败。
  * 空名称 → CLI 客户端把空 name 视为必填缺失(RUNNER_VALIDATION_FAILED),
    修改请求被拒(不达设备), 修改失败。
  * 32 字节超长名 → 客户端/设备 schema 校验拒绝(长度/pattern), 修改失败。
"""

from __future__ import annotations

from framework.checks import Check, op_rejected
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_OK, cleanup_names, create_ok, update_rejected

TITLE = "P0-18037 修改mac地址对象名称有效值和无效值测试"


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created: list[str] = []
    try:
        created.append(unique_random(18037, "seed"))
        seed_name = created[-1]
        create_ok(ctx, result, name=seed_name, label="seed", macs=[MAC_OK])
        # 有效值改名 → 失败(name 不可修改)。
        update_rejected(ctx, result, name=seed_name, label="rename-valid-rejected",
                        new_name=unique_random(18037, "nn"), macs=[MAC_OK])
        # 空名称 → 失败。直接调用(update_rejected 的 ``new_name or name`` 会把
        # 空串退化为原名, 不能表示"空名称")。
        out = ctx.runner.run("mac-pool", "update", id=seed_name, name="",
                             desc="", mac=[MAC_OK])
        result.record(op_rejected(out, ctx=ctx, label="rename-empty-rejected"))
        # 32 字节超长名 → 失败。
        update_rejected(ctx, result, name=seed_name, label="rename-32-rejected",
                        new_name="M" * 32, macs=[MAC_OK])
    finally:
        cleanup_names(ctx, created)
