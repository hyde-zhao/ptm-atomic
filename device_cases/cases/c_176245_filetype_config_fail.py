"""P0-176245: 新建自定义文件类型失败测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 使用/api/v1/appsec/filetype添加对象为空 【check1】新增失败
  2. 使用/api/v1/appsec/filetype新增对象名称为任意非法字符 【check1】新增失败
  3. 使用/api/v1/appsec/filetype新增对象名称为超过字符限制 【check1】新增失败
  4. 使用/api/v1/appsec/filetype新增IDMC-开头的自定义文件类型 【check1】新增失败

设备实测(probe19c): 空名被 runner 客户端校验拦下;IDMC- 前缀为保留段,
设备返回 eRequestParam;超长名被设备拒。非法字符按设备规则判定(首个 run
校准)。被拒断言后复查列表,若设备意外接受了某名称则清理并记 divergence。
"""

from __future__ import annotations

from framework.checks import op_rejected
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, entry_named

TITLE = "P0-176245 新建自定义文件类型失败测试"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    attempted: list[str] = []
    try:
        # step1: 空名称 → 客户端校验拒绝。
        out = ctx.runner.run("filetype", "config", name="")
        result.record(op_rejected(out, ctx=ctx, label="empty-name-rejected"))
        if not ctx.execute:
            return

        # step2: 非法字符(含 / 和 ;)→ 设备拒绝。
        bad = unique_random(176245, "bad") + "/;x"
        attempted.append(bad)
        out = ctx.runner.run("filetype", "config", name=bad)
        result.record(op_rejected(out, ctx=ctx, label="illegal-char-rejected"))
        if not out.success and entry_named(rest.list_entries(keywords=bad), bad):
            result.notes.append("非法字符名称仍被设备接受(divergence,见 illegal-char-rejected)")

        # step3: 超过字符限制(129 字符)→ 设备拒绝。
        long = "176245_" + "n" * 120
        attempted.append(long)
        out = ctx.runner.run("filetype", "config", name=long)
        result.record(op_rejected(out, ctx=ctx, label="overlength-rejected"))

        # step4: IDMC- 前缀(保留段)→ 设备拒绝。
        idmc = f"IDMC-{unique_random(176245, 'resv')}"
        attempted.append(idmc)
        out = ctx.runner.run("filetype", "config", name=idmc)
        result.record(op_rejected(out, ctx=ctx, label="idmc-prefix-rejected",
                                  expect_err_codes=("eRequestParam",)))
    finally:
        if ctx.execute:
            for n in attempted:
                if entry_named(rest.list_entries(keywords=n), n):
                    rest.delete(n)
