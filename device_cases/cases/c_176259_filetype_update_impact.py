"""P3-176259: 修改自定义文件类型对自身的影响.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 创建自定义文件对象
  2. 修改自定义文件对象的名称 【check1】修改失败
  3. 修改自定义文件对象的描述 【check2】修改成功

设备实测(probe19c): filetype 身份是名称,改名即改 identity → 被拒;
改描述 → 200。改名尝试不会留下第二个对象。
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, entry_named

TITLE = "P3-176259 修改自定义文件类型对自身的影响"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    name = unique_random(176259, "ft")
    renamed = unique_random(176259, "renamed")
    new_desc = unique_random(176259, "newdesc")
    try:
        # 准备。
        out = ctx.runner.run("filetype", "config", name=name, description="old")
        result.record(op_succeeded(out, ctx=ctx, label="ft-created"))
        if not ctx.execute:
            return

        # check1: 修改名称 → 失败,对象仍以原名存在。
        out = ctx.runner.run("filetype", "update", id=name, name=renamed)
        result.record(op_rejected(out, ctx=ctx, label="rename-rejected",
                                  expect_err_codes=("eRequestParam",)))
        hit = entry_named(rest.list_entries(keywords=name), name)
        result.record(Check(name="rename-left-no-side-effect",
                            ok=hit is not None and entry_named(
                                rest.list_entries(keywords=renamed), renamed) is None,
                            detail=f"original_present={hit is not None} renamed_absent="
                                   f"{entry_named(rest.list_entries(keywords=renamed), renamed) is None}"))

        # check2: 修改描述 → 成功,列表回显新描述。
        out = ctx.runner.run("filetype", "update", id=name, name=name, description=new_desc)
        result.record(op_succeeded(out, ctx=ctx, label="desc-updated"))
        hit = entry_named(rest.list_entries(keywords=name), name)
        result.record(Check(name="desc-reflected", ok=hit is not None
                            and str(hit.get("description", "")) == new_desc,
                            detail=f"desc={hit and hit.get('description')!r} want={new_desc!r}"))
    finally:
        if ctx.execute:
            if entry_named(rest.list_entries(keywords=name), name):
                result.record(op_succeeded(
                    ctx.runner.run("filetype", "delete", id=name),
                    ctx=ctx, label="cleanup-ft"))
