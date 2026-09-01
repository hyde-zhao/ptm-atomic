"""P3-176255: 自定义文件类型在新增文件类型组时修改测试

xlsx(对象管理用例_重构_563.xlsx):
  1. 创建文件类型组
  2. 文件类型组新增文件对象时修改文件对象文件名【check1】修改失败
  3. 文件类型组新增文件对象时修改文件对象描述【check2】修改成功
  4. 有引用计数的文件在被文件类型组引用时修改描述, 引用计数检查【check3】引用并修改成功

设备实测(55.63): 被组引用的自定义文件类型删除被拒(「文件类型已被引用」, c_176265),
重命名同受引用保护 → 拒绝(名称即引用身份)。改描述不影响引用身份 → 成功且 refcnt
保持 1。
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, entry_named, refcnt_of

TITLE = "P3-176255 自定义文件类型在新增文件类型组时修改测试"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    ft = unique_random(176255, "ft")
    ft_new = f"{ft}-renamed"
    grp = unique_random(176255, "grp")
    grp_alive = False
    try:
        # 1) 创建文件类型 + 组引用它。
        out = ctx.runner.run("filetype", "config", name=ft, description="orig")
        result.record(op_succeeded(out, ctx=ctx, label="ft-created"))
        if not ctx.execute:
            return
        r = rest.create_group(grp, members=[ft], des="ref")
        result.record(Check(name="grp-created", ok=r.status_code == 200,
                            detail=f"create group → {r.status_code}"))
        grp_alive = r.status_code == 200
        if not grp_alive:
            return

        # 2) check1: 被引用时修改文件名(重命名)→ 修改失败。
        rn = ctx.runner.run("filetype", "update", id=ft, name=ft_new, description="renamed")
        if rn.success:
            result.record(Check(name="ft-rename-while-referenced", ok=False,
                                detail="rename unexpectedly accepted (xlsx expects failure)"))
        else:
            result.record(op_rejected(rn, ctx=ctx, label="ft-rename-while-referenced",
                                      expect_err_codes=("eRequestParam",)))

        # 3) check2: 被引用时修改描述 → 修改成功。
        up = ctx.runner.run("filetype", "update", id=ft, name=ft, description="desc-updated")
        result.record(op_succeeded(up, ctx=ctx, label="ft-desc-update-ok"))

        # 4) check3: 修改描述后引用计数仍为 1(组仍在引用), 且描述已生效。
        entries = rest.list_entries(keywords=ft)
        e = entry_named(entries, ft)
        if e is None:
            result.record(Check(name="ft-desc-refcnt-after-update", ok=False,
                                detail="filetype not found in list"))
            result.record(Check(name="ft-desc-reflects-update", ok=False,
                                detail="filetype not found in list"))
        else:
            got = refcnt_of(e)
            result.record(Check(name="ft-desc-refcnt-after-update", ok=got == 1,
                                detail=f"refcnt={got} want 1 (still referenced)"))
            result.record(Check(name="ft-desc-reflects-update",
                                ok=str(e.get("description")) == "desc-updated",
                                detail=f"description={e.get('description')!r}"))
    finally:
        if ctx.execute:
            if grp_alive:
                rest.delete_groups([grp])
            if entry_named(rest.list_entries(keywords=ft), ft):
                rest.delete(ft)
