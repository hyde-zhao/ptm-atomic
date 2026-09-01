"""P3-176268: 修改文件类型组对自身的影响

xlsx(对象管理用例_重构_563.xlsx):
  1. 创建文件类型组
  2. 修改文件类型组的名称【check1】修改失败
  3. 修改文件类型组的描述【check2】修改成功

设备实测(55.63): 组名是更新身份(id 即 name),PUT 改 name 与 id 不符或名称变更
被拒 → 修改失败;改描述不影响身份 → 成功。
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, entry_named

TITLE = "P3-176268 修改文件类型组对自身的影响"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    ft = unique_random(176268, "m")
    grp = unique_random(176268, "g")
    grp_new = f"{grp}-renamed"
    grp_alive = False
    try:
        # 1) 创建成员文件类型 + 组。
        out = ctx.runner.run("filetype", "config", name=ft)
        result.record(op_succeeded(out, ctx=ctx, label="ft-created"))
        if not ctx.execute:
            return
        r = rest.create_group(grp, members=[ft], des="orig")
        result.record(Check(name="grp-created", ok=r.status_code == 200,
                            detail=f"create group → {r.status_code}"))
        grp_alive = r.status_code == 200
        if not grp_alive:
            return

        # 2) check1: 修改组名 → 修改失败。
        rn = ctx.runner.run("filetype", "group-update", id=grp, name=grp_new,
                            des="renamed", filetype=[ft])
        if rn.success:
            result.record(Check(name="grp-rename-rejected", ok=False,
                                detail="rename unexpectedly accepted (xlsx expects failure)"))
        else:
            result.record(op_rejected(rn, ctx=ctx, label="grp-rename-rejected",
                                      expect_err_codes=("eRequestParam",)))

        # 3) check2: 修改组描述 → 修改成功 + verify 反映。
        up = ctx.runner.run("filetype", "group-update", id=grp, name=grp,
                            des="desc-updated", filetype=[ft])
        result.record(op_succeeded(up, ctx=ctx, label="grp-desc-update-ok"))

        vout = ctx.runner.run("filetype", "group-verify", page=1, size=100, keywords=grp)
        result.record(op_succeeded(vout, ctx=ctx, label="grp-verify-query"))
        if vout.success:
            hits = [e for e in vout.response().get("vals", []) if isinstance(e, dict)
                    and e.get("name") == grp]
            grp_hit = hits[0] if hits else None
            result.record(Check(name="grp-desc-reflects-update",
                                ok=grp_hit is not None and str(grp_hit.get("des")) == "desc-updated",
                                detail=f"des={grp_hit.get('des')!r} want 'desc-updated'"))
    finally:
        if ctx.execute:
            if grp_alive:
                rest.delete_groups([grp])
            if entry_named(rest.list_entries(keywords=ft), ft):
                rest.delete(ft)
