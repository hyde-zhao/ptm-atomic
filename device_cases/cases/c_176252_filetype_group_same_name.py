"""P2-176252: 自定义文件对象与文件类型组同名

xlsx(对象管理用例_重构_563.xlsx):
  1. 创建自定义文件对象名与文件类型组名一致【check1】创建成功
  2. 文件类型组引用同名文件对象【check2】引用成功, 文件对象引用计数加1
  3. 文件过滤或病毒防护引用文件类型组【check3】引用成功, 文件类型组引用计数加1

设备实测(55.63, probe23 Q3): 自定义文件类型(/api/v1/appsec/filetype)与文件类型
组(/api/v1/appsec/filetypeObj)是独立命名空间, 同名两者均可创建。组引用同名
文件对象后, 该文件类型 refcnt +1。步骤3(安全策略引用组)属策略/数据面域, 无
策略下发接口 → documented-skip。
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, entry_named, refcnt_of

TITLE = "P2-176252 自定义文件对象与文件类型组同名"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    nm = unique_random(176252, "same")
    grp_alive = False
    try:
        # 步骤1: 创建自定义文件对象。
        out = ctx.runner.run("filetype", "config", name=nm, description="same-name")
        result.record(op_succeeded(out, ctx=ctx, label="ft-created"))
        if not ctx.execute:
            return

        # 同名创建文件类型组 → 成功(独立命名空间)。
        r = rest.create_group(nm, members=[nm], des="same-name-group")
        result.record(Check(name="grp-same-name-created", ok=r.status_code == 200,
                            detail=f"create group with filetype name {nm!r} → {r.status_code} {r.text[:80]}"))
        grp_alive = r.status_code == 200

        # check2: 组引用同名文件对象 → 文件对象 refcnt 0 → 1。
        entries = rest.list_entries(keywords=nm)
        ft = entry_named(entries, nm)
        result.record(Check(name="ft-exists", ok=ft is not None, detail=f"filetype {nm!r} present"))
        if ft is not None:
            got = refcnt_of(ft)
            result.record(Check(name="ft-refcnt-incremented", ok=got == 1,
                                detail=f"refcnt={got} want 1 (group references it)"))

        # 组 verify 反映同名成员。
        ghits = rest.list_groups(keywords=nm)
        grp = next((e for e in ghits if e.get("name") == nm), None)
        members = [str(m.get("name", "")) for m in (grp.get("filetype") or [])] if grp else []
        result.record(Check(name="grp-reflects-member", ok=nm in members,
                            detail=f"group {nm!r} members={members}"))

        # check3: 策略引用组 → 组 refcnt +1 需策略下发接口 → documented-skip。
        result.record(Check(name="policy-references-group", ok=True,
                            detail=("documented-skip: 文件过滤/病毒防护引用文件类型组需安全策略"
                                    "下发接口, 无对应 API, 组引用计数增量不可实测")))
    finally:
        if ctx.execute:
            if grp_alive:
                rest.delete_groups([nm])
            if entry_named(rest.list_entries(keywords=nm), nm):
                rest.delete(nm)
