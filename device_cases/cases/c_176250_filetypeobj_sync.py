"""P3-176250: 自定义文件类型在文件类型组内新建自定义文件类型同步测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 新建文件类型组
  2. 在文件类型组内创建文件对象
  3. 检查文件对象创建状态和引用计数 【check1】创建成功，引用计数正确

设备实测(probe19c): 组成员引用自定义文件类型须 type:true。API 等价流程:
建文件类型 → 建组并带成员 → group-verify 成员可见 + 该对象 refcnt=1。
"""

from __future__ import annotations

import json

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import (FiletypeRest, entry_named, group_member_names,
                                    refcnt_check)

TITLE = "P3-176250 自定义文件类型在文件类型组内新建自定义文件类型同步测试"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    ft = unique_random(176250, "ft")
    grp = unique_random(176250, "grp")
    grp_del = ft_del = False
    try:
        # check1a: 建自定义文件类型。
        out = ctx.runner.run("filetype", "config", name=ft)
        result.record(op_succeeded(out, ctx=ctx, label="ft-created"))
        if not ctx.execute:
            return

        # 建组并引用该对象(member 必须 type:true → payload_json 原样传递)。
        group_payload = json.dumps({
            "id": 0,
            "val": {"name": grp, "des": "sync", "filetype": [{"name": ft, "type": True}]},
        })
        gout = ctx.runner.run("filetype", "group-config", payload_json=group_payload)
        result.record(op_succeeded(gout, ctx=ctx, label="grp-created-with-member"))
        if not gout.success:
            return

        # check1b: 组内可见该对象。
        vout = ctx.runner.run("filetype", "group-verify", page=1, size=100, keywords=grp)
        result.record(op_succeeded(vout, ctx=ctx, label="grp-verify-query"))
        if vout.success:
            grps = rest.list_groups(keywords=grp)
            grp_entry = next((g for g in grps if str(g.get("name", "")) == grp), None)
            members = group_member_names(grp_entry) if grp_entry else []
            result.record(Check(name="grp-reflects-member", ok=ft in members,
                                detail=f"members={members}"))

        # check1c: 引用计数正确(被 1 个组引用 → 1)。
        hit = entry_named(rest.list_entries(keywords=ft), ft)
        result.record(refcnt_check(label="refcnt-after-group-ref", entry=hit, want=1))
    finally:
        if ctx.execute:
            if not grp_del:
                result.record(op_succeeded(
                    ctx.runner.run("filetype", "group-delete-batch", id=grp),
                    ctx=ctx, label="cleanup-grp"))
                grp_del = True
            if not ft_del:
                result.record(op_succeeded(
                    ctx.runner.run("filetype", "delete", id=ft),
                    ctx=ctx, label="cleanup-ft"))
                ft_del = True
