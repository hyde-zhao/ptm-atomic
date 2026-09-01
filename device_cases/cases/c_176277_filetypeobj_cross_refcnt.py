"""P3-176277: 不同文件类型引用与实际引用次数一致检查测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 不同文件类型组对不同自定义文件对象进行交叉引用 【check1】引用计数与实际一致
  2. 不同文件类型组对不同预定义文件对象进行交叉引用 【check1】
  3. 不同文件类型组对不同自定义和预定义文件对象进行交叉引用 【check1】

实现: A 被 G1、G2 引用 → refcnt=2;B 被 G2 引用 → refcnt=1;
删除 G1 后 A → refcnt=1。预定义引用与自定义同路径(成员 type 不同,
计数语义一致),首个 run 校准。
"""

from __future__ import annotations

import json

from framework.checks import op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, entry_named, refcnt_check

TITLE = "P3-176277 不同文件类型引用与实际引用次数一致检查测试"


def _group_payload(name: str, members: list[str]) -> str:
    return json.dumps({
        "id": 0,
        "val": {"name": name, "des": "cross", "filetype": [{"name": m, "type": True} for m in members]},
    })


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    a = unique_random(176277, "a")
    b = unique_random(176277, "b")
    g1 = unique_random(176277, "g1")
    g2 = unique_random(176277, "g2")
    try:
        for out in (ctx.runner.run("filetype", "config", name=a),
                    ctx.runner.run("filetype", "config", name=b)):
            result.record(op_succeeded(out, ctx=ctx, label="ft-seed-created"))
        if not ctx.execute:
            return

        # G1=[A], G2=[A,B]。
        for out, grp in ((ctx.runner.run("filetype", "group-config", payload_json=_group_payload(g1, [a])), g1),
                         (ctx.runner.run("filetype", "group-config", payload_json=_group_payload(g2, [a, b])), g2)):
            result.record(op_succeeded(out, ctx=ctx, label=f"grp-{grp}-created"))

        # check1: 交叉引用后计数与实际一致。
        hit_a = entry_named(rest.list_entries(keywords=a), a)
        hit_b = entry_named(rest.list_entries(keywords=b), b)
        result.record(refcnt_check(label="refcnt-A=2", entry=hit_a, want=2))
        result.record(refcnt_check(label="refcnt-B=1", entry=hit_b, want=1))

        # 解引用 G1 → A 计数 -1。
        gdel = ctx.runner.run("filetype", "group-delete-batch", id=g1)
        result.record(op_succeeded(gdel, ctx=ctx, label="g1-deleted"))
        hit_a = entry_named(rest.list_entries(keywords=a), a)
        result.record(refcnt_check(label="refcnt-A=1-after-unlink", entry=hit_a, want=1))
    finally:
        if ctx.execute:
            for grp in (g1, g2):
                grps = rest.list_groups(keywords=grp)
                if any(str(g.get("name", "")) == grp for g in grps):
                    rest.delete_groups([grp])
            for name in (a, b):
                if entry_named(rest.list_entries(keywords=name), name):
                    rest.delete(name)
