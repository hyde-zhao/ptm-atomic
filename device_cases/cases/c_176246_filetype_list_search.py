"""P0-176246: 自定义文件类型列表搜索功能测试-名称、描述参数.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 使用/api/v1/appsec/filetype?type=custom&keywords=<name>搜索名称 【check1】过滤正确 【check2】引用计数一致
  2. 同上搜索描述 【check1】【check2】
  3. 搜索名称和描述均不存在的数据 【check3】显示为空
  4. 搜索内容为空 【check4】显示全部文件对象内容

单对象 filetype 无 CLI verify op,搜索走 FiletypeRest 原生 GET。
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, entry_named, refcnt_check

TITLE = "P0-176246 自定义文件类型列表搜索功能测试-名称、描述参数"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    f1 = unique_random(176246, "alpha")
    f2 = unique_random(176246, "beta")
    d1 = unique_random(176246, "descalpha")
    made = [f1, f2]
    try:
        # 准备: 两个自定义文件类型,f1 带独特描述。
        for out in (ctx.runner.run("filetype", "config", name=f1, description=d1),
                    ctx.runner.run("filetype", "config", name=f2)):
            result.record(op_succeeded(out, ctx=ctx, label="seed-created"))
        if not ctx.execute:
            return

        # check1: 按名称搜索 → 只回匹配对象。
        hits = rest.list_entries(keywords=f1)
        ok = entry_named(hits, f1) is not None and entry_named(hits, f2) is None
        result.record(Check(name="search-by-name", ok=ok,
                            detail=f"keywords={f1!r} hits={[e['name'] for e in hits]}"))

        # check2: 搜索描述 token → 回对象;引用计数与实际一致(无引用 → 0)。
        hits = rest.list_entries(keywords=d1)
        hit = entry_named(hits, f1)
        result.record(Check(name="search-by-desc", ok=hit is not None,
                            detail=f"keywords={d1!r} hits={[e['name'] for e in hits]}"))
        if hit is not None:
            result.record(refcnt_check(label="refcnt-consistent", entry=hit, want=0))
        else:
            result.record(Check(name="refcnt-consistent", ok=False,
                                detail="search-by-desc did not find f1, refcnt uncheckable"))

        # check3: 名称+描述都不存在 → 空。
        hits = rest.list_entries(keywords="zzz_no_such_token_176246")
        result.record(Check(name="search-no-match-empty", ok=len(hits) == 0,
                            detail=f"hits={len(hits)}"))

        # check4: 搜索内容为空 → 显示全部自定义文件类型(含两个种子)。
        # 只断言本用例种子的 refcnt(设备上可能存在历史对象,不在此范围内)。
        hits = rest.list_entries(keywords="")
        result.record(Check(name="search-empty-shows-all",
                            ok=entry_named(hits, f1) is not None and entry_named(hits, f2) is not None,
                            detail=f"total custom={len(hits)}"))
        for seed in (f1, f2):
            result.record(refcnt_check(label=f"refcnt-{seed}", entry=entry_named(hits, seed), want=0))
    finally:
        if ctx.execute:
            for name in made:
                if entry_named(rest.list_entries(keywords=name), name):
                    rest.delete(name)
