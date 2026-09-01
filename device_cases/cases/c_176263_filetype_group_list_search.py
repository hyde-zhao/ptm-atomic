"""P0-176263: 文件类型组列表搜索功能测试-名称、描述参数

xlsx(对象管理用例_重构_563.xlsx):
  1. 搜索已存在的文件类型组【check1】【check2】
  2. 搜索已存在的文件类型组描述【check1】【check2】
  3. 搜索字符为文件类型组名字存在多个相同的数据【check1】【check2】
  4. 搜索字符为文件类型组描述存在多个相同的数据【check1】【check2】
  5. 搜索名称和描述均不存在的数据【check3】显示为空
  6. 搜索内容为空【check1】【check2】显示全部文件类型组

设备实测(55.63, probe23): /api/v1/appsec/filetypeObj 的 keywords 同时匹配组名
和描述(probe23 Q2: keywords=desc 只回该组)。组条目无 refcnt 字段,含 count
(成员数)字段 → check2 以「count == 实际成员数」落实一致性(refcnt 不对外暴露,
记录说明)。
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, group_member_names

TITLE = "P0-176263 文件类型组列表搜索功能测试-名称、描述参数"


def _count_ok(grp: dict) -> bool:
    """组条目 count 字段与实际成员数一致。"""
    try:
        count = int(grp.get("count", -1))
    except (TypeError, ValueError):
        return False
    return count == len(group_member_names(grp))


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    member = unique_random(176263, "m")
    g1 = unique_random(176263, "grpa")
    g2 = unique_random(176263, "grpb")
    d1 = unique_random(176263, "desca")
    made = [g1, g2]
    try:
        # 准备: 1 个成员文件类型 + 2 个组(g1 带独特描述)。
        r = rest.create(member)
        result.record(Check(name="precondition-member", ok=r.status_code == 200,
                            detail=f"create member {member} → {r.status_code}"))
        r1 = rest.create_group(g1, members=[member], des=d1)
        r2 = rest.create_group(g2, members=[member], des="plain")
        result.record(Check(name="precondition-groups", ok=r1.status_code == 200 and r2.status_code == 200,
                            detail=f"g1={r1.status_code} g2={r2.status_code}"))
        if not ctx.execute:
            return

        # check1: 按组名搜索 → 只回匹配组。
        hits = rest.list_groups(keywords=g1)
        names = [e.get("name") for e in hits]
        ok = g1 in names and g2 not in names
        result.record(Check(name="search-by-name", ok=ok, detail=f"keywords={g1!r} hits={names}"))
        # check2: count 一致性。
        grp = next((e for e in hits if e.get("name") == g1), None)
        result.record(Check(name="count-consistent-by-name", ok=grp is not None and _count_ok(grp),
                            detail=f"count={grp.get('count') if grp else None} members={len(group_member_names(grp)) if grp else 'n/a'}"))

        # check1: 按描述搜索 → 回对应组。
        hits = rest.list_groups(keywords=d1)
        names = [e.get("name") for e in hits]
        ok = g1 in names and g2 not in names
        result.record(Check(name="search-by-desc", ok=ok, detail=f"keywords={d1!r} hits={names}"))
        grp = next((e for e in hits if e.get("name") == g1), None)
        result.record(Check(name="count-consistent-by-desc", ok=grp is not None and _count_ok(grp),
                            detail=f"count={grp.get('count') if grp else None}"))

        # check1(多个相同): 共同前缀搜索 → 两个组都回。
        prefix = g1[:-1]
        hits = rest.list_groups(keywords=prefix)
        names = [e.get("name") for e in hits]
        ok = g1 in names and g2 in names
        result.record(Check(name="search-prefix-multi", ok=ok,
                            detail=f"keywords={prefix!r} hits={names}"))

        # check3: 名称+描述均不存在 → 空。
        hits = rest.list_groups(keywords="zzz_no_such_grp_176263")
        result.record(Check(name="search-no-match-empty", ok=len(hits) == 0,
                            detail=f"hits={len(hits)}"))

        # check1: 搜索为空 → 显示全部(含两个种子组)。
        hits = rest.list_groups(keywords="")
        names = [e.get("name") for e in hits]
        result.record(Check(name="search-empty-shows-all",
                            ok=g1 in names and g2 in names,
                            detail=f"total groups={len(names)}"))
    finally:
        if ctx.execute:
            for name in made:
                if any(e.get("name") == name for e in rest.list_groups(keywords=name)):
                    rest.delete_groups([name])
            rest.delete(member)
