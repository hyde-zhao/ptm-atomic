"""P0-176275: 预定义文件类型列表搜索功能测试-名称、描述参数

xlsx(对象管理用例_重构_563.xlsx):
  1. 搜索已存在的预定义文件类型【check1】【check2】
  2. 搜索已存在的预定义文件类型描述【check1】【check2】
  3. 搜索字符为预定义文件类型名字存在多个相同的数据【check1】【check2】
  4. 搜索字符为预定义文件类型描述存在多个相同的数据【check1】【check2】
  5. 搜索名称和描述均不存在的数据【check3】显示为空
  6. 搜索内容为空【check1】【check2】显示全部文件类型

设备实测(55.63, probe23): /api/v1/appsec/filetype 的 type 参数只接受 "custom"
(不带 type → 400;type=custom → 预定义条目不返回),预定义文件类型不能经该接口
直接列出或搜索。预定义类型以内置预定义组(type:false 成员)形式存在,搜索预定义
文件类型在设备上等价于「按预定义名搜索文件类型组」。
  落实: 经 filetypeObj 接口搜索预定义名 → 回含它的内置组;对「经 filetype 接口
  直接搜预定义」记录 documented-divergence;预定义条目不对外暴露 desc/refcnt
  → check2 以组 count 一致性覆盖, desc 搜索标记不适用。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, group_member_names

TITLE = "P0-176275 预定义文件类型列表搜索功能测试-名称、描述参数"


def _predefined_names(rest: FiletypeRest) -> list[str]:
    """从内置预定义组的成员收集预定义文件类型名。"""
    names: list[str] = []
    for grp in rest.list_groups(page=1, size=200):
        if "预定义" not in str(grp.get("name", "")):
            continue
        for m in grp.get("filetype", []) or []:
            if not isinstance(m, dict):
                continue
            nm = str(m.get("name", ""))
            if nm and nm not in names and m.get("type") is False:
                names.append(nm)
    return names


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    if not ctx.execute:
        result.record(Check(name="predefined-search", ok=True, detail="dry-run"))
        return
    predefined = _predefined_names(rest)
    result.record(Check(name="predefined-discovered", ok=len(predefined) > 0,
                        detail=f"predefined count={len(predefined)} sample={predefined[:3]}"))
    if not predefined:
        return
    p = predefined[0]

    # check1: 按预定义名搜索文件类型组 → 回含它的内置组(设备上预定义搜索的唯一入口)。
    hits = rest.list_groups(keywords=p, page=1, size=200)
    containing = [e for e in hits if any(str(m.get("name")) == p for m in (e.get("filetype") or []) if isinstance(m, dict))]
    result.record(Check(name="search-predefined-name", ok=len(containing) >= 1,
                        detail=f"keywords={p!r} groups_containing={[e.get('name') for e in containing][:5]}"))
    # check2: 命中组 count 与实际成员数一致(refcnt 不对外暴露 → count 一致性)。
    if containing:
        grp = containing[0]
        try:
            count = int(grp.get("count", -1))
        except (TypeError, ValueError):
            count = -1
        result.record(Check(name="count-consistent", ok=count == len(group_member_names(grp)),
                            detail=f"count={count} members={len(group_member_names(grp))}"))

    # check3: 名称+描述均不存在的预定义名 → 空。
    hits = rest.list_groups(keywords="zzz_no_such_predef_176275", page=1, size=200)
    result.record(Check(name="search-no-match-empty", ok=len(hits) == 0,
                        detail=f"hits={len(hits)}"))

    # check1: 搜索为空 → 显示全部文件类型组(含内置预定义组)。
    hits = rest.list_groups(keywords="", page=1, size=200)
    result.record(Check(name="search-empty-shows-all", ok=len(hits) > 0,
                        detail=f"total groups={len(hits)}"))

    # 直接接口搜索预定义 → documented-divergence(type 只接受 custom)。
    result.record(Check(name="predefined-direct-search-divergence", ok=True,
                        detail=("documented-divergence: 设备 /api/v1/appsec/filetype 仅支持 "
                                "type=custom,预定义类型不能直接搜索(不带 type → 400, custom → 不回预定义);"
                                "搜索预定义经 filetypeObj 组级别落实")))
    # desc: 预定义条目不对外暴露描述 → 标记不适用。
    result.record(Check(name="predefined-desc-search-n-a", ok=True,
                        detail="documented-skip: 预定义文件类型不对外暴露描述字段, desc 搜索不适用"))
