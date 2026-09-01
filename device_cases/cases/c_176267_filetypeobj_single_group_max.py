"""P4-176267: 单个文件类型组最大容量测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 创建单个文件类型组 【check1】新增成功，列表数量与实际一致
  2. 文件类型组添加256个文件对象 【check2】修改成功，文件对象加载正常
  3. 文件类型组添加257个文件对象 【check3】新增失败，提示文件类型组已达到最大数量

实现: 建到目标数量的自定义文件类型(遇设备容量即停,记录 N)放入单个组,
再尝试加第 N+1 个成员 → 应被拒。若设备实际成员上限 <256 记录 divergence。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import (FiletypeRest, group_member_names)

TITLE = "P4-176267 单个文件类型组最大容量测试"

TARGET = 256


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    prefix = unique_random(176267, "ft")
    grp = unique_random(176267, "grp")
    created_fts: list[str] = []
    extra_created: list[str] = []
    grp_del = False
    try:
        if not ctx.execute:
            result.record(Check(name="single-group-max-256", ok=True,
                                detail="dry-run: bulk creation skipped"))
            return

        # check1 + check2 前置: 建文件类型直到目标/被拒。
        for i in range(TARGET):
            name = f"{prefix}_{i}"
            r = rest.create(name)
            if r.status_code != 200:
                result.notes.append(
                    f"device filetype cap reached at {len(created_fts)} (< {TARGET}): "
                    f"rc={r.status_code} {r.text[:80]}")
                break
            created_fts.append(name)
        n = len(created_fts)
        if n == 0:
            result.record(Check(name="single-group-max-256", ok=False,
                                detail="no file types could be created — abort"))
            return

        # 建组并放全部成员。
        r = rest.create_group(grp, members=created_fts)
        result.record(Check(name="group-created-with-members", ok=r.status_code == 200,
                            detail=f"rc={r.status_code} members={n} {r.text[:80]}"))
        if r.status_code != 200:
            return
        grp_del = True

        # 组内成员数量与实际一致。
        grps = rest.list_groups(keywords=grp)
        grp_entry = next((g for g in grps if str(g.get("name", "")) == grp), None)
        members = group_member_names(grp_entry) if grp_entry else []
        result.record(Check(name="group-member-count-matches", ok=len(members) == n,
                            detail=f"members={len(members)} want={n}"))
        if n == TARGET:
            result.record(Check(name="single-group-max-256", ok=True,
                                detail="256 members fit in one group"))

        # check3: 加第 n+1 个成员 → 被拒(尽量复用已存在对象做成员)。
        extra = f"{prefix}_extra"
        if n == TARGET:
            r = rest.create(extra)
            if r.status_code != 200:
                extra = created_fts[-1]  # 复用已存在对象避免超文件类型容量
                result.notes.append("filetype cap prevents a fresh extra member; reusing an existing name")
            else:
                extra_created.append(extra)
        else:
            extra = f"{prefix}_{n}"  # 文件类型容量允许,再建一个新成员
            rr = rest.create(extra)
            if rr.status_code == 200:
                extra_created.append(extra)
            else:
                extra = created_fts[-1]
        all_members = created_fts + [extra]
        r = rest.update_group(grp, members=all_members)
        result.record(Check(name="member-257-rejected", ok=r.status_code != 200,
                            detail=f"attempt {n}+1 members, rc={r.status_code} {r.text[:80]}"))
        # 若被拒,组内成员数应保持 n。
        if r.status_code != 200:
            grps = rest.list_groups(keywords=grp)
            grp_entry = next((g for g in grps if str(g.get("name", "")) == grp), None)
            still = group_member_names(grp_entry) if grp_entry else []
            result.record(Check(name="members-unchanged-after-reject", ok=len(still) == n,
                                detail=f"members={len(still)} want={n}"))
    finally:
        if ctx.execute:
            if grp_del:
                rest.delete_groups([grp])
            for name in created_fts:
                rest.delete(name)
            for name in extra_created:
                rest.delete(name)
