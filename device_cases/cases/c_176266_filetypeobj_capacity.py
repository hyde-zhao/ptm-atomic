"""P4-176266: 验证文件类型组容量测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 创建最大数量256个的文件类型组 【check1】新增成功，列表数量与实际一致
  2. 新增第257个文件类型组 【check2】新增失败，提示文件类型组已达到最大数量
  3. 最大数量下任意修改其中的文件类型组 【check3】修改成功，文件对象加载正常

每个组引用同一个自定义文件类型(检验组创建 + 引用计数双路径)。
设备实际容量可能小于256,记录真实 N;溢出拒绝点在任何 N 下都断言。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import (FiletypeRest, entry_named, refcnt_check)

TITLE = "P4-176266 验证文件类型组容量测试"

TARGET = 256
CHUNK = 50


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    prefix = unique_random(176266, "grp")
    ft = unique_random(176266, "ft")
    created_grps: list[str] = []
    ft_del = False
    try:
        if not ctx.execute:
            result.record(Check(name="group-capacity-256", ok=True,
                                detail="dry-run: bulk 256-group creation skipped"))
            return

        # 共享引用对象。
        r = rest.create(ft)
        ft_del = r.status_code == 200

        # check1: 建到目标数量,遇拒即停。
        for i in range(TARGET):
            name = f"{prefix}_{i}"
            r = rest.create_group(name, members=[ft])
            if r.status_code != 200:
                result.notes.append(
                    f"device group cap reached at {len(created_grps)} (< {TARGET}): "
                    f"rc={r.status_code} {r.text[:80]}")
                break
            created_grps.append(name)
        n = len(created_grps)

        # 列表数量与实际一致(keywords 前缀过滤)。
        grps = rest.list_groups(keywords=prefix)
        result.record(Check(name="group-list-count-matches", ok=len(grps) == n,
                            detail=f"created={n} listed={len(grps)}"))

        # check2: 第257个(或容量到达点下一个)被拒。
        r = rest.create_group(f"{prefix}_overflow", members=[ft])
        result.record(Check(name="group-overflow-rejected", ok=r.status_code != 200,
                            detail=f"rc={r.status_code} {r.text[:80]}"))

        # 设备组容量为 256 总数(含内置预定义组),自定义实际上限 = 256 - builtin。
        builtin = sum(1 for g in rest.list_groups() if "预定义" in str(g.get("name", "")))
        total_after = n + builtin
        result.record(Check(name="group-capacity-256", ok=total_after == 256,
                            detail=f"custom={n} builtin={builtin} total={total_after} "
                                   f"(device cap=256 total incl built-in)"))
        if total_after != 256:
            result.notes.append(
                f"设备组容量={total_after}(custom {n} + builtin {builtin}) ≠ 256 — divergence")

        # 共享对象的引用计数 = 实际组数。
        hit = entry_named(rest.list_entries(keywords=ft), ft)
        result.record(refcnt_check(label="refcnt-equals-group-count", entry=hit, want=n))

        # check3: 最大数量下任意修改 → 成功。
        if n:
            r = rest.update_group(created_grps[0], members=[ft], des="cap-update")
            result.record(Check(name="group-update-under-max", ok=r.status_code == 200,
                                detail=f"rc={r.status_code} {r.text[:80]}"))
    finally:
        if ctx.execute:
            for i in range(0, len(created_grps), CHUNK):
                rest.delete_groups(created_grps[i:i + CHUNK])
            if entry_named(rest.list_entries(keywords=ft), ft):
                rest.delete(ft)
