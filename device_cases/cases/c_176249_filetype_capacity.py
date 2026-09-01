"""P4-176249: 自定义文件类型容量测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 创建最大数量256个的自定义文件类型 【check1】新增成功，列表数量与实际一致
  2. 新增第257个自定义文件类型 【check2】新增失败，提示文件对象已达到最大数量
  3. 最大数量下任意修改其中的文件类型 【check3】修改成功，文件对象加载正常

设备实测: 单对象 filetype 容量上限按设备实际取值(可能小于256),记录真实
容量 N;N==256 才判 capacity-256 通过,否则记 divergence。
256 个对象走 FiletypeRest 原生 HTTP 批量创建(CLI 子进程每 op 会太慢)。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, entry_named

TITLE = "P4-176249 自定义文件类型容量测试"

TARGET = 256


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    prefix = unique_random(176249, "cap")
    created: list[str] = []
    try:
        if not ctx.execute:
            result.record(Check(name="capacity-256", ok=True,
                                detail="dry-run: bulk 256-object creation skipped"))
            return

        # check1: 创建到目标数量,遇拒即停,记录真实容量 N。
        for i in range(TARGET):
            name = f"{prefix}_{i}"
            r = rest.create(name)
            if r.status_code != 200:
                result.notes.append(
                    f"device cap reached at {len(created)} (< {TARGET}): "
                    f"rc={r.status_code} {r.text[:80]}")
                break
            created.append(name)
        n = len(created)

        listing = rest.list_entries(keywords=prefix)
        result.record(Check(name="list-count-matches", ok=len(listing) == n,
                            detail=f"created={n} listed={len(listing)}"))

        # check2: 第257个被拒(或容量到达点被拒)。
        r = rest.create(f"{prefix}_overflow")
        result.record(Check(name="overflow-rejected", ok=r.status_code != 200,
                            detail=f"rc={r.status_code} {r.text[:80]}"))
        if n == TARGET:
            result.record(Check(name="capacity-256", ok=True,
                                detail="256 custom filetypes created, 257th rejected"))
        else:
            result.record(Check(name="capacity-256", ok=False,
                                detail=f"device cap={n} < 256 — divergence"))

        # check3: 最大数量下任意修改 → 成功。
        if n:
            r = rest.update(created[0], description="cap-update")
            result.record(Check(name="update-under-max", ok=r.status_code == 200,
                                detail=f"rc={r.status_code} {r.text[:80]}"))
    finally:
        if ctx.execute:
            for name in created:
                rest.delete(name)
            for name in (f"{prefix}_overflow",):
                if entry_named(rest.list_entries(keywords=name), name):
                    rest.delete(name)
