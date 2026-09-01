"""P4-176251: 自定义文件类型和预定义文件类型冲突测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 新建自定义文件类型对象
  2. 文件对象名与预定义名大小写均一致 【check1】创建失败
  3. 文件对象名与预定义名相同，但大小写不一致 【check2】创建成功

预定义名发现(设备实测): /api/v1/appsec/filetype 的 type 参数只接受 "custom",
预定义类型不能直接列出;但内置预定义组(预定义全部文件类型组 / 预定义可执行
文件类型组)的成员即为预定义文件类型(type:false, config_source:18),运行时从
组列表抽取第一个作为冲突样本。
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, entry_named

TITLE = "P4-176251 自定义文件类型和预定义文件类型冲突测试"


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


def _case_variant(p: str) -> str:
    """大小写不一致的变体(swapcase 后去掉非字母字符干扰)。"""
    v = p.swapcase()
    return v if v != p else p + "x"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    if not ctx.execute:
        result.record(Check(name="predefined-conflict", ok=True, detail="dry-run"))
        return
    predefined = _predefined_names(rest)
    if not predefined:
        result.record(Check(name="predefined-discovered", ok=False,
                            detail="no predefined names found in built-in predefined groups"))
        return
    result.record(Check(name="predefined-discovered", ok=True,
                        detail=f"predefined={predefined}"))
    p = predefined[0]
    variant = _case_variant(p)
    created: list[str] = []
    try:
        # check1: 与预定义名大小写完全一致 → 创建失败。
        out = ctx.runner.run("filetype", "config", name=p)
        result.record(op_rejected(out, ctx=ctx, label="exact-predefined-name-rejected",
                                  expect_err_codes=("eObjCreateExist", "eRequestParam")))

        # check2: 大小写不一致 → 创建成功。
        out = ctx.runner.run("filetype", "config", name=variant)
        result.record(op_succeeded(out, ctx=ctx, label="case-variant-created"))
        if out.success:
            created.append(variant)
    finally:
        if ctx.execute:
            for name in created:
                if entry_named(rest.list_entries(keywords=name), name):
                    rest.delete(name)
