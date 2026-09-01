"""P0-18187: 预定义服务列表搜索功能测试-名称参数

xlsx(对象管理用例_重构_563.xlsx):
  依次在 对象>服务对象>预定义 搜索:
  1. 小写英文完整名称【check1】
  2. 大写英文完整名称【check1】
  3. 大小写混合英文部分名称【check1】
  4. 中文/数字/字母混合部分名称【check1】
  【check1】能根据名称关键字有效过滤出对应的服务, 且当没有匹配项的时候返回空列表。

设备实测(55.63, 2026-09-01): /api/v1/servicepool?type=PRESET 的 keywords 参数
  大小写不敏感子串匹配(dns/DNS/DnS 均命中 dns; 'ftp' 命中 ftp+tftp; 无中文预置服务
  → 中文混合关键字返回空列表)。四种搜索变体均符合 xlsx 预期。
"""

from __future__ import annotations

from typing import Any

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.results import CaseResult

TITLE = "P0-18187 预定义服务列表搜索功能测试-名称参数"


def _preset_names(response: Any) -> list[str]:
    names: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            nm = node.get("name")
            if isinstance(nm, str) and nm:
                names.append(nm)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(response)
    return names


def _run_keyword(ctx: CaseContext, result: CaseResult, *, kw: str, label: str,
                 base_names: list[str]) -> None:
    """执行一次 keywords 搜索并断言: 结果全部含关键字(大小写不敏感) 或 为空。"""
    out = ctx.runner.run("service-pool", "verify-preset", page=1, size=200, keywords=kw)
    result.record(op_succeeded(out, ctx=ctx, label=f"{label}-query"))
    if not out.success:
        return
    hits = _preset_names(out.response())
    lo = kw.lower()
    filtered_ok = all(lo in n.lower() for n in hits)
    result.record(
        Check(name=label,
              ok=filtered_ok and (len(hits) > 0 if base_names else len(hits) == 0),
              detail=f"kw={kw!r} hits={len(hits)} "
                     f"({'all-valid' if filtered_ok else 'non-matching-in-results'})"))


def run(ctx: CaseContext, result: CaseResult) -> None:
    # 0) 无过滤预置列表 → 拿到一个真实服务名作关键字种子。
    out = ctx.runner.run("service-pool", "verify-preset", page=1, size=200)
    result.record(op_succeeded(out, ctx=ctx, label="preset-no-filter"))
    if not ctx.execute:
        return
    base_names = _preset_names(out.response()) if out.success else []
    result.record(Check(name="preset-non-empty", ok=len(base_names) > 0,
                        detail=f"preset_names={len(base_names)}"))
    if not base_names:
        result.notes.append("no preset services; name-search checks skipped")
        return

    seed = next((n for n in base_names if len(n) >= 3), base_names[0])

    # check1 各变体: 小写/大写/混合部分名 → 命中; 中文混合 & 不存在名 → 空列表。
    _run_keyword(ctx, result, kw=seed.lower(), label="search-lower-full", base_names=base_names)
    _run_keyword(ctx, result, kw=seed.upper(), label="search-upper-full", base_names=base_names)
    _run_keyword(ctx, result, kw=seed[:2].swapcase(), label="search-mixed-partial",
                 base_names=base_names)
    _run_keyword(ctx, result, kw="中文3ab", label="search-cn-digit-mixed", base_names=[])
    _run_keyword(ctx, result, kw=f"{seed}zzznotfound", label="search-no-match", base_names=[])
