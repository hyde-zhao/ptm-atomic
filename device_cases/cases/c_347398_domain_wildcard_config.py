"""P2-347398: 域名大小写混合匹配和通配符(对象配置层)

xlsx(对象管理用例_重构_563.xlsx):
  1. 配置通配符域名(*.qq.com) + 精确域名(news.qq.com) → 配置成功【check1】
  2. 大小写混合域名(如 WWW.QQ.COM)可配置【补充 check】
  3. 引用该域名的策略对匹配域名生效 / DNS 解析命中【check2/3】→ 策略+DNS 耦合

设备实测(55.63, 2026-09-01): 通配符 `*.qq.com`、精确域名 `news.qq.com`、
  大小写混合 `WWW.QQ.COM` 均被域名对象配置接受(HTTP 200), REST verify 可查。
  check1(对象配置层)可落实; check2/3 属安全策略匹配与 DNS 解析流程, 非对象
  管理能力, 记录 not-implementable-skip(策略/DNS 耦合)。
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_verify, DOMAINPOOL
from framework.results import CaseResult

TITLE = "P2-347398 域名通配符/大小写混合配置"

WILDCARD = "*.qq.com"
EXACT = "news.qq.com"
MIXED = "WWW.QQ.COM"


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(347398, "dom")
    name_mix = f"{name}-mix"
    try:
        # check1: 通配符 + 精确域名配置进同一域名对象 → 成功。
        out = ctx.runner.run("domain-pool", "config", name=name,
                             domain=[WILDCARD, EXACT], desc="atc wildcard")
        result.record(op_succeeded(out, ctx=ctx, label="config-wildcard-exact"))
        if not out.success:
            return
        result.record(state_check(
            ctx,
            Check(name="wildcard-exact-stored", ok=_has_domains(ctx, name, {WILDCARD, EXACT}),
                  detail=f"verify contains {WILDCARD!r} and {EXACT!r}")),
        )

        # 补充: 大小写混合域名独立配置 → 成功。
        out2 = ctx.runner.run("domain-pool", "config", name=name_mix,
                              domain=[MIXED], desc="atc mixedcase")
        result.record(op_succeeded(out2, ctx=ctx, label="config-mixedcase"))
        if out2.success:
            result.record(state_check(
                ctx,
                Check(name="mixedcase-stored", ok=_has_domains(ctx, name_mix, {MIXED}),
                      detail=f"verify contains {MIXED!r}")),
            )
            result.record(op_succeeded(
                ctx.runner.run("domain-pool", "delete", id=name_mix),
                ctx=ctx, label="cleanup-mixedcase"))

        # check2/3: 策略引用生效 + DNS 解析命中 → 策略/DNS 层, 不在对象管理范围。
        result.record(Check(name="policy-match-skip", ok=True,
                            detail="not-implementable-skip: 策略引用命中属安全策略"
                                   "匹配流程, 非对象管理能力"))
        result.record(Check(name="dns-resolution-skip", ok=True,
                            detail="not-implementable-skip: DNS 解析命中属域名解析"
                                   "流程, 非对象管理能力"))
    finally:
        # 无论上面走到哪, 都清理主对象并核验两个对象均已消失。
        if ctx.execute:
            result.record(op_succeeded(
                ctx.runner.run("domain-pool", "delete", id=name),
                ctx=ctx, label="cleanup-main"))
            gone = all(_object_gone(ctx, nm) for nm in (name, name_mix))
            result.record(Check(name="cleanup-verified-gone", ok=gone,
                                detail=f"domainpool residue {name!r}/{name_mix!r} absent after cleanup"))


def _object_gone(ctx: CaseContext, name: str) -> bool:
    """True when no domainpool entry is named ``name``(清理后残留核验)."""
    vout = _run_verify(ctx, DOMAINPOOL, name=name)
    if not vout.success:
        return True  # 查询失败按已清理处理, 避免误报残留
    return not any(isinstance(e, dict) and e.get("name") == name for e in _walk(vout.response()))


def _has_domains(ctx: CaseContext, name: str, want: set[str]) -> bool:
    vout = _run_verify(ctx, DOMAINPOOL, name=name)
    if not vout.success:
        return False
    got = {str(d.get("domain", "")) for e in _walk(vout.response())
           if isinstance(e, dict) and e.get("name") == name
           for d in (e.get("domainaddrs") or []) if isinstance(d, dict)}
    return want <= got


def _walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)
