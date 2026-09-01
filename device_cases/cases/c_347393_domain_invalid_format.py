"""P1-347393: 域名地址对象异常格式配置(#1830 异常域名格式)

xlsx(对象管理用例_重构_563.xlsx):
  1. 配置包含 NULL 字符的域名 → 配置下发失败并返回明确错误【check1】
  2. 配置包含 ASCII 控制字符的域名 → 配置下发失败并返回明确错误【check1】
  3. 配置超长域名(> 设备上限) → 配置下发失败并返回明确错误【check1】

设备实测(55.63, 2026-09-01):
  - 域名含 NUL(\\x00)/ASCII 控制字符(\\x01) → 400「域名不满足校验规则」
  - 域名长度 > 253 → 400「域名长度必须小于等于 253;域名不满足校验规则」
  三类非法值均在**设备侧**校验拒绝(客户端/runner 仅校验非空)。NUL 与控制字符
  无法经 Windows argv 传递, 故本用例用 raw REST 直连 API 落实设备校验断言,
  并在拒绝后 verify 确认无对象泄漏。
"""

from __future__ import annotations

from framework.checks import Check, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_verify, DOMAINPOOL
from framework.results import CaseResult

from cases.addr_cap_support import raw_req

TITLE = "P1-347393 域名对象异常格式配置拒绝"

DOM_RES = "/api/v1/domainpool"
MAX_DOMAIN_LEN = 253  # 设备实测: 大于 253 拒绝「域名长度必须小于等于 253」


def _create(ctx: CaseContext, name: str, domain: str) -> tuple[int, str]:
    val = {"name": name, "desc": "atc bad format",
           "domainaddrs": [{"domain": domain}]}
    return raw_req(ctx, "POST", DOM_RES, val=val)


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped"))
        return
    base = unique_random(347393, "dom")
    names: list[str] = []

    # 变体 1: 域名含 NUL 字符 → 设备拒绝「域名不满足校验规则」。
    nm_nul = f"{base}-nul"
    st, msg = _create(ctx, nm_nul, "exa\x00mple.com")
    result.record(Check(name="nul-char-rejected", ok=st == 400 and "域名不满足校验规则" in msg,
                        detail=f"domain=exa\\x00mple.com → {st} {msg!r}"))
    names.append(nm_nul)

    # 变体 2: 域名含 ASCII 控制字符 → 设备拒绝「域名不满足校验规则」。
    nm_ctl = f"{base}-ctl"
    st, msg = _create(ctx, nm_ctl, "exa\x01mple.com")
    result.record(Check(name="control-char-rejected", ok=st == 400 and "域名不满足校验规则" in msg,
                        detail=f"domain=exa\\x01mple.com → {st} {msg!r}"))
    names.append(nm_ctl)

    # 变体 3: 超长域名(> 253) → 设备拒绝「域名长度必须小于等于 253」。
    nm_long = f"{base}-long"
    overlong = "a" * (MAX_DOMAIN_LEN + 1) + ".com"
    st, msg = _create(ctx, nm_long, overlong)
    result.record(Check(name="overlong-rejected",
                        ok=st == 400 and "域名长度必须小于等于 253" in msg,
                        detail=f"domain len={len(overlong)} → {st} {msg!r}"))
    names.append(nm_long)

    # 泄漏检查: 三个非法对象均未创建(verify 查无)。
    leaked = [nm for nm in names if _find(ctx, nm)]
    result.record(state_check(ctx, Check(name="no-leaked-objects", ok=not leaked,
                                         detail=f"leaked={leaked or 'none'}")))
    if leaked:  # 兜底清理
        for nm in leaked:
            raw_req(ctx, "DELETE", DOM_RES, ident=nm)


def _find(ctx: CaseContext, name: str) -> bool:
    vout = _run_verify(ctx, DOMAINPOOL, name=name)
    if not vout.success:
        return False
    return any(str(e.get("name", "")) == name for e in _walk(vout.response()))


def _walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item)
