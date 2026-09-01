"""P1-347376: 默认域名对象功能验证

xlsx(对象管理用例_重构_563.xlsx):
  1. 检查初始状态下 any 和 TIBLIST 是否存在【check1】配置存在
  2. 尝试删除 any 对象【check2】删除失败
  3. 尝试删除 TIBLIST 对象【check2】删除失败

设备实测(55.63, probe24): /api/v1/domainpool 初始含 any(domainaddrs 空域)与
TIBLIST; 删除任一 → 400 eRequestParam「预定义域名对象不能被删除」, 对象仍在。
"""

from __future__ import annotations

import requests

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.addr_cap_support import raw_headers, raw_req

TITLE = "P1-347376 默认域名对象功能验证"

DOM_RES = "/api/v1/domainpool"
DEFAULTS = ("any", "TIBLIST")


def _dom_names(ctx: CaseContext) -> list[str]:
    r = requests.get(f"{ctx.base_url}{DOM_RES}?page=1&size=200", headers=raw_headers(ctx),
                     verify=bool(ctx.verify_tls), timeout=20)
    try:
        return [str(e.get("name")) for e in (r.json().get("vals") or [])
                if isinstance(e, dict)]
    except Exception:  # noqa: BLE001
        return []


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="default-domain", ok=True, detail="dry-run")); return
    names = _dom_names(ctx)
    # check1: any 与 TIBLIST 初始存在。
    present = {n: (n in names) for n in DEFAULTS}
    result.record(Check(name="defaults-present", ok=all(present.values()),
                        detail=f"present={present} total_domains={len(names)}"))
    if not all(present.values()):
        result.notes.append(f"domainpool names={names[:20]}")

    # check2: 尝试删除 any / TIBLIST → 拒绝且对象仍在。
    for d in DEFAULTS:
        st, msg = raw_req(ctx, "DELETE", DOM_RES, ident=d)
        still = d in _dom_names(ctx)
        ok = st not in (200, 201, 202) and still
        result.record(Check(name=f"delete-{d}-rejected", ok=ok,
                            detail=f"delete → {st} ({msg or 'ok'}), still_present={still}"))
