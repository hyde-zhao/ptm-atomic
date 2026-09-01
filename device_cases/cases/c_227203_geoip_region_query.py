"""P2-227203: 预定义地区对象地区信息查询(#2112)

xlsx(对象管理用例_重构_563.xlsx):
  1. 新建含 IP 的地区对象 → 成功【check1】
  2. 用该 IP 查询地区信息 → 返回对应国家/省份/城市【check2】
  3. 编辑地区对象(改 IP 段) → 成功【check3】
  4. 再用新 IP 查询 → 返回更新后的地区信息【check4】

设备实测(55.63, 2026-09-01): geoip verify(GET /api/v1/geoip/custom) 忽略
  keywords 过滤(恒返回全量), 且无独立「按 IP 查地区」对象管理接口 —— 地区信息
  随对象列表返回(entry 携带 ip/country/province/city)。故「用 IP 查询地区信息」
  落实为: 对全量 verify 响应按 ip 字段客户端匹配, 断言命中 entry 的地区字段。
  注意: 创建入参 country=CN/province=Hunan/city=Changsha 被设备接受, 但 verify
  返回**本地化中文渲染**(country='中国' province='湖南省' city='长沙市')。断言
  country 渲染为 中国(CN 的固定映射), province/city 非空且跨创建/编辑查询稳定。
"""

from __future__ import annotations

from framework.checks import Check, find_entries, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.geoip_support import CITY, PROVINCE

TITLE = "P2-227203 地区对象地区信息查询"

IP_A = "198.18.0.1-198.18.0.9"
IP_B = "198.18.1.1-198.18.1.9"


def run(ctx: CaseContext, result: CaseResult) -> None:
    desc = unique_random(227203, "gip")
    created = False
    deleted = False
    rendered: tuple[str, str, str] | None = None
    try:
        # check1: 新建含 IP 的地区对象 → 成功, 返回数字 id。
        out = ctx.runner.run("geoip", "config", ip=IP_A, country="CN",
                             province=PROVINCE, city=CITY, desc=desc)
        result.record(op_succeeded(out, ctx=ctx, label="create-region-obj"))
        if not ctx.execute:
            return
        gip_id = out.response().get("id")
        created = out.success and isinstance(gip_id, int)
        result.record(Check(name="create-numeric-id", ok=created, detail=f"id={gip_id!r}"))

        # check2: 用该 IP 查询地区信息 → 命中 entry, 地区字段渲染为 中国/省/市。
        v = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v, ctx=ctx, label="verify-region-query"))
        if v.success:
            hits = _by_ip(v.response(), IP_A)
            rendered = _region_of(hits)
            result.record(state_check(
                ctx,
                Check(name="region-query-by-ip",
                      ok=rendered is not None and rendered[0] == "中国",
                      detail=_region_detail(hits, "query-ip-a")),
            ))

        # check3: 编辑地区对象(改 IP 段) → 成功。
        u = ctx.runner.run("geoip", "update", id=gip_id, ip=IP_B, country="CN",
                           province=PROVINCE, city=CITY, desc=desc)
        result.record(op_succeeded(u, ctx=ctx, label="update-region-obj"))

        # check4: 再用新 IP 查询 → 命中更新后的地区信息(渲染稳定); 旧 IP 不再命中。
        v2 = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v2, ctx=ctx, label="verify-after-update"))
        if v2.success:
            new_hits = _by_ip(v2.response(), IP_B)
            rendered2 = _region_of(new_hits)
            result.record(state_check(
                ctx,
                Check(name="region-query-updated-ip",
                      ok=rendered2 is not None and rendered2 == rendered,
                      detail=_region_detail(new_hits, "query-ip-b")),
            ))
            old_hits = _by_ip(v2.response(), IP_A)
            result.record(state_check(
                ctx,
                Check(name="old-ip-region-gone", ok=len(old_hits) == 0,
                      detail=f"old ip {IP_A!r} matches={len(old_hits)}"),
            ))

        d = ctx.runner.run("geoip", "delete-batch", id=[gip_id])
        result.record(op_succeeded(d, ctx=ctx, label="delete-region-obj"))
        deleted = d.success
    finally:
        if created and not deleted:
            ctx.runner.run("geoip", "delete-batch", id=[gip_id])


def _by_ip(response: dict, ip: str) -> list[dict]:
    return find_entries(response, lambda e: str(e.get("ip", "")) == ip)


def _region_of(hits: list[dict]) -> tuple[str, str, str] | None:
    """Device-rendered (country, province, city) if exactly one entry matched."""
    if len(hits) != 1:
        return None
    entry = hits[0]
    region = (str(entry.get("country", "")),
              str(entry.get("province", "")),
              str(entry.get("city", "")))
    return region if all(region) else None


def _region_detail(hits: list[dict], label: str) -> str:
    # 地区为设备本地化渲染(中文), 断言值且打印供核对。
    if not hits:
        return f"{label}: no entry matched ip"
    hit = hits[0]
    return (f"{label}: country={hit.get('country')!r} province={hit.get('province')!r} "
            f"city={hit.get('city')!r}")
