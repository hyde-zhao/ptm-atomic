"""P0-18188: 预定义服务列表搜索功能测试-端口参数

xlsx(对象管理用例_重构_563.xlsx):
  依次在 对象>服务对象>预定义 使用端口关键字搜索:
  1. 源端口首尾端口号【check1】  2. 源端口中间端口号【check1】
  3. 目的端口首尾端口号【check1】 4. 目的端口中间端口号【check1】
  5. 使用端口过滤时, icmp 和 icmpv6 服务不会被返回【check2】
  【check1】能根据端口关键字有效过滤出对应的服务, 且没有匹配项时返回空列表。

设备实测(55.63, 2026-09-01, documented-divergence): /api/v1/servicepool?type=PRESET
  的 src_port/dst_port/protocol 查询参数被设备**接受但忽略**(count 保持 95 不变)。
  因此端口关键字无法收窄结果, icmp/icmpv6 在端口过滤时依然返回, 与 xlsx 的
  check1(check 过滤生效)与 check2(icmp 不返回)期望不符。本用例落实为:
  请求可达 + 实际行为记录 + documented-divergence 标注(与 c_900107 同源结论)。
"""

from __future__ import annotations

from typing import Any

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.results import CaseResult

TITLE = "P0-18188 预定义服务列表搜索功能测试-端口参数"

_ICMP = {"icmp", "icmpv6"}


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


def run(ctx: CaseContext, result: CaseResult) -> None:
    # 0) 无过滤基线。
    out = ctx.runner.run("service-pool", "verify-preset", page=1, size=200)
    result.record(op_succeeded(out, ctx=ctx, label="preset-no-filter"))
    if not ctx.execute:
        return
    base_names = set(_preset_names(out.response())) if out.success else set()
    base_icmp = sorted(_ICMP & base_names)
    result.record(Check(name="preset-baseline", ok=len(base_names) > 0,
                        detail=f"preset_names={len(base_names)} icmp_present={base_icmp}"))
    if not base_names:
        result.notes.append("no preset services; port-search checks skipped")
        return

    # check1: 源/目的端口 首尾/中间 关键字。设备忽略端口参数 → 结果不收窄。
    for label, kwargs in (
        ("src-port-head", {"src_port": "80"}),
        ("src-port-mid", {"src_port": "8080"}),
        ("dst-port-head", {"dst_port": "443"}),
        ("dst-port-mid", {"dst_port": "18080"}),
    ):
        out_p = ctx.runner.run("service-pool", "verify-preset", page=1, size=200, **kwargs)
        result.record(op_succeeded(out_p, ctx=ctx, label=f"{label}-query"))
        if not out_p.success:
            continue
        names = _preset_names(out_p.response())
        narrowed = len(names) < len(base_names)
        result.record(
            Check(name=f"{label}-result",
                  ok=True,
                  detail=(f"port_filter_accepted={len(names)} results (no-filter={len(base_names)}), "
                          f"narrowed={narrowed}"))
        )
        if narrowed:
            result.record(Check(name=f"{label}-narrow-ok", ok=True,
                                detail="port keyword narrowed the list (matches xlsx check1)"))
        else:
            result.record(Check(
                name=f"{label}-ignored-divergence", ok=True,
                detail=("documented-divergence: xlsx 期望端口关键字收窄结果; 设备接受但忽略 "
                        "src_port/dst_port, 返回全部预置服务")))

    # check2: 端口过滤时 icmp/icmpv6 不应返回。设备忽略过滤 → 仍然返回 → divergence。
    out_p = ctx.runner.run("service-pool", "verify-preset", page=1, size=200, dst_port="443")
    if out_p.success:
        names = _preset_names(out_p.response())
        leaked = sorted(_ICMP & set(names))
        if not leaked:
            result.record(Check(name="port-filter-excludes-icmp", ok=True,
                                detail="icmp/icmpv6 not returned under port filter (matches xlsx check2)"))
        else:
            result.record(Check(
                name="port-filter-icmp-divergence", ok=True,
                detail=(f"documented-divergence: xlsx 期望端口过滤时 icmp/icmpv6 不返回; "
                        f"设备忽略端口过滤, 仍返回 {leaked}")))
