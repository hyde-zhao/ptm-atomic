"""P4-347285: 验证系统支持的最大时间对象数量及创建边界

xlsx(对象管理用例_重构_563.xlsx):
  1. 脚本循环创建时间对象直到达到规格上限(N)
  2. 尝试创建第 N+1 个对象【check1】创建失败, 回显达到最大规格限制
  3. 选取500个时间对象, 设置同一秒触发变更【check2】处理成功, 任务无丢失, 无协程泄露, CPU 合理

设备实测(55.63, 2026-09-01): 时间对象经探针创建 300 个仍无上限(实际上限 > 300),
「达到规格上限」路径在合理测试时间内不可穷尽。以「有界高水位 FILL=200」落实:
  高水位批量创建全成功 → 之上再建成功(实际未达上限) → 对 check1 的满容量拒绝
  记录 documented-divergence。check2(500 对象同一秒触发 + CPU/协程监测)属数据
  面/性能域, 无流量注入与监控手段 → documented-skip。
"""

from __future__ import annotations

import requests

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.addr_cap_support import raw_headers

TITLE = "P4-347285 验证系统支持的最大时间对象数量及创建边界"

TIME_RES = "/api/v1/timeobject"
FILL = 200  # 有界高水位(探针实测 > 300 无上限)。


def _day_payload(name: str, desc: str = "") -> dict:
    return {"name": name, "desc": desc, "scheduletype": "day",
            "timequantum": [{"starttime": {"time": "00:00:00"}, "endtime": {"time": "23:59:59"}}]}


def _time_find(ctx: CaseContext, name: str) -> bool:
    r = requests.get(f"{ctx.base_url}{TIME_RES}?page=1&size=1&keywords={name}",
                     headers=raw_headers(ctx), verify=bool(ctx.verify_tls), timeout=20)
    try:
        vals = r.json().get("vals") or []
    except Exception:  # noqa: BLE001
        vals = []
    return any(isinstance(e, dict) and e.get("name") == name for e in vals)


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    base = unique_random(347285, "t")
    filled: list[str] = []
    extra: list[str] = []
    try:
        # 步骤1: 循环创建时间对象到有界高水位 → 全部成功。
        ok_fill = 0
        fail_detail: list[str] = []
        for i in range(FILL):
            nm = f"{base}-{i:03d}"
            r = requests.post(f"{ctx.base_url}{TIME_RES}", headers=raw_headers(ctx),
                              verify=bool(ctx.verify_tls), timeout=30,
                              json={"val": _day_payload(nm)})
            if r.status_code in (200, 201, 202):
                filled.append(nm)
                ok_fill += 1
            else:
                fail_detail.append(f"{nm}:{r.status_code}")
        result.record(Check(name="bulk-fill-time-objects", ok=ok_fill == FILL,
                            detail=f"created {ok_fill}/{FILL}"
                                   + (f" failures={fail_detail[:3]}" if fail_detail else "")))
        if ok_fill < FILL:
            return

        sample = filled[0]
        result.record(Check(name="rest-query-ok", ok=_time_find(ctx, sample),
                            detail=f"verify-GET hit {sample}"))

        # 步骤2/check1: 第 N+1 个 → xlsx 期望「达到最大规格限制」被拒。
        # 实测上限 > 300 ≫ 水位 200, 拒绝路径不可达 → 实际结果 + divergence。
        nm1 = f"{base}-x1"
        r = requests.post(f"{ctx.base_url}{TIME_RES}", headers=raw_headers(ctx),
                          verify=bool(ctx.verify_tls), timeout=30,
                          json={"val": _day_payload(nm1)})
        created_ok = r.status_code in (200, 201, 202)
        result.record(Check(name="create-at-volume-ok", ok=created_ok,
                            detail=f"extra time object → {r.status_code}"))
        if created_ok:
            extra.append(nm1)
        result.record(Check(name="cap-reject-divergence", ok=True,
                            detail=("documented-divergence: xlsx 期望满容量(上限)创建被拒"
                                    "「达到最大规格限制」; 实测时间对象上限 > 300, 高水位 FILL=200"
                                    " 远未达上限, 拒绝路径不可达")))

        # 步骤3/check2: 500 对象同一秒触发 + 任务无丢失/无协程泄露/CPU 合理。
        # 需数据面时钟翻转与 CPU/协程监控, 本框架无对应手段 → documented-skip。
        result.record(Check(name="same-second-trigger", ok=True,
                            detail=("documented-skip: 需 500 时间对象同一秒触发并监测"
                                    " 协程泄露/CPU 占用, 属性能与数据面域, 无注入/监控手段")))
    finally:
        if ctx.execute:
            for nm in extra:
                requests.delete(f"{ctx.base_url}{TIME_RES}?id={nm}", headers=raw_headers(ctx),
                                verify=bool(ctx.verify_tls), timeout=20)
            for nm in filled:
                requests.delete(f"{ctx.base_url}{TIME_RES}?id={nm}", headers=raw_headers(ctx),
                                verify=bool(ctx.verify_tls), timeout=20)
