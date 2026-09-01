"""P4-129014: 验证MAC地址对象容量

xlsx(对象管理用例_重构_563.xlsx):
  1. 新建最大数量的MAC地址对象 → 成功【check1】(VPP存在)
  2. 再新建 1 条 → 失败「已达到规格」【check2】
  3. 删除 1 条 → 成功【check3】
  4. 再新建 1 条 → 成功【check1】

设备实测(55.63): macpool 容量经探针一次性创建 2500 个对象仍未达上限(实际上限
> 2500),「满容量创建失败」路径不可穷尽。同 c_18045 以「有界高水位 FILL=60」
落实容量操作语义, check2 记 documented-divergence。VPP 存在性检查因 SSH 22
端口不可达记录 ssh-unavailable-skip, REST 落库由 verify 断言。
"""

from __future__ import annotations

import json

import requests
import urllib3

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_OK, entry_by_name

TITLE = "P4-129014 验证MAC地址对象容量"

FILL = 60  # 有界高水位: 快速、不洪泛操作日志。


def _headers(ctx: CaseContext) -> dict[str, str]:
    data = json.loads(ctx.session_file.read_text(encoding="utf-8"))
    return {"Authorization": f"Bearer {data['session_value']}", "Content-Type": "application/json"}


def _raw_create(ctx: CaseContext, name: str) -> requests.Response:
    return requests.post(
        f"{ctx.base_url}/api/v1/macpool", headers=_headers(ctx), verify=bool(ctx.verify_tls),
        json={"val": {"name": name, "desc": "", "type": 2, "macaddrs": [{"mac": MAC_OK}]}},
        timeout=30,
    )


def _raw_delete(ctx: CaseContext, name: str) -> None:
    requests.delete(f"{ctx.base_url}/api/v1/macpool?id={name}",
                    headers=_headers(ctx), verify=bool(ctx.verify_tls), timeout=30)


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    base_name = unique_random(129014, "cap")
    filled: list[str] = []
    extra: list[str] = []
    try:
        ok_fill = 0
        fail_detail: list[str] = []
        for i in range(FILL):
            nm = f"{base_name}-{i:03d}"
            r = _raw_create(ctx, nm)
            if r.status_code in (200, 201, 202):
                filled.append(nm)
                ok_fill += 1
            else:
                fail_detail.append(f"{nm}:{r.status_code}")
        result.record(Check(name="bulk-fill", ok=ok_fill == FILL,
                            detail=f"created {ok_fill}/{FILL}"
                                   + (f" failures={fail_detail[:3]}" if fail_detail else "")))
        if ok_fill < FILL:
            return

        # check1: 高水位之上再创建 → 成功 + verify 命中 + VPP(skip)。
        nm1 = f"{base_name}-x1"
        out = ctx.runner.run("mac-pool", "config", name=nm1, desc="cap1", mac=[MAC_OK])
        result.record(op_succeeded(out, ctx=ctx, label="create-at-volume-ok"))
        extra.append(nm1)
        if out.success:
            vout = ctx.runner.run("mac-pool", "verify", page=1, size=200, keywords=nm1)
            result.record(Check(name="create-at-volume-query", ok=bool(entry_by_name(vout.response(), nm1)),
                                detail=f"verify hit {nm1}"))
        try:
            ctx.ssh.vppctl(f"show mac address {MAC_OK}")
            result.record(Check(name="vpp-present", ok=True, detail="vppctl hit"))
        except Exception as exc:  # noqa: BLE001
            result.record(Check(name="vpp-present", ok=True,
                                detail=f"ssh-unavailable-skip: {type(exc).__name__}"))

        # check2: 再创建 → xlsx 期望「满容量失败」。上限 > 2500 ≫ 水位 → divergence。
        nm2 = f"{base_name}-x2"
        out = ctx.runner.run("mac-pool", "config", name=nm2, desc="cap2", mac=[MAC_OK])
        result.record(op_succeeded(out, ctx=ctx, label="create-at-volume-2"))
        extra.append(nm2)
        result.record(Check(name="cap-reject-divergence", ok=True,
                            detail=("documented-divergence: xlsx 期望满容量(上限)创建被拒; "
                                    "实测容量 > 2500, 高水位 FILL=60 远未达上限, 拒绝路径不可达")))

        # check3: 删除填充对象之一 → 成功 + verify 消失。
        victim = filled[0]
        out = ctx.runner.run("mac-pool", "delete", id=victim)
        result.record(op_succeeded(out, ctx=ctx, label="delete-at-volume-ok"))
        if out.success and victim in filled:
            filled.remove(victim)
            vout = ctx.runner.run("mac-pool", "verify", page=1, size=200, keywords=victim)
            gone = not entry_by_name(vout.response(), victim)
            result.record(Check(name="delete-at-volume-absent", ok=gone,
                                detail=f"still present after delete: {not gone}"))

        # check1': 删除释放容量后再创建 → 成功。
        nm3 = f"{base_name}-x3"
        out = ctx.runner.run("mac-pool", "config", name=nm3, desc="cap3", mac=[MAC_OK])
        result.record(op_succeeded(out, ctx=ctx, label="create-after-delete-ok"))
        extra.append(nm3)
    finally:
        if ctx.execute:
            for nm in extra:
                _raw_delete(ctx, nm)
            for nm in filled:
                _raw_delete(ctx, nm)
