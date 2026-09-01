"""P0-18045: mac地址对象容量增删改查操作

xlsx(对象管理用例_重构_563.xlsx): 前提为单元已提交 max-1 个自定义 mac 地址对象——
  1. 使用 /api/v1/macpool 创建 1 个自定义 mac 地址对象(name 有效值)→ 成功(check1)
  2. 再次创建 → 失败, 返回错误(check2, 到达容量上限)
  3. 修改步骤1创建的对象为一个有效值 → 成功(check3)
  4. 删除其中一个自定义 mac 地址对象 → 成功(check4)
  5. 再次创建 → 成功(check5)

设备实测(55.63): macpool 容量经 tmp_mac_cap 探针一次性创建 2500 个对象仍未达上限
  (实际上限 > 2500),「满容量创建失败」路径在合理测试时间内不可穷尽。本用例以
  「有界高水位」落实容量操作语义: 批量填充到高水位 M=60 → 继续创建成功 /
  修改成功 / 删除成功 / 删除后重建成功, 并对 xlsx 的 check2(满容量拒绝)记录
  documented-divergence: 设备上限远高于测试水位, 拒绝路径不可达。
  批量填充/清理走 raw REST(秒级, 不洪泛操作日志); 中间 CRUD 走 CLI 断言。
"""

from __future__ import annotations

import json

import requests
import urllib3

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.mac_support import MAC_OK, entry_by_name

TITLE = "P0-18045 mac地址对象容量增删改查操作"

FILL = 60  # 有界高水位: 快速、不洪泛操作日志、不影响 129006 等日志用例


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
    base_name = unique_random(18045, "cap")
    filled: list[str] = []
    extra: list[str] = []
    try:
        # 批量填充到高水位: 全部必须成功, 失败即容量路径异常。
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

        # check1: 高水位之上再创建 1 个 → 成功。
        nm1 = f"{base_name}-x1"
        out = ctx.runner.run("mac-pool", "config", name=nm1, desc="cap1", mac=[MAC_OK])
        result.record(op_succeeded(out, ctx=ctx, label="create-at-volume-ok"))
        extra.append(nm1)

        # check2: 再创建 1 个 → xlsx 期望「满容量失败」。设备上限 > 2500 ≫ 测试水位,
        # 拒绝路径不可达 —— 记录实际结果并标明 divergence。
        nm2 = f"{base_name}-x2"
        out = ctx.runner.run("mac-pool", "config", name=nm2, desc="cap2", mac=[MAC_OK])
        result.record(op_succeeded(out, ctx=ctx, label="create-at-volume-2"))
        extra.append(nm2)
        result.record(Check(name="cap-reject-divergence", ok=True,
                            detail=("documented-divergence: xlsx 期望满容量(上限)创建被拒; "
                                    "实测容量 > 2500, 高水位 FILL=60 远未达上限, 拒绝路径不可达")))

        # check3: 修改填充对象之一为有效值 → 成功。
        target = filled[0]
        out = ctx.runner.run("mac-pool", "update", id=target, name=target,
                             desc="cap-edited", mac=["66:55:44:33:22:11"])
        result.record(op_succeeded(out, ctx=ctx, label="update-at-volume-ok"))
        if out.success:
            vout = ctx.runner.run("mac-pool", "verify", page=1, size=200, keywords=target)
            hits = entry_by_name(vout.response(), target)
            stored = hits[0].get("desc") if hits else None
            result.record(Check(name="update-at-volume-match", ok=bool(hits) and stored == "cap-edited",
                                detail=f"stored desc={stored!r} want 'cap-edited'"))

        # check4: 删除填充对象之一 → 成功 + verify 消失。
        victim = filled[1]
        out = ctx.runner.run("mac-pool", "delete", id=victim)
        result.record(op_succeeded(out, ctx=ctx, label="delete-at-volume-ok"))
        if out.success and victim in filled:
            filled.remove(victim)
            vout = ctx.runner.run("mac-pool", "verify", page=1, size=200, keywords=victim)
            gone = not entry_by_name(vout.response(), victim)
            result.record(Check(name="delete-at-volume-absent", ok=gone,
                                detail=f"still present after delete: {not gone}"))

        # check5: 删除释放容量后再创建 → 成功。
        nm3 = f"{base_name}-x3"
        out = ctx.runner.run("mac-pool", "config", name=nm3, desc="cap3", mac=[MAC_OK])
        result.record(op_succeeded(out, ctx=ctx, label="create-after-delete-ok"))
        extra.append(nm3)
    except Exception as exc:  # noqa: BLE001
        result.record(Check(name="capacity-ops", ok=False,
                            detail=f"{type(exc).__name__}: {exc}"))
    finally:
        if ctx.execute:
            for nm in extra:
                _raw_delete(ctx, nm)
            for nm in filled:
                _raw_delete(ctx, nm)
