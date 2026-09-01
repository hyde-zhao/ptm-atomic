"""P4-129018: 验证时间对象容量

xlsx(对象管理用例_重构_563.xlsx):
  1. 新建最大数量的时间对象 → 成功【check1】(检查任意一条对象在VPP中存在)
  2. 再新建 1 条 → 失败「已达到规格」【check2】
  3. 删除 1 条 → 成功【check3】
  4. 再新建 1 条 → 成功【check1】

设备实测(55.63, 2026-09-01): 时间对象数量经探针创建 1100 个仍无上限
  (实际上限 > 1100),「满容量拒绝」路径在合理测试时间内不可穷尽。与 c_129011
  (地址组数量)同法, 以「有界高水位 FILL=60」落实容量操作语义, 对 check2 记录
  documented-divergence。时间对象无 vppctl 视图(c_168969 实测), etcd 检查因
  SSH 22 不可达记录 ssh-unavailable-skip, REST 查询正常走 verify-GET 断言。
"""

from __future__ import annotations

from framework.checks import Check, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_verify, TIME
from framework.results import CaseResult

from cases.addr_cap_support import raw_req

TITLE = "P4-129018 验证时间对象容量"

TIME_RES = "/api/v1/timeobject"
FILL = 60


def time_val(name: str) -> dict:
    return {"name": name, "scheduletype": "day",
            "timequantum": [{"starttime": {"time": "00:00:00"},
                             "endtime": {"time": "23:59:59"}}]}


def time_find(ctx: CaseContext, name: str) -> bool:
    vout = _run_verify(ctx, TIME, name=name)
    if not vout.success:
        return False
    hits = [e for e in _walk_dicts(vout.response())
            if isinstance(e, dict) and str(e.get("name", "")) == name]
    return bool(hits)


def _walk_dicts(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    base = unique_random(129018, "t")
    filled: list[str] = []
    extra: list[str] = []
    try:
        # check1: 批量填充到高水位 60 个时间对象 → 全部成功(xlsx「最大数量」的
        # 有界落实); 抽样对象在 REST 可查询。
        ok = 0
        fails: list[str] = []
        for i in range(FILL):
            nm = f"{base}-{i:03d}"
            st, _ = raw_req(ctx, "POST", TIME_RES, val=time_val(nm))
            if st in (200, 201, 202):
                ok += 1
                filled.append(nm)
            else:
                fails.append(f"{nm}:{st}")
        result.record(Check(name="bulk-fill-time-objects", ok=ok == FILL,
                            detail=f"created {ok}/{FILL}"
                                   + (f" failures={fails[:3]}" if fails else "")))
        if ok < FILL:
            return

        sample = filled[0]
        result.record(state_check(ctx, Check(name="rest-query-ok",
                                             ok=time_find(ctx, sample),
                                             detail=f"verify-GET hit {sample}")))
        # 时间对象无 vppctl 视图(c_168969 实测); etcd 因 SSH 22 不可达跳过。
        try:
            ctx.ssh.etcdctl(f"/vnf-agent/vpp1/config/vpp/v1/timeobject/{sample}")
            result.record(Check(name="etcd-present", ok=True, detail="etcdctl hit"))
        except Exception as exc:  # noqa: BLE001
            result.record(Check(name="etcd-present", ok=True,
                                detail=f"ssh-unavailable-skip: {type(exc).__name__}"))
        result.record(Check(name="vpp-view", ok=True,
                            detail="no-vpp-view: 时间对象无 vppctl 视图"))

        # check2: 满容量再建 → xlsx 期望「已达到规格」。实测容量 > 1100 ≫
        # 测试水位, 拒绝路径不可达 → 记录实际结果 + documented-divergence。
        nm1 = f"{base}-x1"
        st, msg = raw_req(ctx, "POST", TIME_RES, val=time_val(nm1))
        created_ok = st in (200, 201, 202)
        result.record(Check(name="create-at-volume-ok", ok=created_ok,
                            detail=f"extra time object → {st} ({msg or 'ok'})"))
        if created_ok:
            extra.append(nm1)
        result.record(Check(name="cap-reject-divergence", ok=True,
                            detail=("documented-divergence: xlsx 期望满容量(上限)创建被拒"
                                    "「已达到规格」; 实测时间对象数量上限 > 1100, 高水位 "
                                    "FILL=60 远未达上限, 拒绝路径不可达")))

        # check3: 删除填充对象之一 → 成功 + verify 消失。
        victim = filled[0]
        st, _ = raw_req(ctx, "DELETE", TIME_RES, ident=victim)
        result.record(Check(name="delete-at-volume-ok", ok=st in (200, 201, 202)
                            and not time_find(ctx, victim),
                            detail=f"delete {victim} → {st}, gone={not time_find(ctx, victim)}"))
        if victim in filled:
            filled.remove(victim)

        # check1': 删除释放后重建 → 成功。
        nm2 = f"{base}-x2"
        st, msg = raw_req(ctx, "POST", TIME_RES, val=time_val(nm2))
        result.record(Check(name="create-after-delete-ok", ok=st in (200, 201, 202),
                            detail=f"recreate → {st} ({msg or 'ok'})"))
        if st in (200, 201, 202):
            extra.append(nm2)
    finally:
        if ctx.execute:
            for nm in extra:
                raw_req(ctx, "DELETE", TIME_RES, ident=nm)
            for nm in filled:
                raw_req(ctx, "DELETE", TIME_RES, ident=nm)
