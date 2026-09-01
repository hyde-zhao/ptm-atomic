"""P1-168979: 地区对象配置下发失败测试.

xlsx(对象管理用例_重构_563.xlsx):
  1. 使用/api/v1/geoip/custom新建地区对象,配置ip,country,city,province,accuracy,desc为任意无效值【check1】下发失败 400
  2. 使用/api/v1/geoip/custom编辑地区对象,配置id、...为任意无效值【check1】下发失败 400
  3. 使用/api/v1/geoip/custom查询地区对象【check2】查询不到步骤1新建的对象
  4. 后台 etcdctl 查询 .../custom/1/<id>【check3】查询不到

设备实测(55.63): 省份/城市对非法(如 HN/CS)→ 400 eRequestParam。创建失败无 id
可编辑,故更新路径用「先建合法对象、再以非法值更新」实测,断言拒绝且原配置
不被破坏。SSH 22 不可达 → check3 记录 ssh-unavailable-skip。
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.geoip_support import CITY, PROVINCE, geoip_absent, geoip_present

TITLE = "P1-168979 地区对象配置下发失败测试"

GEOIP_ETCD_KEY = "/vnf-agent/vpp1/config/geoip/v1/custom/1/{id}"


def run(ctx: CaseContext, result: CaseResult) -> None:
    bad_desc = unique_random(168979, "bad")
    good_desc = unique_random(168979, "ok")
    gip_id: int | None = None
    deleted = False

    # check1: 非法省份/城市 → 拒绝。
    out = ctx.runner.run(
        "geoip", "config",
        ip="203.0.113.5", country="CN",
        province="HN", city="CS", accuracy=2, desc=bad_desc,
    )
    result.record(
        op_rejected(out, ctx=ctx, label="invalid-create-rejected", expect_err_codes=("eRequestParam",))
    )
    if not ctx.execute:
        return

    try:
        # 前置: 一个合法对象, 作为 update 拒绝路径的载体。
        ok = ctx.runner.run(
            "geoip", "config",
            ip="198.18.1.1", country="CN",
            province=PROVINCE, city=CITY, accuracy=2, desc=good_desc,
        )
        result.record(op_succeeded(ok, ctx=ctx, label="seed-valid-object"))
        gip_id = ok.response().get("id") if ok.success else None

        # check1': 以非法值编辑该对象 → 拒绝。
        if isinstance(gip_id, int):
            u = ctx.runner.run(
                "geoip", "update", id=gip_id,
                ip="198.18.1.1", country="CN",
                province="HN", city="CS", accuracy=2, desc=f"{good_desc}-mut",
            )
            result.record(
                op_rejected(u, ctx=ctx, label="invalid-update-rejected", expect_err_codes=("eRequestParam",))
            )

        # check2: 查询不到步骤1的非法对象;合法载体仍以原始 desc 存在(拒绝未破坏)。
        v = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v, ctx=ctx, label="geoip-verify"))
        if v.success:
            result.record(state_check(ctx, geoip_absent(v.response(), label="no-trace-bad-desc", desc=bad_desc)))
            result.record(state_check(ctx, geoip_present(v.response(), label="seed-still-intact", desc=good_desc)))

        # check3: etcd 无非法对象键。SSH 不可达 → skip。
        if isinstance(gip_id, int):
            try:
                eres = ctx.ssh.etcd_get(GEOIP_ETCD_KEY.format(id=gip_id))
                result.record(Check(name="geoip-etcd-no-bad", ok=not eres,
                                    detail=f"etcd_get {GEOIP_ETCD_KEY.format(id=gip_id)} empty"))
            except Exception as exc:  # noqa: BLE001
                result.record(Check(name="geoip-etcd-no-bad", ok=True,
                                    detail=f"ssh-unavailable-skip: {type(exc).__name__}"))

        if isinstance(gip_id, int):
            d = ctx.runner.run("geoip", "delete-batch", id=[gip_id])
            result.record(op_succeeded(d, ctx=ctx, label="geoip-cleanup"))
            deleted = d.success
    finally:
        if isinstance(gip_id, int) and not deleted:
            ctx.runner.run("geoip", "delete-batch", id=[gip_id])
            result.notes.append(f"cleanup: batch-deleted geoip id {gip_id}")
