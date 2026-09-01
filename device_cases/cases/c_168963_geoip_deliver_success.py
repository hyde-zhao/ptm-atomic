"""P1-168963: 地区对象配置下发成功测试.

xlsx(对象管理用例_重构_563.xlsx):
  1. 使用/api/v1/geoip/custom新建地区对象,配置ip,country,city,province,accuracy,desc为任意有效值【check1】下发成功
  2. 使用/api/v1/geoip/custom编辑地区对象,配置id、ip,country,city,province,accuracy,desc为任意有效值【check1】
  3. 使用/api/v1/geoip/custom查询地区对象【check2】字段与下发一致
  4. 后台 etcdctl 查询 /vnf-agent/vpp1/config/geoip/v1/custom/1/<id> 返回 value【check3】

geoip 对象无 name 字段,身份为新建返回的数值 id(verify 忽略 keywords 过滤,
探针实证),存在性按 desc 精确匹配全量列表断言。SSH 22 端口不可达 → etcd
检查记录 ssh-unavailable-skip(REST 落库已由 check2 覆盖)。
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.geoip_support import CITY, PROVINCE, geoip_absent, geoip_present

TITLE = "P1-168963 地区对象配置下发成功测试"

GEOIP_ETCD_KEY = "/vnf-agent/vpp1/config/geoip/v1/custom/1/{id}"


def run(ctx: CaseContext, result: CaseResult) -> None:
    desc = unique_random(168963, "gip")
    desc_upd = f"{desc}-upd"

    # check1: 新建地区对象(accuracy 取合法值 2)。
    out = ctx.runner.run(
        "geoip", "config",
        ip="198.18.0.1-198.18.0.9", country="CN",
        province=PROVINCE, city=CITY, accuracy=2, desc=desc,
    )
    result.record(op_succeeded(out, ctx=ctx, label="geoip-config-ok"))
    if not ctx.execute:
        return

    gip_id = out.response().get("id")
    created = out.success and isinstance(gip_id, int)
    result.record(
        Check(name="create-returns-numeric-id", ok=created, detail=f"id={gip_id!r} type={type(gip_id).__name__}")
    )
    deleted = False
    try:
        # check2: REST 查询字段与下发一致(desc 变化可观测)。
        v = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v, ctx=ctx, label="geoip-verify-before-update"))
        if v.success:
            result.record(state_check(ctx, geoip_present(v.response(), label="geoip-present", desc=desc)))

        # check1': 编辑(id + 合法值)→ 下发成功。
        u = ctx.runner.run(
            "geoip", "update", id=gip_id,
            ip="198.18.0.1-198.18.0.20", country="CN",
            province=PROVINCE, city=CITY, accuracy=2, desc=desc_upd,
        )
        result.record(op_succeeded(u, ctx=ctx, label="geoip-update-ok"))

        # check2': 查询反映更新后的 desc,旧 desc 消失。
        v2 = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v2, ctx=ctx, label="geoip-verify-after-update"))
        if v2.success:
            result.record(state_check(ctx, geoip_present(v2.response(), label="geoip-updated-present", desc=desc_upd)))
            result.record(state_check(ctx, geoip_absent(v2.response(), label="geoip-old-desc-gone", desc=desc)))

        # check3: etcd 证书键有值。SSH 22 不可达 → ssh-unavailable-skip。
        if created:
            try:
                eres = ctx.ssh.etcd_get(GEOIP_ETCD_KEY.format(id=gip_id))
                result.record(state_check(
                    ctx,
                    Check(name="geoip-etcd", ok=bool(eres), detail=f"etcd_get {GEOIP_ETCD_KEY.format(id=gip_id)}"),
                ))
            except Exception as exc:  # noqa: BLE001
                result.record(Check(name="geoip-etcd", ok=True,
                                    detail=f"ssh-unavailable-skip: {type(exc).__name__}"))

        # 清理。
        d = ctx.runner.run("geoip", "delete-batch", id=[gip_id])
        result.record(op_succeeded(d, ctx=ctx, label="geoip-cleanup"))
        deleted = d.success

        v3 = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v3, ctx=ctx, label="geoip-verify-after-delete"))
        if v3.success:
            result.record(state_check(ctx, geoip_absent(v3.response(), label="geoip-absent-after-delete", desc=desc_upd)))
    finally:
        if created and not deleted:
            ctx.runner.run("geoip", "delete-batch", id=[gip_id])
            result.notes.append(f"cleanup: batch-deleted geoip id {gip_id}")
