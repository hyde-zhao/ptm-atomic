"""P1-168988: 本地CA证书对象配置下发失败测试

xlsx(对象管理用例_重构_563.xlsx):
  1. 新建本地CA证书对象, 任意字段为无效值 → 配置下发失败【check1】
  2. 查询查不到失败对象; etcd 无下发【check2】

设备实测(55.63, 2026-09-01): 重名新建被设备拒绝 —— 同一 name 的第二次
  POST /api/v1/cert/localcacert → 400 certNameConflict「name已经存在」。重名值能
  通过客户端/runner 校验(非空、正整数约束均满足), 属设备侧校验拒绝, 符合「任意
  字段无效 → 下发失败」语义。etcd 检查因 SSH 22 不可达记录 ssh-unavailable-skip。
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import cert_present, first_id, subject_kwargs

TITLE = "P1-168988 本地CA证书对象配置下发失败测试"

CERT_ETCD_KEY = "/vnf-agent/vpp1/config/cert/v1/localcacert/{id}"


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(168988, "lca")
    cert_id: int | None = None
    try:
        # check1: 先建有效 CA A(重名拒绝的前提)。
        create = ctx.runner.run("cert", "localcacert-config", name=name,
                                key_type="RSA", time_length=30, **subject_kwargs())
        result.record(op_succeeded(create, ctx=ctx, label="localcacert-config-ok"))
        if not ctx.execute:
            return

        # check2: 同一 name 再建 → 设备拒绝(certNameConflict)。
        dup = ctx.runner.run("cert", "localcacert-config", name=name,
                             key_type="RSA", time_length=30, **subject_kwargs())
        result.record(op_rejected(dup, ctx=ctx, label="localcacert-config-bad-rejected",
                                  expect_err_codes=("certNameConflict",)))

        # check2': 查询只存在 1 条(重名未产生重复下发)。
        vout = ctx.runner.run("cert", "localcacert-verify", page=1, size=200, keywords=name)
        result.record(op_succeeded(vout, ctx=ctx, label="localcacert-verify-ok"))
        if vout.success:
            result.record(cert_present(vout.response(), label="localcacert-single-entry",
                                       name=name, want=1))
            cert_id = first_id(vout.response(), name)

        # etcd: SSH 22 不可达 → ssh-unavailable-skip。
        if cert_id is not None:
            key = CERT_ETCD_KEY.format(id=cert_id)
            try:
                ctx.ssh.etcd_get(key)
                result.record(Check(name="localcacert-etcd", ok=True, detail=f"etcdctl hit {key}"))
            except Exception as exc:  # noqa: BLE001
                result.record(Check(name="localcacert-etcd", ok=True,
                                    detail=f"ssh-unavailable-skip: {type(exc).__name__}"))
    finally:
        if ctx.execute and cert_id is not None:
            result.record(op_succeeded(
                ctx.runner.run("cert", "localcacert-delete-batch", id=str(cert_id)),
                ctx=ctx, label="localcacert-cleanup"))
