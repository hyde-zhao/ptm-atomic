"""P1-168972: 本地CA证书对象配置下发成功测试.

xlsx(对象管理用例_重构_563.xlsx):
  1. 使用/api/v1/cert/localcacert新建本地CA证书对象,配置name,country,location,
     organUnit,organization,state,passwd,timeLenth为任意有效值【check1】下发成功
  2. 使用/api/v1/cert/localcacert编辑本地CA证书对象,配置id、...【check1】
  3. 使用/api/v1/cert/localcacert查询【check2】字段与下发一致
  4. 后台 etcdctl 查询 /vnf-agent/vpp1/config/cert/v1/localcacert/<id>【check3】

设备实测(55.63): localcacert 为自签 CA,以 <name>.crt 存储,subject 为拼接
字符串,按数值 id 批量删除。passwd 为可选口令,xlsx 未给值。
"""

from __future__ import annotations

from framework.checks import Check, etcd_present, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import cert_present, first_id, subject_ok

TITLE = "P1-168972 本地CA证书对象配置下发成功测试"

CERT_ETCD_KEY = "/vnf-agent/vpp1/config/cert/v1/localcacert/{id}"
SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(168972, "ca")
    cert_id: int | None = None
    try:
        # check1: 新建 RSA 自签本地 CA 证书。
        create = ctx.runner.run(
            "cert", "localcacert-config",
            name=name, key_type="RSA", time_length=30,
            country=SUBJECT["country"], state=SUBJECT["state"],
            location=SUBJECT["location"], organization=SUBJECT["organization"],
            organ_unit=SUBJECT["organUnit"],
        )
        result.record(op_succeeded(create, ctx=ctx, label="localcacert-config-ok"))
        if not ctx.execute:
            return

        # check2: 查询反映创建结果(带后缀名、数值 id、subject 字段)。
        vout = ctx.runner.run("cert", "localcacert-verify", page=1, size=200, keywords=name)
        result.record(op_succeeded(vout, ctx=ctx, label="localcacert-verify-ok"))
        if not vout.success:
            return
        result.record(cert_present(vout.response(), label="localcacert-verify-entry", name=name))
        result.record(subject_ok(
            vout.response(), label="localcacert-subject-fields", name=name,
            C="CN", ST="Sichuan", L="Chengdu", O="Atomic", OU="QA",
        ))
        cert_id = first_id(vout.response(), name)
        result.record(
            Check(name="localcacert-numeric-id", ok=cert_id is not None,
                  detail=f"numeric id resolved={cert_id}")
        )

        # check3: etcd cert 键有值。SSH 22 不可达 → 由 etcd_present 记录 skip。
        if cert_id is not None:
            key = CERT_ETCD_KEY.format(id=cert_id)
            eres = ctx.ssh.etcd_get(key)
            result.record(state_check(
                ctx,
                etcd_present(eres, label="localcacert-etcd", key=CERT_ETCD_KEY.format(id=cert_id), want=True),
            ))
    finally:
        if ctx.execute and cert_id is not None:
            result.record(op_succeeded(
                ctx.runner.run("cert", "localcacert-delete-batch", id=str(cert_id)),
                ctx=ctx, label="localcacert-cleanup",
            ))
