"""P1-168971: 本地证书对象配置下发成功测试.

xlsx(对象管理用例_重构_563.xlsx):
  1. 使用/api/v1/cert/localcert新建本地证书对象,配置name,country,location,organUnit,
     organization,state,type,keyLenth,passwd为任意有效值【check1】下发成功
  2. 使用/api/v1/cert/localcert编辑本地证书对象,配置id、...【check1】
  3. 使用/api/v1/cert/localcert查询【check2】字段与下发一致
  4. 后台 etcdctl 查询 /vnf-agent/vpp1/config/cert/v1/localcert/<id>【check3】

设备实测(55.63): localcert 以 <name>.csr 存储,subject 为拼接字符串;PUT 只接受
issue 变体(option/cacert/timeLenth),普通改字段被拒 → 编辑以按数值 id 重新签发
落实。passwd 为可选密钥口令,xlsx 未给值,走既有已验证的 RSA 参数集。
"""

from __future__ import annotations

from framework.checks import Check, etcd_present, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import cert_present, first_id, subject_ok

TITLE = "P1-168971 本地证书对象配置下发成功测试"

CERT_ETCD_KEY = "/vnf-agent/vpp1/config/cert/v1/localcert/{id}"
SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(168971, "lc")
    cert_id: int | None = None
    try:
        # check1: 新建 RSA 本地证书。
        create = ctx.runner.run(
            "cert", "localcert-config",
            name=name, key_type="RSA", key_length=2048,
            country=SUBJECT["country"], state=SUBJECT["state"],
            location=SUBJECT["location"], organization=SUBJECT["organization"],
            organ_unit=SUBJECT["organUnit"],
        )
        result.record(op_succeeded(create, ctx=ctx, label="localcert-config-ok"))
        if not ctx.execute:
            return

        # check2: 查询反映创建结果(带后缀名、数值 id、subject 字段)。
        vout = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=name)
        result.record(op_succeeded(vout, ctx=ctx, label="localcert-verify-ok"))
        if not vout.success:
            return
        result.record(cert_present(vout.response(), label="localcert-verify-entry", name=name))
        result.record(subject_ok(
            vout.response(), label="localcert-subject-fields", name=name,
            C="CN", ST="Sichuan", L="Chengdu", O="Atomic", OU="QA",
        ))
        cert_id = first_id(vout.response(), name)
        result.record(
            Check(name="localcert-numeric-id", ok=cert_id is not None,
                  detail=f"numeric id resolved={cert_id}")
        )

        # check1': 编辑(重新签发,按数值 id;探针实证 PUT 仅接受 issue 变体)。
        if cert_id is not None:
            upd = ctx.runner.run(
                "cert", "localcert-issue", id=str(cert_id),
                cacert="defaultLocalCA.crt", option="1", time_length=30,
            )
            result.record(op_succeeded(upd, ctx=ctx, label="localcert-issue-ok"))

        # check3: etcd cert 键有值。SSH 22 不可达 → 由 etcd_present 记录 skip。
        if cert_id is not None:
            key = CERT_ETCD_KEY.format(id=cert_id)
            eres = ctx.ssh.etcd_get(key)
            result.record(state_check(
                ctx, etcd_present(eres, label="localcert-etcd", key=key, want=True),
            ))
    finally:
        if ctx.execute and cert_id is not None:
            result.record(op_succeeded(
                ctx.runner.run("cert", "localcert-delete-batch", id=str(cert_id)),
                ctx=ctx, label="localcert-cleanup",
            ))
