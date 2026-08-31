"""P1-257655: RSA 本地证书对象配置下发成功.

Create an RSA local certificate (unsigned), update it, confirm the verify
query reflects the (suffixed) name, id and subject fields, confirm the etcd
cert key, then batch-delete by the numeric id.

Device semantics (probe18): localcert stored as <name>.csr; subject is a
"/C=CN/ST=Sichuan/..." concatenated string; delete is by numeric id only.
"""

from __future__ import annotations

from framework.checks import Check, etcd_present, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import cert_present, first_id, subject_ok

TITLE = "P1-257655 RSA 本地证书对象配置下发成功"

CERT_ETCD_KEY = "/vnf-agent/vpp1/config/cert/v1/localcert/{id}"
SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(257655, "lc")
    cert_id: int | None = None
    try:
        # check1: create RSA local certificate.
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

        # check2: verify reflects the created certificate.
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

        # check3: "edit" the local certificate. Probe-confirmed: PUT on a
        # localcert accepts ONLY the issue variant (option/cacert/timeLenth);
        # a plain name/subject/option update is rejected with "本地证书操作,签
        # 发或吊销无效". So edit is expressed as a re-issue by numeric id.
        if cert_id is not None:
            upd = ctx.runner.run(
                "cert", "localcert-issue", id=str(cert_id),
                cacert="defaultLocalCA.crt", option="1", time_length=30,
            )
            result.record(op_succeeded(upd, ctx=ctx, label="localcert-issue-ok"))

        # check4: etcd cert key holds the certificate.
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
