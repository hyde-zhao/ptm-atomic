"""P1-257656: SM2 本地证书对象配置下发成功.

Create an SM2 local certificate (no keyLenth for SM2), update it, confirm the
verify query reflects name/id/subject, confirm the etcd cert key, then
batch-delete by the numeric id. Mirror of 257655 with key_type SM2.
"""

from __future__ import annotations

from framework.checks import Check, etcd_present, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import all_ids, cert_present, first_id, subject_ok

TITLE = "P1-257656 SM2 本地证书对象配置下发成功"

CERT_ETCD_KEY = "/vnf-agent/vpp1/config/cert/v1/localcert/{id}"
SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(257656, "lc")
    cert_id: int | None = None
    try:
        # check1: create SM2 local certificate (SM2 carries no keyLenth).
        create = ctx.runner.run(
            "cert", "localcert-config",
            name=name, key_type="SM2",
            country=SUBJECT["country"], state=SUBJECT["state"],
            location=SUBJECT["location"], organization=SUBJECT["organization"],
            organ_unit=SUBJECT["organUnit"],
        )
        result.record(op_succeeded(create, ctx=ctx, label="localcert-sm2-config-ok"))
        if not ctx.execute:
            return

        # check2: verify reflects the created certificate.
        vout = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=name)
        result.record(op_succeeded(vout, ctx=ctx, label="localcert-sm2-verify-ok"))
        if not vout.success:
            return
        result.record(cert_present(vout.response(), label="localcert-sm2-verify-entry", name=name))
        result.record(subject_ok(
            vout.response(), label="localcert-sm2-subject-fields", name=name,
            C="CN", ST="Sichuan", L="Chengdu", O="Atomic", OU="QA",
        ))
        cert_id = first_id(vout.response(), name)
        result.record(
            Check(name="localcert-sm2-numeric-id", ok=cert_id is not None,
                  detail=f"numeric id resolved={cert_id}")
        )

        # check3: "edit" the SM2 local certificate via the issue variant.
        # SM2 certs must be signed by the SM2 CA (defaultGmLocalCA.crt); the
        # RSA CA rejects them with certCaKeyTypeDismatch.
        if cert_id is not None:
            upd = ctx.runner.run(
                "cert", "localcert-issue", id=str(cert_id),
                cacert="defaultGmLocalCA.crt", option="1", time_length=30,
            )
            result.record(op_succeeded(upd, ctx=ctx, label="localcert-sm2-issue-ok"))

        # check4: etcd cert key holds the certificate.
        if cert_id is not None:
            key = CERT_ETCD_KEY.format(id=cert_id)
            eres = ctx.ssh.etcd_get(key)
            result.record(state_check(
                ctx, etcd_present(eres, label="localcert-sm2-etcd", key=key, want=True),
            ))
    finally:
        if ctx.execute and cert_id is not None:
            # An issued SM2 cert splits into <name>_sig.crt (original id) and
            # <name>_enc.crt (NEW id); deleting only the first id would leave
            # the _enc entry orphaned, so re-verify and delete EVERY matching id.
            v_clean = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=name)
            ids = all_ids(v_clean.response(), name) or [cert_id]
            result.record(op_succeeded(
                ctx.runner.run("cert", "localcert-delete-batch", id=[str(i) for i in ids]),
                ctx=ctx, label="localcert-sm2-cleanup",
            ))
