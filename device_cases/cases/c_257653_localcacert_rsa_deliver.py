"""P1-257653: RSA 本地 CA 证书对象配置下发成功.

Create a self-signed RSA local CA certificate, confirm the verify query
reflects it (numeric id, suffixed name, subject fields), confirm the etcd
cert key is written, then batch-delete by the numeric id.

Device semantics (probe18): localcacert stored as <name>.crt; subject is a
concatenated "CN=...,OU=...,O=...,L=...,ST=...,C=..." string; delete is by
numeric id only.
"""

from __future__ import annotations

from framework.checks import Check, etcd_present, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import cert_present, first_id, subject_ok

TITLE = "P1-257653 RSA 本地 CA 证书对象配置下发成功"

CERT_ETCD_KEY = "/vnf-agent/vpp1/config/cert/v1/localcacert/{id}"
SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(257653, "ca")
    cert_id: int | None = None
    try:
        # check1: create RSA local CA certificate.
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

        # check2: verify reflects the created certificate.
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

        # check3: etcd cert key holds the certificate.
        if cert_id is not None:
            eres = ctx.ssh.etcd_get(CERT_ETCD_KEY.format(id=cert_id))
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
