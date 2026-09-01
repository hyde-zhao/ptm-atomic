"""P3-900023: CA证书引用次数与实际引用一致测试.

Probe-confirmed (probe21b): localcacert verify carries an ``issNum`` field that
counts how many local certificates the CA has issued (0 after create, 1 after
one child is signed). The ``refcnt`` field is only populated on the built-in
CA (defaultLocalCA.crt shows refcnt=1); user-created CAs report it as absent.

Steps 5-7 (受信任的CA证书) are NOT scriptable: no trusted-CA REST endpoint
exists on the device (/api/v1/cert/trustca -> 404). Covered for the local CA
half; the trusted-CA half is a documented divergence.
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import cert_present, entry_field, first_id

TITLE = "P3-900023 CA证书引用次数与实际引用一致测试"

SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}
LOCALCA_DIR = "/appdata/etc/cert/demoCA/localCA"


def run(ctx: CaseContext, result: CaseResult) -> None:
    ca_name = unique_random(900023, "ca")
    child_name = unique_random(900023, "ch")
    ca_id: int | None = None
    child_id: int | None = None
    try:
        # check1: create a local CA certificate; its crt+key files appear.
        create = ctx.runner.run("cert", "localcacert-config", name=ca_name, key_type="RSA", time_length=30,
                                country=SUBJECT["country"], state=SUBJECT["state"], location=SUBJECT["location"],
                                organization=SUBJECT["organization"], organ_unit=SUBJECT["organUnit"])
        result.record(op_succeeded(create, ctx=ctx, label="ca-config-ok"))
        if not ctx.execute:
            return
        v_ca = ctx.runner.run("cert", "localcacert-verify", page=1, size=200, keywords=ca_name)
        result.record(cert_present(v_ca.response(), label="ca-entry", name=ca_name))
        ca_id = first_id(v_ca.response(), ca_name)
        f = ctx.ssh.exec(f"ls {LOCALCA_DIR}/{ca_name}.crt {LOCALCA_DIR}/{ca_name}.key")
        result.record(Check(name="ca-files-on-device", ok=f.ok, detail=f.text()[:120]))
        iss0 = entry_field(v_ca.response(), ca_name, "issNum")
        result.record(Check(name="ca-issNum-initial", ok=iss0 in (0, None),
                            detail=f"issNum={iss0!r} before any signing"))

        # check2+3: create a local certificate signed by that CA; issNum -> 1.
        ccreate = ctx.runner.run("cert", "localcert-config", name=child_name, key_type="RSA", key_length=2048,
                                 country=SUBJECT["country"], state=SUBJECT["state"], location=SUBJECT["location"],
                                 organization=SUBJECT["organization"], organ_unit=SUBJECT["organUnit"])
        result.record(op_succeeded(ccreate, ctx=ctx, label="child-config-ok"))
        v_child = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=child_name)
        child_id = first_id(v_child.response(), child_name)
        if child_id is not None:
            issue = ctx.runner.run("cert", "localcert-issue", id=str(child_id),
                                   cacert=f"{ca_name}.crt", option="1", time_length=30)
            result.record(op_succeeded(issue, ctx=ctx, label="child-issue-with-ca-ok"))
        v_ca2 = ctx.runner.run("cert", "localcacert-verify", page=1, size=200, keywords=ca_name)
        iss1 = entry_field(v_ca2.response(), ca_name, "issNum")
        result.record(Check(name="ca-issNum-after-sign", ok=iss1 == 1,
                            detail=f"issNum={iss1!r} after signing 1 child (want 1 — 引用次数与实际引用一致)"))
    finally:
        if ctx.execute:
            if child_id is not None:
                result.record(op_succeeded(
                    ctx.runner.run("cert", "localcert-delete-batch", id=str(child_id)),
                    ctx=ctx, label="child-cleanup"))
            if ca_id is not None:
                result.record(op_succeeded(
                    ctx.runner.run("cert", "localcacert-delete-batch", id=str(ca_id)),
                    ctx=ctx, label="ca-cleanup"))
