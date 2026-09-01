"""P3-900020: 本地证书签发测试.

Probe-confirmed (probe18/21): a created localcert is stored as <name>.csr;
issuing (PUT option="1") signs it with the chosen CA and the entry becomes
<name>.crt with cacert set and fileState="2". SM2 certs must be issued with
the SM2 CA (defaultGmLocalCA.crt); RSA uses defaultLocalCA.crt.

The xlsx expects the .csr/.crt files to exist under
/appdata/etc/cert/demoCA/localcert; verified via SSH.
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import all_ids, cert_present, entry_field, first_id

TITLE = "P3-900020 本地证书签发测试"

SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}
LOCALCERT_DIR = "/appdata/etc/cert/demoCA/localcert"


def _issue_pair(ctx, result, *, case_id: int, suffix: str, key_type: str, cacert: str) -> None:
    name = unique_random(case_id, suffix)
    cert_id: int | None = None
    try:
        # check1: create a valid certificate; the .csr file appears on the device.
        create = ctx.runner.run("cert", "localcert-config", name=name, key_type=key_type, key_length=2048,
                                country=SUBJECT["country"], state=SUBJECT["state"], location=SUBJECT["location"],
                                organization=SUBJECT["organization"], organ_unit=SUBJECT["organUnit"])
        result.record(op_succeeded(create, ctx=ctx, label=f"{key_type}-config-ok"))
        if not ctx.execute:
            return
        v1 = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=name)
        result.record(cert_present(v1.response(), label=f"{key_type}-csr-entry", name=name))
        cert_id = first_id(v1.response(), name)
        sres = ctx.ssh.exec(f"ls {LOCALCERT_DIR}/{name}.csr")
        result.record(state_check(ctx, Check(
            name=f"{key_type}-csr-file-on-device", ok=sres.ok,
            detail=f"ls {LOCALCERT_DIR}/{name}.csr -> {'found' if sres.ok else sres.text()[:80]}")))

        # A fresh SM2 CSR must NOT be issuable by the RSA CA (device rejects
        # with certCaKeyTypeDismatch). Checked on the CSR, before the real issue.
        if key_type == "SM2" and cert_id is not None:
            bad = ctx.runner.run("cert", "localcert-issue", id=str(cert_id), cacert="defaultLocalCA.crt",
                                 option="1", time_length=30)
            result.record(op_rejected(bad, ctx=ctx, label="sm2-issue-rsa-ca-rejected",
                                      expect_err_codes=("certCaKeyTypeDismatch",)))

        # check2: issue signs the certificate; the .crt entry/file(s) appear.
        # An issued SM2 cert splits into TWO entries: <name>_sig.crt (signature)
        # and <name>_enc.crt (encryption); an RSA cert stays <name>.crt.
        if cert_id is not None:
            issue = ctx.runner.run("cert", "localcert-issue", id=str(cert_id), cacert=cacert, option="1", time_length=30)
            result.record(op_succeeded(issue, ctx=ctx, label=f"{key_type}-issue-ok"))
        v2 = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=name)
        if v2.success:
            want = 2 if key_type == "SM2" else 1
            result.record(cert_present(v2.response(), label=f"{key_type}-crt-entry", name=name, want=want))
            ca_used = entry_field(v2.response(), name, "cacert")
            fstate = entry_field(v2.response(), name, "fileState")
            result.record(Check(
                name=f"{key_type}-issued-fields", ok=ca_used == cacert and fstate == "2",
                detail=f"cacert={ca_used!r} fileState={fstate!r} want cacert={cacert!r} fileState='2' "
                       f"(SM2 sig+enc both carry these)"))
        crt_files = [f"{LOCALCERT_DIR}/{f}" for f in (
            (f"{name}_sig.crt", f"{name}_enc.crt") if key_type == "SM2" else (f"{name}.crt",))]
        # The SM2 _enc.crt file is written asynchronously just after the issue
        # PUT returns; poll a single SSH session (fresh connections lose wall
        # time to handshakes) for up to 45s so a fast check cannot false-negative.
        sres = ctx.ssh.wait_for_paths(crt_files, timeout=45.0, interval=1.0)
        result.record(state_check(ctx, Check(
            name=f"{key_type}-crt-file-on-device", ok=bool(sres and sres.ok),
            detail=f"ls {' '.join(crt_files)} -> "
                   f"{'found' if sres and sres.ok else (sres.text()[:80] if sres else 'ssh-failed')}")))
    finally:
        if ctx.execute and cert_id is not None:
            # An issued SM2 cert splits into <name>_sig.crt (original id) and
            # <name>_enc.crt (NEW id); deleting only the first id would leave
            # the _enc entry orphaned, so re-verify and delete EVERY matching id.
            v_clean = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=name)
            ids = all_ids(v_clean.response(), name) or [cert_id]
            result.record(op_succeeded(
                ctx.runner.run("cert", "localcert-delete-batch", id=[str(i) for i in ids]),
                ctx=ctx, label=f"{key_type}-cleanup"))


def run(ctx: CaseContext, result: CaseResult) -> None:
    _issue_pair(ctx, result, case_id=900020, suffix="rsa", key_type="RSA", cacert="defaultLocalCA.crt")
    _issue_pair(ctx, result, case_id=900020, suffix="sm2", key_type="SM2", cacert="defaultGmLocalCA.crt")
