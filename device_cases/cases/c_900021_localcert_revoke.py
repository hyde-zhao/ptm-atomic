"""P3-900021: 证书吊销测试.

Probe-confirmed (probe21b): PUT localcert with option="2" revokes an issued
certificate — the verify entry's fileState flips "2" -> "0", and the OpenSSL
index (/appdata/etc/cert/demoCA/index.txt) records a revoked ("R") entry for
the certificate subject.

Device divergence from the xlsx: revoke does NOT materialize a .crl file under
localcert/ (the crldir stays empty; CRL is generated on demand at download,
covered by 900019). The scriptable proxy for "吊销成功" is the fileState=0
transition plus the index.txt "R" record.
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import all_ids, cert_present, entry_field, first_id

TITLE = "P3-900021 证书吊销测试"

SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}
INDEX_FILE = "/appdata/etc/cert/demoCA/index.txt"


def _revoke_pair(ctx, result, *, case_id: int, suffix: str, key_type: str, cacert: str) -> None:
    name = unique_random(case_id, suffix)
    cert_id: int | None = None
    try:
        create = ctx.runner.run("cert", "localcert-config", name=name, key_type=key_type, key_length=2048,
                                country=SUBJECT["country"], state=SUBJECT["state"], location=SUBJECT["location"],
                                organization=SUBJECT["organization"], organ_unit=SUBJECT["organUnit"])
        result.record(op_succeeded(create, ctx=ctx, label=f"{key_type}-config-ok"))
        if not ctx.execute:
            return
        v1 = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=name)
        cert_id = first_id(v1.response(), name)
        # After SM2 issue the cert splits into <name>_sig.crt + <name>_enc.crt;
        # revoke acts on the signature cert (same numeric id as the CSR). The
        # _enc entry is not revoked and stays fileState=2.
        check_name = f"{name}_sig.crt" if key_type == "SM2" else name

        # check1: create + issue succeeds; entry is in issued state (no crl yet).
        if cert_id is not None:
            issue = ctx.runner.run("cert", "localcert-issue", id=str(cert_id), cacert=cacert, option="1", time_length=30)
            result.record(op_succeeded(issue, ctx=ctx, label=f"{key_type}-issue-ok"))
        v_issued = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=name)
        fstate = entry_field(v_issued.response(), check_name, "fileState") if v_issued.success else None
        result.record(Check(name=f"{key_type}-issued-fileState", ok=fstate == "2",
                            detail=f"fileState={fstate!r} want '2' ({check_name})"))
        r_before = ctx.ssh.exec(f"grep -c '^R' {INDEX_FILE}")
        r_count_before = int(r_before.text().strip() or 0)

        # check2: revoke (option="2") flips fileState to "0" and logs an R record.
        if cert_id is not None:
            revoke = ctx.runner.run("cert", "localcert-issue", id=str(cert_id), cacert=cacert, option="2", time_length=30)
            result.record(op_succeeded(revoke, ctx=ctx, label=f"{key_type}-revoke-ok"))
        v_revoked = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=name)
        fstate = entry_field(v_revoked.response(), check_name, "fileState") if v_revoked.success else None
        result.record(Check(name=f"{key_type}-revoked-fileState", ok=fstate == "0",
                            detail=f"fileState={fstate!r} want '0' (revoked, {check_name})"))
        r_after = ctx.ssh.exec(f"grep -c '^R' {INDEX_FILE}")
        r_count_after = int(r_after.text().strip() or 0)
        result.record(state_check(ctx, Check(
            name=f"{key_type}-index-R-record", ok=r_count_after > r_count_before,
            detail=f"index.txt revoked entries before={r_count_before} after={r_count_after}")))
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
    _revoke_pair(ctx, result, case_id=900021, suffix="rv", key_type="RSA", cacert="defaultLocalCA.crt")
    _revoke_pair(ctx, result, case_id=900021, suffix="rv", key_type="SM2", cacert="defaultGmLocalCA.crt")
