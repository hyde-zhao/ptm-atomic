"""P2-129008: 验证证书对象操作日志正确性.

Operation-log coverage for the cert family. The generic ``run_oplog`` helper
is family-driven by object names; cert deletes by numeric id and has no
plain update (issue only), so the sequence is written directly:

  1. create a local certificate (success)
  2. create with an invalid subject (device-rejected: creatCertFailByConversionError)
  3. issue it (success, the cert-family "update")
  4. delete it by numeric id (success)
  5. batch-delete a nonexistent id (rejected)

Then capture the operation log and assert the object name appears (successful
operations logged) and a failure entry exists for the rejected create.
"""

from __future__ import annotations

import json

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import oplog_failure_hits, oplog_messages
from framework.results import CaseResult

from cases.cert_support import first_id

TITLE = "P2-129008 验证证书对象操作日志正确性"

SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}
BAD_SUBJECT = json.dumps(
    {"val": {"name": "PLACEHOLDER", "subject": {"country": "CN", "CN": "reject-me"},
             "option": {"type": "RSA", "keyLenth": 2048}}}, ensure_ascii=False)


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(129008, "cert")
    bad_payload = BAD_SUBJECT.replace("PLACEHOLDER", f"{name}-bad")
    cert_id: int | None = None
    try:
        # 1: create success.
        create = ctx.runner.run("cert", "localcert-config", name=name, key_type="RSA", key_length=2048,
                                country=SUBJECT["country"], state=SUBJECT["state"], location=SUBJECT["location"],
                                organization=SUBJECT["organization"], organ_unit=SUBJECT["organUnit"])
        result.record(op_succeeded(create, ctx=ctx, label="oplog-create-ok"))
        if not ctx.execute:
            return
        v1 = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=name)
        cert_id = first_id(v1.response(), name)

        # 2: create failure (invalid subject).
        bad = ctx.runner.run("cert", "localcert-config", payload_json=bad_payload)
        result.record(op_rejected(bad, ctx=ctx, label="oplog-create-bad",
                                  expect_err_codes=("creatCertFailByConversionError", "eObjParse")))

        # 3: issue success (cert-family update).
        if cert_id is not None:
            issue = ctx.runner.run("cert", "localcert-issue", id=str(cert_id),
                                   cacert="defaultLocalCA.crt", option="1", time_length=30)
            result.record(op_succeeded(issue, ctx=ctx, label="oplog-issue-ok"))

        # 4: delete success.
        if cert_id is not None:
            dele = ctx.runner.run("cert", "localcert-delete-batch", id=str(cert_id))
            result.record(op_succeeded(dele, ctx=ctx, label="oplog-delete-ok"))
            cert_id = None

        # 5: delete failure (nonexistent id — single delete rejects, batch is a
        # silent no-op for unknown ids).
        bdel = ctx.runner.run("cert", "localcert-delete", id="99999999")
        result.record(op_rejected(bdel, ctx=ctx, label="oplog-delete-bad", expect_err_codes=("eRequestParam",)))

        # Capture the operation log (wide window: device clock lags ~137s; the
        # log writer can also lag a few seconds, so re-query until the cert
        # name appears, up to 3 tries).
        window_start = int(__import__("time").time()) - 300
        messages: list[str] = []
        for _ in range(3):
            cap = ctx.runner.run("operation-log", "capture", timetype="custom",
                                 starttime=window_start, endtime=int(__import__("time").time()) + 15,
                                 page=1, size=200)
            result.record(op_succeeded(cap, ctx=ctx, label="oplog-capture"))
            if not cap.success:
                return
            messages = oplog_messages(cap.response())
            ready = (
                any(name in m for m in messages)
                and bool(oplog_failure_hits(messages, "生成"))
                and bool(oplog_failure_hits(messages, "删除"))
            )
            if ready:
                break
            __import__("time").sleep(2)
        hits = [m for m in messages if name in m]
        result.record(Check(name="oplog-cert-name", ok=len(hits) >= 1,
                            detail=f"occurrences={len(hits)} needle={name!r}"))
        result.notes.append("CAPTURED_MSGS=" + " || ".join(repr(m)[:80] for m in messages[:12]))
        result.notes.append("ALL_HITS=" + " || ".join(repr(m)[:80] for m in messages if "失败" in m or "生成" in m or "删除" in m))
        # Cert family logs create/delete failures with action "生成"/"删除" +
        # "失败" (message carries no name for failures).
        for action in ("生成", "删除"):
            fails = oplog_failure_hits(messages, action)
            result.record(Check(name=f"oplog-cert-fail-{action}", ok=len(fails) >= 1,
                                detail=f"failure entries={len(fails)} action={action!r}"))
    finally:
        if ctx.execute and cert_id is not None:
            result.record(op_succeeded(
                ctx.runner.run("cert", "localcert-delete-batch", id=str(cert_id)),
                ctx=ctx, label="oplog-cleanup"))
