"""P3-18225: 初始化本地证书不可修改测试.

Device semantics (probe21): the localcert module ships three built-in
certificates — defaultLocalCert.crt (RSA), defaultGmLocalCert_sig.crt (SM2),
defaultGmLocalCert_enc.crt (SM2) — each valid for 10 years. Attempting to
modify (PUT issue variant) or delete any built-in is rejected:
  * PUT issue  -> 400 putCertFailByDefaultCert 「默认内置证书不允许修改」
  * DELETE     -> 400 delCertFailCanNotDel      「默认证书不允许删除」
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.results import CaseResult

from cases.cert_support import find_by_name, validity_years

TITLE = "P3-18225 初始化本地证书不可修改测试"

BUILTINS = ("defaultLocalCert.crt", "defaultGmLocalCert_sig.crt", "defaultGmLocalCert_enc.crt")


def run(ctx: CaseContext, result: CaseResult) -> None:
    vout = ctx.runner.run("cert", "localcert-verify", page=1, size=200)
    result.record(op_succeeded(vout, ctx=ctx, label="init-verify-ok"))
    if not ctx.execute or not vout.success:
        return
    resp = vout.response()

    # check1: the three built-in certificates exist; the RSA default is valid 10y.
    present = [nm for nm in BUILTINS if find_by_name(resp, nm)]
    result.record(
        Check(name="init-builtins-present", ok=len(present) == len(BUILTINS),
              detail=f"builtins={present} want={list(BUILTINS)}")
    )
    yrs = validity_years(resp, "defaultLocalCert.crt")
    result.record(
        Check(name="init-default-validity-10y", ok=yrs is not None and 9.5 <= yrs <= 10.5,
              detail=f"defaultLocalCert.crt validity={yrs} years (want ~10)")
    )

    # check2: modify (issue variant) and delete of the built-in are rejected.
    entry = find_by_name(resp, "defaultLocalCert.crt")
    bid = entry[0]["id"] if entry else None
    if bid is not None:
        upd = ctx.runner.run("cert", "localcert-issue", id=str(bid),
                             cacert="defaultLocalCA.crt", option="1", time_length=30)
        result.record(op_rejected(upd, ctx=ctx, label="builtin-update-rejected",
                                  expect_err_codes=("putCertFailByDefaultCert",)))
        dele = ctx.runner.run("cert", "localcert-delete", id=str(bid))
        result.record(op_rejected(dele, ctx=ctx, label="builtin-delete-rejected",
                                  expect_err_codes=("delCertFailCanNotDel",)))
    else:
        result.record(Check(name="builtin-id-resolved", ok=False, detail="defaultLocalCert.crt not found in verify"))
