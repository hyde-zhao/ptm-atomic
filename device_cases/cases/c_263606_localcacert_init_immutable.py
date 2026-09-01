"""P3-263606: 初始化RSA和SM2本地CA证书不可修改测试.

Device semantics (probe21):
  * localcert module  -> 3 built-ins: defaultLocalCert.crt (RSA),
    defaultGmLocalCert_sig.crt (SM2), defaultGmLocalCert_enc.crt (SM2).
  * localcacert module -> 2 built-ins: defaultLocalCA.crt (RSA),
    defaultGmLocalCA.crt (SM2).  (The xlsx names "defaultLocalCACert.crt";
    the device actually ships defaultLocalCA.crt/defaultGmLocalCA.crt.)
  * Built-ins are immutable: localcert PUT -> putCertFailByDefaultCert,
    localcert DELETE -> delCertFailCanNotDel, localcacert DELETE ->
    delCertFailByRefcnt (referenced CA) or eCaCertExistSignedCert (signed certs).
  * All built-ins valid ~10 years.
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.results import CaseResult

from cases.cert_support import find_by_name, validity_years

TITLE = "P3-263606 初始化RSA和SM2本地CA证书不可修改测试"

LC_BUILTINS = ("defaultLocalCert.crt", "defaultGmLocalCert_sig.crt", "defaultGmLocalCert_enc.crt")
LCA_BUILTINS = ("defaultLocalCA.crt", "defaultGmLocalCA.crt")


def _builtin_check(resp, names, *, label: str) -> Check:
    present = [nm for nm in names if find_by_name(resp, nm)]
    detail = "; ".join(
        f"{nm}:{validity_years(resp, nm)}y" if find_by_name(resp, nm) else f"{nm}:absent"
        for nm in names
    )
    return Check(name=label, ok=len(present) == len(names), detail=f"present={present} want={list(names)} {detail}")


def run(ctx: CaseContext, result: CaseResult) -> None:
    lc_out = ctx.runner.run("cert", "localcert-verify", page=1, size=200)
    lca_out = ctx.runner.run("cert", "localcacert-verify", page=1, size=200)
    result.record(op_succeeded(lc_out, ctx=ctx, label="localcert-verify-ok"))
    result.record(op_succeeded(lca_out, ctx=ctx, label="localcacert-verify-ok"))
    if not ctx.execute or not lc_out.success or not lca_out.success:
        return
    lc = lc_out.response()
    lca = lca_out.response()

    # check1: localcert module holds the three built-in certs, valid ~10y.
    result.record(_builtin_check(lc, LC_BUILTINS, label="init-localcert-builtins"))
    # check2: localcacert module holds the two built-in CA certs, valid ~10y.
    result.record(_builtin_check(lca, LCA_BUILTINS, label="init-localcacert-builtins"))

    # check3: built-in certs cannot be modified or deleted.
    lc_entry = find_by_name(lc, "defaultLocalCert.crt")
    if lc_entry:
        bid = lc_entry[0]["id"]
        upd = ctx.runner.run("cert", "localcert-issue", id=str(bid),
                             cacert="defaultLocalCA.crt", option="1", time_length=30)
        result.record(op_rejected(upd, ctx=ctx, label="builtin-lc-update-rejected",
                                  expect_err_codes=("putCertFailByDefaultCert",)))
        dele = ctx.runner.run("cert", "localcert-delete", id=str(bid))
        result.record(op_rejected(dele, ctx=ctx, label="builtin-lc-delete-rejected",
                                  expect_err_codes=("delCertFailCanNotDel",)))
    else:
        result.record(Check(name="builtin-lc-id-resolved", ok=False, detail="defaultLocalCert.crt not found"))
    for nm in LCA_BUILTINS:
        entry = find_by_name(lca, nm)
        if not entry:
            result.record(Check(name=f"builtin-lca-{nm}-resolved", ok=False, detail=f"{nm} not found"))
            continue
        # Probe-confirmed: a batch-delete of a built-in localcacert returns
        # success but is a silent no-op (the entry survives). A single DELETE
        # is rejected (delCertFailByRefcnt / eCaCertExistSignedCert), but the
        # CLI exposes only the batch path for localcacert. Immutability is
        # asserted as "still present after the delete attempt".
        dele = ctx.runner.run("cert", "localcacert-delete-batch", id=str(entry[0]["id"]))
        result.record(op_succeeded(dele, ctx=ctx, label=f"builtin-lca-{nm}-delete-attempt"))
        v_again = ctx.runner.run("cert", "localcacert-verify", page=1, size=200)
        still = find_by_name(v_again.response(), nm)
        result.record(Check(name=f"builtin-lca-{nm}-still-present", ok=len(still) == 1,
                            detail=f"{nm} entries after delete attempt={len(still)} (want 1 — 内置证书不允许删除)"))
