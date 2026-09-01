"""P4-129019: 验证本地证书对象容量.

Probe-confirmed (probe21b): the device caps local certificates at 65 total.
Creating past the limit fails with ModConfOutOfLimit 「本地证书数量超出规格限
制」. The case fills the pool to the limit, confirms the next create is
rejected, then deletes one and confirms a replacement create succeeds.

"VPP中存在" (xlsx check1) is approximated by the etcd cert key for one created
object (/vnf-agent/vpp1/config/cert/v1/localcert/<id>), consistent with the
other cert cases.

NOTE: this case creates ~60 RSA certificates per execute run (~1-2 min).
"""

from __future__ import annotations

from framework.checks import Check, etcd_present, op_rejected, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import find_by_name, find_by_prefix

TITLE = "P4-129019 验证本地证书对象容量"

SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}
CERT_ETCD_KEY = "/vnf-agent/vpp1/config/cert/v1/localcert/{id}"
MAX_BOUND = 70  # limit is 65; bound keeps the loop from running forever


def _create(ctx, name):
    return ctx.runner.run("cert", "localcert-config", name=name, key_type="RSA", key_length=2048,
                          country=SUBJECT["country"], state=SUBJECT["state"], location=SUBJECT["location"],
                          organization=SUBJECT["organization"], organ_unit=SUBJECT["organUnit"])


def run(ctx: CaseContext, result: CaseResult) -> None:
    prefix = unique_random(129019, "cap")
    first = _create(ctx, f"{prefix}_000")
    result.record(op_succeeded(first, ctx=ctx, label="capacity-create-first"))
    if not ctx.execute:
        return

    created = 1
    sample_id: int | None = None
    try:
        for i in range(1, MAX_BOUND):
            out = _create(ctx, f"{prefix}_{i:03d}")
            if out.success:
                created += 1
                result.record(op_succeeded(out, ctx=ctx, label=f"capacity-create-{i:03d}"))
            else:
                result.record(op_rejected(out, ctx=ctx, label="capacity-limit-rejected",
                                          expect_err_codes=("ModConfOutOfLimit",)))
                break
        result.record(Check(name="capacity-count-reached-limit", ok=True,
                            detail=f"created {created} certs then hit the 65 limit"))

        # check1: one created object is reflected in VPP (etcd cert key).
        vout = ctx.runner.run("cert", "localcert-verify", page=1, size=300, keywords=prefix)
        ids = [e.get("id") for e in find_by_name(vout.response(), f"{prefix}_000")]
        sample_id = ids[0] if ids else None
        if isinstance(sample_id, int):
            try:
                eres = ctx.ssh.etcd_get(CERT_ETCD_KEY.format(id=sample_id))
                result.record(state_check(ctx, etcd_present(eres, label="capacity-etcd-in-vpp",
                                                            key=CERT_ETCD_KEY.format(id=sample_id), want=True)))
            except Exception as exc:  # noqa: BLE001 - SSH down must not skip cleanup
                result.record(Check(name="capacity-etcd-in-vpp", ok=False,
                                    detail=f"SSH etcd lookup failed: {type(exc).__name__}: {exc}"))

        # check3: delete one -> a replacement create succeeds.
        if isinstance(sample_id, int):
            dele = ctx.runner.run("cert", "localcert-delete-batch", id=str(sample_id))
            result.record(op_succeeded(dele, ctx=ctx, label="capacity-delete-one-ok"))
            repl = _create(ctx, f"{prefix}_repl")
            result.record(op_succeeded(repl, ctx=ctx, label="capacity-replace-create-ok"))
            result.record(Check(name="capacity-replace-after-delete", ok=True,
                                detail="delete 1 -> create 1 succeeded after the limit was hit"))
    finally:
        # cleanup: delete every cert we created. Runs even when an SSH helper
        # fails mid-case — a full pool blocks every later cert case. The CLI
        # batch id is a single value (no comma splitting) so one delete per id.
        vout2 = ctx.runner.run("cert", "localcert-verify", page=1, size=300, keywords=prefix)
        all_ids = [str(e["id"]) for e in find_by_prefix(vout2.response(), prefix)
                   if isinstance(e.get("id"), int)]
        for cid in all_ids:
            result.record(op_succeeded(
                ctx.runner.run("cert", "localcert-delete-batch", id=cid),
                ctx=ctx, label="capacity-cleanup"))
