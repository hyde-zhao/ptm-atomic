"""P1-331601: geoip 自定义地区对象全生命周期下发.

Create a custom geoip region object, confirm REST reflects it, update the
mapping (ip range + description), confirm the change, then batch-delete and
confirm absence. geoip objects have no name — the numeric id returned on
create is the identity; the verify endpoint ignores the ``keywords`` filter
(probe-confirmed), so presence is asserted client-side over the full list.
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.geoip_support import CITY, PROVINCE, geoip_absent, geoip_present

TITLE = "P1-331601 geoip 自定义地区对象下发成功"


def run(ctx: CaseContext, result: CaseResult) -> None:
    desc = unique_random(331601, "gip")
    desc_upd = f"{desc}-upd"

    out = ctx.runner.run(
        "geoip", "config",
        ip="198.18.0.1-198.18.0.9", country="CN",
        province=PROVINCE, city=CITY, desc=desc,
    )
    result.record(op_succeeded(out, ctx=ctx, label="create"))
    if not ctx.execute:
        return

    gip_id = out.response().get("id")
    created = out.success and isinstance(gip_id, int)
    result.record(
        Check(name="create-returns-numeric-id", ok=created, detail=f"id={gip_id!r} type={type(gip_id).__name__}")
    )
    deleted = False
    try:
        v = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v, ctx=ctx, label="verify-before-update"))
        if v.success:
            result.record(state_check(ctx, geoip_present(v.response(), label="present-before-update", desc=desc)))

        u = ctx.runner.run(
            "geoip", "update", id=gip_id,
            ip="198.18.0.1-198.18.0.20", country="CN",
            province=PROVINCE, city=CITY, desc=desc_upd,
        )
        result.record(op_succeeded(u, ctx=ctx, label="update"))

        v2 = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v2, ctx=ctx, label="verify-after-update"))
        if v2.success:
            result.record(state_check(ctx, geoip_present(v2.response(), label="updated-present", desc=desc_upd)))
            result.record(state_check(ctx, geoip_absent(v2.response(), label="old-desc-gone", desc=desc)))

        d = ctx.runner.run("geoip", "delete-batch", id=[gip_id])
        result.record(op_succeeded(d, ctx=ctx, label="delete-batch"))
        deleted = d.success

        v3 = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v3, ctx=ctx, label="verify-after-delete"))
        if v3.success:
            result.record(state_check(ctx, geoip_absent(v3.response(), label="absent-after-delete", desc=desc_upd)))
    finally:
        if created and not deleted:
            ctx.runner.run("geoip", "delete-batch", id=[gip_id])
            result.notes.append(f"cleanup: batch-deleted geoip id {gip_id}")
