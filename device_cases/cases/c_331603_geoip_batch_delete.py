"""P1-331603: geoip 批量删除.

Create two custom geoip region objects with distinct ip ranges (an ip range is
globally unique — sharing one is rejected with eGeoipIPConflict), confirm both
are visible, delete them in one batch, then confirm both are gone.
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.geoip_support import CITY, PROVINCE, geoip_absent, geoip_present

TITLE = "P1-331603 geoip 批量删除"


def run(ctx: CaseContext, result: CaseResult) -> None:
    desc_a = unique_random(331603, "gip")
    desc_b = unique_random(331603, "gip")

    a = ctx.runner.run(
        "geoip", "config",
        ip="198.18.2.1", country="CN",
        province=PROVINCE, city=CITY, desc=desc_a,
    )
    result.record(op_succeeded(a, ctx=ctx, label="create-a"))
    b = ctx.runner.run(
        "geoip", "config",
        ip="198.18.2.2", country="CN",
        province=PROVINCE, city=CITY, desc=desc_b,
    )
    result.record(op_succeeded(b, ctx=ctx, label="create-b"))
    if not ctx.execute:
        return

    id_a = a.response().get("id")
    id_b = b.response().get("id")
    created = a.success and b.success and isinstance(id_a, int) and isinstance(id_b, int)
    result.record(
        Check(name="both-return-numeric-id", ok=created, detail=f"id_a={id_a!r} id_b={id_b!r}")
    )
    deleted = False
    try:
        v = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v, ctx=ctx, label="verify-both"))
        if v.success:
            result.record(state_check(ctx, geoip_present(v.response(), label="a-present", desc=desc_a)))
            result.record(state_check(ctx, geoip_present(v.response(), label="b-present", desc=desc_b)))

        db = ctx.runner.run("geoip", "delete-batch", id=[id_a, id_b])
        result.record(op_succeeded(db, ctx=ctx, label="delete-batch"))
        deleted = db.success

        v2 = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v2, ctx=ctx, label="verify-after-batch"))
        if v2.success:
            result.record(state_check(ctx, geoip_absent(v2.response(), label="a-absent", desc=desc_a)))
            result.record(state_check(ctx, geoip_absent(v2.response(), label="b-absent", desc=desc_b)))
    finally:
        if created and not deleted:
            ids = [value for value in (id_a, id_b) if isinstance(value, int)]
            if ids:
                ctx.runner.run("geoip", "delete-batch", id=ids)
                result.notes.append(f"cleanup: batch-deleted geoip ids {ids}")
