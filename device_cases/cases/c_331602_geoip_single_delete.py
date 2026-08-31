"""P1-331602: geoip 单条删除.

Create a custom geoip region object, confirm it is visible, delete it by the
numeric id, then confirm it is gone.
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.geoip_support import CITY, PROVINCE, geoip_absent, geoip_present

TITLE = "P1-331602 geoip 单条删除"


def run(ctx: CaseContext, result: CaseResult) -> None:
    desc = unique_random(331602, "gip")

    out = ctx.runner.run(
        "geoip", "config",
        ip="198.18.1.1", country="CN",
        province=PROVINCE, city=CITY, desc=desc,
    )
    result.record(op_succeeded(out, ctx=ctx, label="create"))
    if not ctx.execute:
        return

    gip_id = out.response().get("id")
    created = out.success and isinstance(gip_id, int)
    result.record(Check(name="create-returns-numeric-id", ok=created, detail=f"id={gip_id!r}"))
    deleted = False
    try:
        v = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v, ctx=ctx, label="verify-before-delete"))
        if v.success:
            result.record(state_check(ctx, geoip_present(v.response(), label="present-before-delete", desc=desc)))

        d = ctx.runner.run("geoip", "delete", id=gip_id)
        result.record(op_succeeded(d, ctx=ctx, label="delete-single"))
        deleted = d.success

        v2 = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v2, ctx=ctx, label="verify-after-delete"))
        if v2.success:
            result.record(state_check(ctx, geoip_absent(v2.response(), label="absent-after-delete", desc=desc)))
    finally:
        if created and not deleted:
            ctx.runner.run("geoip", "delete", id=gip_id)
            result.notes.append(f"cleanup: deleted geoip id {gip_id}")
