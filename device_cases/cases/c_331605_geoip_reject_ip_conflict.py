"""P1-331605: geoip IP 范围冲突被设备拒绝.

Each custom geoip object reserves a globally unique ip range (probe17k: a
second create sharing an ip -> 400 eGeoipIPConflict "IP信息冲突"). The
conflicting create must be rejected and must not add a duplicate entry.
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.geoip_support import CITY, PROVINCE, geoip_absent, geoip_present

TITLE = "P1-331605 geoip IP 范围冲突被拒绝"


def run(ctx: CaseContext, result: CaseResult) -> None:
    desc_first = unique_random(331605, "gip")
    desc_dup = unique_random(331605, "gip")
    shared_ip = "198.18.5.5"

    a = ctx.runner.run(
        "geoip", "config",
        ip=shared_ip, country="CN",
        province=PROVINCE, city=CITY, desc=desc_first,
    )
    result.record(op_succeeded(a, ctx=ctx, label="create-first"))
    if not ctx.execute:
        return

    id_a = a.response().get("id")
    created = a.success and isinstance(id_a, int)
    result.record(Check(name="first-returns-numeric-id", ok=created, detail=f"id={id_a!r}"))
    deleted = False
    try:
        b = ctx.runner.run(
            "geoip", "config",
            ip=shared_ip, country="CN",
            province=PROVINCE, city=CITY, desc=desc_dup,
        )
        result.record(
            op_rejected(b, ctx=ctx, label="conflict-rejected", expect_err_codes=("eGeoipIPConflict",))
        )

        v = ctx.runner.run("geoip", "verify", page=1, size=500)
        result.record(op_succeeded(v, ctx=ctx, label="verify-after-conflict"))
        if v.success:
            result.record(state_check(ctx, geoip_present(v.response(), label="only-first-present", desc=desc_first)))
            result.record(state_check(ctx, geoip_absent(v.response(), label="no-second-trace", desc=desc_dup)))
    finally:
        if created and not deleted:
            ctx.runner.run("geoip", "delete", id=id_a)
            result.notes.append(f"cleanup: deleted geoip id {id_a}")
