"""P1-331604: geoip 非法省份/城市被设备拒绝.

The device validates province/city against its region database (probe17g
isolation: omission or unknown names such as HN/CS -> 400 eRequestParam).
Creating a custom geoip object with an unknown region must be rejected and
leave no object behind.
"""

from __future__ import annotations

from framework.checks import op_rejected, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.geoip_support import geoip_absent

TITLE = "P1-331604 geoip 非法地区参数被设备拒绝"


def run(ctx: CaseContext, result: CaseResult) -> None:
    desc = unique_random(331604, "gip")

    out = ctx.runner.run(
        "geoip", "config",
        ip="203.0.113.5", country="CN",
        province="HN", city="CS", desc=desc,
    )
    result.record(
        op_rejected(out, ctx=ctx, label="invalid-region-rejected", expect_err_codes=("eRequestParam",))
    )
    if not ctx.execute:
        return

    v = ctx.runner.run("geoip", "verify", page=1, size=500)
    result.record(op_succeeded(v, ctx=ctx, label="verify-no-trace"))
    if v.success:
        result.record(state_check(ctx, geoip_absent(v.response(), label="no-trace-after-reject", desc=desc)))
