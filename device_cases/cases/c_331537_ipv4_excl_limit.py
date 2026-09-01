"""P2-331537: IPV4 地址对象排除地址配置上限测试.

A valid object is created; then a create and an update with 11 exclusion
networks (one over the device's per-object limit of 10) are both rejected and
recorded in the operation log. 11 distinct networks are used so the rejection
comes from the capacity check, not the duplicate check.
"""

from __future__ import annotations

import json

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import OBJ_V4, run_excl_reject
from framework.results import CaseResult

TITLE = "P2-331537 IPv4 地址对象排除地址配置上限"

EXCL11 = json.dumps([{"ipaddr": f"10.90.0.{i}", "mask": "32"} for i in range(1, 12)], ensure_ascii=False)


def run(ctx: CaseContext, result: CaseResult) -> None:
    run_excl_reject(
        ctx, result,
        family=OBJ_V4,
        name=unique_random(331537, "excllimit"),
        valid_kwargs={"ipaddr": "10.44.0.0", "mask": "24", "object_desc": "atc excllimit base"},
        bad_excl_networks=EXCL11,
        bad_kwargs={"ipaddr": "10.45.0.0", "mask": "24", "object_desc": "atc excllimit bad"},
        label="limit",
    )
