"""P2-331499: IPV6 地址对象排除地址配置上限测试.

Same as 331537 but for IPv6 objects: a create and an update with 11 exclusion
networks are rejected (device capacity limit) and recorded in the operation
log.
"""

from __future__ import annotations

import json

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import OBJ_V6, run_excl_reject
from framework.results import CaseResult

TITLE = "P2-331499 IPv6 地址对象排除地址配置上限"

EXCL11 = json.dumps([{"ipaddr": f"2001:db8:a::{i:x}", "mask": "128"} for i in range(1, 12)], ensure_ascii=False)


def run(ctx: CaseContext, result: CaseResult) -> None:
    run_excl_reject(
        ctx, result,
        family=OBJ_V6,
        name=unique_random(331499, "excllimit"),
        valid_kwargs={"ipaddr": "2001:db8:4::", "mask": "64", "object_desc": "atc excllimit base"},
        bad_excl_networks=EXCL11,
        bad_kwargs={"ipaddr": "2001:db8:5::", "mask": "64", "object_desc": "atc excllimit bad"},
        label="limit",
    )
