"""P2-263512: IPV6 地址对象重复排除地址配置测试.

IPv6 mirror of case 263478: a valid object is created, then a create and an
update with duplicate exclusion networks are both rejected (device reports
eNotUniqueExclnetworks) and recorded in the operation log.
"""

from __future__ import annotations

import json

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import OBJ_V6, run_excl_reject
from framework.results import CaseResult

TITLE = "P2-263512 IPv6 对象重复排除地址配置"

DUP_EXCL = json.dumps([{"ipaddr": "2001:db8:2::", "mask": "128"}, {"ipaddr": "2001:db8:2::", "mask": "128"}], ensure_ascii=False)


def run(ctx: CaseContext, result: CaseResult) -> None:
    run_excl_reject(
        ctx, result,
        family=OBJ_V6,
        name=unique_random(263512, "dupexcl"),
        valid_kwargs={"ipaddr": "2001:db8:4::", "mask": "64", "object_desc": "atc dupexcl base"},
        bad_excl_networks=DUP_EXCL,
        bad_kwargs={"ipaddr": "2001:db8:5::", "mask": "64", "object_desc": "atc dupexcl bad"},
        label="dup",
    )
