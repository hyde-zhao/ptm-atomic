"""P2-129007: 验证 IPv6 地址对象操作日志正确性.

IPv6 address-object mirror of case 17963: run create/update/delete x
success/failure (6 actions) and assert the operation log records the object
name for every action. Rejected create/update use duplicate exclusion
networks (device-rejected, eNotUniqueExclnetworks).
"""

from __future__ import annotations

import json

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import OBJ_V6, run_oplog
from framework.results import CaseResult

TITLE = "P2-129007 IPv6 地址对象操作日志"

DUP_EXCL = json.dumps([{"ipaddr": "2001:db8:2::", "mask": "128"}, {"ipaddr": "2001:db8:2::", "mask": "128"}], ensure_ascii=False)


def run(ctx: CaseContext, result: CaseResult) -> None:
    obj_name = unique_random(129007, "v6obj")
    run_oplog(
        ctx, result,
        family=OBJ_V6,
        name=obj_name,
        config_kwargs={"ipaddr": "2001:db8:4::", "mask": "64", "object_desc": "atc oplog v6obj"},
        update_kwargs={"ipaddr": "2001:db8:5::", "mask": "64", "object_desc": "atc oplog v6obj upd"},
        bad_kwargs={"ipaddr": "2001:db8:4::", "mask": "64", "excl_networks": DUP_EXCL, "object_desc": "atc oplog v6obj bad"},
        delete_bad_logged=False,
    )
