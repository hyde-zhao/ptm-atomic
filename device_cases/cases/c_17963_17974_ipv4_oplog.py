"""P0-17963 / P0-17974: ipv4 地址对象 / 地址组对象操作日志.

For each family, run create/update/delete x success/failure (6 actions) and
assert the operation log records the object name for every action.
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import (
    GROUP_V4,
    OBJ_V4,
    run_oplog,
)
from framework.results import CaseResult

TITLE = "P0-17963/17974 ipv4 对象与地址组操作日志"


def run(ctx: CaseContext, result: CaseResult) -> None:
    # 17963: ipv4 address object oplog.
    obj_name = unique_random(17963, "v4obj")
    run_oplog(
        ctx, result,
        family=OBJ_V4,
        name=obj_name,
        config_kwargs={"ipaddr": "10.60.0.0", "mask": "24", "object_desc": "atc oplog obj"},
        update_kwargs={"ipaddr": "10.61.0.0", "mask": "24", "object_desc": "atc oplog obj upd"},
        bad_kwargs={"ipaddr": "10.60.0.5", "mask": "0", "object_desc": "atc oplog obj bad"},  # mask=0 is device-rejected
        delete_bad_logged=False,
    )

    # 17974: ipv4 address group oplog (needs a real member object).
    member_name = unique_random(17974, "v4member")
    grp_name = unique_random(17974, "v4grp")
    run_oplog(
        ctx, result,
        family=GROUP_V4,
        name=grp_name,
        config_kwargs={"ippools": [member_name], "desc": "atc oplog grp"},
        update_kwargs={"ippools": [member_name], "desc": "atc oplog grp upd"},
        bad_kwargs={"ippools": ["no_such_member_xyz"], "desc": "atc oplog grp bad"},
        members=[
            (OBJ_V4, member_name, {"ipaddr": "10.62.0.0", "mask": "24", "object_desc": "atc member"}),
        ],
        bad_logged=False,
        delete_bad_logged=False,
    )
