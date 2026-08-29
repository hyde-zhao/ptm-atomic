"""P1-197298: 验证 IPv6 组对象操作日志正确性.

Run create/update/delete x success/failure on an IPv6 address group (6
actions) and assert the operation log records the object name for every
action.
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import GROUP_V6, OBJ_V6, run_oplog
from framework.results import CaseResult

TITLE = "P1-197298 IPv6 组对象操作日志"


def run(ctx: CaseContext, result: CaseResult) -> None:
    member_name = unique_random(197298, "v6member")
    grp_name = unique_random(197298, "v6grp")
    run_oplog(
        ctx, result,
        family=GROUP_V6,
        name=grp_name,
        config_kwargs={"ip6pools": [member_name], "desc": "atc oplog v6grp"},
        update_kwargs={"ip6pools": [member_name], "desc": "atc oplog v6grp upd"},
        bad_kwargs={"ip6pools": ["no_such_member_xyz"], "desc": "atc oplog v6grp bad"},
        members=[
            (OBJ_V6, member_name, {"ipaddr": "2001:db8:3::", "mask": "64", "object_desc": "atc member"}),
        ],
        bad_logged=False,
        delete_bad_logged=False,
    )
