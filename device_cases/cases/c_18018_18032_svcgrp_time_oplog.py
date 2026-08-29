"""P0-18018 / P0-18032: 服务组对象 / 时间对象操作日志.

For each family, run create/update/delete x success/failure (6 actions) and
assert the operation log records the object name for every action.
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import SERVICE, SERVICE_GROUP, TIME, run_oplog
from framework.results import CaseResult

TITLE = "P0-18018/18032 服务组与时间对象操作日志"

MEMBER_RANGE = '[{"proto":6,"s_start":0,"s_end":65535,"d_start":0,"d_end":65535}]'


def run(ctx: CaseContext, result: CaseResult) -> None:
    # 18018: service group oplog (needs a real member service).
    member_name = unique_random(18018, "svcmember")
    grp_name = unique_random(18018, "svcgrp")
    run_oplog(
        ctx, result,
        family=SERVICE_GROUP,
        name=grp_name,
        config_kwargs={"servicepools": [member_name], "desc": "atc oplog svcgrp"},
        update_kwargs={"servicepools": [member_name], "desc": "atc oplog svcgrp upd"},
        bad_kwargs={"servicepools": ["no_such_member_xyz"], "desc": "atc oplog svcgrp bad"},
        members=[
            (SERVICE, member_name, {"ranges": MEMBER_RANGE, "desc": "atc member"}),
        ],
        bad_logged=False,
        delete_bad_logged=False,
    )

    # 18032: time object oplog.
    time_name = unique_random(18032, "time")
    run_oplog(
        ctx, result,
        family=TIME,
        name=time_name,
        config_kwargs={"scheduletype": "day", "start_time": "00:00:00", "end_time": "23:59:59"},
        update_kwargs={"scheduletype": "day", "start_time": "06:00:00", "end_time": "20:00:00"},
        bad_kwargs={"scheduletype": "day", "start_time": "18:00:00", "end_time": "08:00:00"},  # start > end, device rejects
    )
