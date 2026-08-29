"""P1-168969: 时间对象配置下发成功.

Create a valid day-schedule time object -> update -> REST verify -> etcd
timeobject key present (time objects have no vppctl view), then clean up.
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import DATA_PLANE, TIME, run_deliver_success
from framework.results import CaseResult

TITLE = "P1-168969 时间对象下发成功"


def run(ctx: CaseContext, result: CaseResult) -> None:
    etcd_key, vppctl_cmd = DATA_PLANE["time"]

    name = unique_random(168969, "time")
    run_deliver_success(
        ctx, result,
        family=TIME,
        name=name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        create_kwargs={
            "scheduletype": "day",
            "start_time": "00:00:00",
            "end_time": "23:59:59",
        },
        update_kwargs={
            "scheduletype": "day",
            "start_time": "08:00:00",
            "end_time": "18:00:00",
        },
    )
