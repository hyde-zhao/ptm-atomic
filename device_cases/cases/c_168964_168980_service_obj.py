"""P1-168964 / P1-168980: 服务对象配置下发成功 / 失败.

Success: create a custom service pool (proto 6, full port range) -> update ->
REST verify -> etcd servicepool key -> vppctl show serpool name, then clean up.
Failure: a range with s_start > s_end must be rejected and leave no trace.
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import (
    DATA_PLANE,
    SERVICE,
    run_deliver_failure,
    run_deliver_success,
)
from framework.results import CaseResult

TITLE = "P1-168964/168980 服务对象下发成功/失败"

FULL_RANGE = '[{"proto":6,"s_start":0,"s_end":65535,"d_start":0,"d_end":65535}]'


def run(ctx: CaseContext, result: CaseResult) -> None:
    etcd_key, vppctl_cmd = DATA_PLANE["service"]

    ok_name = unique_random(168964, "svc")
    run_deliver_success(
        ctx, result,
        family=SERVICE,
        name=ok_name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        create_kwargs={
            "ranges": FULL_RANGE,
            "desc": "atc svc ok",
        },
        update_kwargs={
            "ranges": '[{"proto":6,"s_start":80,"s_end":80,"d_start":0,"d_end":65535}]',
            "desc": "atc svc updated",
        },
    )

    bad_name = unique_random(168980, "svc")
    run_deliver_failure(
        ctx, result,
        family=SERVICE,
        name=bad_name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        bad_kwargs={
            "ranges": '[{"proto":6,"s_start":2000,"s_end":1000,"d_start":0,"d_end":65535}]',
            "desc": "atc svc bad",
        },
    )
