"""P1-168965 / P1-168981: 服务组对象配置下发成功 / 失败.

Success: create a member service pool, then a service group referencing it;
update and verify via REST/etcd/vppctl; clean up both. Failure: a group
referencing a non-existent service must be rejected with no trace.
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import (
    DATA_PLANE,
    SERVICE,
    SERVICE_GROUP,
    run_deliver_failure,
    run_deliver_success,
)
from framework.results import CaseResult

TITLE = "P1-168965/168981 服务组下发成功/失败"

MEMBER_RANGE = '[{"proto":6,"s_start":0,"s_end":65535,"d_start":0,"d_end":65535}]'


def run(ctx: CaseContext, result: CaseResult) -> None:
    etcd_key, vppctl_cmd = DATA_PLANE["service-group"]
    member_name = unique_random(168965, "svcmember")

    ok_name = unique_random(168965, "svcgrp")
    run_deliver_success(
        ctx, result,
        family=SERVICE_GROUP,
        name=ok_name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        create_kwargs={
            "servicepools": [member_name],
            "desc": "atc svc grp ok",
        },
        update_kwargs={
            "servicepools": [member_name],
            "desc": "atc svc grp updated",
        },
        members=[
            (SERVICE, member_name, {"ranges": MEMBER_RANGE, "desc": "atc member"}),
        ],
    )

    bad_name = unique_random(168981, "svcgrp")
    run_deliver_failure(
        ctx, result,
        family=SERVICE_GROUP,
        name=bad_name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        bad_kwargs={
            "servicepools": ["no_such_member_xyz"],
            "desc": "atc svc grp bad",
        },
    )
