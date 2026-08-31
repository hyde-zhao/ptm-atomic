"""P1-168959 / P1-168975: IPv4 地址组对象配置下发成功 / 失败.

Success: create a member IPv4 object, then a group referencing it; update and
verify via REST/etcd/vppctl; clean up both. Failure: a group referencing a
non-existent member must be rejected with no trace.
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import (
    DATA_PLANE,
    GROUP_V4,
    OBJ_V4,
    run_deliver_failure,
    run_deliver_success,
)
from framework.results import CaseResult

TITLE = "P1-168959/168975 IPv4 地址组下发成功/失败"


def run(ctx: CaseContext, result: CaseResult) -> None:
    etcd_key, vppctl_cmd = DATA_PLANE["ipv4-group"]
    member_name = unique_random(168959, "v4member")

    ok_name = unique_random(168959, "v4grp")
    run_deliver_success(
        ctx, result,
        family=GROUP_V4,
        name=ok_name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        create_kwargs={
            "ippools": [member_name],
            "desc": "atc v4 grp ok",
        },
        update_kwargs={
            "ippools": [member_name],
            "desc": "atc v4 grp updated",
        },
        members=[
            (OBJ_V4, member_name, {"ipaddr": "10.30.0.0", "mask": "24", "object_desc": "atc member"}),
        ],
    )

    bad_name = unique_random(168975, "v4grp")
    run_deliver_failure(
        ctx, result,
        family=GROUP_V4,
        name=bad_name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        bad_kwargs={
            "ippools": ["no_such_member_xyz"],
            "desc": "atc v4 grp bad",
        },
    )
