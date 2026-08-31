"""P1-168960 / P1-168976: IPv6 地址组对象配置下发成功 / 失败.

Mirrors the IPv4 group pair over /api/v1/ip6pool/group with an IPv6 member
object and ip6pool-group / ip6group data-plane checks.
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import (
    DATA_PLANE,
    GROUP_V6,
    OBJ_V6,
    run_deliver_failure,
    run_deliver_success,
)
from framework.results import CaseResult

TITLE = "P1-168960/168976 IPv6 地址组下发成功/失败"


def run(ctx: CaseContext, result: CaseResult) -> None:
    etcd_key, vppctl_cmd = DATA_PLANE["ipv6-group"]
    member_name = unique_random(168960, "v6member")

    ok_name = unique_random(168960, "v6grp")
    run_deliver_success(
        ctx, result,
        family=GROUP_V6,
        name=ok_name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        create_kwargs={
            "ip6pools": [member_name],
            "desc": "atc v6 grp ok",
        },
        update_kwargs={
            "ip6pools": [member_name],
            "desc": "atc v6 grp updated",
        },
        members=[
            (OBJ_V6, member_name, {"ipaddr": "2001:db8:2::", "mask": "64", "object_desc": "atc member"}),
        ],
    )

    bad_name = unique_random(168976, "v6grp")
    run_deliver_failure(
        ctx, result,
        family=GROUP_V6,
        name=bad_name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        bad_kwargs={
            "ip6pools": ["no_such_member_xyz"],
            "desc": "atc v6 grp bad",
        },
    )
