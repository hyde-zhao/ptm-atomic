"""P1-168957 / P1-168973: IPv4 地址对象配置下发成功 / 失败.

Success: create a valid IPv4 address object -> update -> REST verify reflects
the config -> etcd ippool key present -> vppctl show ippool name present, then
clean up. Failure: a device-invalid create (host bits set in a /24 network)
must be rejected and leave no trace in REST/etcd/vppctl.
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import (
    DATA_PLANE,
    OBJ_V4,
    run_deliver_failure,
    run_deliver_success,
)
from framework.results import CaseResult

TITLE = "P1-168957/168973 IPv4 地址对象下发成功/失败"


def run(ctx: CaseContext, result: CaseResult) -> None:
    etcd_key, vppctl_cmd = DATA_PLANE["ipv4-obj"]

    ok_name = unique_random(168957, "v4obj")
    run_deliver_success(
        ctx, result,
        family=OBJ_V4,
        name=ok_name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        create_kwargs={
            "ipaddr": "10.10.0.0",
            "mask": "24",
            "object_desc": "atc v4 obj ok",
        },
        update_kwargs={
            "ipaddr": "10.20.0.0",
            "mask": "24",
            "object_desc": "atc v4 obj updated",
        },
    )

    bad_name = unique_random(168973, "v4obj")
    run_deliver_failure(
        ctx, result,
        family=OBJ_V4,
        name=bad_name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        bad_kwargs={
            "ipaddr": "10.99.0.0",
            "mask": "0",  # device rejects mask=0 (eObjIpMaskErr "掩码不合法")
            "object_desc": "atc v4 obj bad",
        },
    )
