"""P1-168958 / P1-168974: IPv6 地址对象配置下发成功 / 失败.

Mirrors the IPv4 object pair over /api/v1/ip6pool: success delivers a valid
/64 object and verifies via REST/etcd/vppctl; failure attempts a /64 with host
bits set (device-reject candidate) and asserts no trace remains.
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import (
    DATA_PLANE,
    OBJ_V6,
    run_deliver_failure,
    run_deliver_success,
)
from framework.results import CaseResult

TITLE = "P1-168958/168974 IPv6 地址对象下发成功/失败"


def run(ctx: CaseContext, result: CaseResult) -> None:
    etcd_key, vppctl_cmd = DATA_PLANE["ipv6-obj"]

    ok_name = unique_random(168958, "v6obj")
    run_deliver_success(
        ctx, result,
        family=OBJ_V6,
        name=ok_name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        create_kwargs={
            "ipaddr": "2001:db8::",
            "mask": "64",
            "object_desc": "atc v6 obj ok",
        },
        update_kwargs={
            "ipaddr": "2001:db8:1::",
            "mask": "64",
            "object_desc": "atc v6 obj updated",
        },
    )

    bad_name = unique_random(168974, "v6obj")
    run_deliver_failure(
        ctx, result,
        family=OBJ_V6,
        name=bad_name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        bad_kwargs={
            "ipaddr": "2001:db8::",
            "mask": "0",  # device rejects mask=0 (eRequestParam "掩码不合法")
            "object_desc": "atc v6 obj bad",
        },
    )
