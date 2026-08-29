"""P1-256064: 自定义服务配置下发成功.

Deliver a valid custom service pool and confirm it end-to-end: REST query
reflects the config, the etcd servicepool key is created, and vppctl show
serpool lists it. Probing found no etcd refcnt key for service objects, so
delivery is verified through the standard data-plane checks.
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import DATA_PLANE, SERVICE, run_deliver_success
from framework.results import CaseResult

TITLE = "P1-256064 自定义服务配置下发成功"

FULL_RANGE = '[{"proto":6,"s_start":0,"s_end":65535,"d_start":0,"d_end":65535}]'


def run(ctx: CaseContext, result: CaseResult) -> None:
    etcd_key, vppctl_cmd = DATA_PLANE["service"]
    name = unique_random(256064, "svc")
    run_deliver_success(
        ctx, result,
        family=SERVICE,
        name=name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        create_kwargs={"ranges": FULL_RANGE, "desc": "atc 256064 svc"},
        update_kwargs={"ranges": FULL_RANGE, "desc": "atc 256064 svc upd"},
    )
