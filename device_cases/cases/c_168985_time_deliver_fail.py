"""P4-168985: 时间对象配置下发失败测试

xlsx(对象管理用例_重构_563.xlsx):
  1. /api/v1/timeobject 新建时间对象, 任意字段为无效值【check1】→ 400, 含 errCode/errMsg
  2. /api/v1/timeobject 查询 → 查不到该对象【check2】
  3. etcdctl 查询 /vnf-agent/vpp1/config/vpp/v1/timeobject/<name> → 查不到【check3】

设备实测(55.63, 2026-09-01): day 计划 start_time > end_time 被设备拒绝(400)。
  等 timeobject 键无下发残留走 check_absent_anywhere(REST 查无 + etcd/vppctl);
  SSH 22 不可达时 etcd/vppctl 记录 ssh-unavailable-skip。
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import DATA_PLANE, TIME, run_deliver_failure
from framework.results import CaseResult

TITLE = "P4-168985 时间对象配置下发失败测试"


def run(ctx: CaseContext, result: CaseResult) -> None:
    etcd_key, vppctl_cmd = DATA_PLANE["time"]
    name = unique_random(168985, "time")

    run_deliver_failure(
        ctx, result,
        family=TIME,
        name=name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        # day 计划 start_time > end_time → 设备拒绝(400)。
        bad_kwargs={
            "scheduletype": "day",
            "start_time": "18:00:00",
            "end_time": "08:00:00",
        },
    )
