"""P1-168978: 域名对象配置下发失败测试

xlsx(对象管理用例_重构_563.xlsx):
  /api/v1/domainpool 新建域名对象, 任意字段为无效值 → 400 含 errCode/errMsg;
  查询查不到; etcdctl 查不到。

设备实测(55.63, 2026-09-01): 非空但含空格的域名(客户端校验通过)被设备拒绝
  「域名不满足校验规则」。etcd/vppctl 因 SSH 22 不可达记录 ssh-unavailable-skip。
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import DATA_PLANE, DOMAINPOOL, run_deliver_failure
from framework.results import CaseResult

TITLE = "P1-168978 域名对象配置下发失败测试"


def run(ctx: CaseContext, result: CaseResult) -> None:
    etcd_key, vppctl_cmd = DATA_PLANE["domain"]
    name = unique_random(168978, "dom")

    run_deliver_failure(
        ctx, result,
        family=DOMAINPOOL,
        name=name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        # 非空但含空格 → 过客户端校验, 设备拒绝(「域名不满足校验规则」)。
        bad_kwargs={"domain": ["bad domain"], "desc": "atc deliver bad"},
    )
