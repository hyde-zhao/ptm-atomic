"""P1-168962: 域名对象配置下发成功测试

xlsx(对象管理用例_重构_563.xlsx):
  /api/v1/domainpool 新建/编辑/查询域名对象 → 下发成功, 字段与下发一致;
  后台 etcdctl 查询返回 value 一致。

设备实测(55.63, 2026-09-01): domainpool POST/PUT/DELETE 均可用, 成员字段
  domainaddrs:[{domain}]。etcd 检查因 SSH 22 不可达记录 ssh-unavailable-skip;
  域名对象无 vppctl 视图。
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import DATA_PLANE, DOMAINPOOL, run_deliver_success
from framework.results import CaseResult

TITLE = "P1-168962 域名对象配置下发成功测试"


def run(ctx: CaseContext, result: CaseResult) -> None:
    etcd_key, vppctl_cmd = DATA_PLANE["domain"]
    name = unique_random(168962, "dom")
    run_deliver_success(
        ctx, result,
        family=DOMAINPOOL,
        name=name,
        etcd_key=etcd_key,
        vppctl_cmd=vppctl_cmd,
        create_kwargs={"domain": ["probe.example.com"], "desc": "atc deliver ok"},
        update_kwargs={"domain": ["probe2.example.com", "probe3.example.com"], "desc": "atc deliver upd"},
    )
