"""P2-129005: 验证域名对象操作日志正确性

xlsx(对象管理用例_重构_563.xlsx):
  新建/修改/删除域名对象 成功与失败, 各查看操作日志【check1】→ 日志产生成功, 记录正确。

设备实测(55.63, 2026-09-01):
  * 成功操作均记录: 「新增/修改/删除 域名地址对象 <name> 成功」。
  * 删除不存在的对象记录失败: 「删除 域名地址对象 <name-gone> 失败」。
  * 失败的「新增/修改」(域名校验失败) 设备不写操作日志 → bad_logged=False
    (记录拒绝结果但不断言失败日志)。
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import DOMAINPOOL, run_oplog
from framework.results import CaseResult

TITLE = "P2-129005 验证域名对象操作日志正确性"


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(129005, "dom")
    run_oplog(
        ctx, result,
        family=DOMAINPOOL,
        name=name,
        config_kwargs={"domain": ["probe.example.com"], "desc": "atc oplog domain"},
        update_kwargs={"domain": ["probe2.example.com"], "desc": "atc oplog domain upd"},
        # 非空但含空格 → 通过客户端校验, 被设备拒绝(「域名不满足校验规则」)。
        bad_kwargs={"domain": ["bad domain"], "desc": "atc oplog domain bad"},
        bad_logged=False,
        delete_bad_logged=True,
    )
