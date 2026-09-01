"""P2-129006: 验证MAC地址对象操作日志正确性

xlsx(对象管理用例_重构_563.xlsx): 新建/修改/删除 MAC 地址对象 × 成功/失败 →
操作日志记录正确(kw=320, 操作日志)。

设备实测(55.63):
  成功的新增/修改/删除均记录一条带对象名的日志:
    「新增/修改/删除 MAC地址对象 <name> 成功」
  删除不存在对象记录:
    「删除 MAC地址对象 <gone> 失败」(delete_bad_logged=True)
  失败的新建/修改(mac 格式非法)在客户端/设备侧校验拒绝,设备不落日志 →
    bad_logged=False。
"""

from __future__ import annotations

from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import MACPOOL, run_oplog
from framework.results import CaseResult

from cases.mac_support import MAC_OK

TITLE = "P2-129006 验证MAC地址对象操作日志正确性"


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(129006, "mac")
    run_oplog(
        ctx, result,
        family=MACPOOL,
        name=name,
        config_kwargs={"desc": "atc oplog mac", "mac": [MAC_OK]},
        update_kwargs={"desc": "atc oplog mac upd", "mac": ["66:55:44:33:22:11"]},
        bad_kwargs={"mac": ["00:11:22:33:44"]},   # 非法 mac → 新增/修改均被拒
        bad_logged=False,          # 设备不为失败的新建/修改落日志
        delete_bad_logged=True,    # 删除不存在对象会记录「删除 ... <name> 失败」
    )
