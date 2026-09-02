"""P2-18148: ipv4地址引用与解引用.

xlsx: 新增地址对象【check1】→ 策略勾选引用【check2】→ 尝试删除被引用地址【check3】失败 →
解除策略占用后再删【check4】成功。

设备实测(55.63, probe31): ipv4 地址被**地址组**引用时删除被拒 400「{name}被引用无法被删除」;
解引用(把组成员更新为另一对象,组不允许空成员列表)后再删成功。策略引用为数据面载体 →
本用例以地址组落实同等的删锁语义(镜像 c_256060 服务口径)。
"""
from __future__ import annotations

from framework.context import CaseContext
from framework.results import CaseResult

from cases.refcnt_support import addr_unref

TITLE = "P2-18148 ipv4地址引用与解引用"


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        from framework.checks import Check
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    addr_unref(ctx, result, case_id=18148, v6=False)
