"""反复操作本地证书对象对功能的影响

xlsx(对象管理用例_重构_563.xlsx) P4: 多次 create→verify→update→verify→delete→verify-gone
循环落实「反复操作」, 每轮断言配置成功、查询网元配置与下发配置一致(check1);
策略引用+流量 / 设备掉电或命令复位重启10次以上 属数据面/物理域 skip(check2/check3)。
"""

from __future__ import annotations

from functools import partial

from framework.context import CaseContext
from framework.results import CaseResult

from cases.repeat_support import cycle_localcert, run_repeat

TITLE = "P4-18218 反复操作本地证书对象对功能的影响"

def run(ctx: CaseContext, result: CaseResult) -> None:
    run_repeat(ctx, result, case_id=18218, cycles=3, cycle=cycle_localcert,
               policy_note='documented-skip: httpserver引用该本地证书对象并访问 属数据面域')
