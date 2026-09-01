"""P0-18108: 添加本地CA证书有效期有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 1-3650 有效; 空/0/3651/其他 无效
设备实测: timeLenth 1-3650 有效;3651+拒「签发有效期必须小于等于 3650」;0 拒(正整数);空默认 30(divergence)
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok, create_rejected,
)

TITLE = "P0-18108 添加本地CA证书有效期有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created = []
    try:
        for tl in (1, 3650, 30):
            created.append(create_ok(ctx, result, resource="localcacert",
                                     name=unique_random(18108, "tl"), label=f"validity-{tl}",
                                     kwargs={**base_kwargs("localcacert"), "time_length": tl}))
        create_rejected(ctx, result, resource="localcacert", name=unique_random(18108, "tl"),
                        label="validity-0", kwargs={**base_kwargs("localcacert"), "time_length": 0})
        create_rejected(ctx, result, resource="localcacert", name=unique_random(18108, "tl"),
                        label="validity-3651", kwargs={**base_kwargs("localcacert"), "time_length": 3651})
    finally:
        cleanup_ids(ctx, "localcacert", created)
