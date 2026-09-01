"""P0-18087: 添加本地证书省/州有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 0-127字节字符串有效(空有效); 128字节 无效
设备实测(divergence): state 上限 31 字节(空/31 有效,32+ 拒「长度必须小于等于 31」)。xlsx 的 0-127 按设备 0-31 断言
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok, create_rejected,
)

TITLE = "P0-18087 添加本地证书省/州有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created = []
    try:
        created.append(create_ok(ctx, result, resource="localcert",
                                 name=unique_random(18087, "st"), label="state-31",
                                 kwargs={**base_kwargs("localcert"), "state": "S" * 31}))
        created.append(create_ok(ctx, result, resource="localcert",
                                 name=unique_random(18087, "st"), label="state-empty",
                                 kwargs={**base_kwargs("localcert"), "state": ""}))
        create_rejected(ctx, result, resource="localcert", name=unique_random(18087, "st"),
                        label="state-32", kwargs={**base_kwargs("localcert"), "state": "S" * 32})
    finally:
        cleanup_ids(ctx, "localcert", created)
