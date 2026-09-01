"""P0-18106: 添加本地CA证书部门有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 0-127字节字符串有效(空有效); 128字节 无效
设备实测(divergence): organUnit 上限 31 字节(空/31 有效,32+ 拒)
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok, create_rejected,
)

TITLE = "P0-18106 添加本地CA证书部门有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created = []
    try:
        created.append(create_ok(ctx, result, resource="localcacert",
                                 name=unique_random(18106, "ou"), label="unit-31",
                                 kwargs={**base_kwargs("localcacert"), "organ_unit": "U" * 31}))
        created.append(create_ok(ctx, result, resource="localcacert",
                                 name=unique_random(18106, "ou"), label="unit-empty",
                                 kwargs={**base_kwargs("localcacert"), "organ_unit": ""}))
        create_rejected(ctx, result, resource="localcacert", name=unique_random(18106, "ou"),
                        label="unit-32", kwargs={**base_kwargs("localcacert"), "organ_unit": "U" * 32})
    finally:
        cleanup_ids(ctx, "localcacert", created)
