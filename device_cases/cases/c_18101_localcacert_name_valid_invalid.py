"""P0-18101: 添加本地CA证书名称有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 1-31字节 字母数字中文连接符点 有效; 空/特殊字符/32字节 无效
设备实测(divergence): name 只接受 [A-Za-z0-9-]; 中文/点被拒。容量 localcacert=9 含 2 内置
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok, create_rejected,
)

TITLE = "P0-18101 添加本地CA证书名称有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created = []
    try:
        created.append(create_ok(ctx, result, resource="localcacert",
                                 name=unique_random(18101, "nm"), label="name-valid"))
        exact31 = (unique_random(18101, "nm31")[:20].replace("-", "a") + "b" * 11)[:31]
        created.append(create_ok(ctx, result, resource="localcacert",
                                 name=exact31, label="name-31-exact"))
        create_rejected(ctx, result, resource="localcacert", name="",
                        label="name-empty", kwargs=base_kwargs("localcacert"))
        create_rejected(ctx, result, resource="localcacert", name=unique_random(18101, "sp") + "!",
                        label="name-special", kwargs=base_kwargs("localcacert"))
        create_rejected(ctx, result, resource="localcacert", name="Y" * 32,
                        label="name-32", kwargs=base_kwargs("localcacert"))
        create_rejected(ctx, result, resource="localcacert", name="证书中文",
                        label="name-cn", kwargs=base_kwargs("localcacert"))
    finally:
        cleanup_ids(ctx, "localcacert", created)
