"""P0-18092: 添加本地证书密钥长度有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 512/1024/2048/3072/4096 有效; 空/其他数字/字符串 无效
设备实测: 512-4096 四档有效;256/8192/非数字拒「密钥长度无效」;空默认 2048(divergence: xlsx 认为空无效)
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok, create_rejected,
)

TITLE = "P0-18092 添加本地证书密钥长度有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created = []
    try:
        for kl in (512, 1024, 2048, 3072, 4096):
            created.append(create_ok(ctx, result, resource="localcert",
                                     name=unique_random(18092, "kl"), label=f"keylen-{kl}",
                                     kwargs={**base_kwargs("localcert"), "key_length": kl}))
        create_rejected(ctx, result, resource="localcert", name=unique_random(18092, "kl"),
                        label="keylen-256", kwargs={**base_kwargs("localcert"), "key_length": 256})
        create_rejected(ctx, result, resource="localcert", name=unique_random(18092, "kl"),
                        label="keylen-8192", kwargs={**base_kwargs("localcert"), "key_length": 8192})
    finally:
        cleanup_ids(ctx, "localcert", created)
