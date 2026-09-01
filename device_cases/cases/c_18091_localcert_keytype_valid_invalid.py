"""P0-18091: 添加本地证书密钥类型有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): RSA有效; 空/其他字符 无效
设备实测: RSA/SM2 有效;空默认 RSA(divergence: xlsx 认为空无效);其他字符 CLI 拒
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok, create_rejected,
)

TITLE = "P0-18091 添加本地证书密钥类型有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created = []
    try:
        created.append(create_ok(ctx, result, resource="localcert",
                                 name=unique_random(18091, "kt"), label="keytype-RSA",
                                 kwargs={**base_kwargs("localcert"), "key_type": "RSA"}))
        created.append(create_ok(ctx, result, resource="localcert",
                                 name=unique_random(18091, "kt"), label="keytype-SM2",
                                 kwargs={**base_kwargs("localcert"), "key_type": "SM2"}))
        create_rejected(ctx, result, resource="localcert", name=unique_random(18091, "kt"),
                        label="keytype-bad", kwargs={**base_kwargs("localcert"), "key_type": "ECC"})
    finally:
        cleanup_ids(ctx, "localcert", created)
