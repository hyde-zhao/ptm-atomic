"""P0-18102: 添加本地CA证书国家/地区有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 存在的2字符国家代码有效; 空/1字符/3字符/超长 无效
设备实测: country 必须 2 字符 ISO 码;空→长度>=1,1/3字符→拒,超长→拒
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok, create_rejected,
)

TITLE = "P0-18102 添加本地CA证书国家/地区有效值和无效值测试"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    created = []
    try:
        created.append(create_ok(ctx, result, resource="localcacert",
                                 name=unique_random(18102, "ct"), label="country-CN",
                                 kwargs={**base_kwargs("localcacert"), "country": "CN"}))
        create_rejected(ctx, result, resource="localcacert", name=unique_random(18102, "ct"),
                        label="country-empty", kwargs={**base_kwargs("localcacert"), "country": ""})
        create_rejected(ctx, result, resource="localcacert", name=unique_random(18102, "ct"),
                        label="country-1char", kwargs={**base_kwargs("localcacert"), "country": "C"})
        create_rejected(ctx, result, resource="localcacert", name=unique_random(18102, "ct"),
                        label="country-3char", kwargs={**base_kwargs("localcacert"), "country": "CNX"})
        create_rejected(ctx, result, resource="localcacert", name=unique_random(18102, "ct"),
                        label="country-overlong", kwargs={**base_kwargs("localcacert"), "country": "A" * 200})
    finally:
        cleanup_ids(ctx, "localcacert", created)
