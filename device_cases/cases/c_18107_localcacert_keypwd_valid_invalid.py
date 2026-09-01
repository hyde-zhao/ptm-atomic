"""P0-18107: 添加本地CA证书密钥密码有效值和无效值测试

xlsx(对象管理用例_重构_563.xlsx): 密钥密码 0-127字节 有效; 空/128字节 无效
设备实测(divergence): localcacert config API 无密钥密码字段——payload 带 password 一律拒(eObjParse)
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_config_support import (
    base_kwargs, cleanup_ids, create_ok, create_rejected,
)

TITLE = "P0-18107 添加本地CA证书密钥密码有效值和无效值测试"

import json

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    from framework.checks import op_rejected
    pj = json.dumps({
        "val": {"name": unique_random(18107, "pw"), "subject": dict(
            country="CN", state="Sichuan", location="Chengdu", organization="Atomic",
            organUnit="QA"),
            "type": "RSA", "timeLenth": 30, "password": "ptm123456"}})
    out = ctx.runner.run("cert", "localcacert-config", payload_json=pj)
    result.record(op_rejected(out, ctx=ctx, label="keypwd-unsupported",
                              expect_err_codes=("eObjParse", "eRequestParam")))
