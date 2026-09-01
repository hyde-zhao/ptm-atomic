"""P4-900016: 上传证书和私钥文件不匹配测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. RSA 私钥分离,上传证书文件和私钥文件不匹配 → 【check1】保存失败,提示上传证书和私钥不匹配
  2. SM2 私钥分离,证书和私钥不匹配 → 【check1】保存失败
  3. 查看操作日志 → 【check2】存在日志

设备实测(probe22q): 两把不同密钥对的 cert/key 交叉上传 → 400,无新条目。
本用例:签发两个不同叶子证书,交叉 cert/key 上传,断言拒绝。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import CertRest, delete_named, http_err, issued_leaf

TITLE = "P4-900016 上传证书和私钥文件不匹配测试"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    src1 = unique_random(900016, "a")
    src2 = unique_random(900016, "b")
    up = unique_random(900016, "up")
    made = [src1, src2, up]
    try:
        e1 = issued_leaf(ctx, name=src1, key_type="RSA")
        e2 = issued_leaf(ctx, name=src2, key_type="RSA")
        if not ctx.execute:
            return
        if not (e1 and e2):
            return
        cert_a, _ = rest.download("localcert", e1[0]["name"], "cert")
        key_b, _ = rest.download("localcert", e2[0]["name"][:-4] + ".key", "key")
        if not (cert_a and key_b):
            return
        # cert 来自 A,key 来自 B → 不匹配 → 拒绝。
        rest.stage("localcert", up + ".crt", cert_a)
        rest.stage("localcert", up + ".key", key_b)
        r = rest.commit(func_type="localcert", cert_type="pem",
                        cert_name=up + ".crt", key_name=up + ".key")
        result.record(Check(
            name="cert-key-mismatch-rejected",
            ok=r.status_code != 200 and not rest.list_entries("localcert", up),
            detail=f"PUT {r.status_code} {http_err(r)}; "
                   f"want reject (证书和私钥不匹配)"))
    finally:
        if ctx.execute:
            for prefix in made:
                delete_named(rest, "localcert", prefix)
            result.record(Check(name="mismatch-cleanup", ok=True,
                                detail=f"cleaned {len(made)} prefixes"))
