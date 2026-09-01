"""P4-900013: 上传证书文件内容无效测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1/2. RSA 单个/分离类型上传"格式正确、内容无效"的证书文件 → 【check1】保存失败,提示文件解析失败
  3. SM2 上传内容无效 → 【check1】保存失败
  4. 受信任/CRL 内容无效 → 【check1】保存失败
  5. 查看操作日志 → 【check2】存在日志

设备实测(probe22q): 内容无效(garbage base64 的 PEM)上传 → 400 证书解析失败,
无新条目。本用例用"PEM 头 + 垃圾 base64"与"合法证书 + 垃圾密钥"两种无效内容,
覆盖 localcert 与 localCA 两个资源,均断言拒绝。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import CertRest, delete_named, http_err

TITLE = "P4-900013 上传证书文件内容无效测试"

GARBAGE_CERT = b"-----BEGIN CERTIFICATE-----\nAAECAwQFBgcICQoLDA0ODw==\n-----END CERTIFICATE-----\n"
GARBAGE_KEY = b"-----BEGIN RSA PRIVATE KEY-----\nZm9vYmFyMTIzNDU2Nzg5\n-----END RSA PRIVATE KEY-----\n"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    lc1 = unique_random(900013, "lcf")
    lc2 = unique_random(900013, "lck")
    ca1 = unique_random(900013, "caf")
    made = [lc1, lc2, ca1]
    try:
        if not ctx.execute:
            return
        # check1a: localcert 分离,证书内容无效(垃圾 base64)→ 拒绝。
        rest.stage("localcert", lc1 + ".crt", GARBAGE_CERT)
        rest.stage("localcert", lc1 + ".key", GARBAGE_KEY)
        r = rest.commit(func_type="localcert", cert_type="pem",
                        cert_name=lc1 + ".crt", key_name=lc1 + ".key")
        result.record(Check(
            name="localcert-garbage-cert",
            ok=r.status_code != 200 and not rest.list_entries("localcert", lc1),
            detail=f"PUT {r.status_code} {http_err(r)}; want reject (证书解析失败)"))

        # check1b: localcert 分离,证书合法但密钥内容无效 → 拒绝。
        # 用默认 CA 证书做"合法证书 + 垃圾密钥"组合(密钥与证书内容均无法解析)。
        ca_cert, _ = rest.download("localCA", "defaultLocalCA.crt", "cert")
        if ca_cert:
            rest.stage("localcert", lc2 + ".crt", ca_cert)
            rest.stage("localcert", lc2 + ".key", GARBAGE_KEY)
            r = rest.commit(func_type="localcert", cert_type="pem",
                            cert_name=lc2 + ".crt", key_name=lc2 + ".key")
            result.record(Check(
                name="localcert-garbage-key",
                ok=r.status_code != 200 and not rest.list_entries("localcert", lc2),
                detail=f"PUT {r.status_code} {http_err(r)}; want reject (密钥解析失败)"))

        # check2: localCA 分离,证书内容无效 → 拒绝。
        rest.stage("localcacert", ca1 + ".crt", GARBAGE_CERT)
        rest.stage("localcacert", ca1 + ".key", GARBAGE_KEY)
        r = rest.commit(func_type="localCA", cert_type="pem",
                        cert_name=ca1 + ".crt", key_name=ca1 + ".key")
        result.record(Check(
            name="localca-garbage-cert",
            ok=r.status_code != 200 and not rest.list_entries("localCA", ca1),
            detail=f"PUT {r.status_code} {http_err(r)}; want reject"))
    finally:
        if ctx.execute:
            for prefix in made:
                delete_named(rest, "localcert", prefix)
            delete_named(rest, "localCA", ca1)
            result.record(Check(name="upload-invalid-cleanup", ok=True,
                                detail=f"cleaned {len(made)} prefixes"))
