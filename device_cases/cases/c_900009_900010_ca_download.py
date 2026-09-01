"""P3-900009/900010: 本地证书/本地CA证书下载测试(下载矩阵).

xlsx(对象管理用例_重构_563.xlsx)两条用例步骤相同,合并为一个下载矩阵:
  2. 选中默认 RSA 的 CA 证书,点击下载 → 【check1】弹出导出页面
  3. "CA证书密钥分离"导出 CA 证书和密钥文件 → 【check2】导出 crt 和 key 成功
  4. "单个CA证书"导出,输入错误 CA 密码 → 【check3】导出失败
  5. "单个CA证书"导出,输入正确 CA 密码 → 【check4】导出 pkcs 文件成功
  6. SM2 默认 CA 签名/加密证书下载 → 【check1】
  7. 新建 RSA/SM2 的 CA 证书,下载 → 【check1-4】
  8. .cer 第三方生成证书,下载 → 【check1-4】(受信任 CA,见 900022)

设备实测(probe22q/22t): 下载端点不校验 pfxPasswd 内容,密码仅加密导出文件;故"错误
密码→导出失败"改为 openssl pkcs12 打开性校验(18237 同款)。SM2 默认/新建 CA 在
localcacert 均为单个 <name>.crt 条目(不像 localcert 拆 _sig/_enc)。
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import (CertRest, find_by_name, first_id, http_err,
                                keypair_matches, p12_openable, subject_kwargs)

TITLE = "P3-900009/900010 本地证书/本地CA证书下载测试"

DEFAULT_RSA_CA = "defaultLocalCA.crt"
DEFAULT_SM2_CA = "defaultGmLocalCA.crt"
P12_OK_PWD = "ptm123456"
P12_BAD_PWD = "ptm654321"


def _pem(b: bytes | None) -> bool:
    return b is not None and b.startswith(b"-----BEGIN CERTIFICATE-----")


def _check_ca_download(rest: CertRest, result: CaseResult, *, entry_name: str, label: str) -> None:
    """证书密钥分离下载 + p12 错误/正确密码语义(对应 xlsx 步骤 3-5)."""
    cert_b, _ = rest.download("localCA", entry_name, "cert")
    key_b, _ = rest.download("localCA", entry_name[:-4] + ".key", "key")
    is_cert = _pem(cert_b)
    is_key = key_b is not None and (b"PRIVATE KEY" in key_b or b"BEGIN RSA" in key_b)
    match = bool(cert_b and key_b) and keypair_matches(cert_b, key_b)
    result.record(Check(
        name=f"{label}-cert-key-separate",
        ok=is_cert and is_key and match,
        detail=f"cert={len(cert_b) if cert_b else 0}B isCert={is_cert} "
               f"key={len(key_b) if key_b else 0}B isKey={is_key} modulusMatch={match}"))

    bad_b, r_bad = rest.download("localCA", entry_name, "pfx", pfx_passwd=P12_BAD_PWD)
    bad_open_ok = bool(bad_b) and p12_openable(bad_b, P12_OK_PWD)
    result.record(Check(
        name=f"{label}-pfx-wrong-password",
        ok=bad_b is not None and not bad_open_ok,
        detail=f"p12(pwd={P12_BAD_PWD!r}) {len(bad_b) if bad_b else 0}B "
               f"({http_err(r_bad)}); opened with correct pwd={bad_open_ok}"))

    ok_b, r_ok = rest.download("localCA", entry_name, "pfx", pfx_passwd=P12_OK_PWD)
    ok_open = bool(ok_b) and p12_openable(ok_b, P12_OK_PWD)
    result.record(Check(
        name=f"{label}-pfx-correct-password",
        ok=ok_open,
        detail=f"p12(pwd={P12_OK_PWD!r}) {len(ok_b) if ok_b else 0}B "
               f"({http_err(r_ok)}); opened={ok_open}"))


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    rsa_name = unique_random(900009, "dlca")
    sm2_name = unique_random(900010, "dlca")
    made: list[str] = []
    try:
        # check1: 默认 RSA/SM2 CA 下载 → PEM 证书(弹出导出页的 REST 代理)。
        if ctx.execute:
            for ca, tag in ((DEFAULT_RSA_CA, "default-rsa"), (DEFAULT_SM2_CA, "default-sm2")):
                cert_b, r = rest.download("localCA", ca, "cert")
                result.record(Check(
                    name=f"{tag}-ca-download", ok=_pem(cert_b),
                    detail=f"download {ca} -> {len(cert_b) if cert_b else 0}B "
                           f"isPEM={_pem(cert_b)} ({http_err(r)})"))

        # 新建 RSA + SM2 本地 CA 作为下载源。
        for kt, nm in (("RSA", rsa_name), ("SM2", sm2_name)):
            create = ctx.runner.run("cert", "localcacert-config", name=nm, key_type=kt,
                                    time_length=30, **subject_kwargs())
            result.record(op_succeeded(create, ctx=ctx, label=f"{kt.lower()}-ca-config-ok"))
            made.append(nm)
        if not ctx.execute:
            return

        for kt, nm in (("RSA", rsa_name), ("SM2", sm2_name)):
            v = ctx.runner.run("cert", "localcacert-verify", page=1, size=200, keywords=nm)
            hits = find_by_name(v.response(), nm)
            entry = hits[0]["name"] if hits else f"{nm}.crt"
            _check_ca_download(rest, result, entry_name=entry, label=f"{kt.lower()}-created-ca")
    finally:
        if ctx.execute:
            for nm in made:
                v = ctx.runner.run("cert", "localcacert-verify", page=1, size=200, keywords=nm)
                cid = first_id(v.response(), nm)
                if cid is not None:
                    result.record(op_succeeded(
                        ctx.runner.run("cert", "localcacert-delete-batch", id=str(cid)),
                        ctx=ctx, label=f"cleanup-{nm}"))
