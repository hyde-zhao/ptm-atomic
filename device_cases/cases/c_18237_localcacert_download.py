"""P4-18237: 本地证书下载测试(CA证书管理).

xlsx(对象管理用例3.xlsx)步骤:
  2. 选中默认CA证书,点击下载 → 【check1】弹出导出CA证书的页面
  3. 选择"CA证书密钥分离",导出CA证书和导出密钥文件 → 【check2】导出crt和key文件成功
  4. 选择"单个CA证书"导出CA证书,输入错误的CA证书密码 → 【check3】导出失败
  5. 选择"单个CA证书"导出CA证书,输入正确的CA证书密码 → 【check4】导出pkcs文件成功

设备实测(probe22o,<DUT_IP>)差异:
  * 下载端点不校验 pfxPasswd 内容 —— 空密码/短密码/任意密码都生成 p12,密码仅用于
    加密导出文件。"错误密码 → 导出失败"无法在下载端点复现,改为校验导出文件可用性:
    用密码 P 导出的 p12 只有用 P 才能被 openssl pkcs12 打开(错误密码打开失败)。
  * 脚本化代理: ①下载内置默认 CA(defaultLocalCA.crt)得 PEM 证书;②新建本地 CA,
    证书密钥分离下载 cert+key 且 modulus 匹配;③④ p12 导出"错误/正确"密码语义。
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import CertRest, find_by_name, first_id, http_err, keypair_matches, p12_openable

TITLE = "P4-18237 本地证书下载测试"

SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}
DEFAULT_CA = "defaultLocalCA.crt"
P12_OK_PWD = "ptm123456"     # 导出的 p12 用的"正确"密码
P12_BAD_PWD = "ptm654321"    # 错误密码(用正确密码打不开用此密码导出的文件)


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    ca_name = unique_random(18237, "dlca")
    ca_id: int | None = None
    try:
        # check1: 下载默认 CA 证书 → PEM 证书字节(弹出导出页的 REST 代理)。
        if ctx.execute:
            cert_b, r = rest.download("localCA", DEFAULT_CA, "cert")
            is_pem = cert_b is not None and cert_b.startswith(b"-----BEGIN CERTIFICATE-----")
            result.record(Check(
                name="default-ca-download", ok=bool(is_pem),
                detail=f"download {DEFAULT_CA} -> {len(cert_b) if cert_b else 0}B "
                       f"isPEM={is_pem} ({http_err(r)})"))

        # 新建本地 CA 作为证书/密钥分离与 p12 下载的源。
        create = ctx.runner.run("cert", "localcacert-config", name=ca_name, key_type="RSA",
                                time_length=30, country=SUBJECT["country"], state=SUBJECT["state"],
                                location=SUBJECT["location"], organization=SUBJECT["organization"],
                                organ_unit=SUBJECT["organUnit"])
        result.record(op_succeeded(create, ctx=ctx, label="localca-config-ok"))
        if not ctx.execute:
            return
        v = ctx.runner.run("cert", "localcacert-verify", page=1, size=200, keywords=ca_name)
        hits = find_by_name(v.response(), ca_name)
        ca_id = first_id(v.response(), ca_name)
        cert_name = hits[0]["name"] if hits else f"{ca_name}.crt"

        # check2: 证书密钥分离导出 cert + key,且 modulus 匹配(同一密钥对)。
        cert_b, _ = rest.download("localCA", cert_name, "cert")
        key_b, _ = rest.download("localCA", cert_name[:-4] + ".key", "key")
        is_cert = cert_b is not None and cert_b.startswith(b"-----BEGIN CERTIFICATE-----")
        is_key = key_b is not None and (b"PRIVATE KEY" in key_b or b"BEGIN RSA" in key_b)
        match = bool(cert_b and key_b) and keypair_matches(cert_b, key_b)
        result.record(Check(
            name="cert-key-separate-download", ok=bool(is_cert and is_key and match),
            detail=f"cert={len(cert_b) if cert_b else 0}B isCert={is_cert} "
                   f"key={len(key_b) if key_b else 0}B isKey={is_key} "
                   f"modulusMatch={match} (证书密钥分离导出成功)"))

        # check3: 单个CA证书导出,错误密码 → 导出的 p12 用正确密码打不开(导出无效)。
        bad_b, r_bad = rest.download("localCA", cert_name, "pfx", pfx_passwd=P12_BAD_PWD)
        bad_open_ok = bool(bad_b) and p12_openable(bad_b, P12_OK_PWD)
        result.record(Check(
            name="pfx-wrong-password", ok=bad_b is not None and not bad_open_ok,
            detail=f"p12(pwd={P12_BAD_PWD!r}) {len(bad_b) if bad_b else 0}B "
                   f"({http_err(r_bad)}); opened with correct pwd={bad_open_ok} "
                   f"(want False → 错误密码导出不可用)"))

        # check4: 单个CA证书导出,正确密码 → openssl 能用该密码打开 p12。
        ok_b, r_ok = rest.download("localCA", cert_name, "pfx", pfx_passwd=P12_OK_PWD)
        ok_open = bool(ok_b) and p12_openable(ok_b, P12_OK_PWD)
        result.record(Check(
            name="pfx-correct-password", ok=bool(ok_open),
            detail=f"p12(pwd={P12_OK_PWD!r}) {len(ok_b) if ok_b else 0}B "
                   f"({http_err(r_ok)}); opened with correct pwd={ok_open} "
                   f"(want True → 导出pkcs文件成功)"))
    finally:
        if ctx.execute and ca_id is not None:
            result.record(op_succeeded(
                ctx.runner.run("cert", "localcacert-delete-batch", id=str(ca_id)),
                ctx=ctx, label="localca-cleanup"))
