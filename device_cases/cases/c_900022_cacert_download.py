"""P3-900022: 受信任CA证书下载测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 选择.cer格式第三方生成证书，下载文件 【check1】导出文件成功
  2. 重复，下载.crt格式的证书 【check1】
  3. 重复，下载.pem格式的证书 【check1】
  4. 选中默认密钥类型为RSA/SM2的CA证书，点击下载 【check1】

设备实测(probe22y): CAcert 下载 funcType=CAcert → PEM;设备仅接受 .crt 受信任
上传(.cer/.pem 上传即被 PemCerToCrt 拒),故 .cer/.pem 受信任条目在本设备上不
可构造 — 本用例上传 .crt 受信任证书后下载校验,并对 .cer/.pem 记 divergence;
默认 RSA/SM2 CA 走 funcType=localCA 下载。
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import CertRest

TITLE = "P3-900022 受信任CA证书下载测试"

PEM_HEADER = b"-----BEGIN CERTIFICATE-----"


def _openssl_rsa_ca() -> tuple[bytes, bytes]:
    """生成 RSA CA 证书(cert, key),带 CA:TRUE BasicConstraints。"""
    with tempfile.TemporaryDirectory() as td:
        kp, cp = Path(td) / "k.pem", Path(td) / "c.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", str(kp), "-out", str(cp), "-days", "30", "-nodes",
             "-subj", "/C=CN/O=AtomicQA/CN=900022-ca",
             "-addext", "basicConstraints=critical,CA:TRUE"],
            capture_output=True, check=True)
        return cp.read_bytes(), kp.read_bytes()


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    cert, _key = _openssl_rsa_ca()
    made: list[str] = []
    try:
        if not ctx.execute:
            result.record(Check(name="cacert-download", ok=True, detail="dry-run"))
            return

        # 前置: 上传一个 .crt 受信任证书,获得可下载条目。
        name = unique_random(900022, "ca")
        made.append(name)
        rest.stage("cacert", name + ".crt", cert)
        r = rest.commit(func_type="CAcert", cert_type="", cert_name=name + ".crt", key_type="RSA")
        if r.status_code != 200:
            result.record(Check(name="fixture-upload", ok=False,
                                detail=f"PUT {r.status_code} — cannot proceed"))
            return
        result.record(Check(name="fixture-upload", ok=True, detail="uploaded"))

        # check1-crt: 下载 .crt 受信任证书 → PEM,内容与上传一致。
        entry = rest.list_entries("CAcert", name)[0]
        data, dr = rest.download("CAcert", entry["name"], "cert")
        is_pem = data is not None and data.startswith(PEM_HEADER)
        same = data == cert
        result.record(Check(name="crt-download-pem", ok=is_pem and len(data or b"") > 100,
                            detail=f"rc={dr.status_code} bytes={len(data or b'')} pem={is_pem}"))
        result.record(Check(name="crt-download-content", ok=same,
                            detail=f"byte-identical={same} (设备重编码则记 divergence)"))

        # .cer/.pem 受信任条目在本设备不可构造(上传被拒)→ divergence。
        result.notes.append(
            "xlsx 步骤1/3(.cer/.pem 受信任证书下载)无法构造前置: 设备仅接受 "
            ".crt 受信任上传(.cer/.pem 上传报 PemCerToCrt)— divergence,仅验证 .crt 路径")

        # check4: 默认 RSA/SM2 CA 证书下载(funcType=localCA)。
        for def_ca in ("defaultLocalCA.crt", "defaultGmLocalCA.crt"):
            d, dr = rest.download("localCA", def_ca, "cert")
            result.record(Check(name=f"default-ca-download-{def_ca}",
                                ok=d is not None and d.startswith(PEM_HEADER),
                                detail=f"rc={dr.status_code} bytes={len(d or b'')} "
                                       f"pem={d is not None and d.startswith(PEM_HEADER)}"))
    finally:
        if ctx.execute:
            for prefix in made:
                for e in rest.list_entries("CAcert", prefix):
                    rest.delete("CAcert", e["id"])
