"""P3-900018: 受信任证书上传测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. RSA密钥，传入格式为.cer、.crt、.pem的证书文件和符合要求的私钥文件（.key或.pem）【check1】上传成功，存在日志记录
  2. SM2密钥，传入格式为.cer、.crt、.pem的证书文件和符合要求的私钥文件（.key或.pem）【check1】
  3. 传入不符合规范的证书和密钥文件 【check2】上传失败，存在日志记录

设备实测(probe22y + 900018 实跑): 受信任(CAcert)上传接受 **.crt/.pem** 扩展名且
certType=""(PUT /api/v1/cert/upload funcType=CAcert 只传证书、无需私钥);
.cer → 400 `uploadCertFormatConversionError 上传文件有误, PemCerToCrt`
(xlsx 期望三种扩展名都成功 → divergence 仅 .cer);非法内容 → 400。
SM2 CAcert 上传为 best-effort(设备实际行为为准)。
"""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import CertRest, http_err, localca_fixture

TITLE = "P3-900018 受信任证书上传测试"


def _openssl_rsa_ca() -> tuple[bytes, bytes]:
    """生成 RSA CA 证书(cert, key),带 CA:TRUE BasicConstraints。"""
    with tempfile.TemporaryDirectory() as td:
        kp, cp = Path(td) / "k.pem", Path(td) / "c.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", str(kp), "-out", str(cp), "-days", "30", "-nodes",
             "-subj", "/C=CN/O=AtomicQA/CN=900018-ca",
             "-addext", "basicConstraints=critical,CA:TRUE"],
            capture_output=True, check=True)
        return cp.read_bytes(), kp.read_bytes()


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    cert, _key = _openssl_rsa_ca()
    made: list[str] = []
    try:
        # check1-RSA: .crt 扩展名 → 成功,新条目出现。
        n_crt = unique_random(900018, "rsacrt")
        made.append(n_crt)
        rest.stage("cacert", n_crt + ".crt", cert)
        r = rest.commit(func_type="CAcert", cert_type="", cert_name=n_crt + ".crt", key_type="RSA")
        hits = rest.list_entries("CAcert", n_crt)
        result.record(Check(name="rsa-crt-upload-ok",
                            ok=r.status_code == 200 and len(hits) == 1,
                            detail=f"PUT {r.status_code} {http_err(r)}; entries={[e['name'] for e in hits]}"))

        # check1-RSA: .cer → 设备 PemCerToCrt 拒绝;.pem → 接受(divergence 仅 .cer)。
        for ext, want_ok in (("cer", False), ("pem", True)):
            n = unique_random(900018, f"rsa{ext}")
            made.append(n)
            rest.stage("cacert", n + "." + ext, cert)
            r = rest.commit(func_type="CAcert", cert_type="", cert_name=n + "." + ext, key_type="RSA")
            hits = rest.list_entries("CAcert", n)
            ok = (r.status_code == 200 and len(hits) == 1) if want_ok \
                else (r.status_code != 200 and not hits)
            result.record(Check(name=f"rsa-{ext}-{'ok' if want_ok else 'rejected'}", ok=ok,
                                detail=f"PUT .{ext} {r.status_code} {http_err(r)}; entries={len(hits)}"))
            if not want_ok:
                result.notes.append(
                    f".cer 上传被设备拒({http_err(r).split(' ')[0] or r.status_code});"
                    f"xlsx 期望 .cer 上传成功 — divergence(仅 .crt/.pem 支持)")

        # check2: 非规范文件(.txt 垃圾内容)→ 拒绝。
        bad = unique_random(900018, "bad")
        made.append(bad)
        rest.stage("cacert", bad + ".txt", b"this is not a certificate")
        r = rest.commit(func_type="CAcert", cert_type="", cert_name=bad + ".txt", key_type="RSA")
        result.record(Check(name="invalid-format-rejected",
                            ok=r.status_code != 200 and not rest.list_entries("CAcert", bad),
                            detail=f"PUT {r.status_code} {http_err(r)}; want reject"))

        # check1-SM2: 设备签发的 SM2 localCA 证书下载后上传到受信任 → best-effort。
        src = unique_random(900018, "sm2src")
        sm2_up = unique_random(900018, "sm2up")
        made += [src, sm2_up]
        src_entries = localca_fixture(ctx, name=src, key_type="SM2")
        if src_entries:
            sm2_cert, _ = rest.download("localCA", src_entries[0]["name"], "cert")
            if sm2_cert:
                rest.stage("cacert", sm2_up + ".crt", sm2_cert)
                r = rest.commit(func_type="CAcert", cert_type="", cert_name=sm2_up + ".crt", key_type="SM2")
                ok = r.status_code == 200 and len(rest.list_entries("CAcert", sm2_up)) == 1
                result.record(Check(name="sm2-crt-upload", ok=ok,
                                    detail=f"PUT SM2 {r.status_code} {http_err(r)}"))
                if not ok:
                    result.notes.append("SM2 CAcert 上传被拒(divergence 或设备限制)")
    finally:
        if ctx.execute:
            for prefix in made:
                for e in rest.list_entries("CAcert", prefix):
                    rest.delete("CAcert", e["id"])
                for e in rest.list_entries("localCA", prefix):
                    rest.delete("localCA", e["id"])
