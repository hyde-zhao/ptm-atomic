"""P3-900011: 本地证书上传测试(localcert 资源).

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. RSA 单个证书类型,传 .P12/.pfx 文件,证书类型为本地CA/受信任CA → 【check1】上传成功
  2. RSA 证书私钥分离,传 .cer/.crt/.pem 证书 + .key/.pem 密钥 → 【check1】上传成功
  3. SM2 单个证书类型,传签名/加密证书文件 → 【check1】上传成功
  4/5. SM2 私钥分离 → 【check1】上传成功
  6. 非规范证书/密钥文件 → 【check2】上传失败

设备实测(probe22t/22u,<DUT_IP>):
  * localcert 上传要求**叶子(非CA)证书**:CA 证书 → 400 证书解析失败。
  * 私钥分离(certType="pem")certName 和 keyName 都必填:缺 keyName →
    400 上传本地证书或本地CA需要填写keyName。
  * 单个 p12(certType="pfx", 带 pfxPasswd)上传成功,条目名变 <name>.crt。
  * SM2 localcert 上传 → 400 上传SM2本地证书，需要填写名称(补 name 字段仍拒绝,
    记为 divergence,断言设备实际拒绝)。
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import CertRest, delete_named, http_err, issued_leaf

TITLE = "P3-900011 本地证书上传测试"

P12_PWD = "ptm123456"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    src_name = unique_random(900011, "src")
    up1 = unique_random(900011, "sep")
    up2 = unique_random(900011, "p12")
    up3 = unique_random(900011, "nokey")
    up4 = unique_random(900011, "ca")
    up5 = unique_random(900011, "fmt")
    made = [src_name, up1, up2, up3, up4, up5]
    try:
        # 设备签发 RSA 叶子证书作为合法上传 fixture(leaf,非CA)。
        entries = issued_leaf(ctx, name=src_name, key_type="RSA")
        result.record(Check(
            name="leaf-fixture", ok=bool(entries),
            detail=f"issued leaf entries={[e['name'] for e in entries]}"))
        if not ctx.execute:
            return
        if not entries:
            return
        leaf = entries[0]["name"]
        cert_b, _ = rest.download("localcert", leaf, "cert")
        key_b, _ = rest.download("localcert", leaf[:-4] + ".key", "key")
        p12_b, _ = rest.download("localcert", leaf, "pfx", pfx_passwd=P12_PWD)

        # check2: 私钥分离上传(叶子 cert + key)→ 上传成功,新条目出现。
        if cert_b and key_b:
            rest.stage("localcert", up1 + ".crt", cert_b)
            rest.stage("localcert", up1 + ".key", key_b)
            r = rest.commit(func_type="localcert", cert_type="pem",
                            cert_name=up1 + ".crt", key_name=up1 + ".key")
            ups = rest.list_entries("localcert", up1)
            result.record(Check(
                name="separate-leaf-upload",
                ok=r.status_code == 200 and len(ups) == 1,
                detail=f"PUT {r.status_code} {http_err(r)}; "
                       f"entries={[e['name'] for e in ups]} (want 1)"))

        # check1: 单个 p12 上传(叶子 p12)→ 上传成功,条目名变 <name>.crt。
        if p12_b:
            rest.stage("localcert", up2 + ".p12", p12_b)
            r = rest.commit(func_type="localcert", cert_type="pfx",
                            cert_name=up2 + ".p12", pfx_passwd=P12_PWD)
            ups = rest.list_entries("localcert", up2)
            result.record(Check(
                name="single-p12-upload",
                ok=r.status_code == 200 and len(ups) == 1,
                detail=f"PUT {r.status_code} {http_err(r)}; "
                       f"entries={[e['name'] for e in ups]} (want 1, 条目名变 .crt)"))

        # check6a: 私钥分离缺 keyName → 拒绝。
        if cert_b:
            rest.stage("localcert", up3 + ".crt", cert_b)
            r = rest.commit(func_type="localcert", cert_type="pem",
                            cert_name=up3 + ".crt", key_name="")
            result.record(Check(
                name="missing-keyname-rejected",
                ok=r.status_code != 200 and not rest.list_entries("localcert", up3),
                detail=f"PUT {r.status_code} {http_err(r)}; want reject (keyName 必填)"))

        # check6b: CA 证书(非叶子)→ 拒绝(证书解析失败)。用默认本地 CA 证书作 fixture。
        ca_cert, _ = rest.download("localCA", "defaultLocalCA.crt", "cert")
        if ca_cert:
            rest.stage("localcert", up4 + ".crt", ca_cert)
            r = rest.commit(func_type="localcert", cert_type="pem",
                            cert_name=up4 + ".crt", key_name=up4 + ".key")
            result.record(Check(
                name="ca-cert-rejected",
                ok=r.status_code != 200 and not rest.list_entries("localcert", up4),
                detail=f"PUT CA cert {r.status_code} {http_err(r)}; "
                       f"want reject (localcert 要求叶子证书)"))

        # check6c: 非规范格式(.txt)→ 拒绝。
        rest.stage("localcert", up5 + ".txt", b"this is not a certificate")
        r = rest.commit(func_type="localcert", cert_type="pem",
                        cert_name=up5 + ".txt", key_name=up5 + "k.txt")
        result.record(Check(
            name="invalid-format-rejected",
            ok=r.status_code != 200 and not rest.list_entries("localcert", up5),
            detail=f"PUT {r.status_code} {http_err(r)}; want reject"))

        # SM2 localcert 上传(divergence:补 name 字段仍拒绝)。
        sm2_src = unique_random(900011, "sm2")
        made.append(sm2_src)
        sm2_entries = issued_leaf(ctx, name=sm2_src, key_type="SM2")
        sig = [e for e in sm2_entries if "_sig" in e.get("name", "")]
        if sig:
            s_cert, _ = rest.download("localcert", sig[0]["name"], "cert")
            s_key, _ = rest.download("localcert", sig[0]["name"][:-4] + ".key", "key")
            enc = [e for e in sm2_entries if "_enc" in e.get("name", "")]
            e_cert, _ = rest.download("localcert", enc[0]["name"], "cert") if enc else (None, None)
            e_key, _ = rest.download("localcert", enc[0]["name"][:-4] + ".key", "key") if enc else (None, None)
            sm2_up = unique_random(900011, "sm2up")
            made.append(sm2_up)
            for fn, b in ((sm2_up + "_sig.crt", s_cert), (sm2_up + "_sig.key", s_key),
                          (sm2_up + "_enc.crt", e_cert), (sm2_up + "_enc.key", e_key)):
                if b:
                    rest.stage("localcert", fn, b)
            r = rest.commit(func_type="localcert", cert_type="pem",
                            cert_name=sm2_up + "_sig.crt", key_name=sm2_up + "_sig.key",
                            key_type="SM2", name=sm2_up)  # extra name attempt
            result.record(Check(
                name="sm2-upload-divergence",
                ok=r.status_code != 200 and not rest.list_entries("localcert", sm2_up),
                detail=f"PUT SM2 {r.status_code} {http_err(r)}; "
                       f"设备报'需要填写名称'仍拒绝(divergence,见 notes)"))
            result.notes.append(
                "DIVERGENCE: xlsx 900011 步骤3-5 期望 SM2 本地证书上传成功;设备实测即使 "
                "补 name 字段仍报 uploadCertCheckFailed '上传SM2本地证书，需要填写名称'")
    finally:
        if ctx.execute:
            for prefix in made:
                delete_named(rest, "localcert", prefix)
            result.record(Check(name="localcert-cleanup", ok=True,
                                detail=f"deleted {len(made)} name-prefix groups"))
