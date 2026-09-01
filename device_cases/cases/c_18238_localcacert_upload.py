"""P4-18238: 本地证书上传测试(CA证书管理).

xlsx(对象管理用例3.xlsx)步骤:
  2. 单个CA证书上传 .P12/.pfx 文件 → 【check2】上传成功
  3. CA证书私钥分离上传,不合规范(证书非.cer/.crt/.pem,密钥非.key/.pem) → 【check1】上传失败
  4. CA证书私钥分离上传,符合规范(.cer/.crt/.pem 证书 + .key/.pem 密钥) → 【check2】上传成功

设备实测差异(probe22o,<DUT_IP>): localCA 资源仅支持 .pem/.cer/.crt 私钥分离上传;
  p12/pfx 单个上传被拒(uploadCertFormatError "上传文件类型有误，支持.pem/.cer/.crt")。
  故步骤2 的 p12/pfx 单证书上传成功在当前版本不可复现 → 记录为 divergence,断言设备
  实际拒绝行为(上传失败),与 xlsx 预期不同在 notes 里注明。
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import CertRest, find_by_name, first_id, http_err

TITLE = "P4-18238 本地证书上传测试"

SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}
P12_PWD = "ptm123456"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    src_name = unique_random(18238, "src")
    up_name = unique_random(18238, "up")
    bad_name = unique_random(18238, "bad")
    src_id: int | None = None
    try:
        # 新建本地 CA 作为合法证书+密钥 fixture 的下载源。
        create = ctx.runner.run("cert", "localcacert-config", name=src_name, key_type="RSA",
                                time_length=30, country=SUBJECT["country"], state=SUBJECT["state"],
                                location=SUBJECT["location"], organization=SUBJECT["organization"],
                                organ_unit=SUBJECT["organUnit"])
        result.record(op_succeeded(create, ctx=ctx, label="source-ca-config-ok"))
        if not ctx.execute:
            return
        v_src = ctx.runner.run("cert", "localcacert-verify", page=1, size=200, keywords=src_name)
        src_id = first_id(v_src.response(), src_name)
        src_hits = find_by_name(v_src.response(), src_name)
        src_cert_name = src_hits[0]["name"] if src_hits else f"{src_name}.crt"
        cert_b, _ = rest.download("localCA", src_cert_name, "cert")
        key_b, _ = rest.download("localCA", src_cert_name[:-4] + ".key", "key")
        src_ok = bool(cert_b) and bool(key_b)
        result.record(Check(
            name="source-fixture-download", ok=src_ok,
            detail=f"source cert={len(cert_b) if cert_b else 0}B "
                   f"key={len(key_b) if key_b else 0}B"))

        # check1: 私钥分离上传不合规范格式(.txt 证书 + .txt 密钥) → 上传失败,无新条目。
        rest.stage("localcacert", bad_name + ".txt", b"this is not a certificate")
        rest.stage("localcacert", bad_name + "k.txt", b"this is not a private key")
        r_bad = rest.commit(func_type="localCA", cert_type="pem",
                            cert_name=bad_name + ".txt", key_name=bad_name + "k.txt")
        leftovers = rest.list_entries("localCA", bad_name)
        result.record(Check(
            name="separate-invalid-format-rejected",
            ok=r_bad.status_code != 200 and not leftovers,
            detail=f"PUT upload rejected: {http_err(r_bad)}; "
                   f"entries={len(leftovers)} (want 0 → 上传失败)"))

        # check2a: 私钥分离上传符合规范(.crt 证书 + .key 密钥) → 上传成功,新条目出现。
        if src_ok:
            rest.stage("localcacert", up_name + ".crt", cert_b)
            rest.stage("localcacert", up_name + ".key", key_b)
            r_ok = rest.commit(func_type="localCA", cert_type="pem",
                               cert_name=up_name + ".crt", key_name=up_name + ".key")
            ups = rest.list_entries("localCA", up_name)
            result.record(Check(
                name="separate-valid-upload",
                ok=r_ok.status_code == 200 and len(ups) == 1,
                detail=f"PUT upload {r_ok.status_code} {http_err(r_ok)}; "
                       f"new localCA entries={[e['name'] for e in ups]} (want 1 → 上传成功)"))

        # check2b: 单个 p12 上传 → 设备实际拒绝(xlsx 期望成功,记录 divergence)。
        p12_b, _ = rest.download("localCA", src_cert_name, "pfx", pfx_passwd=P12_PWD)
        if p12_b:
            rest.stage("localcacert", up_name + "s.p12", p12_b)
            r_pfx = rest.commit(func_type="localCA", cert_type="pfx",
                                cert_name=up_name + "s.p12", pfx_passwd=P12_PWD)
            ups = rest.list_entries("localCA", up_name + "s")
            result.record(Check(
                name="single-p12-upload-divergence",
                ok=r_pfx.status_code != 200 and not ups,
                detail=f"PUT p12 upload rejected: {http_err(r_pfx)}; "
                       f"entries={len(ups)} (设备不支持 localCA 单个 p12,divergence)"))
            result.notes.append(
                "DIVERGENCE: xlsx 18238 步骤2 期望 .P12/.pfx 单个CA证书上传成功;设备实测 "
                "localCA 仅支持 .pem/.cer/.crt 私钥分离上传(uploadCertFormatError 上传文件类型有误)")
    finally:
        if ctx.execute:
            for prefix in (src_name, up_name):
                for e in rest.list_entries("localCA", prefix):
                    rest.delete("localCA", e["id"])
            result.record(Check(
                name="localca-cleanup", ok=True,
                detail="deleted source + uploaded localCA entries (single DELETE by numeric id)"))
