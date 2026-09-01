"""P3-900017: 本地CA证书上传测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. RSA,传 .cer/.crt/.pem 的 CA 证书 + 符合要求的私钥文件 → 【check1】上传成功
  2. SM2,传 .cer/.crt/.pem 的 CA 证书 + 私钥文件 → 【check1】上传成功
  3. 非规范 CA 证书/密钥文件 → 【check2】上传失败

设备实测(18238 + probe22q): localCA 仅支持 .pem/.cer/.crt 私钥分离上传
(certType="pem", certName+keyName 必填);RSA/SM2 均可用。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import CertRest, http_err, localca_fixture

TITLE = "P3-900017 本地CA证书上传测试"


def _upload(rest: CertRest, *, key_type: str, up: str, cert_b: bytes, key_b: bytes) -> None:
    rest.stage("localcacert", up + ".crt", cert_b)
    rest.stage("localcacert", up + ".key", key_b)
    return rest.commit(func_type="localCA", cert_type="pem",
                       cert_name=up + ".crt", key_name=up + ".key",
                       key_type=key_type)


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    made: list[str] = []
    try:
        for kt in ("RSA", "SM2"):
            src = unique_random(900017, f"src{kt.lower()}")
            up = unique_random(900017, f"up{kt.lower()}")
            made += [src, up]
            src_entries = localca_fixture(ctx, name=src, key_type=kt)
            result.record(Check(
                name=f"{kt.lower()}-source", ok=bool(src_entries),
                detail=f"source localCA entries={[e['name'] for e in src_entries]}"))
            if not ctx.execute:
                return
            if not src_entries:
                continue
            cert_b, _ = rest.download("localCA", src_entries[0]["name"], "cert")
            key_b, _ = rest.download("localCA", src_entries[0]["name"][:-4] + ".key", "key")
            if not (cert_b and key_b):
                continue
            # check1/2: RSA/SM2 分离上传 → 成功,新条目出现。
            r = _upload(rest, key_type=kt, up=up, cert_b=cert_b, key_b=key_b)
            ups = rest.list_entries("localCA", up)
            result.record(Check(
                name=f"{kt.lower()}-upload-ok",
                ok=r.status_code == 200 and len(ups) == 1,
                detail=f"PUT {kt} {r.status_code} {http_err(r)}; "
                       f"entries={[e['name'] for e in ups]} (want 1)"))

        # check3: 非规范格式(.txt)→ 拒绝。
        bad = unique_random(900017, "bad")
        made.append(bad)
        rest.stage("localcacert", bad + ".txt", b"this is not a certificate")
        rest.stage("localcacert", bad + "k.txt", b"this is not a private key")
        r = rest.commit(func_type="localCA", cert_type="pem",
                        cert_name=bad + ".txt", key_name=bad + "k.txt")
        result.record(Check(
            name="invalid-format-rejected",
            ok=r.status_code != 200 and not rest.list_entries("localCA", bad),
            detail=f"PUT {r.status_code} {http_err(r)}; want reject"))
    finally:
        if ctx.execute:
            # 只清本用例前缀,避免误删内置 CA。
            for prefix in made:
                for e in rest.list_entries("localCA", prefix):
                    rest.delete("localCA", e["id"])
            result.record(Check(name="localca-upload-cleanup", ok=True,
                                detail=f"cleaned {len(made)} prefixes"))
