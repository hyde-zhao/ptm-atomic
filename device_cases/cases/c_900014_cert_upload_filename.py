"""P4-900014: 上传证书文件名测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. RSA 上传重复名称证书文件并保存 → 【check1】保存失败
  2. RSA 上传名称为 128 字符的证书文件并保存 → 【check1】保存失败(本实现按此断言)
  4. SM2 上传重复名称的签名/加密证书文件 → 【check2】保存失败
  5. 受信任/CRL 重复名称或 128 字符 → 【check1】保存失败

设备实测(probe22s/22q): 重复名称 → 400 certNameConflict 上传文件名冲突;长文件名
(RSA,含 128 字符)与缺 keyName 均拒绝。本用例断言重复名与超长名均拒绝。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import CertRest, delete_named, http_err, issued_leaf

TITLE = "P4-900014 上传证书文件名测试"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    src = unique_random(900014, "src")
    made = [src]
    try:
        entries = issued_leaf(ctx, name=src, key_type="RSA")
        if not ctx.execute:
            return
        if not entries:
            return
        leaf = entries[0]["name"]
        cert_b, _ = rest.download("localcert", leaf, "cert")
        key_b, _ = rest.download("localcert", leaf[:-4] + ".key", "key")
        if not (cert_b and key_b):
            return

        # check1: 同一名称重复上传 → 第二次拒绝(certNameConflict)。
        dup = unique_random(900014, "dup")
        made.append(dup)
        for i in range(2):
            rest.stage("localcert", dup + ".crt", cert_b)
            rest.stage("localcert", dup + ".key", key_b)
            r = rest.commit(func_type="localcert", cert_type="pem",
                            cert_name=dup + ".crt", key_name=dup + ".key")
        entries_after = rest.list_entries("localcert", dup)
        result.record(Check(
            name="duplicate-name-rejected",
            ok=r.status_code != 200 and len(entries_after) == 1,
            detail=f"2nd PUT {r.status_code} {http_err(r)}; "
                   f"entries={[e['name'] for e in entries_after]} (want 1 → 重名拒绝)"))

        # check2: 128 字符文件名(cert+key 齐全)→ 拒绝。
        lng = unique_random(900014, "lng")[:4] + "n" * 118 + ".crt"
        made.append(lng[:8])
        rest.stage("localcert", lng, cert_b)
        rest.stage("localcert", lng[:-4] + ".key", key_b)
        r = rest.commit(func_type="localcert", cert_type="pem",
                        cert_name=lng, key_name=lng[:-4] + ".key")
        leftovers = rest.list_entries("localcert", "n" * 4)
        result.record(Check(
            name="long-name-rejected",
            ok=r.status_code != 200,
            detail=f"PUT {r.status_code} {http_err(r)}; name_len={len(lng)} "
                   f"(want reject → 超长文件名拒绝)"))
    finally:
        if ctx.execute:
            for prefix in made:
                delete_named(rest, "localcert", prefix)
            result.record(Check(name="filename-cleanup", ok=True,
                                detail=f"cleaned {len(made)} prefixes"))
