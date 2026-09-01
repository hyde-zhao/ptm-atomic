"""P4-900015: 上传证书文件密码无效测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. RSA 单个证书类型,证书文件格式正确、密码非法 → 【check1】保存失败
  2. RSA 私钥分离类型,证书和私钥格式正确且匹配、密码非法 → 【check1】保存失败
  5. 查看操作日志 → 【check2】存在日志

设备实测(probe22t/22u): 单个 p12(certType="pfx")上传,条目名变 <name>.crt。
本用例:用密码 A 导出的叶子 p12,上传时填错误密码 B → 设备解密失败 → 拒绝。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import CertRest, delete_named, http_err, issued_leaf

TITLE = "P4-900015 上传证书文件密码无效测试"

GOOD_PWD = "ptm123456"
BAD_PWD = "ptm654321"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    src = unique_random(900015, "src")
    up = unique_random(900015, "up")
    made = [src, up]
    try:
        entries = issued_leaf(ctx, name=src, key_type="RSA")
        if not ctx.execute:
            return
        if not entries:
            return
        leaf = entries[0]["name"]
        # 用正确密码导出 p12。
        p12_b, _ = rest.download("localcert", leaf, "pfx", pfx_passwd=GOOD_PWD)
        if not p12_b:
            return
        # 上传时填错误密码 → 解密失败 → 拒绝,无新条目。
        rest.stage("localcert", up + ".p12", p12_b)
        r = rest.commit(func_type="localcert", cert_type="pfx",
                        cert_name=up + ".p12", pfx_passwd=BAD_PWD)
        result.record(Check(
            name="wrong-pfx-password-rejected",
            ok=r.status_code != 200 and not rest.list_entries("localcert", up),
            detail=f"PUT p12(wrong pwd) {r.status_code} {http_err(r)}; "
                   f"want reject (证书密码非法 → 解密失败)"))
    finally:
        if ctx.execute:
            for prefix in made:
                delete_named(rest, "localcert", prefix)
            result.record(Check(name="bad-password-cleanup", ok=True,
                                detail=f"cleaned {len(made)} prefixes"))
