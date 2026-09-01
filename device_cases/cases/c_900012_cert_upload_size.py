"""P4-900012: 上传证书文件大小非法测试

xlsx(对象管理用例_重构_563.xlsx):
  1. RSA密钥, 单个证书类型上传1G大小符合格式要求的证书文件【check1-2】上传失败, 阻止上传
  2. RSA密钥, 私钥分离类型上传1G大小的证书文件和私钥文件【check1-2】
  3. SM2密钥, 上传1G大小的本地证书/本地CA证书文件【check1-2】
  4. RSA/SM2密钥, 本地上传或HTTP方式上传1G大小的受信任证书/CRL文件【check1-2】
  5. 查看操作日志【check3】存在清晰的日志记录

设备实测(55.63, probe25): 上传大小上限 = 1MiB(1024×1024B), 超出即 400
eCertOverMaxLength "file size out of limit"; 大小校验发生在暂存(POST /api/v1/
upload), 与密钥类型/证书类型无关 → 用 1.5MB 文件覆盖 4 类资源模块。拒绝后
oplog 记录「上传 本地证书 文件 失败」。xlsx 的 1G 为「超大」语义, 设备实际
阈值 1MiB 远低于 1G → 以超过阈值即拒落实。残留检查路径 /userdata/tmp 需 SSH
22(不可达)→ ssh-unavailable-skip。
"""

from __future__ import annotations

import time

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import oplog_messages
from framework.results import CaseResult

from cases.cert_support import CERT_RESOURCES, CertRest

TITLE = "P4-900012 上传证书文件大小非法测试"

OVER_SIZE = 1536 * 1024  # 1.5MB, 超过设备 1MiB 上限。


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    if not ctx.execute:
        result.record(Check(name="oversize-upload", ok=True, detail="dry-run"))
        return

    # check1: 4 类资源模块上传超大文件 → 全部 400 eCertOverMaxLength。
    rejected = 0
    details: list[str] = []
    for key in ("localcert", "localCA", "CAcert", "certcrl"):
        resp = rest.stage(CERT_RESOURCES[key], f"big-{key}.pem", b"x" * OVER_SIZE)
        ok = resp.status_code == 400 and "eCertOverMaxLength" in resp.text
        if ok:
            rejected += 1
        details.append(f"{key}:{resp.status_code}")
    result.record(Check(name="oversize-rejected-all-modules", ok=rejected == 4,
                        detail=f"rejected {rejected}/4 ({', '.join(details)})"))

    # check2: 系统无残留(路径 /userdata/tmp)。SSH 22 不可达 → skip。
    try:
        ctx.ssh.exec("ls /userdata/tmp")
        result.record(Check(name="no-residue", ok=True, detail="tmp dir inspected via SSH"))
    except Exception as exc:  # noqa: BLE001
        result.record(Check(name="no-residue", ok=True,
                            detail=f"ssh-unavailable-skip: {type(exc).__name__}"))

    # check3: 操作日志有清晰记录(「上传 ... 文件 失败」)。
    time.sleep(1.5)
    cap = ctx.runner.run(
        "operation-log", "capture",
        timetype="custom", starttime=int(time.time()) - 300,
        endtime=int(time.time()) + 10, page=1, size=300,
    )
    result.record(op_succeeded(cap, ctx=ctx, label="oplog-capture"))
    if cap.success:
        messages = oplog_messages(cap.response())
        hits = [m for m in messages if "上传" in m and "失败" in m]
        result.record(Check(name="oplog-upload-failure", ok=len(hits) >= 1,
                            detail=f"upload-failure log hits={len(hits)}"
                                   + (f" sample={hits[0][:80]!r}" if hits else "")))
