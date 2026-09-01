"""P3-900019: CRL证书下载测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 通过本地上传密钥类型为SM2的CRL证书【check1】
  2. 通过HTTP方式上传密钥类型为SM2的CRL证书【check1】
  3. 下载通过本地上传的SM2 CRL证书【check2】
  4. 下载通过HTTP方式上传的SM2 CRL证书【check2】
  5. 重复步骤1-4,密钥类型为RSA的CRL证书【check1】【check2】
预期: 【check1】上传成功,存在日志记录;【check2】导出文件成功,存在日志记录。

设备实测(55.63, 2026-09-01): certcrl 上传接口不区分密钥类型(cert_type=""),
  SM2 与 RSA 签名的 CRL 均以 X509 CRL 字节 blob 落库;下载 funcType=certcrl
  fileType=cert 返回 `-----BEGIN X509 CRL-----`(行尾 CRLF)。本用例用 openssl
  生成真实签名的 CRL fixture —— SM2-with-SM3 与 RSA-with-SHA256 —— 各自走
  local + http 两条上传路径并下载校验字节, 最后在操作日志中确认记录存在。
"""

from __future__ import annotations

import http.server
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import oplog_messages
from framework.results import CaseResult

from cases.cert_support import CertRest, http_err

TITLE = "P3-900019 CRL证书下载测试"

ALGOS = ("SM2", "RSA")


def _generate_crl(tmpdir: Path, crl_name: str, algo: str) -> Path:
    """openssl: 生成指定算法签名的自签 CA + 空 CRL.

    ``algo`` in ("SM2", "RSA"): SM2 走 genpkey -algorithm SM2 + default_md sm3
    (CRL 签名算法 SM2-with-SM3);RSA 走 rsa:2048 + default_md sha256。
    """
    ca_key, ca_crt, crl = tmpdir / "cakey.pem", tmpdir / "cacert.pem", tmpdir / crl_name
    if algo == "SM2":
        default_md = "sm3"
        subprocess.run(["openssl", "genpkey", "-algorithm", "SM2", "-out", str(ca_key)],
                       capture_output=True, check=True)
        subprocess.run(["openssl", "req", "-new", "-x509", "-key", str(ca_key),
                        "-out", str(ca_crt), "-days", "30", "-subj", "/C=CN/O=ptmcrl-sm2"],
                       capture_output=True, check=True)
    else:
        default_md = "sha256"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(ca_key),
                        "-out", str(ca_crt), "-days", "30", "-nodes", "-subj", "/C=CN/O=ptmcrl"],
                       capture_output=True, check=True)
    cnf = tmpdir / "openssl.cnf"
    cnf.write_text(
        "[ ca ]\ndefault_ca = CA_default\n"
        "[ CA_default ]\ndatabase = " + str(tmpdir / "index.txt").replace("\\", "/") + "\n"
        "new_certs_dir = " + str(tmpdir).replace("\\", "/") + "\n"
        "certificate = " + str(ca_crt).replace("\\", "/") + "\n"
        "private_key = " + str(ca_key).replace("\\", "/") + "\n"
        "default_md = " + default_md + "\nserial = " + str(tmpdir / "serial").replace("\\", "/") + "\n"
        "default_days = 30\ndefault_crl_days = 30\n", encoding="utf-8")
    (tmpdir / "index.txt").write_text("", encoding="utf-8")
    (tmpdir / "serial").write_text("01\n", encoding="utf-8")
    r = subprocess.run(["openssl", "ca", "-gencrl", "-keyfile", str(ca_key), "-cert", str(ca_crt),
                        "-out", str(crl), "-config", str(cnf)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0 or not crl.exists():
        raise RuntimeError(f"openssl gencrl ({algo}) failed: {r.stderr[-300:]}")
    return crl


def _local_ip(ctx: CaseContext) -> str:
    """Test-host IP on the route toward the device (http URL must be reachable)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((ctx.device, 443))
        return s.getsockname()[0]
    finally:
        s.close()


class _CrlServer:
    """Ephemeral http.server serving a directory; records incoming GET paths."""

    def __init__(self, directory: Path) -> None:
        hits: list[str] = []

        class Handler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *a, **kw):  # noqa: D102
                super().__init__(*a, directory=str(directory), **kw)

            def do_GET(self):  # noqa: D102
                hits.append(self.path)
                super().do_GET()

            def log_message(self, *args):  # noqa: D102 - silence to stderr
                pass

        self.hits = hits
        self.server = http.server.ThreadingHTTPServer(("0.0.0.0", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]

    def url(self, ip: str, filename: str) -> str:
        return f"http://{ip}:{self.port}/{filename}"

    def shutdown(self) -> None:
        self.server.shutdown()


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = CertRest(ctx)
    name = unique_random(900019, "crl")
    server: _CrlServer | None = None
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped"))
        return
    try:
        with tempfile.TemporaryDirectory(prefix="ptm-crl9-") as td:
            tmpdir = Path(td)
            for algo in ALGOS:
                low = algo.lower()
                crl_bytes = _generate_crl(tmpdir, f"{name}-{algo}.crl", algo).read_bytes()
                # 上传名称长度上限 31:本地上传的 cert_name 必须 ≤31(http 路径
                # 名称取自 URL 末段文件名, 不受此限, 但同样压短保持一致)。
                local_name = f"{name}-{low}.crl"
                http_name = f"{name}-{low}-h.crl"
                (tmpdir / http_name).write_bytes(crl_bytes)

                # check1a: 本地上传 + 落库条目 + 可下载为 X509 CRL。
                rest.stage("certcrl", local_name, crl_bytes)
                r_local = rest.commit(func_type="certcrl", cert_type="", cert_name=local_name,
                                      upload_type="local")
                lgot = any(e["name"].startswith(local_name)
                           for e in rest.list_entries("certcrl", local_name))
                dl_b = rest.download("certcrl", local_name, "cert")[0] if lgot else None
                result.record(Check(
                    name=f"crl-{low}-local-upload",
                    ok=r_local.status_code == 200 and lgot and bool(dl_b) and b"X509 CRL" in dl_b,
                    detail=f"local upload {r_local.status_code} {http_err(r_local)}; "
                           f"entry={lgot}; download {len(dl_b) if dl_b else 0}B isCRL={bool(dl_b) and b'X509 CRL' in dl_b}"))

                # check1b: HTTP 上传(设备主动 GET 该 URL)+ 落库条目 + 可下载。
                server = _CrlServer(tmpdir)
                url = server.url(_local_ip(ctx), http_name)
                r_http = rest.commit(func_type="certcrl", cert_type="", cert_name="",
                                     upload_type="http", url_name=url)
                pulled = False
                for _ in range(15):
                    if any(http_name in h for h in server.hits):
                        pulled = True
                        break
                    time.sleep(1)
                hgot = any(e["name"].startswith(http_name)
                           for e in rest.list_entries("certcrl", http_name))
                hdl_b = rest.download("certcrl", http_name, "cert")[0] if hgot else None
                result.record(Check(
                    name=f"crl-{low}-http-upload",
                    ok=r_http.status_code == 200 and pulled and hgot and bool(hdl_b) and b"X509 CRL" in hdl_b,
                    detail=f"http upload {r_http.status_code} {http_err(r_http)}; "
                           f"device_pulled={pulled} hits={server.hits[:3]}; entry={hgot}; "
                           f"download {len(hdl_b) if hdl_b else 0}B isCRL={bool(hdl_b) and b'X509 CRL' in hdl_b}"))
                server.shutdown()
                server = None

            # check: 操作日志存在 CRL 上传/下载记录(设备时钟偏斜 ~137s, 重查至多 3 次)。
            window_start = int(time.time()) - 300
            messages: list[str] = []
            for _ in range(3):
                cap = ctx.runner.run("operation-log", "capture", timetype="custom",
                                     starttime=window_start, endtime=int(time.time()) + 15,
                                     page=1, size=200)
                result.record(op_succeeded(cap, ctx=ctx, label="oplog-capture"))
                if not cap.success:
                    break
                messages = oplog_messages(cap.response())
                if any(name in m for m in messages):
                    break
                time.sleep(2)
            result.record(Check(
                name="crl-oplog-recorded",
                ok=any(name in m for m in messages),
                detail=f"crl names seen in {len(messages)} oplog messages "
                       f"({sum(1 for m in messages if name in m)} hits)"))
    finally:
        if ctx.execute:
            if server is not None:
                server.shutdown()
            for e in rest.list_entries("certcrl", name):
                rest.delete("certcrl", e["id"])
            result.record(Check(
                name="certcrl-cleanup", ok=True,
                detail="deleted SM2+RSA local+http CRL entries (single DELETE by numeric id)"))
