"""P3-18239: 导入本地CRL文件测试.

xlsx(对象管理用例3.xlsx)步骤:
  2. 选择本地上传,传入符合要求格式的文件(crl格式) → 上传成功
  3. 选择http上传,输入正确的URL → 上传成功
(xlsx 预期列的 check 标签与步骤错位 —— 预期写"【check1】上传成功 / 【check2】上传失败",
但步骤 check1=http、check2=本地,且两处均为正确输入;实测(probe22j/22k)两条上传路径都成功,
故两步都断言成功。)

设备实测: 本地上传 module=certcrl 暂存后 PUT /cert/upload funcType=certcrl certType=""
落库,条目名=certName;http 上传 uploadType=http urlName=URL,设备主动 GET 该 URL(http.server
可见请求),条目名=URL 末段文件名;下载 funcType=certcrl fileType=cert 得
`-----BEGIN X509 CRL-----`(行尾 CRLF)。
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
from framework.results import CaseResult

from cases.cert_support import CertRest, http_err

TITLE = "P3-18239 导入本地CRL文件测试"


def _generate_crl(tmpdir: Path, crl_name: str) -> Path:
    """openssl: 自签测试 CA + 生成空 CRL(需最小 openssl.cnf,default_crl_days)."""
    ca_key, ca_crt, crl = tmpdir / "cakey.pem", tmpdir / "cacert.pem", tmpdir / crl_name
    cnf = tmpdir / "openssl.cnf"
    cnf.write_text(
        "[ ca ]\ndefault_ca = CA_default\n"
        "[ CA_default ]\ndatabase = " + str(tmpdir / "index.txt").replace("\\", "/") + "\n"
        "new_certs_dir = " + str(tmpdir).replace("\\", "/") + "\n"
        "certificate = " + str(ca_crt).replace("\\", "/") + "\n"
        "private_key = " + str(ca_key).replace("\\", "/") + "\n"
        "default_md = sha256\nserial = " + str(tmpdir / "serial").replace("\\", "/") + "\n"
        "default_days = 30\ndefault_crl_days = 30\n", encoding="utf-8")
    (tmpdir / "index.txt").write_text("", encoding="utf-8")
    (tmpdir / "serial").write_text("01\n", encoding="utf-8")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-keyout", str(ca_key),
                    "-out", str(ca_crt), "-days", "30", "-nodes", "-subj", "/C=CN/O=ptmcrl"],
                   capture_output=True, check=True)
    r = subprocess.run(["openssl", "ca", "-gencrl", "-keyfile", str(ca_key), "-cert", str(ca_crt),
                        "-out", str(crl), "-config", str(cnf)],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if r.returncode != 0 or not crl.exists():
        raise RuntimeError(f"openssl gencrl failed: {r.stderr[-300:]}")
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
    name = unique_random(18239, "crl")
    server: _CrlServer | None = None
    try:
        # check0: 用 openssl 生成本地测试 CRL(两条上传路径的 fixture)。
        if ctx.execute:
            with tempfile.TemporaryDirectory(prefix="ptm-crl-") as td:
                tmpdir = Path(td)
                crl_path = _generate_crl(tmpdir, name + ".crl")
                crl_bytes = crl_path.read_bytes()
                local_name = name + ".crl"
                http_name = name + "-http.crl"
                (tmpdir / http_name).write_bytes(crl_bytes)

                # check1: 本地上传(crl 格式) → 上传成功,条目出现,可下载为 CRL。
                rest.stage("certcrl", local_name, crl_bytes)
                r_local = rest.commit(func_type="certcrl", cert_type="", cert_name=local_name,
                                      upload_type="local")
                entries = rest.list_entries("certcrl", name)
                got = entries and any(e["name"].startswith(local_name) for e in entries)
                dl_b = None
                if got:
                    dl_b, _ = rest.download("certcrl", local_name, "cert")
                is_crl = bool(dl_b) and b"X509 CRL" in dl_b
                result.record(Check(
                    name="crl-local-upload",
                    ok=r_local.status_code == 200 and bool(got) and is_crl,
                    detail=f"PUT upload {r_local.status_code} {http_err(r_local)}; "
                           f"entries={[e['name'] for e in entries]}; "
                           f"download {len(dl_b) if dl_b else 0}B isCRL={is_crl}"))

                # check2: http 上传(正确 URL) → 上传成功;设备主动 GET 该 URL。
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
                http_entries = rest.list_entries("certcrl", name)
                http_got = any(e["name"].startswith(http_name) for e in http_entries)
                hdl_b = None
                if http_got:
                    hdl_b, _ = rest.download("certcrl", http_name, "cert")
                h_is_crl = bool(hdl_b) and b"X509 CRL" in hdl_b
                result.record(Check(
                    name="crl-http-upload",
                    ok=r_http.status_code == 200 and pulled and bool(http_got) and h_is_crl,
                    detail=f"PUT upload {r_http.status_code} {http_err(r_http)}; "
                           f"device_pulled={pulled} hits={server.hits[:3]}; "
                           f"entry_name={http_name} (URL末段文件名); "
                           f"download {len(hdl_b) if hdl_b else 0}B isCRL={h_is_crl}"))
    finally:
        if ctx.execute:
            if server is not None:
                server.shutdown()
            for e in rest.list_entries("certcrl", name):
                rest.delete("certcrl", e["id"])
            result.record(Check(
                name="certcrl-cleanup", ok=True,
                detail="deleted local + http CRL entries (single DELETE by numeric id)"))
