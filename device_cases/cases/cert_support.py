"""Shared helpers for the local-certificate cases (257653/257655/257656).

Probe-confirmed device semantics for /api/v1/cert/*:
  * Identity is a numeric ``id``; the verify query is name-keyed via ``keywords``.
  * A created localcert is stored as ``<name>.csr`` (localcacert as ``<name>.crt``)
    — verify entries carry the suffixed name, while the input ``name`` is used
    for create/update.
  * ``subject`` is returned as a single concatenated string (RFC 4514-ish), e.g.
    ``/C=CN/ST=Sichuan/L=Chengdu/O=Atomic/OU=QA/CN=<name>`` for localcert and
    ``CN=<name>,OU=QA,O=Atomic,L=Chengdu,ST=Sichuan,C=CN`` for localcacert.
  * Delete is by the numeric id ONLY — deleting by the base (or suffixed) name
    fails with ``delCertFailCanNotDel``.
  * etcd key: /vnf-agent/vpp1/config/cert/v1/{localcert|localcacert}/<id>.

Also hosts the raw REST client (``CertRest``) for the /cert/upload|download
endpoints, which have no CLI ops (probe22h/22i/22j/22k/22o), plus the
openssl-backed validators used by the download/upload cases (18237/18238).
"""

from __future__ import annotations

import json
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests
import urllib3

urllib3.disable_warnings()

from framework.checks import Check, find_entries

# 证书用例共享的 subject 字段(cert 族 REST 信封统一形状)。
SUBJECT = {"country": "CN", "state": "Sichuan", "location": "Chengdu",
           "organization": "Atomic", "organUnit": "QA"}


def subject_kwargs() -> dict[str, str]:
    """SUBJECT 转成 CLI runner 子命令的 kwarg(organUnit → organ_unit)."""
    return {k: SUBJECT[k] for k in ("country", "state", "location", "organization")} | {
        "organ_unit": SUBJECT["organUnit"]}

CERT_SUBJECT_FIELDS = ("C", "ST", "L", "O", "OU", "CN")


def find_by_name(response: Any, name: str) -> list[dict[str, Any]]:
    """Every verify entry whose name is ``name`` or one of its device suffixes.

    A created localcert is stored as ``<name>.csr``; after issue an RSA cert is
    ``<name>.crt`` while an SM2 cert splits into TWO entries ``<name>_sig.crt``
    (signature keypair) and ``<name>_enc.crt`` (encryption keypair). localcacert
    is always ``<name>.crt``.
    """
    suffixes = (name, f"{name}.csr", f"{name}.crt", f"{name}_sig.crt", f"{name}_enc.crt")
    return find_entries(
        response,
        lambda e: str(e.get("name", "")).lower() in {s.lower() for s in suffixes},
    )


def find_by_prefix(response: Any, prefix: str) -> list[dict[str, Any]]:
    """Every verify entry whose name starts with ``prefix`` (case-insensitive)."""
    return find_entries(
        response,
        lambda e: str(e.get("name", "")).lower().startswith(prefix.lower()),
    )


def cert_present(response: Any, *, label: str, name: str, want: int = 1) -> Check:
    """Assert exactly ``want`` entries for this cert name appear in a verify response."""
    hits = find_by_name(response, name)
    ok = len(hits) == want
    detail = f"name={name!r} matching_entries={len(hits)} want={want}"
    if hits:
        sample = hits[0]
        detail += " e.g. {" + ", ".join(
            f"{k!r}: {sample.get(k)!r}" for k in ("id", "name", "keyType", "keyLenth") if k in sample
        ) + "}"
    return Check(name=label, ok=ok, detail=detail)


def cert_absent(response: Any, *, label: str, name: str) -> Check:
    """Assert no entry with this cert name appears in a verify response."""
    return cert_present(response, label=label, name=name, want=0)


def first_id(response: Any, name: str) -> int | None:
    """Numeric id of the entry matching ``name`` (or its suffix), if any."""
    for entry in find_by_name(response, name):
        value = entry.get("id")
        if isinstance(value, int):
            return value
    return None


def all_ids(response: Any, name: str) -> list[int]:
    """Numeric ids of EVERY entry matching ``name`` (all suffixes).

    An issued SM2 cert splits into TWO entries (``<name>_sig.crt`` with the
    original id and ``<name>_enc.crt`` with a NEW id), so a cleanup that only
    deletes the first id leaves the ``_enc`` entry orphaned on the device.
    Deletion must collect and batch-delete every matching id.
    """
    return [e["id"] for e in find_by_name(response, name)
            if isinstance(e.get("id"), int)]


def subject_contains(response: Any, name: str, **field_values: str) -> list[str]:
    """Subject tokens present in the matching entry's concatenated subject.

    Returns the list of ``field_values`` keys whose ``<KEY>=<value>`` appears
    in the entry subject (case-insensitive). localcert encodes subject as
    ``/C=CN/ST=Sichuan/...``; localcacert as ``CN=...,ST=Sichuan,...``.
    """
    present: list[str] = []
    for entry in find_by_name(response, name):
        subject = str(entry.get("subject", ""))
        for key, value in field_values.items():
            if f"{key}={value}".lower() in subject.lower():
                present.append(key)
    return present


def subject_ok(response: Any, *, label: str, name: str, **field_values: str) -> Check:
    """Assert the verify entry's subject carries every requested field=value."""
    present = subject_contains(response, name, **field_values)
    missing = [k for k in field_values if k not in present]
    ok = not missing
    detail = f"subject fields present={sorted(present)} missing={missing or 'none'} name={name!r}"
    return Check(name=label, ok=ok, detail=detail)


def entry_field(response: Any, name: str, field: str) -> Any:
    """Value of ``field`` on the first verify entry matching ``name`` (or None)."""
    for entry in find_by_name(response, name):
        if field in entry:
            return entry[field]
    return None


def validity_years(response: Any, name: str) -> float | None:
    """Approximate validity of the matching entry in years, from startTime/endTime.

    The device returns "YYYY-MM-DD HH:MM" strings. Returns None when either
    timestamp is absent or unparsable.
    """
    try:
        from datetime import datetime
        start = datetime.strptime(str(entry_field(response, name, "startTime")), "%Y-%m-%d %H:%M")
        end = datetime.strptime(str(entry_field(response, name, "endTime")), "%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return None
    return (end - start).days / 365.25


# ---------------------------------------------------------------------------
# Raw REST access to /cert/upload|download (no CLI ops for these endpoints).
# Probe-confirmed on <DUT_IP> (probe22h/22i/22j/22k/22o).
# ---------------------------------------------------------------------------

# resource key -> REST path (also the module for POST /api/v1/upload)
CERT_RESOURCES = {
    "localcert": "/api/v1/cert/localcert",
    "localCA": "/api/v1/cert/localcacert",
    "CAcert": "/api/v1/cert/cacert",
    "certcrl": "/api/v1/cert/certcrl",
}

UPLOAD_MODULE = {"localcert": "localcert", "localCA": "localcacert",
                 "CAcert": "cacert", "certcrl": "certcrl"}


class CertRest:
    """Thin authenticated client for cert endpoints not exposed via the CLI.

    Two-step upload:  POST /api/v1/upload (stage) then PUT /api/v1/cert/upload.
    Two-step download: PUT /api/v1/cert/download returns a ``tmpcert/...`` path,
    then GET /api/v1/downloadfile?id=<urlencoded path> returns the file bytes.
    Session token is read from ``ctx.session_file`` (never printed).
    """

    def __init__(self, ctx) -> None:
        self.ctx = ctx
        self.base = f"https://{ctx.device}"
        self._sid: str | None = None
        self._verify = bool(getattr(ctx, "verify_tls", False))

    @property
    def sid(self) -> str:
        if self._sid is None:
            data = json.loads(self.ctx.session_file.read_text(encoding="utf-8"))
            self._sid = str(data["session_value"])
        return self._sid

    def _headers(self, json_body: bool) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self.sid}"}
        if json_body:
            headers["Content-Type"] = "application/json"
        return headers

    def request(self, method: str, path: str, *, payload=None, params=None,
                files=None, data=None) -> requests.Response:
        return requests.request(
            method, self.base + path,
            headers=self._headers(payload is not None),
            json=payload, params=params, files=files, data=data,
            verify=self._verify, timeout=40,
        )

    # ---- upload two-step ----
    def stage(self, module: str, filename: str, content: bytes) -> requests.Response:
        """POST /api/v1/upload — stage the file for the following commit."""
        return self.request("POST", "/api/v1/upload",
                            files={"file": (filename, content, "application/octet-stream")},
                            data={"module": module})

    def commit(self, *, func_type: str, cert_type: str, cert_name: str, key_name: str = "",
               pfx_passwd: str = "", key_passwd: str = "", upload_type: str = "local",
               url_name: str = "", key_type: str = "RSA", name: str = "") -> requests.Response:
        """PUT /api/v1/cert/upload — commit the staged file into the store.

        ``name`` is only forwarded when set; the SM2 localcert upload asks for
        a 名称 (name) field but still rejects (probe22v — device divergence).
        """
        val = {"funcType": func_type, "certType": cert_type, "certName": cert_name,
               "keyName": key_name, "pfxPasswd": pfx_passwd, "keyPasswd": key_passwd,
               "uploadType": upload_type, "urlName": url_name, "crlAutoUpTime": "",
               "keyType": key_type}
        if name:
            val["name"] = name
        return self.request("PUT", "/api/v1/cert/upload", payload={"id": "0", "val": val})

    # ---- download two-step ----
    def download(self, func_type: str, cert_name: str, file_type: str,
                 pfx_passwd: str = "") -> tuple[bytes | None, requests.Response]:
        """Download ``file_type`` (cert/key/pfx/csr) of a store entry.

        Returns ``(bytes, last_response)``; bytes is None when the PUT does not
        return a ``tmpcert`` path or the GET yields a JSON error body.
        """
        put = self.request("PUT", "/api/v1/cert/download",
                           payload={"id": "0", "val": {"funcType": func_type,
                                                       "certName": cert_name,
                                                       "fileType": file_type,
                                                       "pfxPasswd": pfx_passwd}})
        path = put.text.strip()
        if not path.startswith("tmpcert"):
            return None, put
        get = self.request("GET", f"/api/v1/downloadfile?id={quote(path, safe='')}")
        if get.content[:1] in (b"{", b"["):
            return None, get
        return get.content, get

    # ---- list / delete ----
    def list_entries(self, resource: str, prefix: str) -> list[dict[str, Any]]:
        r = self.request("GET", CERT_RESOURCES[resource],
                         params={"page": 1, "size": 300, "keywords": prefix})
        try:
            vals = r.json().get("vals") or []
        except ValueError:
            vals = []
        return [e for e in vals if str(e.get("name", "")).startswith(prefix)]

    def delete(self, resource: str, entry_id) -> requests.Response:
        return self.request("DELETE", f"{CERT_RESOURCES[resource]}?id={entry_id}")


def http_err(r: requests.Response | None) -> str:
    """Short device error text from a raw response ('' when absent)."""
    if r is None:
        return ""
    try:
        body = r.json()
        code = str(body.get("errCode") or body.get("err_code") or "")
        msg = str(body.get("errMsg") or body.get("message") or body.get("msg") or "")
    except ValueError:
        return f"{r.status_code} {r.text[:80]}"
    return f"{r.status_code} {code}: {msg}".strip()


# ---------------------------------------------------------------------------
# openssl-backed validators (used by the 18237/18238 cases).
# ---------------------------------------------------------------------------


def run_openssl(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    return subprocess.run(["openssl", *args], capture_output=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


def keypair_matches(cert_pem: bytes, key_pem: bytes) -> bool:
    """True when the cert and key belong to the same keypair (证书密钥分离匹配).

    RSA: compares the modulus (``openssl x509 -modulus`` vs ``openssl rsa
    -modulus``). ECC/SM2 keys have no modulus, so when the RSA path fails it
    falls back to comparing the SPKI public key (``openssl x509 -pubkey`` vs
    ``openssl pkey -pubout``).
    """
    if not cert_pem or not key_pem:
        return False
    with tempfile.TemporaryDirectory() as td:
        cert = Path(td) / "cert.pem"
        key = Path(td) / "key.pem"
        cert.write_bytes(cert_pem)
        key.write_bytes(key_pem)
        # RSA path.
        c = run_openssl("x509", "-in", str(cert), "-noout", "-modulus")
        k = run_openssl("rsa", "-in", str(key), "-noout", "-modulus")
        if (c.returncode == 0 and k.returncode == 0
                and "Modulus=" in c.stdout and "Modulus=" in k.stdout):
            return (c.stdout.split("Modulus=", 1)[1].strip()
                    == k.stdout.split("Modulus=", 1)[1].strip())
        # ECC/SM2 path: compare public keys.
        cp = run_openssl("x509", "-in", str(cert), "-noout", "-pubkey")
        kp = run_openssl("pkey", "-in", str(key), "-pubout")
        return (cp.returncode == 0 and kp.returncode == 0
                and cp.stdout.strip() == kp.stdout.strip())


def p12_openable(p12_bytes: bytes, password: str) -> bool:
    """True when ``openssl pkcs12`` parses the p12 with the given password.

    A p12 exported with password A fails to open with any other password, so a
    "wrong password" export is provably unusable (18237 check3). The device's
    p12s are legacy (SHA1) PKCS#12, so openssl 3.x needs ``-legacy`` to accept
    them (default provider rejects with ``unsupported``).
    """
    if not p12_bytes:
        return False
    with tempfile.TemporaryDirectory() as td:
        p12 = Path(td) / "bundle.p12"
        p12.write_bytes(p12_bytes)
        r = run_openssl("pkcs12", "-in", str(p12), "-passin", f"pass:{password}",
                        "-noout", "-legacy")
        return r.returncode == 0


# ---------------------------------------------------------------------------
# Fixture helpers for the upload/download edge cases (900009-900018/900022).
# A device-issued localcert is a NON-CA (leaf) certificate; upload to
# ``localcert`` requires a leaf (a CA cert is rejected with 证书解析失败).
# ---------------------------------------------------------------------------


def issued_leaf(ctx, *, name: str, key_type: str = "RSA",
                key_length: int = 2048, cacert: str | None = None) -> list[dict[str, Any]]:
    """Create + issue a localcert on the device; return its verify entries.

    RSA yields one ``<name>.crt`` entry; SM2 yields ``<name>_sig.crt`` and
    ``<name>_enc.crt``. The entries can be downloaded (cert/key/pfx) and used
    as upload fixtures. Returns [] when config or issue fails.
    """
    create = ctx.runner.run("cert", "localcert-config", name=name, key_type=key_type,
                            key_length=key_length, **subject_kwargs())
    if not create.success:
        return []
    v = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=name)
    cert_id = first_id(v.response(), name)
    if cert_id is None:
        return []
    cacert = cacert or ("defaultGmLocalCA.crt" if key_type == "SM2" else "defaultLocalCA.crt")
    issue = ctx.runner.run("cert", "localcert-issue", id=str(cert_id),
                           cacert=cacert, option="1", time_length=30)
    if not issue.success:
        return []
    time.sleep(2)  # the SM2 _enc.crt entry is written asynchronously
    v = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=name)
    return find_by_name(v.response(), name)


def localca_fixture(ctx, *, name: str, key_type: str = "RSA") -> list[dict[str, Any]]:
    """Create a local CA on the device; return its verify entries."""
    create = ctx.runner.run("cert", "localcacert-config", name=name, key_type=key_type,
                            time_length=30, **subject_kwargs())
    if not create.success:
        return []
    v = ctx.runner.run("cert", "localcacert-verify", page=1, size=200, keywords=name)
    return find_by_name(v.response(), name)


def fixture_download(rest: "CertRest", func_type: str, entry_name: str) -> tuple[bytes | None, bytes | None, bytes | None]:
    """Download cert/key/pfx of one store entry as an upload fixture.

    Returns ``(cert, key, p12)``; each may be None when the download fails.
    """
    cert, _ = rest.download(func_type, entry_name, "cert")
    key, _ = rest.download(func_type, entry_name[:-4] + ".key", "key")
    p12, _ = rest.download(func_type, entry_name, "pfx", pfx_passwd="ptm123456")
    return cert, key, p12


def delete_named(rest: "CertRest", resource: str, prefix: str) -> None:
    """Delete every store entry whose name starts with ``prefix`` (self-clean)."""
    for e in rest.list_entries(resource, prefix):
        rest.delete(resource, e["id"])
