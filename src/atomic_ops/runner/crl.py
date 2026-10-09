"""NGFW CRL (certificate revocation list) runner for /api/v1/cert/certcrl.

CRL 是一个**两步异步流**，按 `docs/naming-convention.md`「Asynchronous Workflow Atoms」
折叠进单个 atom、由 runner 内部驱动全序列 —— 不拆成一步一 atom，因为 test-case YAML
的 ``tight_sequence`` 只携带 ``op_id``/``wait_ms``/``on_error``，第 1 步产出的临时文件名
无法传给第 2 步。两个折叠流：

- **上传+注册**（``fw_config_crl``）：``upload_type=local`` 时先
  ``POST /api/v1/upload``（multipart 暂存）再 ``PUT /api/v1/cert/upload``（注册生效）；
  ``upload_type=http`` 时**跳过暂存**，设备自行按 ``urlName`` 拉取。
- **下载**（``fw_download_crl``）：``PUT /api/v1/cert/download`` 返回**纯文本**
  ``tmpcert/<file>`` 路径（不是 JSON），再 ``GET /api/v1/downloadfile?id=<路径>`` 取字节。

字段真相来自 2026-10 的实机探测（probe22h/22i/22j/22k/22o），其中 ``keyType`` 是规格
2.2 未列、但实测报文携带的字段。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.batch import build_batch_delete_payload
from atomic_ops.runner.errors import (
    RunnerError,
    raise_if_device_session_rejected,
    raise_if_resource_not_found,
)
from atomic_ops.runner.http import request_bytes, request_json, request_multipart
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.object_transfer import _download_and_store, _validate_output_path
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
UPLOAD_STATUS = {200, 201, 202}

# 搜索参数名：与关键字族**相反**。实机探测（2026-10-09，<DUT_IP>）冻结：
#   /api/v1/cert/certcrl?keywords=ZZZNOPE -> count=0（过滤生效）
#   /api/v1/cert/certcrl?key=ZZZNOPE      -> count=1（参数被忽略，静默返回全量）
# 规格 2.4 写 `keywords`，正确；两族取值刻意各自持有，不抽公共常量。
SEARCH_QUERY_KEY = "keywords"

CRL_MODULE = "certcrl"
CRL_RESOURCE = "/api/v1/cert/certcrl"
BATCH_PATH = "/api/v1/batch"
UPLOAD_PATH = "/api/v1/upload"
CERT_UPLOAD_PATH = "/api/v1/cert/upload"
CERT_DOWNLOAD_PATH = "/api/v1/cert/download"
DOWNLOAD_FILE_PATH = "/api/v1/downloadfile"

# 暂存成功的判据：下载触发接口以纯文本返回该前缀的路径；非此前缀即失败
# （设备失败时返回 JSON 错误体，见 cert_support.CertRest.download）。
TMPCERT_PREFIX = "tmpcert"

CRL_ENDPOINTS = {
    "fw_config_crl": ("PUT", CERT_UPLOAD_PATH),
    "fw_verify_crl": ("GET", CRL_RESOURCE),
    "fw_download_crl": ("PUT", CERT_DOWNLOAD_PATH),
    "fw_delete_batch_crl": ("POST", BATCH_PATH),
}
GET_OPS = {"fw_verify_crl"}
BATCH_OPS = {"fw_delete_batch_crl"}
PAGINATED_OPS = {"fw_verify_crl"}

UPLOAD_TYPES = ("local", "http")
KEY_TYPES = ("RSA", "SM2")
FILE_TYPES = ("cert", "key", "pfx", "csr")


def build_crl_upload_payload(
    *,
    cert_name: str,
    upload_type: str = "local",
    key_type: str = "RSA",
    cert_type: str = "",
    key_name: str = "",
    pfx_passwd: str = "",
    key_passwd: str = "",
    url_name: str = "",
    crl_auto_up_time: str = "",
) -> dict[str, Any]:
    """构造注册载荷（规格 2.2）：``{"id": "0", "val": {...}}``。

    ``id`` 按规格固定为字符串 ``"0"`` —— 上传注册不针对既有条目。
    ``keyType`` 为规格未列、实测报文携带的字段（见模块 docstring）。
    """
    _validate_non_empty("cert_name", cert_name)
    _validate_choice("upload_type", upload_type, UPLOAD_TYPES)
    _validate_choice("key_type", key_type, KEY_TYPES)
    if upload_type == "http":
        _validate_non_empty("url_name", url_name)
    return {
        "id": "0",
        "val": {
            "funcType": CRL_MODULE,
            "certType": cert_type,
            "certName": cert_name,
            "keyName": key_name,
            "pfxPasswd": pfx_passwd,
            "keyPasswd": key_passwd,
            "uploadType": upload_type,
            "urlName": url_name,
            "crlAutoUpTime": crl_auto_up_time,
            "keyType": key_type,
        },
    }


def build_crl_download_payload(
    *,
    cert_name: str,
    file_type: str = "cert",
    pfx_passwd: str = "",
) -> dict[str, Any]:
    """构造下载触发载荷（规格 2.3）：``{"id": "0", "val": {...}}``。"""
    _validate_non_empty("cert_name", cert_name)
    _validate_choice("file_type", file_type, FILE_TYPES)
    return {
        "id": "0",
        "val": {
            "funcType": CRL_MODULE,
            "certName": cert_name,
            "fileType": file_type,
            "pfxPasswd": pfx_passwd,
        },
    }


def build_crl_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    """构造批量删除载荷（规格 2.5，resource = ``/api/v1/cert/certcrl``）。"""
    return build_batch_delete_payload(entry_ids=entry_ids, resource=CRL_RESOURCE)


def validate_crl_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if op_id in BATCH_OPS:
        return _validate_batch_payload(payload)
    return payload


def build_crl_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    keywords: str,
    upload_file: str,
    output_path: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    """构造 dry-run 信封。

    ``fw_config_crl`` 的 dry-run 声明**两步**（暂存 + 注册）以便审阅折叠行为；
    两个请求都不发出。``fw_download_crl`` 同理声明触发 + 取字节两步。
    """
    method, _path = _method_path(op_id)
    request: dict[str, Any] = {
        "method": method,
        "url": _request_url(base_url, op_id, page=page, size=size, keywords=keywords),
        "auth": {"name": auth_header, "value": "<session-ref>"},
        "content_type": "application/json",
        "payload": None if op_id in GET_OPS else payload,
    }
    result: dict[str, Any] = {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": request,
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }
    if op_id == "fw_config_crl":
        result["upload_steps"] = _upload_steps(upload_file, payload)
    if op_id == "fw_download_crl":
        result["download_steps"] = [
            {"method": "PUT", "path": CERT_DOWNLOAD_PATH, "note": "returns a plain-text tmpcert path"},
            {"method": "GET", "path": DOWNLOAD_FILE_PATH, "note": f"writes bytes to {output_path}"},
        ]
    return result


def execute_crl(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    keywords: str,
    upload_file: str,
    output_path: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    if op_id == "fw_config_crl":
        return _execute_upload(
            base_url=base_url,
            session_file=session_file,
            auth_header=auth_header,
            payload=payload or {},
            upload_file=upload_file,
            verify_tls=verify_tls,
            timeout=timeout,
        )
    if op_id == "fw_download_crl":
        return _execute_download(
            base_url=base_url,
            session_file=session_file,
            auth_header=auth_header,
            payload=payload or {},
            output_path=output_path,
            verify_tls=verify_tls,
            timeout=timeout,
        )
    method, path = _method_path(op_id)
    headers = _auth_headers(session_file, auth_header, base_url=base_url)
    status_code, response_payload, _text = request_json(
        method,
        _request_url(base_url, op_id, page=page, size=size, keywords=keywords),
        headers=headers,
        json_payload=None if op_id in GET_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise_if_device_session_rejected(status_code, response_payload)
        # 目标资源不存在 == 目标状态已达成（幂等删除契约，权威门见 errors.py 登记表）
        raise_if_resource_not_found(status_code, response_payload, op_id=op_id)
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "CRL device request did not return a success status.",
            {
                "op_id": op_id,
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    return {
        "op_id": op_id,
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": method,
            "path": path,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }


def _execute_upload(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    upload_file: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    """折叠驱动：暂存（仅 local）→ 注册。任一步失败即中断，不发出后续请求。"""
    val = payload.get("val") or {}
    upload_type = str(val.get("uploadType") or "local")
    headers = _auth_headers(session_file, auth_header, base_url=base_url)
    staged: dict[str, Any] | None = None

    if upload_type == "local":
        path = _validate_upload_file(upload_file)
        upload_headers = dict(headers)
        # multipart 由 requests 自行设置带 boundary 的 Content-Type，不能沿用 JSON 头。
        upload_headers.pop("Content-Type", None)
        status_code, response_payload, _text = request_multipart(
            f"{normalize_base_url(base_url)}{UPLOAD_PATH}",
            fields={"module": CRL_MODULE},
            files={"file": (path.name, path.read_bytes(), "application/octet-stream")},
            headers=upload_headers,
            timeout=timeout,
            verify_tls=verify_tls,
        )
        if status_code not in UPLOAD_STATUS:
            raise RunnerError(
                "RUNNER_CONFIG_REJECTED",
                "CRL file staging did not return a success status.",
                {
                    "step": "upload",
                    "status_code": status_code,
                    "err_code": response_payload.get("errCode"),
                    "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                },
            )
        staged = {
            "module": CRL_MODULE,
            "file_name": path.name,
            "file_size": path.stat().st_size,
            "status_code": status_code,
        }

    status_code, response_payload, _text = request_json(
        "PUT",
        f"{normalize_base_url(base_url)}{CERT_UPLOAD_PATH}",
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response_payload)
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "CRL registration did not return a success status.",
            {
                "step": "register",
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
            },
        )
    return {
        "op_id": "fw_config_crl",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "PUT",
            "path": CERT_UPLOAD_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "staged": staged,
        "response": response_payload,
    }


def _execute_download(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    output_path: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    """折叠驱动：触发下载（纯文本路径）→ 取字节落盘。

    触发接口回答的是 **plain text** 而非 JSON，故不能用 ``request_json``
    （非 JSON 根会抛 ``RUNNER_RESPONSE_INVALID``）；失败时设备返回 JSON 错误体，
    判据是文本不以 ``tmpcert`` 开头。
    """
    destination = _validate_output_path(output_path)
    headers = _auth_headers(session_file, auth_header, base_url=base_url)
    status_code, content = request_bytes(
        "PUT",
        f"{normalize_base_url(base_url)}{CERT_DOWNLOAD_PATH}",
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    text = content.decode("utf-8", "replace").strip()
    if status_code != 200 or not text.startswith(TMPCERT_PREFIX):
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "CRL download trigger did not return a temporary file path.",
            {
                "status_code": status_code,
                "body_excerpt": text[:200],
                "expected_prefix": TMPCERT_PREFIX,
            },
        )
    # 复用对象导出族的两步下载落盘（同一 tmpcert 路径语义，同一 ``/downloadfile`` 端点）。
    result = _download_and_store(
        text,
        destination,
        base_url=base_url,
        headers=headers,
        timeout=timeout,
        verify_tls=verify_tls,
        auth_header=auth_header,
    )
    result["op_id"] = "fw_download_crl"
    result["status"] = "success"
    result["request"] = {
        "method": "PUT",
        "path": CERT_DOWNLOAD_PATH,
        "auth": {"name": auth_header, "value": "<session-ref>"},
    }
    result["tmpcert_path"] = text
    return result


def _upload_steps(upload_file: str, payload: dict[str, Any] | None) -> list[dict[str, Any]]:
    val = (payload or {}).get("val") or {}
    if str(val.get("uploadType") or "local") == "http":
        return [
            {"method": "PUT", "path": CERT_UPLOAD_PATH,
             "note": "uploadType=http: the device fetches the file itself; no staging POST is sent"}
        ]
    return [
        {"method": "POST", "path": UPLOAD_PATH, "module": CRL_MODULE,
         "file": upload_file, "note": "stage the local .crl file"},
        {"method": "PUT", "path": CERT_UPLOAD_PATH, "note": "register the staged file"},
    ]


def _validate_upload_file(upload_file: str) -> Path:
    _validate_non_empty("file", upload_file)
    path = Path(upload_file).expanduser()
    if not path.is_file():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "CRL upload input must be an existing file.",
            {"field": "file", "value": str(path)},
        )
    return path


def _auth_headers(session_file: Path, auth_header: str, *, base_url: str) -> dict[str, str]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    return {"Content-Type": "application/json", auth_header: header_value}


def _request_url(base_url: str, op_id: str, *, page: int, size: int, keywords: str) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in PAGINATED_OPS:
        _validate_positive_int("page", page)
        _validate_positive_int("size", size)
        query: dict[str, Any] = {"page": page, "size": size}
        if keywords:
            query[SEARCH_QUERY_KEY] = keywords
        url = f"{url}?{urlencode(query, doseq=True)}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return CRL_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this CRL operation.",
            {"op_id": op_id},
        ) from exc


def _validate_batch_payload(payload: dict[str, Any]) -> dict[str, Any]:
    batch = payload.get("batch")
    if not isinstance(batch, list) or not batch:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Batch delete payload must contain a non-empty batch list.",
            {"field": "batch"},
        )
    for item in batch:
        if not isinstance(item, dict):
            raise RunnerError("RUNNER_VALIDATION_FAILED", "Batch item must be an object.", {"field": "batch"})
        if item.get("method") != "DELETE" or item.get("resource") != CRL_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                f"Batch delete only supports DELETE {CRL_RESOURCE} items.",
                {"method": item.get("method"), "resource": item.get("resource")},
            )
        body = item.get("body")
        ids = body.get("id") if isinstance(body, dict) else None
        if not isinstance(ids, list) or not ids:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch delete item body.id must be a non-empty list.",
                {"field": "batch"},
            )
    return payload


def _validate_choice(field: str, value: str, allowed: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"CRL {field} must be one of: {', '.join(allowed)}.",
            {"field": field, "value": value, "allowed": list(allowed)},
        )
    return value


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "CRL field is required and must be non-empty.",
            {"field": field},
        )


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "CRL field must be a positive integer.",
            {"field": field},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "CRL field must be a positive integer.",
            {"field": field, "value": value},
        )
    return parsed
