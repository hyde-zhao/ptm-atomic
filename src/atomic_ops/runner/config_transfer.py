"""NGFW configuration import/export runner.

Export workflow (3 steps over ``/api/v1/downloadfilehandle`` +
``/api/v1/downloadfile``):
    1. POST ``/api/v1/downloadfilehandle`` -> ``vals[0].downloadtaskid``
    2. GET  ``/api/v1/downloadfilehandle?id=<taskid>`` (poll) -> ``vals[0].filename``
    3. GET  ``/api/v1/downloadfile?id=<urlencoded filename>`` -> binary stream

Import workflow (4 steps over ``/api/v1/uploadfile`` +
``/api/v1/uploadfilehandle`` + ``/api/v1/importfile``):
    1. POST ``/api/v1/uploadfile`` (multipart) -> file staged on device
    2. POST ``/api/v1/uploadfilehandle`` -> ``vals[0].uploadtaskid``
    3. GET  ``/api/v1/uploadfilehandle?id=<taskid>`` (poll) -> ``msg == "success"``
    4. GET  ``/api/v1/importfile`` -> ``vals[0].havefile == true``

A reboot via :mod:`atomic_ops.runner.reboot` is required after import for the
configuration to take effect; it is intentionally a separate atom.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_bytes, request_json, request_multipart
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.polling import poll_until
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
DOWNLOAD_HANDLE_PATH = "/api/v1/downloadfilehandle"
DOWNLOAD_FILE_PATH = "/api/v1/downloadfile"
UPLOAD_FILE_PATH = "/api/v1/uploadfile"
UPLOAD_HANDLE_PATH = "/api/v1/uploadfilehandle"
IMPORT_FILE_PATH = "/api/v1/importfile"

DEFAULT_POLL_TIMEOUT_MS = 60000
DEFAULT_POLL_INTERVAL_MS = 2000


# ── payload builders ───────────────────────────────────────


def build_export_payload(*, moduletype: str, filetype: str, data_id: list[str] | None = None) -> dict[str, Any]:
    _validate_non_empty("moduletype", moduletype)
    _validate_non_empty("filetype", filetype)
    return {
        "val": {
            "dataId": list(data_id or []),
            "moduletype": moduletype,
            "filetype": filetype,
        }
    }


def build_import_handle_payload(
    *,
    moduletype: str,
    filetype: str,
    operationtype: str,
    chunkornot: bool = False,
) -> dict[str, Any]:
    _validate_non_empty("moduletype", moduletype)
    _validate_non_empty("filetype", filetype)
    _validate_non_empty("operationtype", operationtype)
    return {
        "val": {
            "chunkornot": bool(chunkornot),
            "moduletype": moduletype,
            "filetype": filetype,
            "operationtype": operationtype,
        }
    }


# ── validators ─────────────────────────────────────────────


def validate_export_payload(payload: dict[str, Any]) -> dict[str, Any]:
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError("RUNNER_VALIDATION_FAILED", "Export payload val object is required.", {"field": "val"})
    _validate_non_empty("moduletype", str(val.get("moduletype") or ""))
    _validate_non_empty("filetype", str(val.get("filetype") or ""))
    if not isinstance(val.get("dataId"), list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Export payload val.dataId must be a list.",
            {"field": "dataId"},
        )
    return payload


def validate_import_handle_payload(payload: dict[str, Any]) -> dict[str, Any]:
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError("RUNNER_VALIDATION_FAILED", "Import handle payload val object is required.", {"field": "val"})
    _validate_non_empty("moduletype", str(val.get("moduletype") or ""))
    _validate_non_empty("filetype", str(val.get("filetype") or ""))
    _validate_non_empty("operationtype", str(val.get("operationtype") or ""))
    return payload


def validate_output_path(output_path: str) -> Path:
    _validate_non_empty("output_path", output_path)
    path = Path(output_path).expanduser()
    parent = path.parent
    if not parent.exists():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Export output_path parent directory does not exist.",
            {"field": "output_path", "parent": str(parent)},
        )
    if path.exists() and not path.is_file():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Export output_path is not a regular file.",
            {"field": "output_path", "value": str(path)},
        )
    return path


def validate_input_path(input_path: str) -> Path:
    _validate_non_empty("input_path", input_path)
    path = Path(input_path).expanduser()
    if not path.is_file():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Import input_path must be an existing file.",
            {"field": "input_path", "value": str(path)},
        )
    return path


# ── dry-run envelopes ──────────────────────────────────────


def build_export_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    moduletype: str,
    filetype: str,
    output_path: str,
    data_id: list[str] | None,
    poll_timeout_ms: int,
    poll_interval_ms: int,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    payload = validate_export_payload(build_export_payload(moduletype=moduletype, filetype=filetype, data_id=data_id))
    return {
        "op_id": "fw_config_export_file",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "POST",
            "url": f"{normalize_base_url(base_url)}{DOWNLOAD_HANDLE_PATH}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "poll": {"timeout_ms": poll_timeout_ms, "interval_ms": poll_interval_ms},
        "download": {"path": DOWNLOAD_FILE_PATH, "output_path": output_path},
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def build_import_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    moduletype: str,
    filetype: str,
    operationtype: str,
    input_path: str,
    chunkornot: bool,
    poll_timeout_ms: int,
    poll_interval_ms: int,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    handle_payload = validate_import_handle_payload(
        build_import_handle_payload(
            moduletype=moduletype, filetype=filetype, operationtype=operationtype, chunkornot=chunkornot,
        )
    )
    return {
        "op_id": "fw_config_import_file",
        "status": "dry_run",
        "execute_required": True,
        "upload": {
            "method": "POST",
            "url": f"{normalize_base_url(base_url)}{UPLOAD_FILE_PATH}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "input_path": input_path,
            "fields": {"file_name": Path(input_path).name, "chunkornot": "no", "filetype": filetype},
        },
        "handle_request": {
            "method": "POST",
            "url": f"{normalize_base_url(base_url)}{UPLOAD_HANDLE_PATH}",
            "payload": handle_payload,
        },
        "poll": {"timeout_ms": poll_timeout_ms, "interval_ms": poll_interval_ms},
        "confirm": {"path": IMPORT_FILE_PATH},
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


# ── execute ───────────────────────────────────────────────


def execute_export_file(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    moduletype: str,
    filetype: str,
    output_path: str,
    data_id: list[str] | None,
    poll_timeout_ms: int,
    poll_interval_ms: int,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    payload = validate_export_payload(build_export_payload(moduletype=moduletype, filetype=filetype, data_id=data_id))
    out_path = validate_output_path(output_path)
    headers = _auth_headers(session_file, auth_header)

    # 步骤 1：发起下载任务，取 downloadtaskid
    status_code, response = _post_json(
        f"{normalize_base_url(base_url)}{DOWNLOAD_HANDLE_PATH}", headers, payload, timeout, verify_tls,
    )
    task_id = _extract_task_id(response, "downloadtaskid", "download")
    poll_url = f"{normalize_base_url(base_url)}{DOWNLOAD_HANDLE_PATH}?id={task_id}"

    # 步骤 2：轮询直到 filename 就绪
    filename = poll_until(
        lambda: _get_json(poll_url, headers, timeout, verify_tls),
        timeout_ms=poll_timeout_ms,
        interval_ms=poll_interval_ms,
        is_done=_export_task_done,
    )
    ready_filename = _extract_filename(filename)

    # 步骤 3：下载二进制写入本地
    download_url = f"{normalize_base_url(base_url)}{DOWNLOAD_FILE_PATH}?id={quote(ready_filename, safe='')}"
    dl_status, content = request_bytes(
        "GET", download_url, headers=headers, timeout=timeout, verify_tls=verify_tls,
    )
    if dl_status != 200:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Export file download did not return a success status.",
            {"status_code": dl_status, "url": _safe_url(download_url)},
        )
    out_path.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()

    return {
        "op_id": "fw_config_export_file",
        "status": "success",
        "moduletype": moduletype,
        "download_task_id": task_id,
        "file_ref": str(out_path),
        "file_size": len(content),
        "sha256": digest,
        "request": {"method": "POST", "path": DOWNLOAD_HANDLE_PATH, "auth": {"name": auth_header, "value": "<session-ref>"}},
        "response": {"filename": ready_filename, "status_code": dl_status},
    }


def execute_import_file(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    moduletype: str,
    filetype: str,
    operationtype: str,
    input_path: str,
    chunkornot: bool,
    poll_timeout_ms: int,
    poll_interval_ms: int,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    handle_payload = validate_import_handle_payload(
        build_import_handle_payload(
            moduletype=moduletype, filetype=filetype, operationtype=operationtype, chunkornot=chunkornot,
        )
    )
    in_path = validate_input_path(input_path)
    headers = _auth_headers(session_file, auth_header)
    # multipart 上传不要带 Content-Type，requests 会自动设置 boundary
    upload_headers = {auth_header: headers[auth_header]}

    # 步骤 1：multipart 上传文件
    with in_path.open("rb") as handle:
        files = {"filename": (in_path.name, handle, "application/gzip")}
        fields = {"file_name": in_path.name, "chunkornot": "no", "filetype": filetype}
        up_status, up_response = _post_multipart(
            f"{normalize_base_url(base_url)}{UPLOAD_FILE_PATH}", fields, files, upload_headers, timeout, verify_tls,
        )

    # 步骤 2：发起导入处理任务，取 uploadtaskid
    handle_status, handle_response = _post_json(
        f"{normalize_base_url(base_url)}{UPLOAD_HANDLE_PATH}", headers, handle_payload, timeout, verify_tls,
    )
    task_id = _extract_task_id(handle_response, "uploadtaskid", "import")

    # 步骤 3：轮询直到任务完成
    poll_url = f"{normalize_base_url(base_url)}{UPLOAD_HANDLE_PATH}?id={task_id}"
    poll_until(
        lambda: _get_json(poll_url, headers, timeout, verify_tls),
        timeout_ms=poll_timeout_ms,
        interval_ms=poll_interval_ms,
        is_done=_import_task_done,
    )

    # 步骤 4：确认 importfile
    confirm_url = f"{normalize_base_url(base_url)}{IMPORT_FILE_PATH}"
    confirm_response = _get_json(confirm_url, headers, timeout, verify_tls)
    havefile = _extract_havefile(confirm_response)

    return {
        "op_id": "fw_config_import_file",
        "status": "success",
        "moduletype": moduletype,
        "upload_task_id": task_id,
        "import_confirmed": bool(havefile),
        "havefile": bool(havefile),
        "request": {"method": "POST", "path": UPLOAD_FILE_PATH, "auth": {"name": auth_header, "value": "<session-ref>"}},
        "response": {"upload_status_code": up_status, "handle_status_code": handle_status, "havefile": havefile},
    }


# ── HTTP wrappers (centralize error mapping for multi-step flows) ──


def _auth_headers(session_file: Path, auth_header: str) -> dict[str, str]:
    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    return {"Content-Type": "application/json", auth_header: header_value}


def _post_json(url: str, headers: dict[str, str], payload: dict[str, Any], timeout: float, verify_tls: bool) -> tuple[int, dict[str, Any]]:
    status_code, response, _text = request_json(
        "POST", url, headers=headers, json_payload=payload, timeout=timeout, verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "Config transfer request did not return a success status.",
            {"status_code": status_code, "url": _safe_url(url), "err_msg": response.get("errMsg") or response.get("msg")},
        )
    return status_code, response


def _get_json(url: str, headers: dict[str, str], timeout: float, verify_tls: bool) -> dict[str, Any]:
    status_code, response, _text = request_json(
        "GET", url, headers=headers, json_payload=None, timeout=timeout, verify_tls=verify_tls,
    )
    if status_code not in GET_SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Config transfer query did not return a success status.",
            {"status_code": status_code, "url": _safe_url(url)},
        )
    return response


def _post_multipart(
    url: str,
    fields: dict[str, str],
    files: dict[str, tuple],
    headers: dict[str, str],
    timeout: float,
    verify_tls: bool,
) -> tuple[int, dict[str, Any]]:
    status_code, response, _text = request_multipart(
        url, fields=fields, files=files, headers=headers, timeout=timeout, verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "Config upload did not return a success status.",
            {"status_code": status_code, "url": _safe_url(url), "err_msg": response.get("errMsg") or response.get("msg")},
        )
    return status_code, response


# ── response extractors ────────────────────────────────────


def _extract_task_id(response: dict[str, Any], key: str, label: str) -> int:
    vals = response.get("vals")
    if not isinstance(vals, list) or not vals or not isinstance(vals[0], dict):
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            f"{label} response did not include a task id.",
            {"response_keys": sorted(response.keys())},
        )
    try:
        return int(vals[0].get(key))
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            f"{label} response task id is invalid.",
            {"field": key, "value": vals[0].get(key)},
        ) from exc


def _export_task_done(response: dict[str, Any]) -> bool:
    vals = response.get("vals")
    if isinstance(vals, list) and vals and isinstance(vals[0], dict):
        filename = vals[0].get("filename")
        return isinstance(filename, str) and bool(filename.strip())
    return False


def _extract_filename(response: dict[str, Any]) -> str:
    vals = response.get("vals")
    if not isinstance(vals, list) or not vals or not isinstance(vals[0], dict):
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Export poll response did not include a filename.",
            {"response_keys": sorted(response.keys())},
        )
    filename = vals[0].get("filename")
    if not isinstance(filename, str) or not filename.strip():
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Export poll response filename is empty.",
            {"field": "filename"},
        )
    return filename


def _import_task_done(response: dict[str, Any]) -> bool:
    return str(response.get("msg") or "").lower() == "success"


def _extract_havefile(response: dict[str, Any]) -> bool:
    vals = response.get("vals")
    if isinstance(vals, list) and vals and isinstance(vals[0], dict):
        return bool(vals[0].get("havefile"))
    return False


# ── shared helpers ─────────────────────────────────────────


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required config transfer field is empty.",
            {"field": field},
        )


def _safe_url(url: str) -> str:
    return url.split("?", 1)[0]
