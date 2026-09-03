"""NGFW object data import/export runner.

Object-level (per-module) Excel import/export is distinct from the whole-system
configuration transfer in :mod:`atomic_ops.runner.config_transfer`. It moves
module data such as ippool / ip6pool / macpool / domainpool / geoip / serpool
through five shared REST endpoints:

    1. POST ``/api/v1/upload``         multipart (module + .xlsx) -> staged path
    2. POST ``/api/v1/dataimport``     starts the async import task
    3. PUT  ``/api/v1/ip4policy/exportpolicy``   generates an export file
    4. GET  ``/api/v1/dataexport``     alternative export generation trigger
    5. GET  ``/api/v1/downloadfile``   downloads a template or export file

Evidence sources: ``导入+导出规范文档.txt`` and the <DUT_IP> captures in
``导入+导出.txt``. Not every module exposes every step (for example no import
capture exists for ``ip4group`` and no export trigger capture exists for
``macpool``/``domainpool``/``geoip``/``serpool``); module validation below only
accepts the endpoint/module pairs the captures document.

Export naming: generated export files live under ``exportDir/<module>_<ts>.xlsx``
where ``<ts>`` is a server timestamp. The id is learned from the trigger
response when the device returns it; the runner never fabricates a timestamp.

Import flow notes:
    - ``/api/v1/upload`` returns the server path of the staged file. The
      runner prefers the path parsed from the response and falls back to the
      documented ``/userdata/userfile/policyfile/<module>/<basename>`` pattern
      when the response carries no path.
    - ``/api/v1/dataimport`` is asynchronous: ``{"data":"导入任务启动成功"}``
      only means the task was accepted, not that the rows landed. No task
      completion endpoint is documented, so the op reports acceptance.
    - ``is_skip_dup=true`` (default) skips duplicate entries; ``false``
      overrides or rejects them depending on the device.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import quote

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_bytes, request_json, request_multipart
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file

SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

UPLOAD_PATH = "/api/v1/upload"
DATA_IMPORT_PATH = "/api/v1/dataimport"
EXPORT_POLICY_PATH = "/api/v1/ip4policy/exportpolicy"
DATA_EXPORT_PATH = "/api/v1/dataexport"
DOWNLOAD_FILE_PATH = "/api/v1/downloadfile"

XLSX_MIME = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
XLSX_EXTENSIONS = (".xlsx",)

# Module sets documented by the capture evidence.
IMPORT_MODULES = (
    "ippool",
    "ip6pool",
    "ip6group",
    "macpool",
    "domainpool",
    "geoip",
    "serpool",
    "sergrouppool",
    "appObject",
    "urlObject",
)
EXPORT_POLICY_MODULES = ("ippool", "ip6pool", "ip4group")
# The spec documents ip6pool; 55.63 probes (2026-09-03) confirmed ippool,
# macpool and geoip answer /api/v1/dataexport with the same exportDir shape.
DATA_EXPORT_MODULES = ("ippool", "ip6pool", "macpool", "geoip")

# Fields inspected (in order) when a response must name a staged or generated
# file. Key shapes differ across device versions; generic candidates keep the
# runner honest without inventing the id.
_PATH_KEY_CANDIDATES = ("file_name", "fileName", "file_path", "path", "url", "data", "filename", "msg")
_STORAGE_HINTS = ("/userdata/userfile/policyfile/", "exportDir/", "temp/", "policyfile/")


def _is_module(value: str, allowed: tuple[str, ...], label: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"Required object transfer field is empty: {label}.",
            {"field": label},
        )
    if value not in allowed:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"Module type {value!r} is not documented for this operation.",
            {"field": label, "value": value, "supported": list(allowed)},
            suggestion=f"Use one of the documented module types: {', '.join(allowed)}.",
        )


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required object transfer field is empty.",
            {"field": field},
        )


def _is_xlsx_path(path: Path) -> None:
    if not path.is_file():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Import input_path must be an existing file.",
            {"field": "input_path", "value": str(path)},
        )
    if not str(path).lower().endswith(XLSX_EXTENSIONS):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Import input file must have an .xlsx extension.",
            {"field": "input_path", "value": str(path)},
        )


def _validate_output_path(output_path: str) -> Path:
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


# ── payload builders ───────────────────────────────────────


def build_import_payload(*, module: str, file_name: str, is_skip_dup: bool) -> dict[str, Any]:
    return {
        "val": {
            "file_name": file_name,
            "module_type": module,
            "is_skip_dup": bool(is_skip_dup),
        }
    }


def build_export_policy_payload(*, module: str) -> dict[str, Any]:
    return {"id": "0", "val": {"uploadType": module}}


def validate_import_payload(payload: dict[str, Any]) -> dict[str, Any]:
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Import payload val object is required.",
            {"field": "val"},
        )
    _is_module(str(val.get("module_type") or ""), IMPORT_MODULES, "module_type")
    _validate_non_empty("file_name", str(val.get("file_name") or ""))
    return payload


def validate_export_policy_payload(payload: dict[str, Any]) -> dict[str, Any]:
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Export policy payload val object is required.",
            {"field": "val"},
        )
    _is_module(str(val.get("uploadType") or ""), EXPORT_POLICY_MODULES, "uploadType")
    return payload


# ── file id extraction (shared by upload and export triggers) ──


def _collect_strings(node: Any, out: list[tuple[str, str]]) -> None:
    if isinstance(node, dict):
        for key, value in node.items():
            if isinstance(value, str):
                out.append((str(key), value))
            else:
                _collect_strings(value, out)
    elif isinstance(node, list):
        for item in node:
            _collect_strings(item, out)


def _looks_like_file_ref(value: str, *, hints: tuple[str, ...]) -> bool:
    if not value or not value.endswith(".xlsx"):
        return False
    return any(hint in value for hint in hints)


def extract_file_ref(response: dict[str, Any], *, hints: tuple[str, ...]) -> str | None:
    """Return the best file reference (server path or exportDir/temp id) in a response.

    Walks the response JSON for string values that carry one of the storage
    hints and end in .xlsx. Explicitly named path keys are preferred; the
    first matching generic string is the fallback. Returns None when the
    device response does not name a file.
    """
    if not isinstance(response, dict):
        return None
    strings: list[tuple[str, str]] = []
    _collect_strings(response, strings)
    for key in _PATH_KEY_CANDIDATES:
        for seen_key, value in strings:
            if seen_key == key and _looks_like_file_ref(value, hints=hints):
                return value
    for seen_key, value in strings:
        if seen_key in _PATH_KEY_CANDIDATES:
            continue
        if _looks_like_file_ref(value, hints=hints):
            return value
    return None


def derive_import_path(module: str, uploaded_name: str) -> str:
    """Fallback server path when /upload returns no path:
    /userdata/userfile/policyfile/<module>/<basename> (capture-consistent)."""
    return f"/userdata/userfile/policyfile/{module}/{uploaded_name}"


# ── auth / HTTP wrappers ──────────────────────────────────


def _auth_headers(session_file: Path, auth_header: str) -> dict[str, str]:
    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    return {"Content-Type": "application/json", auth_header: header_value}


def _post_json(url: str, headers: dict[str, str], payload: dict[str, Any], timeout: float, verify_tls: bool, label: str, method: str = "POST") -> tuple[int, dict[str, Any]]:
    """Send a JSON body request; ``method`` defaults to POST but endpoints like
    the exportpolicy template trigger require PUT."""
    status_code, response, _text = request_json(
        method, url, headers=headers, json_payload=payload, timeout=timeout, verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_OBJECT_TRANSFER_REJECTED",
            f"Object transfer request was rejected ({label}).",
            {"status_code": status_code, "url": _safe_url(url), "err_msg": response.get("errMsg") or response.get("msg")},
        )
    return status_code, response


def _get_json(url: str, headers: dict[str, str], timeout: float, verify_tls: bool, label: str) -> dict[str, Any]:
    status_code, response, _text = request_json(
        "GET", url, headers=headers, json_payload=None, timeout=timeout, verify_tls=verify_tls,
    )
    if status_code not in GET_SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            f"Object transfer query did not return a success status ({label}).",
            {"status_code": status_code, "url": _safe_url(url)},
        )
    return response


def _safe_url(url: str) -> str:
    return url.split("?", 1)[0]


def _download_and_store(download_id: str, output_path: Path, *, base_url: str, headers: dict[str, str], timeout: float, verify_tls: bool, auth_header: str) -> dict[str, Any]:
    download_url = f"{normalize_base_url(base_url)}{DOWNLOAD_FILE_PATH}?id={quote(download_id, safe='')}"
    dl_status, content = request_bytes(
        "GET", download_url, headers=headers, timeout=timeout, verify_tls=verify_tls,
    )
    if dl_status != 200:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Object file download did not return a success status.",
            {"status_code": dl_status, "url": _safe_url(download_url)},
        )
    if not content:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Object file download returned an empty body.",
            {"file_id": download_id, "url": _safe_url(download_url)},
        )
    output_path.write_bytes(content)
    return {
        "download": {
            "method": "GET",
            "path": DOWNLOAD_FILE_PATH,
            "file_id": download_id,
            "output_path": str(output_path),
            "file_size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
            "auth": {"name": auth_header, "value": "<session-ref>"},
        }
    }


# ── dry-run envelopes ──────────────────────────────────────


def build_object_import_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    module: str,
    input_path: str,
    is_skip_dup: bool,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    in_path = Path(input_path).expanduser()
    staged_path = derive_import_path(module, in_path.name)
    payload = validate_import_payload(build_import_payload(module=module, file_name=staged_path, is_skip_dup=is_skip_dup))
    return {
        "op_id": "fw_import_object_file",
        "status": "dry_run",
        "execute_required": True,
        "upload": {
            "method": "POST",
            "url": f"{normalize_base_url(base_url)}{UPLOAD_PATH}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "extra_headers": {"X-Requested-With": "XMLHttpRequest"},
            "fields": {"module": module},
            "file_field": "file",
            "input_path": str(in_path),
            "content_type": XLSX_MIME,
        },
        "import_request": {
            "method": "POST",
            "url": f"{normalize_base_url(base_url)}{DATA_IMPORT_PATH}",
            "payload": payload,
            "staged_path_fallback": staged_path,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def build_object_export_policy_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    module: str,
    output_path: str | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    payload = validate_export_policy_payload(build_export_policy_payload(module=module))
    return {
        "op_id": "fw_export_object_policy",
        "status": "dry_run",
        "execute_required": True,
        "trigger": {
            "method": "PUT",
            "url": f"{normalize_base_url(base_url)}{EXPORT_POLICY_PATH}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "download": {"path": DOWNLOAD_FILE_PATH, "output_path": output_path} if output_path else None,
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def build_object_export_data_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    module: str,
    output_path: str | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    _is_module(module, DATA_EXPORT_MODULES, "module")
    return {
        "op_id": "fw_export_object_data",
        "status": "dry_run",
        "execute_required": True,
        "trigger": {
            "method": "GET",
            "url": f"{normalize_base_url(base_url)}{DATA_EXPORT_PATH}?type={module}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "download": {"path": DOWNLOAD_FILE_PATH, "output_path": output_path} if output_path else None,
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def build_object_download_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    file_id: str,
    output_path: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    _validate_non_empty("file_id", file_id)
    return {
        "op_id": "fw_download_object_file",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": f"{normalize_base_url(base_url)}{DOWNLOAD_FILE_PATH}?id={quote(file_id, safe='')}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "download": {"file_id": file_id, "output_path": output_path},
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


# ── execute ───────────────────────────────────────────────


def execute_object_import(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    module: str,
    input_path: str,
    is_skip_dup: bool,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    _is_module(module, IMPORT_MODULES, "module")
    in_path = Path(input_path).expanduser()
    _is_xlsx_path(in_path)
    headers = _auth_headers(session_file, auth_header)

    # 步骤 1：multipart 上传到 /api/v1/upload
    upload_headers = {auth_header: headers[auth_header], "X-Requested-With": "XMLHttpRequest"}
    with in_path.open("rb") as handle:
        files = {"file": (in_path.name, handle, XLSX_MIME)}
        fields = {"module": module}
        up_status, up_response, _up_text = request_multipart(
            f"{normalize_base_url(base_url)}{UPLOAD_PATH}",
            fields=fields,
            files=files,
            headers=upload_headers,
            timeout=timeout,
            verify_tls=verify_tls,
        )
    if up_status not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_OBJECT_TRANSFER_REJECTED",
            "Object file upload did not return a success status.",
            {"status_code": up_status, "url": _safe_url(f"{normalize_base_url(base_url)}{UPLOAD_PATH}"),
             "err_msg": up_response.get("errMsg") or up_response.get("msg")},
        )

    derived_path = derive_import_path(module, in_path.name)
    staged_path = extract_file_ref(up_response, hints=_STORAGE_HINTS) or derived_path
    staged_source = "response" if staged_path != derived_path else "derived"

    # 步骤 2：POST /api/v1/dataimport 启动异步导入
    import_payload = validate_import_payload(
        build_import_payload(module=module, file_name=staged_path, is_skip_dup=is_skip_dup)
    )
    import_status, import_response = _post_json(
        f"{normalize_base_url(base_url)}{DATA_IMPORT_PATH}", headers, import_payload, timeout, verify_tls, "dataimport"
    )

    return {
        "op_id": "fw_import_object_file",
        "status": "success",
        "module_type": module,
        "input_file": str(in_path),
        "staged_file": staged_path,
        "staged_path_source": staged_source,
        "is_skip_dup": bool(is_skip_dup),
        "import_message": import_response.get("data") or import_response.get("msg"),
        "request": {"method": "POST", "path": UPLOAD_PATH, "auth": {"name": auth_header, "value": "<session-ref>"}},
        "response": {
            "upload_status_code": up_status,
            "import_status_code": import_status,
            "import_body": import_response,
        },
    }


def _run_export_trigger(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    module: str,
    output_path: str | None,
    verify_tls: bool,
    timeout: float,
    trigger_request: dict[str, Any],
    request_desc: dict[str, Any],
) -> dict[str, Any]:
    """Shared tail of the two export trigger executors.

    ``trigger_request`` has already performed the trigger HTTP call and
    returns ``(method_label, status_code, response)``; ``request_desc`` names
    the request for the result envelope. When ``output_path`` is given the
    export file id must come out of the trigger response.
    """
    _validate_output_path(output_path) if output_path else None
    method_label, trigger_status, trigger_response = trigger_request
    export_file_id = extract_file_ref(trigger_response, hints=_STORAGE_HINTS)

    result: dict[str, Any] = {
        "op_id": op_id,
        "status": "success",
        "module_type": module,
        "export_file_id": export_file_id,
        "request": request_desc,
        "response": {"trigger_status_code": trigger_status, "trigger_body": trigger_response},
    }
    if output_path and export_file_id:
        result.update(_download_and_store(
            export_file_id, Path(output_path).expanduser(),
            base_url=base_url, headers=_auth_headers(session_file, auth_header),
            timeout=timeout, verify_tls=verify_tls, auth_header=auth_header,
        ))
    elif output_path:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Export trigger response did not name the generated export file.",
            {"module_type": module, "response_keys": sorted(trigger_response.keys()) if isinstance(trigger_response, dict) else None},
            suggestion="Pass the export file id explicitly to fw_download_object_file once the device has generated it.",
        )
    return result


def execute_object_export_policy(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    module: str,
    output_path: str | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    payload = validate_export_policy_payload(build_export_policy_payload(module=module))
    headers = _auth_headers(session_file, auth_header)
    status_code, response = _post_json(
        f"{normalize_base_url(base_url)}{EXPORT_POLICY_PATH}", headers, payload, timeout, verify_tls, "exportpolicy",
        method="PUT",
    )
    return _run_export_trigger(
        op_id="fw_export_object_policy",
        base_url=base_url, session_file=session_file, auth_header=auth_header,
        module=module, output_path=output_path, verify_tls=verify_tls, timeout=timeout,
        trigger_request=("PUT", status_code, response),
        request_desc={"method": "PUT", "path": EXPORT_POLICY_PATH, "auth": {"name": auth_header, "value": "<session-ref>"}},
    )


def execute_object_export_data(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    module: str,
    output_path: str | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    _is_module(module, DATA_EXPORT_MODULES, "module")
    headers = _auth_headers(session_file, auth_header)
    url = f"{normalize_base_url(base_url)}{DATA_EXPORT_PATH}?type={module}"
    response = _get_json(url, headers, timeout, verify_tls, "dataexport")
    return _run_export_trigger(
        op_id="fw_export_object_data",
        base_url=base_url, session_file=session_file, auth_header=auth_header,
        module=module, output_path=output_path, verify_tls=verify_tls, timeout=timeout,
        trigger_request=("GET", 200, response),
        request_desc={"method": "GET", "path": DATA_EXPORT_PATH, "auth": {"name": auth_header, "value": "<session-ref>"}},
    )


def execute_object_download(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    file_id: str,
    output_path: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    _validate_non_empty("file_id", file_id)
    out_path = _validate_output_path(output_path)
    result = _download_and_store(
        file_id, out_path,
        base_url=base_url, headers=_auth_headers(session_file, auth_header),
        timeout=timeout, verify_tls=verify_tls, auth_header=auth_header,
    )
    return {
        "op_id": "fw_download_object_file",
        "status": "success",
        "file_id": file_id,
        "request": {"method": "GET", "path": DOWNLOAD_FILE_PATH, "auth": {"name": auth_header, "value": "<session-ref>"}},
        "response": result["download"],
    }
