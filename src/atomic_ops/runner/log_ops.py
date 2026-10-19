"""NGFW IPS 日志管理 runner。

覆盖用户补充的日志能力：

- 导出：GET /api/v1/export?id=logexport&logtype=ipslog&type=csv&timetype=...
- 清除：DELETE /api/v1/deletelog?logtype=ipslog
- 备份/保留时间设置：PUT/GET /api/v1/logsetting/logtimesetting
- 日志缓存设置读取：GET /api/v1/logsetting/logcacheset
- 备份文件列表：GET /api/v1/logsetting/logbackcsv
- 导出/下载任务三段式：POST/GET /api/v1/downloadfilehandle +
  GET /api/v1/downloadfile

除日志缓存设置的 PUT 已在 runner/ips.py 中实现外，其余只读/管理操作
都放在本模块。响应结构未在文档中给出的部分一律原样返回，不做字段重映射。
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
from atomic_ops.runner.http import request_bytes, request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

EXPORT_PATH = "/api/v1/export"
DELETE_LOG_PATH = "/api/v1/deletelog"
LOG_TIME_SETTING_PATH = "/api/v1/logsetting/logtimesetting"
LOG_CACHE_SETTING_PATH = "/api/v1/logsetting/logcacheset"
LOG_BACKUP_LIST_PATH = "/api/v1/logsetting/logbackcsv"
DOWNLOAD_FILE_HANDLE_PATH = "/api/v1/downloadfilehandle"
DOWNLOAD_FILE_PATH = "/api/v1/downloadfile"

LOG_TYPES = ("ipslog",)
EXPORT_TYPES = ("csv",)
TIMETYPES = ("24h", "all", "1h", "7d", "1m", "custom")


# ── 日志导出 ──────────────────────────────────────────────


def build_ips_log_export_query(
    *,
    logtype: str = "ipslog",
    export_type: str = "csv",
    timetype: str = "24h",
    starttime: int | str | None = None,
    endtime: int | str | None = None,
) -> dict[str, Any]:
    _validate_choice("logtype", logtype, LOG_TYPES)
    _validate_choice("type", export_type, EXPORT_TYPES)
    _validate_choice("timetype", timetype, TIMETYPES)
    query: dict[str, Any] = {
        "id": "logexport",
        "logtype": logtype,
        "type": export_type,
        "timetype": timetype,
    }
    if timetype == "custom":
        if starttime is None or endtime is None:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Custom timetype requires both starttime and endtime.",
                {"fields": ["starttime", "endtime"]},
            )
        query["starttime"] = _validate_non_negative_int("starttime", starttime)
        query["endtime"] = _validate_non_negative_int("endtime", endtime)
    return query


def build_ips_log_export_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    query: dict[str, Any],
    output_path: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    _validate_output_path("output_path", output_path)
    return {
        "op_id": "fw_export_ips_log",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": f"{normalize_base_url(base_url)}{EXPORT_PATH}?{urlencode(query)}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "download": {"output_path": output_path},
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_ips_log_export(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    query: dict[str, Any],
    output_path: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    target = _validate_output_path("output_path", output_path)
    headers = _session_headers(session_file, auth_header, base_url=base_url)
    url = f"{normalize_base_url(base_url)}{EXPORT_PATH}?{urlencode(query)}"
    status_code, content = request_bytes(
        "GET", url, headers=headers, timeout=timeout, verify_tls=verify_tls,
    )
    if status_code != 200:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "IPS log export did not return a success status.",
            {"op_id": "fw_export_ips_log", "status_code": status_code},
        )
    target.write_bytes(content)
    result: dict[str, Any] = {
        "op_id": "fw_export_ips_log",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "GET",
            "path": EXPORT_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "query": dict(query),
        },
        "download": {
            "output_path": str(target),
            "file_size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        },
    }
    # 导出端点通常直接返回 CSV 字节；若设备改为返回 JSON，则原样暴露但不解析。
    try:
        parsed = json.loads(content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        parsed = None
    if isinstance(parsed, dict):
        result["response"] = parsed
    return result


# ── 日志清除 ──────────────────────────────────────────────


def build_clear_ips_log_query(*, logtype: str = "ipslog") -> dict[str, str]:
    _validate_choice("logtype", logtype, LOG_TYPES)
    return {"logtype": logtype}


def build_clear_ips_log_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    query: dict[str, str],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_clear_ips_log",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "DELETE",
            "url": f"{normalize_base_url(base_url)}{DELETE_LOG_PATH}?{urlencode(query)}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_clear_ips_log(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    query: dict[str, str],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    headers = _session_headers(session_file, auth_header, base_url=base_url)
    status_code, response_payload, _text = request_json(
        "DELETE",
        f"{normalize_base_url(base_url)}{DELETE_LOG_PATH}?{urlencode(query)}",
        headers=headers,
        json_payload=None,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response_payload, op_id="fw_clear_ips_log")
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "IPS log clear did not return a success status.",
            {
                "op_id": "fw_clear_ips_log",
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
            },
        )
    return {
        "op_id": "fw_clear_ips_log",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "DELETE",
            "path": DELETE_LOG_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "query": dict(query),
        },
        "response": response_payload,
        "cleared": True,
        "logtype": query.get("logtype"),
    }


# ── 备份/保留时间设置 ─────────────────────────────────────


def build_log_time_set_payload(*, id: str = "0", time_set: int | str = 180) -> dict[str, Any]:
    if not isinstance(id, str) or not id.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Log time-setting id must be a non-empty string (captured value: 0).",
            {"field": "id", "value": id},
        )
    return {
        "id": id,
        "val": {"timeSet": _validate_non_negative_int("timeSet", time_set)},
    }


def build_log_time_set_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_config_log_time_set",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "PUT",
            "url": f"{normalize_base_url(base_url)}{LOG_TIME_SETTING_PATH}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_log_time_set(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    headers = _session_headers(session_file, auth_header, base_url=base_url)
    status_code, response_payload, _text = request_json(
        "PUT",
        f"{normalize_base_url(base_url)}{LOG_TIME_SETTING_PATH}",
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response_payload, op_id="fw_config_log_time_set")
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "Log time-setting request did not return a success status.",
            {
                "op_id": "fw_config_log_time_set",
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
            },
        )
    val = payload.get("val") if isinstance(payload.get("val"), dict) else {}
    return {
        "op_id": "fw_config_log_time_set",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "PUT",
            "path": LOG_TIME_SETTING_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
        "requested_time_set": val.get("timeSet"),
    }


def build_log_time_verify_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_verify_log_time_set",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": f"{normalize_base_url(base_url)}{LOG_TIME_SETTING_PATH}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_log_time_verify(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    response_payload = _get_json(
        f"{normalize_base_url(base_url)}{LOG_TIME_SETTING_PATH}",
        session_file,
        auth_header,
        base_url=base_url,
        timeout=timeout,
        verify_tls=verify_tls,
        op_id="fw_verify_log_time_set",
    )
    return {
        "op_id": "fw_verify_log_time_set",
        "status": "success",
        "status_code": 200,
        "request": {
            "method": "GET",
            "path": LOG_TIME_SETTING_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
        "time_set": _extract_time_set(response_payload),
    }


# ── 日志缓存设置读取 ──────────────────────────────────────


def build_log_cache_verify_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_verify_log_cache_set",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": f"{normalize_base_url(base_url)}{LOG_CACHE_SETTING_PATH}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_log_cache_verify(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    response_payload = _get_json(
        f"{normalize_base_url(base_url)}{LOG_CACHE_SETTING_PATH}",
        session_file,
        auth_header,
        base_url=base_url,
        timeout=timeout,
        verify_tls=verify_tls,
        op_id="fw_verify_log_cache_set",
    )
    return {
        "op_id": "fw_verify_log_cache_set",
        "status": "success",
        "status_code": 200,
        "request": {
            "method": "GET",
            "path": LOG_CACHE_SETTING_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
        "enabled": _extract_bool(response_payload, ("enable", "enabled")),
        "time_set": _extract_time_set(response_payload),
    }


# ── 备份文件列表 ──────────────────────────────────────────


def build_log_backup_list_query(
    *,
    page: int | str = 1,
    size: int | str = 10,
    keywords: str = "",
) -> dict[str, Any]:
    return {
        "page": _validate_positive_int("page", page),
        "size": _validate_positive_int("size", size),
        "keywords": "" if keywords is None else str(keywords),
    }


def build_log_backup_list_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    query: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_verify_log_backup_list",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": f"{normalize_base_url(base_url)}{LOG_BACKUP_LIST_PATH}?{urlencode(query)}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_log_backup_list(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    query: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    response_payload = _get_json(
        f"{normalize_base_url(base_url)}{LOG_BACKUP_LIST_PATH}?{urlencode(query)}",
        session_file,
        auth_header,
        base_url=base_url,
        timeout=timeout,
        verify_tls=verify_tls,
        op_id="fw_verify_log_backup_list",
    )
    vals = response_payload.get("vals")
    backup_files: list[dict[str, Any]] = []
    if isinstance(vals, list):
        for item in vals:
            if not isinstance(item, dict):
                continue
            backup_files.append(
                {
                    "name": item.get("name"),
                    "mtime": item.get("mtime"),
                    "logtype": item.get("logtype"),
                }
            )
    return {
        "op_id": "fw_verify_log_backup_list",
        "status": "success",
        "status_code": 200,
        "request": {
            "method": "GET",
            "path": LOG_BACKUP_LIST_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "query": dict(query),
        },
        "response": response_payload,
        "count": response_payload.get("count"),
        "backup_files": backup_files,
    }


# ── 日志下载任务三段式 ────────────────────────────────────


def build_log_download_task_payload(
    *,
    data_ids: list[str],
    moduletype: str = "influxTask",
    filetype: str = "csv",
) -> dict[str, Any]:
    if not isinstance(data_ids, list) or not data_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one dataId is required for a log download task.",
            {"field": "dataId"},
        )
    normalized_ids: list[str] = []
    for item in data_ids:
        if not isinstance(item, str) or not item.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each dataId must be a non-empty string.",
                {"field": "dataId", "value": item},
            )
        normalized_ids.append(item)
    _validate_choice("moduletype", moduletype, ("influxTask",))
    _validate_choice("filetype", filetype, EXPORT_TYPES)
    return {
        "val": {
            "dataId": normalized_ids,
            "moduletype": moduletype,
            "filetype": filetype,
        }
    }


def build_log_download_task_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_create_log_download_task",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "POST",
            "url": f"{normalize_base_url(base_url)}{DOWNLOAD_FILE_HANDLE_PATH}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_log_download_task(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    headers = _session_headers(session_file, auth_header, base_url=base_url)
    status_code, response_payload, _text = request_json(
        "POST",
        f"{normalize_base_url(base_url)}{DOWNLOAD_FILE_HANDLE_PATH}",
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response_payload, op_id="fw_create_log_download_task")
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "Log download-task creation did not return a success status.",
            {
                "op_id": "fw_create_log_download_task",
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
            },
        )
    task_id = _extract_first_value(
        response_payload,
        ("downloadtaskid", "taskid", "task_id", "id"),
    )
    if task_id is None:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Log download-task response did not include a task id.",
            {"op_id": "fw_create_log_download_task", "response_keys": sorted(response_payload.keys())},
        )
    return {
        "op_id": "fw_create_log_download_task",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "POST",
            "path": DOWNLOAD_FILE_HANDLE_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
        "task_id": task_id,
    }


def build_log_download_task_verify_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    task_id: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    _validate_non_empty("task_id", task_id)
    return {
        "op_id": "fw_verify_log_download_task",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": f"{normalize_base_url(base_url)}{DOWNLOAD_FILE_HANDLE_PATH}?{urlencode({'id': task_id})}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_log_download_task_verify(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    task_id: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    _validate_non_empty("task_id", task_id)
    url = f"{normalize_base_url(base_url)}{DOWNLOAD_FILE_HANDLE_PATH}?{urlencode({'id': task_id})}"
    response_payload = _get_json(
        url,
        session_file,
        auth_header,
        base_url=base_url,
        timeout=timeout,
        verify_tls=verify_tls,
        op_id="fw_verify_log_download_task",
    )
    filename = _extract_first_value(response_payload, ("filename", "fileName"))
    return {
        "op_id": "fw_verify_log_download_task",
        "status": "success",
        "status_code": 200,
        "request": {
            "method": "GET",
            "path": DOWNLOAD_FILE_HANDLE_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "query": {"id": task_id},
        },
        "response": response_payload,
        "task_id": task_id,
        "filename": filename,
        "ready": isinstance(filename, str) and bool(filename.strip()),
    }


def build_download_log_file_dry_run(
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
    _validate_output_path("output_path", output_path)
    return {
        "op_id": "fw_download_log_file",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": f"{normalize_base_url(base_url)}{DOWNLOAD_FILE_PATH}?id={quote(file_id, safe='')}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "download": {"file_id": file_id, "output_path": output_path},
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_download_log_file(
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
    target = _validate_output_path("output_path", output_path)
    headers = _session_headers(session_file, auth_header, base_url=base_url)
    url = f"{normalize_base_url(base_url)}{DOWNLOAD_FILE_PATH}?id={quote(file_id, safe='')}"
    status_code, content = request_bytes(
        "GET", url, headers=headers, timeout=timeout, verify_tls=verify_tls,
    )
    if status_code != 200:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Log file download did not return a success status.",
            {"op_id": "fw_download_log_file", "status_code": status_code},
        )
    if not content:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Log file download returned an empty body.",
            {"op_id": "fw_download_log_file", "file_id": file_id},
        )
    target.write_bytes(content)
    return {
        "op_id": "fw_download_log_file",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "GET",
            "path": DOWNLOAD_FILE_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "download": {
            "file_id": file_id,
            "output_path": str(target),
            "file_size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        },
    }


# ── 内部 helper ───────────────────────────────────────────


def _session_headers(session_file: Path, auth_header: str, *, base_url: str) -> dict[str, str]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    return {"Content-Type": "application/json", auth_header: header_value}


def _get_json(
    url: str,
    session_file: Path,
    auth_header: str,
    *,
    base_url: str,
    timeout: float,
    verify_tls: bool,
    op_id: str,
) -> dict[str, Any]:
    headers = _session_headers(session_file, auth_header, base_url=base_url)
    status_code, response_payload, _text = request_json(
        "GET", url, headers=headers, json_payload=None, timeout=timeout, verify_tls=verify_tls,
    )
    if status_code not in GET_SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response_payload, op_id=op_id)
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Log query did not return a success status.",
            {
                "op_id": op_id,
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
            },
        )
    return response_payload


def _extract_time_set(response_payload: dict[str, Any]) -> Any:
    for container in (response_payload, response_payload.get("val"), _first_val(response_payload)):
        if isinstance(container, dict) and "timeSet" in container:
            return container.get("timeSet")
    return None


def _extract_bool(response_payload: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for container in (response_payload, response_payload.get("val"), _first_val(response_payload)):
        if isinstance(container, dict):
            for key in keys:
                if key in container:
                    return container.get(key)
    return None


def _extract_first_value(response_payload: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for container in (response_payload, _first_val(response_payload)):
        if isinstance(container, dict):
            for key in keys:
                value = container.get(key)
                if value is not None and value != "":
                    return value
    return None


def _first_val(response_payload: dict[str, Any]) -> dict[str, Any]:
    vals = response_payload.get("vals")
    if isinstance(vals, list) and vals and isinstance(vals[0], dict):
        return vals[0]
    return {}


def _validate_choice(field: str, value: str, allowed: tuple[str, ...]) -> None:
    if value not in allowed:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} is unsupported for this log operation.",
            {"field": field, "value": value, "allowed": list(allowed)},
        )


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required log field is empty.",
            {"field": field},
        )


def _validate_positive_int(field: str, value: int | str) -> int:
    parsed = _validate_non_negative_int(field, value)
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Log pagination field must be positive.",
            {"field": field, "value": value},
        )
    return parsed


def _validate_non_negative_int(field: str, value: int | str) -> int:
    if isinstance(value, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Log field must be a non-negative integer.",
            {"field": field, "value": value},
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Log field must be a non-negative integer.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Log field must be non-negative.",
            {"field": field, "value": value},
        )
    return parsed


def _validate_output_path(field: str, value: str) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Output path is required.",
            {"field": field},
        )
    path = Path(value).expanduser()
    if not path.parent.exists():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Output path parent directory does not exist.",
            {"field": field, "parent": str(path.parent)},
        )
    if path.exists() and not path.is_file():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Output path is not a regular file.",
            {"field": field, "value": str(path)},
        )
    return path
