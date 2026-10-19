"""NGFW iplink and linkgroup runner for /api/v1/iplink and /api/v1/linkgroup."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.interface import load_json_payload
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
IPLINK_ENDPOINTS = {
    "fw_config_iplink": ("POST", "/api/v1/iplink"),
    "fw_update_iplink": ("PUT", "/api/v1/iplink"),
    "fw_delete_iplink": ("DELETE", "/api/v1/iplink"),
    "fw_verify_iplink": ("GET", "/api/v1/iplink"),
    "fw_config_iplink_group": ("POST", "/api/v1/linkgroup"),
    "fw_update_iplink_group": ("PUT", "/api/v1/linkgroup"),
    "fw_delete_iplink_group": ("DELETE", "/api/v1/linkgroup"),
    "fw_verify_iplink_group": ("GET", "/api/v1/linkgroup"),
    # 引用计数/引用详情查询（2026-09-16 实测）：module 大小写敏感 ipLink/ipLinkGroup
    "fw_verify_iplink_refcount": ("GET", "/api/v1/refcount"),
    "fw_delete_batch_iplink": ("POST", "/api/v1/batch"),
    "fw_delete_batch_iplink_group": ("POST", "/api/v1/batch"),
}
GET_OPS = {"fw_verify_iplink", "fw_verify_iplink_group"}
DELETE_OPS = {"fw_delete_iplink", "fw_delete_iplink_group"}
BATCH_OPS = {"fw_delete_batch_iplink", "fw_delete_batch_iplink_group"}
NO_BODY_OPS = GET_OPS | DELETE_OPS
IPLINK_RESOURCE = "/api/v1/iplink"
LINKGROUP_RESOURCE = "/api/v1/linkgroup"
BATCH_RESOURCE_BY_OP = {
    "fw_delete_batch_iplink": IPLINK_RESOURCE,
    "fw_delete_batch_iplink_group": LINKGROUP_RESOURCE,
}


def build_iplink_payload(
    *,
    name: str,
    destination: str,
    interface: str,
    port: int | str = 0,
    detect_type: int | str = 0,
    interval: int | str = 3,
    retry: int | str = 1,
) -> dict[str, Any]:
    _validate_non_empty("name", name)
    _validate_non_empty("destination", destination)
    _validate_non_empty("interface", interface)
    return {
        "val": {
            "name": name,
            "port": _validate_non_negative_int("port", port),
            "destination": destination,
            "detectType": _validate_non_negative_int("detect_type", detect_type),
            "interface": interface,
            "interval": _validate_positive_int("interval", interval),
            "retry": _validate_non_negative_int("retry", retry),
        }
    }


def build_linkgroup_payload(
    *,
    name: str,
    description: str = "",
    mode_strict: bool = True,
    link_name: list[str] | None = None,
) -> dict[str, Any]:
    _validate_non_empty("name", name)
    names = link_name or []
    if not isinstance(names, list) or not names:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Linkgroup payload link_name must be a non-empty list.",
            {"field": "link_name"},
        )
    return {
        "val": {
            "name": name,
            "description": description,
            "mode_strict": bool(mode_strict),
            "link_name": [str(item) for item in names],
        }
    }


def build_iplink_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    return _build_batch_delete_payload(entry_ids=entry_ids, resource=IPLINK_RESOURCE)


def build_linkgroup_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    return _build_batch_delete_payload(entry_ids=entry_ids, resource=LINKGROUP_RESOURCE)


def _build_batch_delete_payload(*, entry_ids: list[str], resource: str) -> dict[str, Any]:
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_non_empty("id", entry_id)
        batch.append({"method": "DELETE", "resource": resource, "body": {"id": [entry_id]}})
    return {"batch": batch}


def validate_iplink_payload(payload: dict[str, Any]) -> dict[str, Any]:
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError("RUNNER_VALIDATION_FAILED", "Iplink payload val object is required.", {"field": "val"})
    _validate_non_empty("name", str(val.get("name") or ""))
    return payload


def validate_linkgroup_payload(payload: dict[str, Any]) -> dict[str, Any]:
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError("RUNNER_VALIDATION_FAILED", "Linkgroup payload val object is required.", {"field": "val"})
    _validate_non_empty("name", str(val.get("name") or ""))
    link_name = val.get("link_name")
    if not isinstance(link_name, list) or not link_name:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Linkgroup payload link_name must be a non-empty list.",
            {"field": "link_name"},
        )
    return payload


def validate_batch_payload(payload: dict[str, Any], *, allowed_resource: str) -> dict[str, Any]:
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
        if item.get("method") != "DELETE" or item.get("resource") != allowed_resource:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch item only supports DELETE on the target resource.",
                {"method": item.get("method"), "resource": item.get("resource")},
            )
        body = item.get("body")
        ids = body.get("id") if isinstance(body, dict) else None
        if not isinstance(ids, list) or not ids:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch item body.id must be a non-empty list.",
                {"field": "body.id"},
            )
    return payload


def build_iplink_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    key: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, _path = _method_path(op_id)
    return {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(base_url, op_id, payload=payload, page=page, size=size, key=key),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in NO_BODY_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_iplink(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    key: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    status_code, response_payload, _text = request_json(
        method,
        _request_url(base_url, op_id, payload=payload, page=page, size=size, key=key),
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "Iplink device request did not return a success status.",
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


def _request_url(
    base_url: str,
    op_id: str,
    *,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
    key: str,
) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in GET_OPS:
        _validate_positive_int("page", page)
        _validate_positive_int("size", size)
        query: dict[str, Any] = {"page": page, "size": size}
        if key:
            query["key"] = key
        url = f"{url}?{urlencode(query)}"
    if op_id in DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return IPLINK_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this iplink or linkgroup operation.",
            {"op_id": op_id},
        ) from exc


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required iplink or linkgroup field is empty.",
            {"field": field},
        )


def _validate_non_negative_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Iplink or linkgroup integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Iplink or linkgroup integer field must be non-negative.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_positive_int(field: str, value: int | str) -> int:
    parsed = _validate_non_negative_int(field, value)
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Iplink or linkgroup integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed


# ===== 引用计数 / 引用详情查询（/api/v1/refcount）=====
# 设备接口（2026-09-16 在 122 实测）：
#   GET /api/v1/refcount?module=<模块>&key=<对象名>&page=<页>&size=<条数>
# 返回：
#   {"data": {"current_module": "", "total": N,
#             "counts": [{"module": "<引用方模块>", "count": N}, ...],
#             "vals":   [{"id": "<引用方 id>", "refence_module": "<引用方模块>",
#                         "aliases": "", "count": N}, ...]}}
# - module 合法值大小写敏感：ipLink（IP-Link）/ ipLinkGroup（IP-Link 组）；
#   其他写法（linkgroup/group/iplinkGroup）报 eRequestParam "http请求参数错误"。
# - total=引用总数，counts=按引用方模块汇总，vals=引用方明细
#   （即禅道"点开引用计数能看到引用它的特性"）。
REFCOUNT_PATH = "/api/v1/refcount"
VALID_REFCOUNT_MODULES = ("ipLink", "ipLinkGroup")


def _validate_refcount_module(module: str) -> str:
    # 注意：本模块的 _validate_non_empty 是纯校验函数（无返回值），不可用于赋值。
    _validate_non_empty("module", module)
    if module not in VALID_REFCOUNT_MODULES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "module must be one of the supported reference modules (case-sensitive).",
            {"field": "module", "value": module, "supported": list(VALID_REFCOUNT_MODULES)},
        )
    return module


def build_refcount_url(
    base_url: str,
    *,
    module: str,
    key: str,
    page: int | str = 1,
    size: int | str = 10,
) -> str:
    """拼接引用计数查询 URL（module/key 必填，page/size 默认 1/10）。"""
    module = _validate_refcount_module(module)
    _validate_non_empty("key", key)
    page = _validate_positive_int("page", page)
    size = _validate_positive_int("size", size)
    query = urlencode({"module": module, "key": key, "page": page, "size": size})
    return f"{normalize_base_url(base_url)}{REFCOUNT_PATH}?{query}"


def build_refcount_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    module: str,
    key: str,
    page: int | str = 1,
    size: int | str = 10,
    verify_tls: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    _validate_non_empty("key", key)
    return {
        "op_id": "fw_verify_iplink_refcount",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": build_refcount_url(base_url, module=module, key=key, page=page, size=size),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_refcount(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    module: str,
    key: str,
    page: int | str = 1,
    size: int | str = 10,
    expect_total: int | str | None = None,
    verify_tls: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """查询引用计数与引用方明细；把 total/counts/referers 提到 data 顶层。

    expect_total 给定时做**真实断言**：total 不等于期望值即抛 STATE_MISMATCH
    （2026-09-16：case_runner 的 success_condition 只是轮询提前退出条件、不做断言，
    故数值断言必须由 op 承担；配合用例 retry 可实现"轮询到计数正确为止"）。
    """
    _validate_non_empty("key", key)
    url = build_refcount_url(base_url, module=module, key=key, page=page, size=size)
    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    status_code, response_payload, _text = request_json(
        "GET", url, headers=headers, json_payload=None, timeout=timeout, verify_tls=verify_tls,
    )
    if status_code not in GET_SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Reference-count query did not return a success status.",
            {
                "op_id": "fw_verify_iplink_refcount",
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    inner = response_payload.get("data")
    inner = inner if isinstance(inner, dict) else {}
    if expect_total is not None:
        actual = inner.get("total")
        try:
            expected_int = int(expect_total)
        except (TypeError, ValueError) as exc:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "expect_total must be an integer.",
                {"field": "expect_total", "value": expect_total},
            ) from exc
        if int(actual or 0) != expected_int:
            raise RunnerError(
                "RUNNER_STATE_MISMATCH",
                f"引用计数不符：期望 {expected_int}，实际 {actual}。",
                {"module": module, "key": key, "expect_total": expected_int, "actual_total": actual},
            )
    return {
        "op_id": "fw_verify_iplink_refcount",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "GET",
            "path": REFCOUNT_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
        # 便捷字段（用例 success_condition 可直接断言 data.total / data.counts）
        "module": module,
        "key": key,
        "total": inner.get("total"),
        "counts": inner.get("counts"),
        "referers": inner.get("vals"),
    }


# ===== 容量用例支持的批量创建（--count N，2026-09-16）=====
# 设备 /api/v1/batch 不支持创建（只支持 DELETE），故批量创建=循环逐条 POST。
# 名称递增规则与策略路由 increment_value 保持一致：末尾数字段递增并保留宽度；
# 无末尾数字时追加 4 位补零序号。count=1 时名称保持原值（与单条创建完全一致）。
def _increment_name(name: str, index: int) -> str:
    match = re.search(r"(\d+)$", name)
    if match:
        digits = match.group(1)
        return f"{name[:match.start()]}{int(digits) + index - 1:0{len(digits)}d}"
    return f"{name}{index:04d}"


def build_iplink_payloads(*, count: int | str = 1, increment: bool = True, **kwargs: Any) -> list[dict[str, Any]]:
    """循环构造 count 条 iplink 创建 payload（名称按序号递增）。"""
    total = _validate_positive_int("count", count)
    payloads: list[dict[str, Any]] = []
    for index in range(1, total + 1):
        entry = dict(kwargs)
        if increment:
            entry["name"] = _increment_name(str(kwargs["name"]), index)
        payloads.append(build_iplink_payload(**entry))
    return payloads


def build_linkgroup_payloads(*, count: int | str = 1, increment: bool = True, **kwargs: Any) -> list[dict[str, Any]]:
    """循环构造 count 条 linkgroup 创建 payload（名称按序号递增，成员列表不递增）。"""
    total = _validate_positive_int("count", count)
    payloads: list[dict[str, Any]] = []
    for index in range(1, total + 1):
        entry = dict(kwargs)
        if increment:
            entry["name"] = _increment_name(str(kwargs["name"]), index)
        payloads.append(build_linkgroup_payload(**entry))
    return payloads


def execute_iplink_batch_create(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payloads: list[dict[str, Any]],
    verify_tls: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """循环逐条创建，返回聚合结果（created/failed/失败明细）。"""
    created: list[str] = []
    failures: list[dict[str, Any]] = []
    last_response: dict[str, Any] = {}
    for payload in payloads:
        name = str((payload.get("val") or {}).get("name") or "")
        try:
            result = execute_iplink(
                op_id=op_id, base_url=base_url, session_file=session_file,
                auth_header=auth_header, payload=payload, page=1, size=1, key="",
                verify_tls=verify_tls, timeout=timeout,
            )
            created.append(name)
            last_response = result.get("response") or {}
        except RunnerError as exc:
            failures.append({"name": name, "error_code": exc.error_code, "message": exc.message})
            break
    status = "success" if not failures else "error"
    return {
        "op_id": op_id,
        "status": status,
        "requested": len(payloads),
        "created": len(created),
        "failed": len(failures),
        "created_names": created,
        "failures": failures,
        "request": {"method": "POST", "path": _method_path(op_id)[1], "auth": {"name": auth_header, "value": "<session-ref>"}},
        "response": last_response,
    }


def build_iplink_batch_create_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payloads: list[dict[str, Any]],
    verify_tls: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    return {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "requested": len(payloads),
        "planned_names": [str((p.get("val") or {}).get("name") or "") for p in payloads],
        "request": {
            "method": method,
            "url": f"{normalize_base_url(base_url)}{path}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payloads[0] if payloads else None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


# 批量删除分片执行（2026-09-16 实测）：一次性提交 128 条的 batch 会导致设备侧
# 请求中断（Device request failed before a response was received），故按 chunk_size 分片。
BATCH_DELETE_CHUNK_SIZE = 16


def execute_iplink_batch_delete_chunked(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    entry_ids: list[str],
    chunk_size: int = BATCH_DELETE_CHUNK_SIZE,
    verify_tls: bool = False,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """分片批量删除，聚合结果（deleted_count/failed/失败分片）。"""
    if not entry_ids:
        raise RunnerError("RUNNER_VALIDATION_FAILED", "At least one id is required for batch delete.", {"field": "id"})
    resource = BATCH_RESOURCE_BY_OP[op_id]
    size = max(1, int(chunk_size))
    deleted: list[str] = []
    failures: list[dict[str, Any]] = []
    last_response: dict[str, Any] = {}
    for start in range(0, len(entry_ids), size):
        chunk = entry_ids[start:start + size]
        payload = _build_batch_delete_payload(entry_ids=chunk, resource=resource)
        try:
            result = execute_iplink(
                op_id=op_id, base_url=base_url, session_file=session_file,
                auth_header=auth_header, payload=payload, page=1, size=1, key="",
                verify_tls=verify_tls, timeout=timeout,
            )
            deleted.extend(chunk)
            last_response = result.get("response") or {}
        except RunnerError as exc:
            failures.append({"chunk": chunk, "error_code": exc.error_code, "message": exc.message})
            break
    return {
        "op_id": op_id,
        "status": "success" if not failures else "error",
        "requested": len(entry_ids),
        "deleted": len(deleted),
        "failed": len(failures),
        "deleted_names": deleted,
        "failures": failures,
        "request": {"method": "POST", "path": _method_path(op_id)[1], "auth": {"name": auth_header, "value": "<session-ref>"}},
        "response": last_response,
    }
