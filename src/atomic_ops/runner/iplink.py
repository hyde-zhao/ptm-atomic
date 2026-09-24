"""NGFW iplink and linkgroup runner for /api/v1/iplink and /api/v1/linkgroup."""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
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


#: iplink 的**可写**字段白名单（build_iplink_payload 的产出集，与设备 PUT 契约一致）。
_IPLINK_WRITABLE_VAL_KEYS = (
    "name", "port", "destination", "detectType", "interface", "interval", "retry",
)
#: iplink 回读记录里的**只读输出**字段（设备自己算的，写回去会被拒）。
_IPLINK_READONLY_VAL_KEYS = ("config_source", "refcnt", "status")


def validate_iplink_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """校验并**归一到可写字段集**（快照重放必需，2026-09-23）。

    为什么需要归一：ptm-team 的 `restore_snapshot` 回滚把设备 GET 回的记录**整包**原样
    发回（`{"id":.., "val": {回读记录}}`），而回读记录是**扁平**的、含 3 个只读输出字段
    （`config_source` / `refcnt` / `status`，见 `_IPLINK_READONLY_VAL_KEYS`）。
    真机实测（PC-STRATEGYROUTE-ROUTING-LOADBALANCE-012）：原样重放被设备拒
    —— HTTP 400 `/ eObjParse`「iplink JISON格式错误」。

    归一规则（**不静默吞未知字段**，与接口族 `validate_interface_payload` 同款纪律）：
      - 白名单内的键保留；
      - 已知**只读输出**键静默剔除（它们是设备回读产物，天然不该出现在 PUT body）；
      - **其余未知键**一律 `RUNNER_VALIDATION_FAILED` 点名 —— 避免把字段名拼写错误
        静默丢掉后照样下发、还被判成功。

    Args:
        payload: 完整请求体，形如 ``{"val": {...}}``（update 另带顶层 ``id``）

    Returns:
        归一后的 payload（顶层键原样保留，只重写 ``val``）

    Raises:
        RunnerError: val 缺失 / name 为空 / 含未知字段
    """
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError("RUNNER_VALIDATION_FAILED", "Iplink payload val object is required.", {"field": "val"})
    _validate_non_empty("name", str(val.get("name") or ""))
    unknown = [k for k in val
               if k not in _IPLINK_WRITABLE_VAL_KEYS and k not in _IPLINK_READONLY_VAL_KEYS]
    if unknown:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Iplink payload contains unknown val field(s).",
            {"unknown_fields": sorted(unknown),
             "writable": list(_IPLINK_WRITABLE_VAL_KEYS)},
        )
    normalized = dict(payload)
    normalized["val"] = {k: val[k] for k in _IPLINK_WRITABLE_VAL_KEYS if k in val}
    return normalized


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
    session_payload = read_session_file(session_file, expect_base_url=base_url)
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
        raise_if_device_session_rejected(status_code, response_payload)
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
