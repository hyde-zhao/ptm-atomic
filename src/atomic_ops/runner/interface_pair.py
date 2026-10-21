"""NGFW interface-pair runner for /api/v1/intf/pair.

Endpoint family:

- ``POST   /api/v1/intf/pair``           create a pair (body ``{"val": {...}}``)
- ``GET    /api/v1/intf/pair?page&size`` list pairs (no server-side filters)
- ``PUT    /api/v1/intf/pair``           update a pair (body ``{"id", "val"}``)
- ``DELETE /api/v1/intf/pair?id=<name>`` delete a pair (query id, no body)

The GET endpoint only accepts ``page`` and ``size``. Name/receive/transmit
filters are therefore applied client-side: the runner fetches all pages,
filters the entries, and then applies the requested page/size slice. When no
filter is supplied the query is passed through unchanged.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import (
    RunnerError,
    is_resource_not_found,
    raise_if_device_session_rejected,
)
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
PAIR_ENDPOINTS = {
    "fw_config_interface_pair": ("POST", "/api/v1/intf/pair"),
    "fw_verify_interface_pair": ("GET", "/api/v1/intf/pair"),
    "fw_update_interface_pair": ("PUT", "/api/v1/intf/pair"),
    "fw_delete_interface_pair": ("DELETE", "/api/v1/intf/pair"),
}
NO_BODY_OPS = {"fw_verify_interface_pair", "fw_delete_interface_pair"}
PAIR_VAL_FIELDS = (
    "name",
    "remark",
    "receive_interface",
    "transmit_interface",
    "status_sync",
    "allowed_vlan",
)
PAIR_RESULT_FIELDS = (
    "name",
    "remark",
    "receive_interface",
    "transmit_interface",
    "allowed_vlan",
    "status_sync",
    "config_source",
    "create_time",
)
PAIR_FILTER_FIELDS = ("name", "receive_interface", "transmit_interface")
DEFAULT_FILTER_PAGE_SIZE = 100
MAX_FILTER_PAGES = 1000
# 设备实测（2026-10-21，<DUT_IP>）：接口对名称只允许中文、字母、数字、
# 短横线和点，长度 1-31，**下划线不合法**。创建/更新在本地先按该规则拦截，
# 避免把必然被设备拒绝的名称发出去。
PAIR_NAME_PATTERN = re.compile(r"^[一-龥a-zA-Z0-9.-]{1,31}$")
PAIR_NAME_RULE = (
    "Interface-pair name allows only Chinese characters, letters, digits, '-' and "
    "'.'; length must be 1-31 characters; underscores are not allowed."
)


# ── payload builders ───────────────────────────────────────


def build_interface_pair_payload(
    *,
    name: str,
    receive_interface: str,
    transmit_interface: str,
    remark: str = "",
    status_sync: bool = False,
    allowed_vlan: str | int = "0",
) -> dict[str, Any]:
    """Build the create envelope ``{"val": {...}}`` (POST carries no top-level id)."""
    return {
        "val": _build_pair_val(
            name=name,
            receive_interface=receive_interface,
            transmit_interface=transmit_interface,
            remark=remark,
            status_sync=status_sync,
            allowed_vlan=allowed_vlan,
        )
    }


def build_interface_pair_update_payload(
    *,
    entry_id: str,
    name: str | None = None,
    receive_interface: str,
    transmit_interface: str,
    remark: str = "",
    status_sync: bool = False,
    allowed_vlan: str | int = "0",
) -> dict[str, Any]:
    """Build the update envelope ``{"id": <pair-name>, "val": {...}}``."""
    _validate_non_empty("id", entry_id)
    effective_name = entry_id if name is None else name
    val = _build_pair_val(
        name=effective_name,
        receive_interface=receive_interface,
        transmit_interface=transmit_interface,
        remark=remark,
        status_sync=status_sync,
        allowed_vlan=allowed_vlan,
    )
    if val["name"] != entry_id:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair id and val.name must match.",
            {"id": entry_id, "name": val["name"]},
        )
    return {"id": entry_id, "val": val}


def _build_pair_val(
    *,
    name: str,
    receive_interface: str,
    transmit_interface: str,
    remark: str,
    status_sync: bool,
    allowed_vlan: str | int,
) -> dict[str, Any]:
    _validate_non_empty("name", name)
    _validate_pair_name(name)
    _validate_non_empty("receive_interface", receive_interface)
    _validate_non_empty("transmit_interface", transmit_interface)
    if not isinstance(remark, str):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair remark must be a string.",
            {"field": "remark", "type": type(remark).__name__},
        )
    if not isinstance(status_sync, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair status_sync must be a boolean.",
            {"field": "status_sync", "value": status_sync},
        )
    # required_vlan 的 Swagger 类型是 string（例如 "0" 或 "1-4094"）；
    # 这里同时接受整数写法并转成字符串，避免调用方把 0 当数字传入时被设备拒绝。
    if isinstance(allowed_vlan, bool) or not isinstance(allowed_vlan, (str, int)):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair allowed_vlan must be a string or integer.",
            {"field": "allowed_vlan", "type": type(allowed_vlan).__name__},
        )
    vlan_text = str(allowed_vlan).strip()
    if not vlan_text:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair allowed_vlan must not be empty.",
            {"field": "allowed_vlan"},
        )
    return {
        "name": name,
        "remark": remark,
        "receive_interface": receive_interface,
        "transmit_interface": transmit_interface,
        "status_sync": status_sync,
        "allowed_vlan": vlan_text,
    }


def validate_interface_pair_payload(
    payload: dict[str, Any] | None,
    *,
    op_id: str,
) -> dict[str, Any] | None:
    """Validate and normalize a pair payload for the given operation."""
    if op_id == "fw_verify_interface_pair":
        return payload
    if op_id == "fw_delete_interface_pair":
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        return {"id": entry_id}
    if op_id not in {"fw_config_interface_pair", "fw_update_interface_pair"}:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this interface-pair operation.",
            {"op_id": op_id},
        )
    if not isinstance(payload, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair payload must be an object.",
            {"op_id": op_id, "type": type(payload).__name__},
        )
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair payload val object is required.",
            {"field": "val"},
        )

    entry_id: str | None = None
    if op_id == "fw_update_interface_pair":
        entry_id = str(payload.get("id") or "")
        _validate_non_empty("id", entry_id)
    elif payload.get("id") is not None:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair create payload must not carry a top-level id.",
            {"field": "id"},
        )

    normalized_val = _normalize_pair_val(val, default_name=entry_id)
    if entry_id is not None and normalized_val["name"] != entry_id:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair id and val.name must match.",
            {"id": entry_id, "name": normalized_val["name"]},
        )
    if entry_id is None:
        return {"val": normalized_val}
    return {"id": entry_id, "val": normalized_val}


def _normalize_pair_val(val: dict[str, Any], *, default_name: str | None) -> dict[str, Any]:
    name = val.get("name")
    if name is None and default_name is not None:
        name = default_name
    if not isinstance(name, str) or not name.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair val.name is required.",
            {"field": "val.name"},
        )
    _validate_pair_name(name)
    receive_interface = val.get("receive_interface")
    transmit_interface = val.get("transmit_interface")
    if not isinstance(receive_interface, str) or not receive_interface.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair val.receive_interface is required.",
            {"field": "val.receive_interface"},
        )
    if not isinstance(transmit_interface, str) or not transmit_interface.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair val.transmit_interface is required.",
            {"field": "val.transmit_interface"},
        )
    remark = val.get("remark", "")
    if not isinstance(remark, str):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair val.remark must be a string.",
            {"field": "val.remark", "type": type(remark).__name__},
        )
    status_sync = val.get("status_sync", False)
    if not isinstance(status_sync, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair val.status_sync must be a boolean.",
            {"field": "val.status_sync", "value": status_sync},
        )
    allowed_vlan = val.get("allowed_vlan", "0")
    if isinstance(allowed_vlan, bool) or not isinstance(allowed_vlan, (str, int)):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair val.allowed_vlan must be a string or integer.",
            {"field": "val.allowed_vlan", "type": type(allowed_vlan).__name__},
        )
    vlan_text = str(allowed_vlan).strip()
    if not vlan_text:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Interface-pair val.allowed_vlan must not be empty.",
            {"field": "val.allowed_vlan"},
        )
    return {
        "name": name,
        "remark": remark,
        "receive_interface": receive_interface,
        "transmit_interface": transmit_interface,
        "status_sync": status_sync,
        "allowed_vlan": vlan_text,
    }


def build_interface_pair_filters(
    *,
    name: str | None = None,
    receive_interface: str | None = None,
    transmit_interface: str | None = None,
) -> dict[str, str]:
    """Return the non-empty client-side filters keyed by API field name."""
    filters: dict[str, str] = {}
    for field, value in (
        ("name", name),
        ("receive_interface", receive_interface),
        ("transmit_interface", transmit_interface),
    ):
        if value is None:
            continue
        text = str(value)
        if not text.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Interface-pair filter must not be empty when supplied.",
                {"field": field},
            )
        filters[field] = text
    return filters


# ── dry-run + execute ──────────────────────────────────────


def build_interface_pair_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
    query: dict[str, int] | None = None,
    filters: dict[str, str] | None = None,
) -> dict[str, Any]:
    method, _path = _method_path(op_id)
    return {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(base_url, op_id, payload=payload, query=query),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in NO_BODY_OPS else payload,
            "query": dict(query) if query else None,
            "filters": dict(filters) if filters else None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_interface_pair(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
    query: dict[str, int] | None = None,
    filters: dict[str, str] | None = None,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}

    if op_id == "fw_verify_interface_pair":
        return _execute_verify_pair(
            base_url=base_url,
            headers=headers,
            auth_header=auth_header,
            verify_tls=verify_tls,
            timeout=timeout,
            query=query,
            filters=filters,
        )

    status_code, response_payload, _text = request_json(
        method,
        _request_url(base_url, op_id, payload=payload),
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        _raise_for_failure(op_id, method, status_code, response_payload)
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


def _execute_verify_pair(
    *,
    base_url: str,
    headers: dict[str, str],
    auth_header: str,
    verify_tls: bool,
    timeout: float,
    query: dict[str, int] | None,
    filters: dict[str, str] | None,
) -> dict[str, Any]:
    method, path = PAIR_ENDPOINTS["fw_verify_interface_pair"]
    normalized_query = _validate_query(query)
    normalized_filters = dict(filters or {})

    if normalized_filters:
        if (normalized_query.get("page") is None) != (normalized_query.get("size") is None):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Interface-pair page and size must be supplied together when filtering.",
                {"query": normalized_query},
            )
        entries = _fetch_all_pair_entries(
            base_url=base_url,
            headers=headers,
            verify_tls=verify_tls,
            timeout=timeout,
        )
        matched = [
            entry
            for entry in entries
            if _entry_matches_filters(entry, normalized_filters)
        ]
        count = len(matched)
        page = normalized_query.get("page")
        size = normalized_query.get("size")
        if page is not None and size is not None:
            start = (page - 1) * size
            matched = matched[start : start + size]
        vals = [_project_pair_entry(entry) for entry in matched]
        status_code = 200
    else:
        status_code, response_payload, _text = request_json(
            method,
            _request_url(
                base_url,
                "fw_verify_interface_pair",
                query=normalized_query or None,
            ),
            headers=headers,
            json_payload=None,
            timeout=timeout,
            verify_tls=verify_tls,
        )
        if status_code not in GET_SUCCESS_STATUS:
            _raise_for_failure("fw_verify_interface_pair", method, status_code, response_payload)
        raw_vals = response_payload.get("vals")
        if raw_vals is None:
            raw_vals = []
        if not isinstance(raw_vals, list):
            raise RunnerError(
                "RUNNER_RESPONSE_INVALID",
                "Interface-pair query response vals must be a list.",
                {"op_id": "fw_verify_interface_pair", "type": type(raw_vals).__name__},
            )
        raw_count = response_payload.get("count")
        count = raw_count if isinstance(raw_count, int) else len(raw_vals)
        vals = [_project_pair_entry(entry) for entry in raw_vals]

    return {
        "op_id": "fw_verify_interface_pair",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": method,
            "path": path,
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "query": normalized_query or None,
            "filters": normalized_filters or None,
        },
        "count": count,
        "vals": vals,
        "filtered": bool(normalized_filters),
    }


def _fetch_all_pair_entries(
    *,
    base_url: str,
    headers: dict[str, str],
    verify_tls: bool,
    timeout: float,
) -> list[Any]:
    method, _path = PAIR_ENDPOINTS["fw_verify_interface_pair"]
    entries: list[Any] = []
    total: int | None = None
    for page in range(1, MAX_FILTER_PAGES + 1):
        status_code, response_payload, _text = request_json(
            method,
            _request_url(
                base_url,
                "fw_verify_interface_pair",
                query={"page": page, "size": DEFAULT_FILTER_PAGE_SIZE},
            ),
            headers=headers,
            json_payload=None,
            timeout=timeout,
            verify_tls=verify_tls,
        )
        if status_code not in GET_SUCCESS_STATUS:
            _raise_for_failure("fw_verify_interface_pair", method, status_code, response_payload)
        if total is None and isinstance(response_payload.get("count"), int):
            total = response_payload["count"]
        raw_vals = response_payload.get("vals")
        if not isinstance(raw_vals, list) or not raw_vals:
            break
        entries.extend(raw_vals)
        if isinstance(total, int) and len(entries) >= total:
            break
        if len(raw_vals) < DEFAULT_FILTER_PAGE_SIZE:
            break
    return entries


def _entry_matches_filters(entry: Any, filters: dict[str, str]) -> bool:
    if not isinstance(entry, dict):
        return False
    for field, expected in filters.items():
        if str(entry.get(field)) != expected:
            return False
    return True


def _project_pair_entry(entry: Any) -> dict[str, Any]:
    if not isinstance(entry, dict):
        return {}
    return {field: entry[field] for field in PAIR_RESULT_FIELDS if field in entry}


def _validate_query(query: dict[str, int] | None) -> dict[str, int]:
    normalized: dict[str, int] = {}
    for field in ("page", "size"):
        value = (query or {}).get(field)
        if value is None:
            continue
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Interface-pair pagination parameter must be a positive integer.",
                {"field": field, "value": value},
            ) from exc
        if parsed < 1:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Interface-pair pagination parameter must be a positive integer.",
                {"field": field, "value": parsed},
            )
        normalized[field] = parsed
    return normalized


def _raise_for_failure(
    op_id: str,
    method: str,
    status_code: int,
    response_payload: dict[str, Any],
) -> None:
    raise_if_device_session_rejected(status_code, response_payload, op_id=op_id)
    err_code = response_payload.get("errCode")
    err_msg = response_payload.get("errMsg") or response_payload.get("message")
    details: dict[str, Any] = {
        "op_id": op_id,
        "status_code": status_code,
        "err_code": err_code,
        "err_msg": err_msg,
        "response_keys": sorted(response_payload.keys()),
    }

    # 2026-10-21 实测（<DUT_IP>）：重复创建接口对返回 400
    # {"errCode": "eObjCreateExist", "errMsg": "接口对名称已存在"}。这是明确的
    # 配置拒绝（名称冲突），不是本地参数格式错误，故映射为 CONFIG_REJECTED，
    # 并把设备原始 errCode/errMsg 原样保留在 details。
    if (
        op_id in {"fw_config_interface_pair", "fw_update_interface_pair"}
        and status_code == 400
        and err_code == "eObjCreateExist"
    ):
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "Interface-pair name already exists on the device; the request was rejected.",
            {**details, "error_type": "CONFIG_REJECTED"},
        )

    # 2026-10-21 实测（<DUT_IP>）：删除不存在的接口对返回 400
    # {"errCode": "eObjGetNoExist", "errMsg": "未找到对应的接口对"}。该 op 声明
    # idempotent: false —— 重复删除**不视为成功**；这里只把设备语义归类为
    # RESOURCE_NOT_FOUND（details.error_type），运行时代码仍为
    # RUNNER_CONFIG_REJECTED（exit 48），且**不写** idempotent 幂等键。
    if op_id == "fw_delete_interface_pair" and is_resource_not_found(
        status_code, response_payload, op_id=op_id
    ):
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "Interface-pair was not found on the device; repeat delete is not treated as success.",
            {**details, "error_type": "RESOURCE_NOT_FOUND"},
        )

    raise RunnerError(
        "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
        "Interface-pair device request did not return a success status.",
        details,
    )


def _request_url(
    base_url: str,
    op_id: str,
    *,
    payload: dict[str, Any] | None = None,
    query: dict[str, Any] | None = None,
) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id == "fw_delete_interface_pair":
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        return f"{url}?{urlencode({'id': entry_id})}"
    if op_id == "fw_verify_interface_pair" and query:
        return f"{url}?{urlencode(query)}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return PAIR_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this interface-pair operation.",
            {"op_id": op_id},
        ) from exc


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required interface-pair field is empty.",
            {"field": field},
        )


def _validate_pair_name(name: str) -> None:
    """接口对名称本地校验（创建/更新）。

    设备实测规则：只允许中文/字母/数字/``-``/``.``，长度 1-31，不允许下划线。
    不匹配时返回 RUNNER_VALIDATION_FAILED，错误信息直接给出规则，details 携带
    字段名、实际值与正则，便于调用方定位。
    """
    if not PAIR_NAME_PATTERN.fullmatch(name):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"Invalid interface-pair name {name!r}: {PAIR_NAME_RULE}",
            {
                "field": "name",
                "value": name,
                "pattern": PAIR_NAME_PATTERN.pattern,
                "rule": PAIR_NAME_RULE,
            },
        )
