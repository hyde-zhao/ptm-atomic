"""NGFW keyword object runner for /api/v1/keywords.

关键字对象（Keyword Object）是本仓首个无 name/id 双轨的纯名称族：条目的稳定标识
就是 ``name`` 本身 —— 创建不带 id，编辑与批量删除都以 ``name`` 定位（规格 1.2／1.4
的 ``id`` 字段承载的是名称，不是数字 id）。

批量删除**必须**经 :func:`atomic_ops.runner.batch.build_batch_delete_payload`
构造载荷：``tests/test_batch.py`` 以 ``ast.walk`` 扫描 ``runner/*.py``，任何字面
``{"id": [...]}`` 形态都会被记为命中，模块名不在 ``UNINCLUDED_FAMILIES`` 即失败。
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
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

KEYWORD_RESOURCE = "/api/v1/keywords"
BATCH_PATH = "/api/v1/batch"

KEYWORD_ENDPOINTS = {
    "fw_config_keyword": ("POST", KEYWORD_RESOURCE),
    "fw_update_keyword": ("PUT", KEYWORD_RESOURCE),
    "fw_verify_keyword": ("GET", KEYWORD_RESOURCE),
    "fw_delete_batch_keyword": ("POST", BATCH_PATH),
}
GET_OPS = {"fw_verify_keyword"}
BATCH_OPS = {"fw_delete_batch_keyword"}
NO_BODY_OPS = GET_OPS
PAGINATED_OPS = GET_OPS

# 规格 1.3 把搜索参数写作 `key`，而本仓与设备其余族（含 CRL 查询的规格 2.4）
# 一律用 `keywords`。设备只认其中一个，猜错会让过滤静默失效（返回全量而非报错），
# 故取值集中在此常量，不在 loader 或 CLI 里散落字面量。
#
# 实机探测（2026-10-09，<DUT_IP>，2 个对象）冻结结论：规格正确。
#   /api/v1/keywords?key=atc_kw_2      -> count=1（过滤生效）
#   /api/v1/keywords?keywords=atc_kw_2 -> count=2（参数被忽略，静默返回全量）
# 反向：/api/v1/cert/certcrl 恰好相反，只认 `keywords`（见 runner/crl.py）。
# 两个端点参数名不同且互不报错，故两族各自持有自己的常量，不得统一。
SEARCH_QUERY_KEY = "key"


def build_keyword_payload(
    *,
    name: str,
    desc: str = "",
    content: list[str] | None = None,
) -> dict[str, Any]:
    """构造新建载荷 ``{"val": {name, desc, content}}``（规格 1.1）。"""
    return {"val": _keyword_val(name=name, desc=desc, content=content)}


def build_keyword_update_payload(
    *,
    entry_id: str,
    name: str,
    desc: str = "",
    content: list[str] | None = None,
) -> dict[str, Any]:
    """构造编辑载荷 ``{"id": <名称>, "val": {name, desc, content}}``（规格 1.2）。

    ``entry_id`` 是目标对象的唯一标识／名称（规格原文），不是数字 id。
    """
    _validate_non_empty("id", entry_id)
    return {"id": entry_id, "val": _keyword_val(name=name, desc=desc, content=content)}


def build_keyword_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    """构造批量删除载荷（规格 1.4，resource = ``/api/v1/keywords``）。"""
    return build_batch_delete_payload(entry_ids=entry_ids, resource=KEYWORD_RESOURCE)


def validate_keyword_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if op_id in BATCH_OPS:
        return _validate_batch_payload(payload)
    return payload


def build_keyword_dry_run(
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
            "url": _request_url(base_url, op_id, page=page, size=size, key=key),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in NO_BODY_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_keyword(
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
        _request_url(base_url, op_id, page=page, size=size, key=key),
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
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
            "Keyword device request did not return a success status.",
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


def _keyword_val(*, name: str, desc: str, content: list[str] | None) -> dict[str, Any]:
    _validate_non_empty("name", name)
    return {
        "name": name,
        "desc": "" if desc is None else str(desc),
        "content": _validate_content(content),
    }


def _validate_content(content: list[str] | None) -> list[str]:
    """规格 1.1／1.2 均把 content 标为必填的字符串列表。"""
    if not isinstance(content, list) or not content:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "content must be a non-empty list of keyword strings.",
            {"field": "content"},
        )
    for item in content:
        if not isinstance(item, str) or not item.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Keyword content entry must be a non-empty string.",
                {"field": "content", "value": item},
            )
    return [str(item) for item in content]


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
        if item.get("method") != "DELETE" or item.get("resource") != KEYWORD_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                f"Batch delete only supports DELETE {KEYWORD_RESOURCE} items.",
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


def _request_url(base_url: str, op_id: str, *, page: int, size: int, key: str) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in PAGINATED_OPS:
        _validate_positive_int("page", page)
        _validate_positive_int("size", size)
        query: dict[str, Any] = {"page": page, "size": size}
        if key:
            query[SEARCH_QUERY_KEY] = key
        url = f"{url}?{urlencode(query, doseq=True)}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return KEYWORD_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this keyword operation.",
            {"op_id": op_id},
        ) from exc


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Keyword field is required and must be non-empty.",
            {"field": field},
        )


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Keyword field must be a positive integer.",
            {"field": field},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Keyword field must be a positive integer.",
            {"field": field, "value": value},
        )
    return parsed
