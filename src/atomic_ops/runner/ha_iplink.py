"""NGFW HA iplink / linkgroup monitor runner.

haiplink and halinkgroup monitor objects reuse the iplink/linkgroup payload
shape but diverge on the DELETE path:

- POST/GET go to ``/api/v1/haiplink`` and ``/api/v1/halinkgroup`` (GET is
  paginated with ``page``/``size``).
- Single DELETE and batch DELETE go through ``/api/v1/ha/iplink``; a
  linkgroup delete additionally carries ``isGroup=true`` (query for single
  delete, ``body.isGroup`` list for batch delete).
- PUT is not supported by the device.

The ``isGroup`` divergence is why these live in their own runner instead of
reusing :mod:`atomic_ops.runner.iplink`.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}


def load_json_payload(*, payload_file: str | None, payload_json: str | None) -> dict[str, Any] | None:
    if payload_file and payload_json:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "--payload-file and --payload-json cannot be used together.",
            {"fields": ["payload_file", "payload_json"]},
        )
    if not payload_file and not payload_json:
        return None
    try:
        raw = Path(payload_file).read_text(encoding="utf-8") if payload_file else str(payload_json)
        payload = json.loads(raw)
    except OSError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA iplink payload file cannot be read.",
            {"path": payload_file, "reason": exc.__class__.__name__},
        ) from exc
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA iplink payload must be valid JSON.",
            {"reason": exc.msg},
        ) from exc
    if not isinstance(payload, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA iplink payload JSON root must be an object.",
            {"type": type(payload).__name__},
        )
    return payload

HAIPLINK_ENDPOINTS = {
    "fw_config_haiplink": ("POST", "/api/v1/haiplink"),
    "fw_verify_haiplink": ("GET", "/api/v1/haiplink"),
    "fw_delete_haiplink": ("DELETE", "/api/v1/ha/iplink"),
    "fw_delete_batch_haiplink": ("POST", "/api/v1/batch"),
    "fw_config_halinkgroup": ("POST", "/api/v1/halinkgroup"),
    "fw_verify_halinkgroup": ("GET", "/api/v1/halinkgroup"),
    "fw_delete_halinkgroup": ("DELETE", "/api/v1/ha/iplink"),
    "fw_delete_batch_halinkgroup": ("POST", "/api/v1/batch"),
}
GET_OPS = {"fw_verify_haiplink", "fw_verify_halinkgroup"}
DELETE_OPS = {"fw_delete_haiplink", "fw_delete_halinkgroup"}
BATCH_OPS = {"fw_delete_batch_haiplink", "fw_delete_batch_halinkgroup"}
NO_BODY_OPS = GET_OPS | DELETE_OPS

# DELETE 和 batch 都走 ha/iplink；halinkgroup 带 isGroup=true。
HA_IPLINK_DELETE_RESOURCE = "/api/v1/ha/iplink"
LINKGROUP_OPS = {"fw_config_halinkgroup", "fw_verify_halinkgroup", "fw_delete_halinkgroup", "fw_delete_batch_halinkgroup"}


# ── payload builders ───────────────────────────────────────


def build_haiplink_payload(
    *,
    name: str,
    destination: str,
    interface: str,
    port: int | str = 0,
    detect_type: int | str = 0,
    interval: int | str = 1,
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


def build_halinkgroup_payload(
    *,
    name: str,
    description: str = "",
    mode_strict: bool = False,
    link_name: list[str] | None = None,
) -> dict[str, Any]:
    _validate_non_empty("name", name)
    names = link_name or []
    if not isinstance(names, list) or not names:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA linkgroup payload link_name must be a non-empty list.",
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


def build_haiplink_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    return _build_batch_delete_payload(entry_ids=entry_ids, is_group=False)


def build_halinkgroup_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    return _build_batch_delete_payload(entry_ids=entry_ids, is_group=True)


def _build_batch_delete_payload(*, entry_ids: list[str], is_group: bool) -> dict[str, Any]:
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    # 接口示例：body.isGroup 是与 id 一一对应的字符串列表（"true" 或 "undefined"）。
    is_group_values = ["true" if is_group else "undefined"] * len(entry_ids)
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_non_empty("id", entry_id)
        batch.append(
            {
                "method": "DELETE",
                "resource": HA_IPLINK_DELETE_RESOURCE,
                "body": {"id": [str(entry_id)], "isGroup": list(is_group_values)},
            }
        )
    return {"batch": batch}


# ── validators ─────────────────────────────────────────────


def validate_haiplink_payload(payload: dict[str, Any]) -> dict[str, Any]:
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError("RUNNER_VALIDATION_FAILED", "HA iplink payload val object is required.", {"field": "val"})
    _validate_non_empty("name", str(val.get("name") or ""))
    return payload


def validate_halinkgroup_payload(payload: dict[str, Any]) -> dict[str, Any]:
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError("RUNNER_VALIDATION_FAILED", "HA linkgroup payload val object is required.", {"field": "val"})
    _validate_non_empty("name", str(val.get("name") or ""))
    link_name = val.get("link_name")
    if not isinstance(link_name, list) or not link_name:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA linkgroup payload link_name must be a non-empty list.",
            {"field": "link_name"},
        )
    return payload


def validate_batch_payload(payload: dict[str, Any], *, is_group: bool) -> dict[str, Any]:
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
        if item.get("method") != "DELETE" or item.get("resource") != HA_IPLINK_DELETE_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch item only supports DELETE on /api/v1/ha/iplink.",
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


# ── dry-run + execute ──────────────────────────────────────


def build_ha_iplink_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
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
            "url": _request_url(base_url, op_id, payload=payload, page=page, size=size),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in NO_BODY_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_ha_iplink(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    page: int,
    size: int,
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
        _request_url(base_url, op_id, payload=payload, page=page, size=size),
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "HA iplink device request did not return a success status.",
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


# ── helpers ────────────────────────────────────────────────


def _request_url(base_url: str, op_id: str, *, payload: dict[str, Any] | None, page: int, size: int) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in GET_OPS:
        _validate_positive_int("page", page)
        _validate_positive_int("size", size)
        url = f"{url}?{urlencode({'page': page, 'size': size})}"
    if op_id in DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        query: dict[str, Any] = {"id": entry_id}
        if op_id == "fw_delete_halinkgroup":
            query["isGroup"] = "true"
        url = f"{url}?{urlencode(query)}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return HAIPLINK_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this HA iplink or linkgroup operation.",
            {"op_id": op_id},
        ) from exc


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required HA iplink or linkgroup field is empty.",
            {"field": field},
        )


def _validate_non_negative_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA iplink or linkgroup integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA iplink or linkgroup integer field must be non-negative.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_positive_int(field: str, value: int | str) -> int:
    parsed = _validate_non_negative_int(field, value)
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA iplink or linkgroup integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed
