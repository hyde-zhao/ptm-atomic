"""NGFW HA (high availability) runner.

Covers the HA endpoints that are NOT the iplink/linkgroup monitor variants:

- ``/api/v1/hasync``        PUT  sync configuration (single-step, ``module`` open string)
- ``/api/v1/hasynclist``    GET  list sync status (no pagination, returns ``menuList``)
- ``/api/v1/haconfig``      PUT  HA configuration (single-step, nested ``hb`` object)
- ``/api/v1/hainterface``   POST/GET/DELETE/batch  monitored interface entries
- ``/api/v1/havrrp``        POST/PUT/GET/DELETE/batch  VRRP entries

haiplink/halinkgroup live in :mod:`atomic_ops.runner.ha_iplink` because their
DELETE path (``/api/v1/ha/iplink`` with an ``isGroup`` flag) diverges from the
iplink pattern. GET endpoints here have no pagination, mirroring the iptun
runner; batch deletes reuse the iplink batch shape.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
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
            "HA payload file cannot be read.",
            {"path": payload_file, "reason": exc.__class__.__name__},
        ) from exc
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA payload must be valid JSON.",
            {"reason": exc.msg},
        ) from exc
    if not isinstance(payload, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA payload JSON root must be an object.",
            {"type": type(payload).__name__},
        )
    return payload

HA_ENDPOINTS = {
    "fw_config_hasync": ("PUT", "/api/v1/hasync"),
    "fw_verify_hasynclist": ("GET", "/api/v1/hasynclist"),
    "fw_config_haconfig": ("PUT", "/api/v1/haconfig"),
    "fw_config_hainterface": ("POST", "/api/v1/hainterface"),
    "fw_verify_hainterface": ("GET", "/api/v1/hainterface"),
    "fw_delete_hainterface": ("DELETE", "/api/v1/hainterface"),
    "fw_delete_batch_hainterface": ("POST", "/api/v1/batch"),
    "fw_config_havrrp": ("POST", "/api/v1/havrrp"),
    "fw_update_havrrp": ("PUT", "/api/v1/havrrp"),
    "fw_verify_havrrp": ("GET", "/api/v1/havrrp"),
    "fw_delete_havrrp": ("DELETE", "/api/v1/havrrp"),
    "fw_delete_batch_havrrp": ("POST", "/api/v1/batch"),
}
GET_OPS = {"fw_verify_hasynclist", "fw_verify_hainterface", "fw_verify_havrrp"}
DELETE_OPS = {"fw_delete_hainterface", "fw_delete_havrrp"}
BATCH_OPS = {"fw_delete_batch_hainterface", "fw_delete_batch_havrrp"}
NO_BODY_OPS = GET_OPS | DELETE_OPS

BATCH_RESOURCE_BY_OP = {
    "fw_delete_batch_hainterface": "/api/v1/hainterface",
    "fw_delete_batch_havrrp": "/api/v1/havrrp",
}


# ── payload builders ───────────────────────────────────────


def build_hasync_payload(*, module: str = "all") -> dict[str, Any]:
    _validate_non_empty("module", module)
    return {"id": 0, "val": {"module": module}}


def build_haconfig_payload(
    *,
    enable: bool = True,
    no_sync_config: bool = False,
    no_sync_state: bool = False,
    base_sync: bool = True,
    force_permit_enable: bool = False,
    permit_tcp_syn: int = 0,
    permit_time: int = 500,
    mode: str = "MB",
    role: str = "BACKUP",
    preempt: bool = True,
    shock_time_unit: int = 120,
    advertise_period: int = 1000,
    hb_interface: str = "",
    local_addr: str = "",
    remote_addr: str = "",
) -> dict[str, Any]:
    val: dict[str, Any] = {
        "enable": bool(enable),
        "noSyncConfig": bool(no_sync_config),
        "noSyncState": bool(no_sync_state),
        "baseSync": bool(base_sync),
        "forcePermitEnable": bool(force_permit_enable),
        "permitTcpSyn": _validate_non_negative_int("permit_tcp_syn", permit_tcp_syn),
        "permitTime": _validate_non_negative_int("permit_time", permit_time),
        "mode": mode,
        "role": role,
        "preempt": bool(preempt),
        "shockTimeUnit": _validate_non_negative_int("shock_time_unit", shock_time_unit),
        "advertisePeriod": _validate_non_negative_int("advertise_period", advertise_period),
        "hb": {
            "interface": hb_interface,
            "localAddr": local_addr,
            "remoteAddr": remote_addr,
        },
    }
    return {"id": "haconfig", "val": val}


def build_hainterface_payload(*, track_intf: str) -> dict[str, Any]:
    _validate_non_empty("track_intf", track_intf)
    return {"val": {"trackIntf": track_intf}}


def build_havrrp_payload(
    *,
    enable: bool = True,
    interface: str,
    ip_addr: str = "0.0.0.0",
    vr_id: int,
    vr_role: str,
    vips: list[str],
    use_virtual_mac: bool = False,
) -> dict[str, Any]:
    _validate_non_empty("interface", interface)
    _validate_non_empty("vr_role", vr_role)
    if not isinstance(vips, list) or not vips:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA VRRP vips must be a non-empty list.",
            {"field": "vips"},
        )
    return {
        "val": {
            "enable": bool(enable),
            "interface": interface,
            "ipAddr": ip_addr,
            "vrId": _validate_non_negative_int("vr_id", vr_id),
            "vrRole": vr_role,
            "vips": list(vips),
            "useVirtualMac": bool(use_virtual_mac),
        }
    }


def build_havrrp_update_payload(
    *,
    entry_id: str,
    interface: str,
    ip_addr: str = "0.0.0.0",
    vr_id: int,
    vr_role: str,
    vips: list[str],
) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    _validate_non_empty("interface", interface)
    _validate_non_empty("vr_role", vr_role)
    if not isinstance(vips, list) or not vips:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA VRRP vips must be a non-empty list.",
            {"field": "vips"},
        )
    return {
        "id": entry_id,
        "val": {
            "interface": interface,
            "ipAddr": ip_addr,
            "vrId": _validate_non_negative_int("vr_id", vr_id),
            "vrRole": vr_role,
            "vips": list(vips),
        },
    }


def build_hainterface_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    return _build_batch_delete_payload(entry_ids=entry_ids, resource="/api/v1/hainterface")


def build_havrrp_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    return _build_batch_delete_payload(entry_ids=entry_ids, resource="/api/v1/havrrp")


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
        batch.append({"method": "DELETE", "resource": resource, "body": {"id": [str(entry_id)]}})
    return {"batch": batch}


# ── validators ─────────────────────────────────────────────


def validate_ha_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if op_id in BATCH_OPS:
        return validate_batch_payload(payload, allowed_resource=BATCH_RESOURCE_BY_OP[op_id])
    if op_id in DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        return {"id": entry_id}
    if op_id in GET_OPS:
        return payload
    if op_id == "fw_update_havrrp":
        entry_id = str(payload.get("id") or "")
        _validate_non_empty("id", entry_id)
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError("RUNNER_VALIDATION_FAILED", "HA payload val object is required.", {"field": "val"})
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


# ── dry-run + execute ──────────────────────────────────────


def build_ha_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
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
            "url": _request_url(base_url, op_id, payload=payload),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in NO_BODY_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_ha(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
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
        _request_url(base_url, op_id, payload=payload),
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
            "HA device request did not return a success status.",
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


def _request_url(base_url: str, op_id: str, *, payload: dict[str, Any] | None) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return HA_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this HA operation.",
            {"op_id": op_id},
        ) from exc


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required HA field is empty.",
            {"field": field},
        )


def _validate_non_negative_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "HA integer field must be non-negative.",
            {"field": field, "value": parsed},
        )
    return parsed
