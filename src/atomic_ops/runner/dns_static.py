"""NGFW static DNS entry runner.

Static DNS entries are managed through ``/api/v1/dns/cache``:

- POST creates (or overwrites) one entry; the body is ``{"val": {name,
  ip4addr, ip6addr?}}``.
- DELETE removes one entry by domain name; the domain travels as the
  ``?id=<domain>`` query parameter and no JSON body is sent.
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

DNS_STATIC_ENDPOINTS = {
    "fw_config_static_dns": ("POST", "/api/v1/dns/cache"),
    "fw_delete_static_dns": ("DELETE", "/api/v1/dns/cache"),
}
DELETE_OPS = {"fw_delete_static_dns"}
NO_BODY_OPS = DELETE_OPS


# ── payload builders ───────────────────────────────────────


def build_static_dns_payload(*, name: str, ip4addr: str, ip6addr: str | None = None) -> dict[str, Any]:
    """Build the POST body ``{"val": {name, ip4addr, ip6addr?}}``."""
    val: dict[str, Any] = {"name": name, "ip4addr": ip4addr}
    if ip6addr is not None:
        val["ip6addr"] = ip6addr
    return {"val": val}


def validate_static_dns_payload(payload: dict[str, Any]) -> dict[str, Any]:
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static DNS payload must contain a val object.",
            {"field": "val"},
        )
    for field in ("name", "ip4addr"):
        if not isinstance(val.get(field), str) or not val[field].strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Static DNS entry requires non-empty name and ip4addr.",
                {"field": field},
            )
    if "ip6addr" in val and (not isinstance(val["ip6addr"], str) or not val["ip6addr"].strip()):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static DNS ip6addr must be a non-empty string when provided.",
            {"field": "ip6addr"},
        )
    return payload


# ── dry-run + execute ──────────────────────────────────────


def build_static_dns_dry_run(
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


def execute_static_dns(
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
    session_payload = read_session_file(session_file)
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
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "Static DNS device request did not return a success status.",
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
        return DNS_STATIC_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this static DNS operation.",
            {"op_id": op_id},
        ) from exc


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required static DNS field is empty.",
            {"field": field},
        )


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
            "Static DNS payload file cannot be read.",
            {"path": payload_file, "reason": exc.__class__.__name__},
        ) from exc
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static DNS payload must be valid JSON.",
            {"reason": exc.msg},
        ) from exc
    if not isinstance(payload, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Static DNS payload JSON root must be an object.",
            {"type": type(payload).__name__},
        )
    return payload
