"""NGFW system DNS and DNS proxy server runner.

System DNS servers are managed through ``/api/v1/sysdns``:

- PUT configures the system DNS servers; the body is ``{"id": 0, "val":
  {"serveraddr": [...]}}`` where the first entry is the primary server and
  the second is the backup.
- GET returns the configured system DNS servers as ``{"data": [{"serveraddr":
  [...]}]}``.

The global DNS proxy and its proxy servers go through ``/api/v1/dns/global``
and ``/api/v1/dns/globalserver``:

- PUT /api/v1/dns/global toggles the global DNS proxy; the body is ``{"id":
  "dnsServer", "val": {"enable": bool}}``.
- POST /api/v1/dns/globalserver creates one or more proxy servers; the body
  is ``{"val": {"servers": [{"addr": ...}]}}``.
- DELETE /api/v1/dns/globalserver removes one proxy server by address; the
  address travels as the ``?id=<addr>`` query parameter and no JSON body is
  sent.
- Batch delete goes through ``/api/v1/batch`` with one DELETE
  ``/api/v1/dns/globalserver`` item per address.
- GET /api/v1/dns/globalserver returns the configured proxy servers.
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

DNS_SYS_ENDPOINTS = {
    "fw_config_dns_server": ("PUT", "/api/v1/sysdns"),
    "fw_verify_dns_server": ("GET", "/api/v1/sysdns"),
    "fw_config_dns_proxy": ("PUT", "/api/v1/dns/global"),
    "fw_config_dns_proxy_server": ("POST", "/api/v1/dns/globalserver"),
    "fw_delete_dns_proxy_server": ("DELETE", "/api/v1/dns/globalserver"),
    "fw_verify_dns_proxy_server": ("GET", "/api/v1/dns/globalserver"),
    "fw_delete_batch_dns_proxy_server": ("POST", "/api/v1/batch"),
}
DELETE_OPS = {"fw_delete_dns_proxy_server"}
BATCH_OPS = {"fw_delete_batch_dns_proxy_server"}
NO_BODY_OPS = DELETE_OPS | {"fw_verify_dns_server", "fw_verify_dns_proxy_server"}
DNS_PROXY_SERVER_DELETE_RESOURCE = "/api/v1/dns/globalserver"
DNS_SYS_OP_IDS = frozenset(DNS_SYS_ENDPOINTS)


# ── payload builders ───────────────────────────────────────


def build_dns_server_payload(serveraddrs: list[str]) -> dict[str, Any]:
    """Build the PUT body ``{"id": 0, "val": {"serveraddr": [...]}}``.

    The first server address is the primary DNS server and the second is
    the backup.
    """
    return {"id": 0, "val": {"serveraddr": list(serveraddrs)}}


def build_dns_proxy_payload(enable: bool) -> dict[str, Any]:
    """Build the PUT body ``{"id": "dnsServer", "val": {"enable": bool}}``."""
    return {"id": "dnsServer", "val": {"enable": enable}}


def build_dns_proxy_server_payload(addrs: list[str]) -> dict[str, Any]:
    """Build the POST body ``{"val": {"servers": [{"addr": ...}]}}``."""
    return {"val": {"servers": [{"addr": addr} for addr in addrs]}}


def build_dns_proxy_server_delete_payload(addr: str) -> dict[str, Any]:
    """Build the delete payload ``{"id": <addr>}``; the addr goes to ?id=."""
    return {"id": addr}


def build_dns_proxy_server_batch_delete_payload(addrs: list[str]) -> dict[str, Any]:
    """Build the batch body with one DELETE /api/v1/dns/globalserver item per address."""
    return {
        "batch": [
            {"method": "DELETE", "resource": DNS_PROXY_SERVER_DELETE_RESOURCE, "body": {"id": [addr]}}
            for addr in addrs
        ]
    }


# ── validators ─────────────────────────────────────────────


def validate_dns_server_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("id") != 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "System DNS payload id must be 0.",
            {"field": "id", "value": payload.get("id")},
        )
    serveraddrs = (payload.get("val") or {}).get("serveraddr") if isinstance(payload.get("val"), dict) else None
    if not isinstance(serveraddrs, list) or not serveraddrs:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "System DNS payload requires a non-empty val.serveraddr list.",
            {"field": "val.serveraddr"},
        )
    for addr in serveraddrs:
        if not isinstance(addr, str) or not addr.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "System DNS serveraddr entries must be non-empty strings.",
                {"field": "val.serveraddr"},
            )
    return payload


def validate_dns_proxy_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if payload.get("id") != "dnsServer":
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "DNS proxy payload id must be dnsServer.",
            {"field": "id", "value": payload.get("id")},
        )
    val = payload.get("val")
    if not isinstance(val, dict) or not isinstance(val.get("enable"), bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "DNS proxy payload val.enable must be a boolean.",
            {"field": "val.enable"},
        )
    return payload


def validate_dns_proxy_server_payload(payload: dict[str, Any]) -> dict[str, Any]:
    val = payload.get("val")
    servers = val.get("servers") if isinstance(val, dict) else None
    if not isinstance(servers, list) or not servers:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "DNS proxy server payload requires a non-empty val.servers list.",
            {"field": "val.servers"},
        )
    for server in servers:
        if not isinstance(server, dict) or not isinstance(server.get("addr"), str) or not server["addr"].strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "DNS proxy server entries must carry a non-empty addr.",
                {"field": "val.servers[].addr"},
            )
    return payload


def validate_dns_proxy_server_delete_payload(payload: dict[str, Any]) -> dict[str, Any]:
    _validate_non_empty("id", str((payload or {}).get("id") or ""))
    return payload


def validate_dns_proxy_server_batch_payload(payload: dict[str, Any]) -> dict[str, Any]:
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
        if item.get("method") != "DELETE" or item.get("resource") != DNS_PROXY_SERVER_DELETE_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch item only supports DELETE on /api/v1/dns/globalserver.",
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


def build_dns_sys_dry_run(
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


def execute_dns_sys(
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
            "System DNS device request did not return a success status.",
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
        addr = str((payload or {}).get("id") or "")
        _validate_non_empty("id", addr)
        url = f"{url}?{urlencode({'id': addr})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return DNS_SYS_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this system DNS operation.",
            {"op_id": op_id},
        ) from exc


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required system DNS field is empty.",
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
            "System DNS payload file cannot be read.",
            {"path": payload_file, "reason": exc.__class__.__name__},
        ) from exc
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "System DNS payload must be valid JSON.",
            {"reason": exc.msg},
        ) from exc
    if not isinstance(payload, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "System DNS payload JSON root must be an object.",
            {"type": type(payload).__name__},
        )
    return payload
