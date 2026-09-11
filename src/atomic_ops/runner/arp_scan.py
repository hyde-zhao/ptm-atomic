"""NGFW ARP scan runner for /api/v1/neighbor/scan endpoints.

Captured from F12 evidence (arp抓取.txt, 2026-08-26):
- fw_config_arp_scan:  PUT /api/v1/neighbor/scan/intf, id=neighbor_scan_intf
  body: {"id": "neighbor_scan_intf", "val": {"intfs": [{"name", "enable", "nets"[]}]}}
- fw_trigger_arp_scan: PUT /api/v1/neighbor/scan/trigger, id=neighbor_scan_trigger
  body: {"id": "neighbor_scan_trigger", "val": {"is_periodic", "period_in_seconds", "start_at_once"}}
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file

SUCCESS_STATUS = {200, 201, 202}
ARP_SCAN_ENDPOINTS = {
    "fw_config_arp_scan": ("PUT", "/api/v1/neighbor/scan/intf"),
    "fw_trigger_arp_scan": ("PUT", "/api/v1/neighbor/scan/trigger"),
}

CONFIG_OP = "fw_config_arp_scan"
TRIGGER_OP = "fw_trigger_arp_scan"
CIDR_RE = re.compile(r"^([0-9]{1,3}\.){3}[0-9]{1,3}/\d{1,2}$")


def build_arp_scan_config_payload(
    *,
    interface: str,
    nets: list[str],
    enable: bool,
) -> dict[str, Any]:
    _validate_non_empty("interface", interface)
    if not nets:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one CIDR net is required for ARP scan config.",
            {"field": "nets"},
        )
    for net in nets:
        _validate_cidr("nets", net)
    return {
        "id": "neighbor_scan_intf",
        "val": {
            "intfs": [
                {
                    "name": interface,
                    "enable": bool(enable),
                    "nets": list(nets),
                }
            ]
        },
    }


def build_arp_scan_trigger_payload(
    *,
    is_periodic: bool,
    period_in_seconds: int,
    start_at_once: bool,
) -> dict[str, Any]:
    period = _validate_positive_int("period_in_seconds", period_in_seconds)
    return {
        "id": "neighbor_scan_trigger",
        "val": {
            "is_periodic": bool(is_periodic),
            "period_in_seconds": period,
            "start_at_once": bool(start_at_once),
        },
    }


def validate_arp_scan_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RunnerError("RUNNER_VALIDATION_FAILED", "ARP scan payload must be an object.", {"field": "payload"})
    if op_id not in ARP_SCAN_ENDPOINTS:
        raise RunnerError("RUNNER_UNSUPPORTED_OP", "Runner does not support this ARP scan operation.", {"op_id": op_id})
    if str(payload.get("id") or "") != "neighbor_scan_intf" and op_id == CONFIG_OP:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ARP scan config payload id must be neighbor_scan_intf.",
            {"field": "id", "value": payload.get("id")},
        )
    if str(payload.get("id") or "") != "neighbor_scan_trigger" and op_id == TRIGGER_OP:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ARP scan trigger payload id must be neighbor_scan_trigger.",
            {"field": "id", "value": payload.get("id")},
        )
    val = payload.get("val")
    if not isinstance(val, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ARP scan payload val object is required.",
            {"field": "val"},
        )
    if op_id == CONFIG_OP:
        _validate_config_val(val)
    else:
        _validate_trigger_val(val)
    return payload


def _validate_config_val(val: dict[str, Any]) -> None:
    intfs = val.get("intfs")
    if not isinstance(intfs, list) or not intfs:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ARP scan config val.intfs must be a non-empty list.",
            {"field": "val.intfs"},
        )
    for item in intfs:
        if not isinstance(item, dict):
            raise RunnerError("RUNNER_VALIDATION_FAILED", "Each intfs item must be an object.", {"field": "val.intfs"})
        _validate_non_empty("name", str(item.get("name") or ""))
        if not isinstance(item.get("enable"), bool):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "ARP scan intfs enable must be a boolean.",
                {"field": "val.intfs[].enable"},
            )
        nets = item.get("nets")
        if not isinstance(nets, list) or not nets:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "ARP scan intfs nets must be a non-empty list.",
                {"field": "val.intfs[].nets"},
            )
        for net in nets:
            _validate_cidr("val.intfs[].nets", str(net))


def _validate_trigger_val(val: dict[str, Any]) -> None:
    if not isinstance(val.get("is_periodic"), bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ARP scan trigger is_periodic must be a boolean.",
            {"field": "val.is_periodic"},
        )
    if not isinstance(val.get("start_at_once"), bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ARP scan trigger start_at_once must be a boolean.",
            {"field": "val.start_at_once"},
        )
    _validate_positive_int("val.period_in_seconds", val.get("period_in_seconds"))


def build_arp_scan_dry_run(
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
            "url": _request_url(base_url, op_id),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_arp_scan(
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
        _request_url(base_url, op_id),
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response_payload)
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "ARP scan device request did not return a success status.",
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


def _request_url(base_url: str, op_id: str) -> str:
    _method, path = _method_path(op_id)
    return f"{normalize_base_url(base_url)}{path}"


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return ARP_SCAN_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this ARP scan operation.",
            {"op_id": op_id},
        ) from exc


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required ARP scan field is empty.",
            {"field": field},
        )


def _validate_cidr(field: str, value: str) -> None:
    _validate_non_empty(field, value)
    if not CIDR_RE.match(value):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ARP scan net must be a CIDR string such as 66.1.1.0/24.",
            {"field": field, "value": value},
        )


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ARP scan integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ARP scan integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed
