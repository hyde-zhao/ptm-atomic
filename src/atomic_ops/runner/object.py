"""NGFW address-object configuration runner."""

from __future__ import annotations

from ipaddress import ip_address
from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}


def build_address_object_payload(
    *,
    object_name: str,
    ipaddr: str,
    mask: str,
    object_desc: str | None,
) -> dict[str, Any]:
    _validate_object_name(object_name)
    _validate_ipaddr(ipaddr)
    _validate_ipv4_mask(mask)
    return {
        "val": {
            "name": object_name,
            "desc": object_desc if object_desc is not None else object_name,
            "type": 4,
            "ranges": [],
            "networks": [
                {
                    "ipaddr": ipaddr,
                    "mask": str(mask),
                }
            ],
        }
    }


def build_address_object_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_config_object",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "POST",
            "url": f"{normalize_base_url(base_url)}/api/v1/ippool",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_address_object(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    normalized = normalize_base_url(base_url)
    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {
        "Content-Type": "application/json",
        auth_header: header_value,
    }
    status_code, response_payload, _text = request_json(
        "POST",
        f"{normalized}/api/v1/ippool",
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "Address-object configuration was rejected by the device.",
            {
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    return {
        "op_id": "fw_config_object",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "POST",
            "path": "/api/v1/ippool",
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }


def _validate_object_name(value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object name is required.",
            {"field": "object_name"},
        )
    if not value.replace("-", "").isalnum():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object name may contain only letters, numbers, and hyphens.",
            {"field": "object_name"},
        )


def _validate_ipaddr(value: str) -> None:
    try:
        parsed = ip_address(value)
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object ipaddr must be a valid IP address.",
            {"field": "ipaddr"},
        ) from exc
    if parsed.version != 4:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "This runner currently supports IPv4 address objects only.",
            {"field": "ipaddr", "version": parsed.version},
        )


def _validate_ipv4_mask(value: str) -> None:
    try:
        mask = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object mask must be an integer from 0 to 32.",
            {"field": "mask"},
        ) from exc
    if mask < 0 or mask > 32:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Address-object mask must be an integer from 0 to 32.",
            {"field": "mask", "mask": value},
        )
