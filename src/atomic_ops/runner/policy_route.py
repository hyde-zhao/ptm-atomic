"""NGFW policy-route configuration runner."""

from __future__ import annotations

from ipaddress import ip_address
from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}


def build_policy_route_payload(
    *,
    source_network: str,
    source_network_is_group: bool,
    dst_network: str,
    dst_network_is_group: bool,
    next_hop_ip: str,
    in_interface: str,
    outgoing_interface: str,
    service: str,
    weight: int,
    time_obj: str,
) -> dict[str, Any]:
    _validate_non_empty("source_network", source_network)
    _validate_non_empty("dst_network", dst_network)
    _validate_non_empty("next_hop_ip", next_hop_ip)
    _validate_non_empty("in_interface", in_interface)
    try:
        parsed_next_hop = ip_address(next_hop_ip)
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "next-hop IP must be a valid IP address.",
            {"field": "next_hop_ip"},
        ) from exc
    if parsed_next_hop.version != 4:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "This runner currently supports IPv4 policy routes only.",
            {"field": "next_hop_ip", "version": parsed_next_hop.version},
        )
    if weight < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Policy-route forwarding path weight must be at least 1.",
            {"field": "weight", "weight": weight},
        )

    return {
        "id": 0,
        "val": {
            "type": "ipv4",
            "in_interface": in_interface,
            "source_network": source_network,
            "source_network_is_group": source_network_is_group,
            "dst_network": dst_network,
            "dst_network_is_group": dst_network_is_group,
            "service": service,
            "service_is_group": False,
            "applist": [],
            "app_tag_name": [],
            "forwarding_paths": [
                {
                    "next_hop_ip": next_hop_ip,
                    "outgoing_interface": outgoing_interface,
                    "weight": weight,
                }
            ],
            "time_obj": time_obj,
            "action": 1,
        },
    }


def build_policy_route_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_config_policy_route",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "POST",
            "url": f"{normalize_base_url(base_url)}/api/v1/policyroute",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_policy_route(
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
        f"{normalized}/api/v1/policyroute",
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "Policy-route configuration was rejected by the device.",
            {
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    return {
        "op_id": "fw_config_policy_route",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "POST",
            "path": "/api/v1/policyroute",
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required policy-route field is empty.",
            {"field": field},
        )
