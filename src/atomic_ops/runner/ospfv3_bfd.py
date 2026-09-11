"""NGFW OSPFv3 and BFD runner."""

from __future__ import annotations

from ipaddress import ip_address
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
OSPFV3_BFD_ENDPOINTS = {
    "fw_config_ospfv3_global": ("PUT", "/api/v1/ospf6config"),
    "fw_verify_ospfv3_global": ("GET", "/api/v1/ospf6config"),
    "fw_config_ospfv3_redistribution": ("PUT", "/api/v1/ospf6redist"),
    "fw_verify_ospfv3_redistribution": ("GET", "/api/v1/ospf6redist"),
    "fw_config_ospfv3_network": ("POST", "/api/v1/ospf6network"),
    "fw_config_ospfv3_network_update": ("PUT", "/api/v1/ospf6network"),
    "fw_delete_ospfv3_network": ("DELETE", "/api/v1/ospf6network"),
    "fw_verify_ospfv3_network": ("GET", "/api/v1/ospf6network"),
    "fw_config_ospfv3_interface": ("POST", "/api/v1/ospf6interface"),
    "fw_config_ospfv3_interface_update": ("PUT", "/api/v1/ospf6interface"),
    "fw_delete_ospfv3_interface": ("DELETE", "/api/v1/ospf6interface"),
    "fw_verify_ospfv3_interface": ("GET", "/api/v1/ospf6interface"),
    "fw_verify_ospfv3_neighbor": ("GET", "/api/v1/ospf6neighbor"),
    "fw_capture_ospfv3_log": ("GET", "/api/v1/ospf6log"),
    "fw_config_bfd_global": ("PUT", "/api/v1/bfdconfig"),
    "fw_verify_bfd_global": ("GET", "/api/v1/bfdconfig"),
    "fw_verify_bfd_session": ("GET", "/api/v1/bfdsession"),
    "fw_capture_bfd_log": ("GET", "/api/v1/bfdlog"),
}
PAGINATED_OPS = {
    "fw_verify_ospfv3_neighbor",
    "fw_capture_ospfv3_log",
    "fw_verify_bfd_session",
    "fw_capture_bfd_log",
}
QUERY_ID_DELETE_OPS = {"fw_delete_ospfv3_interface"}
OSPFV3_REDISTRIBUTE_PROTOCOLS = {"connected", "static"}


def build_ospfv3_bfd_payload(op_id: str, params: dict[str, Any]) -> dict[str, Any] | None:
    if op_id == "fw_config_ospfv3_global":
        return build_ospfv3_global_payload(
            entry_id=str(params.get("id") or "0"),
            enable=_required_bool(params, "enable"),
            router_id=str(params.get("router_id") or ""),
        )
    if op_id == "fw_config_ospfv3_redistribution":
        return build_ospfv3_redistribution_payload(
            entry_id=str(params.get("id") or "0"),
            redistribute=list(params.get("redistribute") or []),
        )
    if op_id in {"fw_config_ospfv3_network", "fw_config_ospfv3_network_update"}:
        return build_ospfv3_network_payload(
            interface=str(params.get("interface") or ""),
            area=str(params.get("area") or ""),
            entry_id=_optional_required_id(op_id, params),
        )
    if op_id in {"fw_delete_ospfv3_network", "fw_delete_ospfv3_interface"}:
        return build_delete_payload(entry_id=str(params.get("id") or ""))
    if op_id in {"fw_config_ospfv3_interface", "fw_config_ospfv3_interface_update"}:
        return build_ospfv3_interface_payload(
            interface=str(params.get("interface") or ""),
            cost=str(params.get("cost") or ""),
            priority=str(params.get("priority") or ""),
            hello_interval=str(params.get("hello_interval") or ""),
            retransmit_interval=str(params.get("retransmit_interval") or ""),
            dead_interval=str(params.get("dead_interval") or ""),
            transmit_delay=str(params.get("transmit_delay") or ""),
            type_network=params.get("type_network"),
            entry_id=_optional_required_id(op_id, params),
        )
    if op_id == "fw_config_bfd_global":
        return build_bfd_global_payload(
            entry_id=str(params.get("id") or "0"),
            enable=_required_bool(params, "enable"),
        )
    if op_id in OSPFV3_BFD_ENDPOINTS:
        return None
    raise RunnerError(
        "RUNNER_UNSUPPORTED_OP",
        "Runner does not support this OSPFv3 or BFD operation.",
        {"op_id": op_id},
    )


def build_ospfv3_global_payload(*, entry_id: str, enable: bool, router_id: str) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    _validate_ipv4("router_id", router_id)
    return {"id": str(entry_id), "val": {"enable": enable, "routerId": router_id}}


def build_ospfv3_redistribution_payload(*, entry_id: str, redistribute: list[str]) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    if not redistribute:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one OSPFv3 redistribution mapping is required.",
            {"field": "redistribute"},
        )
    entries: list[dict[str, str]] = []
    for raw_item in redistribute:
        if "=" not in raw_item:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Redistribution item must use protocol=metric format.",
                {"field": "redistribute", "value": raw_item},
            )
        protocol, metric = raw_item.split("=", 1)
        protocol = protocol.strip()
        metric = metric.strip()
        if protocol not in OSPFV3_REDISTRIBUTE_PROTOCOLS:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Unsupported OSPFv3 redistribution protocol.",
                {"field": "protocol", "protocol": protocol, "allowed": sorted(OSPFV3_REDISTRIBUTE_PROTOCOLS)},
            )
        _validate_non_negative_int_string("metric", metric)
        entries.append({"protocol": protocol, "metric": metric})
    return {"id": str(entry_id), "val": {"redistribute": entries}}


def build_ospfv3_network_payload(*, interface: str, area: str, entry_id: str | None = None) -> dict[str, Any]:
    _validate_non_empty("interface", interface)
    _validate_non_empty("area", area)
    payload: dict[str, Any] = {"val": {"interface": interface, "area": area}}
    if entry_id is not None:
        _validate_non_empty("id", entry_id)
        payload["id"] = str(entry_id)
    return payload


def build_ospfv3_interface_payload(
    *,
    interface: str,
    cost: str,
    priority: str,
    hello_interval: str,
    retransmit_interval: str,
    dead_interval: str,
    transmit_delay: str,
    type_network: Any,
    entry_id: str | None = None,
) -> dict[str, Any]:
    _validate_non_empty("interface", interface)
    for field, value in (
        ("cost", cost),
        ("priority", priority),
        ("hello_interval", hello_interval),
        ("retransmit_interval", retransmit_interval),
        ("dead_interval", dead_interval),
        ("transmit_delay", transmit_delay),
    ):
        _validate_non_negative_int_string(field, value)
    payload: dict[str, Any] = {
        "val": {
            "interface": interface,
            "cost": cost,
            "priority": priority,
            "helloInterval": hello_interval,
            "retransmitInterval": retransmit_interval,
            "deadInterval": dead_interval,
            "transmitDelay": transmit_delay,
            "typeNetwork": _validate_non_negative_int("type_network", type_network),
        }
    }
    if entry_id is not None:
        _validate_non_empty("id", entry_id)
        payload["id"] = str(entry_id)
    return payload


def build_bfd_global_payload(*, entry_id: str, enable: bool) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    return {"id": str(entry_id), "val": {"enable": enable}}


def build_delete_payload(*, entry_id: str) -> dict[str, str]:
    _validate_non_empty("id", entry_id)
    return {"id": str(entry_id)}


def build_ospfv3_bfd_dry_run(
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
            "url": _request_url(base_url, op_id, page=page, size=size, payload=payload),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in QUERY_ID_DELETE_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_ospfv3_bfd(
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
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    status_code, response_payload, _text = request_json(
        method,
        _request_url(base_url, op_id, page=page, size=size, payload=payload),
        headers=headers,
        json_payload=None if op_id in QUERY_ID_DELETE_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise_if_device_session_rejected(status_code, response_payload)
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED" if method != "GET" else "RUNNER_RESPONSE_INVALID",
            "OSPFv3 or BFD device request did not return a success status.",
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
    page: int,
    size: int,
    payload: dict[str, Any] | None = None,
) -> str:
    _validate_pagination(page, size)
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in PAGINATED_OPS:
        url = f"{url}?{urlencode({'page': page, 'size': size})}"
    if op_id in QUERY_ID_DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return OSPFV3_BFD_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this OSPFv3 or BFD operation.",
            {"op_id": op_id},
        ) from exc


def _optional_required_id(op_id: str, params: dict[str, Any]) -> str | None:
    if op_id.endswith("_update"):
        entry_id = str(params.get("id") or "")
        _validate_non_empty("id", entry_id)
        return entry_id
    return None


def _required_bool(params: dict[str, Any], field: str) -> bool:
    value = params.get(field)
    if value is None:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required boolean flag is missing.",
            {"field": field},
        )
    if not isinstance(value, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Boolean flag must be true or false.",
            {"field": field},
        )
    return value


def _validate_pagination(page: int, size: int) -> None:
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)


def _validate_ipv4(field: str, value: str) -> None:
    try:
        parsed = ip_address(value)
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Field must be a valid IPv4 address.",
            {"field": field},
        ) from exc
    if parsed.version != 4:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Field must be an IPv4 address.",
            {"field": field, "version": parsed.version},
        )


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required field is empty.",
            {"field": field},
        )


def _validate_non_negative_int_string(field: str, value: str) -> None:
    _validate_non_empty(field, value)
    try:
        parsed = int(value)
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Field must be a non-negative integer string.",
            {"field": field},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Field must be a non-negative integer string.",
            {"field": field, "value": value},
        )


def _validate_non_negative_int(field: str, value: Any) -> int:
    parsed = _parse_int(field, value)
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Field must be a non-negative integer.",
            {"field": field, "value": value},
        )
    return parsed


def _validate_positive_int(field: str, value: Any) -> int:
    parsed = _parse_int(field, value)
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Field must be a positive integer.",
            {"field": field, "value": value},
        )
    return parsed


def _parse_int(field: str, value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Field must be an integer.",
            {"field": field},
        ) from exc
