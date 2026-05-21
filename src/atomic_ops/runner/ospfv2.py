"""NGFW OSPFv2 runner."""

from __future__ import annotations

from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
OSPFV2_ENDPOINTS = {
    "fw_config_ospfv2_global": ("PUT", "/api/v1/ospfconfig"),
    "fw_verify_ospfv2_global": ("GET", "/api/v1/ospfconfig"),
    "fw_config_ospfv2_redistribution": ("PUT", "/api/v1/ospfredist"),
    "fw_verify_ospfv2_redistribution": ("GET", "/api/v1/ospfredist"),
    "fw_config_ospfv2_network": ("POST", "/api/v1/ospfnetwork"),
    "fw_config_ospfv2_network_update": ("PUT", "/api/v1/ospfnetwork"),
    "fw_delete_ospfv2_network": ("DELETE", "/api/v1/ospfnetwork"),
    "fw_verify_ospfv2_network": ("GET", "/api/v1/ospfnetwork"),
    "fw_config_ospfv2_interface": ("POST", "/api/v1/ospfinterface"),
    "fw_config_ospfv2_interface_update": ("PUT", "/api/v1/ospfinterface"),
    "fw_delete_ospfv2_interface": ("DELETE", "/api/v1/ospfinterface"),
    "fw_verify_ospfv2_interface": ("GET", "/api/v1/ospfinterface"),
    "fw_verify_ospfv2_neighbor": ("GET", "/api/v1/ospfneighbor"),
    "fw_capture_ospfv2_log": ("GET", "/api/v1/ospflog"),
}
PAGINATED_OPS = {"fw_verify_ospfv2_neighbor", "fw_capture_ospfv2_log"}
QUERY_ID_DELETE_OPS = {"fw_delete_ospfv2_network", "fw_delete_ospfv2_interface"}
REDISTRIBUTE_PROTOCOLS = {"connected", "static", "rip"}


def build_ospfv2_payload(op_id: str, params: dict[str, Any]) -> dict[str, Any] | None:
    if op_id == "fw_config_ospfv2_global":
        return build_ospfv2_global_payload(
            router_id=str(params.get("router_id") or ""),
            enable=_required_bool(params, "enable"),
            originate=_required_bool(params, "originate"),
            always=_required_bool(params, "always"),
            entry_id=str(params.get("id") or "0"),
        )
    if op_id == "fw_config_ospfv2_redistribution":
        return build_ospfv2_redistribution_payload(
            redistribute=list(params.get("redistribute") or []),
            entry_id=str(params.get("id") or "0"),
        )
    if op_id in {"fw_config_ospfv2_network", "fw_config_ospfv2_network_update"}:
        return build_ospfv2_network_payload(
            network=str(params.get("network") or ""),
            area=str(params.get("area") or ""),
            entry_id=_optional_required_id(op_id, params),
        )
    if op_id in {"fw_delete_ospfv2_network", "fw_delete_ospfv2_interface"}:
        return build_ospfv2_delete_payload(entry_id=str(params.get("id") or ""))
    if op_id in {"fw_config_ospfv2_interface", "fw_config_ospfv2_interface_update"}:
        return build_ospfv2_interface_payload(
            interface=str(params.get("interface") or ""),
            cost=str(params.get("cost") or ""),
            priority=str(params.get("priority") or ""),
            hello_interval=str(params.get("hello_interval") or ""),
            retransmit_interval=str(params.get("retransmit_interval") or ""),
            dead_interval=str(params.get("dead_interval") or ""),
            transmit_delay=str(params.get("transmit_delay") or ""),
            type_network=params.get("type_network"),
            int_auth_mode=params.get("int_auth_mode"),
            bfd_enable=_required_bool(params, "bfd_enable"),
            detect_multiplier=params.get("detect_multiplier"),
            min_rx_interval=params.get("min_rx_interval"),
            min_tx_interval=params.get("min_tx_interval"),
            entry_id=_optional_required_id(op_id, params),
        )
    if op_id in OSPFV2_ENDPOINTS:
        return None
    raise RunnerError(
        "RUNNER_UNSUPPORTED_OP",
        "Runner does not support this OSPFv2 operation.",
        {"op_id": op_id},
    )


def build_ospfv2_global_payload(
    *,
    router_id: str,
    enable: bool,
    originate: bool,
    always: bool,
    entry_id: str = "0",
) -> dict[str, Any]:
    _validate_ipv4("router_id", router_id)
    _validate_non_empty("id", entry_id)
    return {
        "id": str(entry_id),
        "val": {
            "enable": enable,
            "routerId": router_id,
            "originate": originate,
            "always": always,
        },
    }


def build_ospfv2_redistribution_payload(
    *,
    redistribute: list[str],
    entry_id: str = "0",
) -> dict[str, Any]:
    _validate_non_empty("id", entry_id)
    if not redistribute:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one OSPFv2 redistribution mapping is required.",
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
        if protocol not in REDISTRIBUTE_PROTOCOLS:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Unsupported OSPFv2 redistribution protocol.",
                {"field": "protocol", "protocol": protocol, "allowed": sorted(REDISTRIBUTE_PROTOCOLS)},
            )
        _validate_non_negative_int_string("metric", metric)
        entries.append({"protocol": protocol, "metric": metric})
    return {"id": str(entry_id), "val": {"redistribute": entries}}


def build_ospfv2_network_payload(
    *,
    network: str,
    area: str,
    entry_id: str | None = None,
) -> dict[str, Any]:
    _validate_ipv4_network("network", network)
    _validate_non_empty("area", area)
    payload: dict[str, Any] = {"val": {"network": network, "area": area}}
    if entry_id is not None:
        _validate_non_empty("id", entry_id)
        payload["id"] = str(entry_id)
    return payload


def build_ospfv2_delete_payload(*, entry_id: str) -> dict[str, str]:
    _validate_non_empty("id", entry_id)
    return {"id": str(entry_id)}


def build_ospfv2_interface_payload(
    *,
    interface: str,
    cost: str,
    priority: str,
    hello_interval: str,
    retransmit_interval: str,
    dead_interval: str,
    transmit_delay: str,
    type_network: Any,
    int_auth_mode: Any,
    bfd_enable: bool,
    detect_multiplier: Any,
    min_rx_interval: Any,
    min_tx_interval: Any,
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

    val = {
        "interface": interface,
        "cost": cost,
        "priority": priority,
        "helloInterval": hello_interval,
        "retransmitInterval": retransmit_interval,
        "deadInterval": dead_interval,
        "transmitDelay": transmit_delay,
        "typeNetwork": _validate_non_negative_int("type_network", type_network),
        "intAuthMode": _validate_non_negative_int("int_auth_mode", int_auth_mode),
        "bfdEnable": bfd_enable,
        "detectMultiplier": _validate_positive_int("detect_multiplier", detect_multiplier),
        "minRxInterval": _validate_positive_int("min_rx_interval", min_rx_interval),
        "minTxInterval": _validate_positive_int("min_tx_interval", min_tx_interval),
    }
    payload: dict[str, Any] = {"val": val}
    if entry_id is not None:
        _validate_non_empty("id", entry_id)
        payload["id"] = str(entry_id)
    return payload


def build_ospfv2_dry_run(
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


def execute_ospfv2(
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
    headers = {
        "Content-Type": "application/json",
        auth_header: header_value,
    }
    url = _request_url(base_url, op_id, page=page, size=size, payload=payload)
    status_code, response_payload, _text = request_json(
        method,
        url,
        headers=headers,
        json_payload=None if op_id in QUERY_ID_DELETE_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED" if method != "GET" else "RUNNER_RESPONSE_INVALID",
            "OSPFv2 device request did not return a success status.",
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
        return OSPFV2_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this OSPFv2 operation.",
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
            "Required OSPFv2 boolean flag is missing.",
            {"field": field},
        )
    if not isinstance(value, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "OSPFv2 boolean flag must be true or false.",
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
            "OSPFv2 field must be a valid IPv4 address.",
            {"field": field},
        ) from exc
    if parsed.version != 4:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "OSPFv2 field must be an IPv4 address.",
            {"field": field, "version": parsed.version},
        )


def _validate_ipv4_network(field: str, value: str) -> None:
    if "/" not in value:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "OSPFv2 field must be an IPv4 CIDR network.",
            {"field": field},
        )
    try:
        parsed = ip_network(value, strict=False)
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "OSPFv2 field must be a valid IPv4 network.",
            {"field": field},
        ) from exc
    if parsed.version != 4:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "OSPFv2 field must be an IPv4 network.",
            {"field": field, "version": parsed.version},
        )


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required OSPFv2 field is empty.",
            {"field": field},
        )


def _validate_non_negative_int_string(field: str, value: str) -> None:
    _validate_non_empty(field, value)
    try:
        parsed = int(value)
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "OSPFv2 field must be a non-negative integer string.",
            {"field": field},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "OSPFv2 field must be a non-negative integer string.",
            {"field": field, "value": value},
        )


def _validate_non_negative_int(field: str, value: Any) -> int:
    parsed = _parse_int(field, value)
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "OSPFv2 field must be a non-negative integer.",
            {"field": field, "value": value},
        )
    return parsed


def _validate_positive_int(field: str, value: Any) -> int:
    parsed = _parse_int(field, value)
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "OSPFv2 field must be a positive integer.",
            {"field": field, "value": value},
        )
    return parsed


def _parse_int(field: str, value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "OSPFv2 field must be an integer.",
            {"field": field},
        ) from exc
