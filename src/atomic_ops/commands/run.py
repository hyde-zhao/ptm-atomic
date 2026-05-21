"""Implementation for the atomic-ops run command."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

import yaml

from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import DEFAULT_SESSION_FILE, resolve_session_file


OSPFV2_OPS = (
    "fw_config_ospfv2_global",
    "fw_verify_ospfv2_global",
    "fw_config_ospfv2_redistribution",
    "fw_verify_ospfv2_redistribution",
    "fw_config_ospfv2_network",
    "fw_config_ospfv2_network_update",
    "fw_delete_ospfv2_network",
    "fw_verify_ospfv2_network",
    "fw_config_ospfv2_interface",
    "fw_config_ospfv2_interface_update",
    "fw_delete_ospfv2_interface",
    "fw_verify_ospfv2_interface",
    "fw_verify_ospfv2_neighbor",
    "fw_capture_ospfv2_log",
)
OSPFV3_BFD_OPS = (
    "fw_config_ospfv3_global",
    "fw_verify_ospfv3_global",
    "fw_config_ospfv3_redistribution",
    "fw_verify_ospfv3_redistribution",
    "fw_config_ospfv3_network",
    "fw_config_ospfv3_network_update",
    "fw_delete_ospfv3_network",
    "fw_verify_ospfv3_network",
    "fw_config_ospfv3_interface",
    "fw_config_ospfv3_interface_update",
    "fw_delete_ospfv3_interface",
    "fw_verify_ospfv3_interface",
    "fw_verify_ospfv3_neighbor",
    "fw_capture_ospfv3_log",
    "fw_config_bfd_global",
    "fw_verify_bfd_global",
    "fw_verify_bfd_session",
    "fw_capture_bfd_log",
)
POLICY_ROUTE_OPS = (
    "fw_config_policy_route",
    "fw_update_policy_route",
    "fw_delete_policy_route",
    "fw_verify_policy_route",
    "fw_update_policy_route_priority",
)
SUPPORTED_OPS = (
    "fw_login_web_management",
    "fw_config_object",
    *POLICY_ROUTE_OPS,
    *OSPFV2_OPS,
    *OSPFV3_BFD_OPS,
)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("op_id", help="Operation id to run.")
    parser.add_argument(
        "--format",
        choices=("json", "yaml"),
        default="yaml",
        help="Output format.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Perform live device requests. Omit for dry-run.",
    )
    parser.add_argument(
        "--base-url",
        required=True,
        help="Device management base URL, for example https://10.0.0.1.",
    )
    parser.add_argument(
        "--session-file",
        default=str(DEFAULT_SESSION_FILE),
        help="Session file path. Defaults to ~/.local/state/atomic-ops/ngfw/session.json.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify the device TLS certificate. Disabled by default for lab NGFW devices.",
    )

    parser.add_argument("--username", help="NGFW web-management username for fw_login_web_management.")
    parser.add_argument(
        "--password-env",
        help="Environment variable containing the NGFW web-management password.",
    )
    parser.add_argument(
        "--change-default-password",
        action="store_true",
        help="Allow fw_login_web_management to call /api/v1/changeDefPwd when the device requires it.",
    )
    parser.add_argument(
        "--new-password-env",
        help="Environment variable containing the replacement password for --change-default-password.",
    )

    parser.add_argument("--object-name", help="Address-object name for fw_config_object.")
    parser.add_argument("--ipaddr", help="IPv4 address or network address for fw_config_object.")
    parser.add_argument("--mask", help="IPv4 mask length for fw_config_object, for example 16 or 24.")
    parser.add_argument("--object-desc", help="Optional address-object description.")

    parser.add_argument("--source-network", help="Policy-route source address object or address-group name.")
    parser.add_argument(
        "--source-network-is-group",
        action="store_true",
        help="Treat --source-network as an address-group name.",
    )
    parser.add_argument("--dst-network", default="any", help="Policy-route destination address object or address-group name.")
    parser.add_argument(
        "--dst-network-is-group",
        action="store_true",
        help="Treat --dst-network as an address-group name.",
    )
    parser.add_argument("--next-hop-ip", help="Policy-route forwarding next-hop IPv4 address.")
    parser.add_argument("--in-interface", help="Policy-route incoming interface.")
    parser.add_argument("--outgoing-interface", default="", help="Policy-route outgoing interface.")
    parser.add_argument("--service", default="any", help="Policy-route service object/name.")
    parser.add_argument("--service-is-group", action="store_true", help="Treat --service as a service-group name.")
    parser.add_argument("--weight", type=int, default=100, help="Policy-route forwarding path weight.")
    parser.add_argument("--time-obj", default="", help="Policy-route time object.")
    parser.add_argument(
        "--policy-route-type",
        choices=("ipv4", "ipv6"),
        default="ipv4",
        help="Policy-route address family. Also controls is_ip6 for query and priority operations.",
    )
    policy_route_active_group = parser.add_mutually_exclusive_group()
    policy_route_active_group.add_argument(
        "--policy-route-active",
        dest="policy_route_active",
        action="store_true",
        default=True,
        help="Enable the policy route.",
    )
    policy_route_active_group.add_argument(
        "--policy-route-inactive",
        dest="policy_route_active",
        action="store_false",
        help="Disable the policy route.",
    )
    parser.add_argument("--policy-route-action", type=int, default=1, help="Policy-route action value.")
    parser.add_argument("--config-source", type=int, default=0, help="Policy-route config_source value.")
    parser.add_argument(
        "--targetsite",
        choices=("before", "after", "first", "last"),
        help="Policy-route priority target site for fw_update_policy_route_priority.",
    )
    parser.add_argument("--targetid", help="Policy-route priority target id.")
    parser.add_argument("--moveid", help="Policy-route priority moving route id.")

    parser.add_argument("--id", help="OSPFv2 entry id for global, redistribution, update, or delete operations.")
    enable_group = parser.add_mutually_exclusive_group()
    enable_group.add_argument("--enable", dest="enable", action="store_true", default=None, help="Enable OSPFv2 globally.")
    enable_group.add_argument("--disable", dest="enable", action="store_false", help="Disable OSPFv2 globally.")
    parser.add_argument("--router-id", help="OSPFv2 router ID IPv4 address.")
    originate_group = parser.add_mutually_exclusive_group()
    originate_group.add_argument("--originate", dest="originate", action="store_true", default=None, help="Enable default route origination.")
    originate_group.add_argument("--no-originate", dest="originate", action="store_false", help="Disable default route origination.")
    always_group = parser.add_mutually_exclusive_group()
    always_group.add_argument("--always", dest="always", action="store_true", default=None, help="Always originate the default route.")
    always_group.add_argument("--no-always", dest="always", action="store_false", help="Do not always originate the default route.")
    parser.add_argument(
        "--redistribute",
        action="append",
        default=[],
        help="OSPFv2 redistribution mapping in protocol=metric form. May be repeated.",
    )
    parser.add_argument("--network", help="OSPFv2 network in IPv4 CIDR form.")
    parser.add_argument("--area", help="OSPFv2 area id.")
    parser.add_argument("--interface", help="OSPFv2 interface name.")
    parser.add_argument("--cost", help="OSPFv2 interface cost.")
    parser.add_argument("--priority", help="OSPFv2 interface priority.")
    parser.add_argument("--hello-interval", help="OSPFv2 hello interval.")
    parser.add_argument("--retransmit-interval", help="OSPFv2 retransmit interval.")
    parser.add_argument("--dead-interval", help="OSPFv2 dead interval.")
    parser.add_argument("--transmit-delay", help="OSPFv2 transmit delay.")
    parser.add_argument("--type-network", type=int, help="OSPFv2 interface network type.")
    parser.add_argument("--int-auth-mode", type=int, help="OSPFv2 interface authentication mode.")
    bfd_group = parser.add_mutually_exclusive_group()
    bfd_group.add_argument("--bfd-enable", dest="bfd_enable", action="store_true", default=None, help="Enable BFD on the OSPFv2 interface.")
    bfd_group.add_argument("--bfd-disable", dest="bfd_enable", action="store_false", help="Disable BFD on the OSPFv2 interface.")
    parser.add_argument("--detect-multiplier", type=int, help="OSPFv2 BFD detect multiplier.")
    parser.add_argument("--min-rx-interval", type=int, help="OSPFv2 BFD minimum receive interval.")
    parser.add_argument("--min-tx-interval", type=int, help="OSPFv2 BFD minimum transmit interval.")
    parser.add_argument("--page", type=int, default=1, help="OSPFv2 paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="OSPFv2 paginated query page size.")
    parser.add_argument(
        "--auth-header",
        choices=("Authorization", "AuthorizationToken"),
        default="Authorization",
        help="Authentication header used for object and policy-route execution.",
    )


def run(args: argparse.Namespace) -> int:
    output_format = getattr(args, "format", "yaml")
    try:
        if not getattr(args, "verify_tls"):
            write_warning(
                {
                    "warning_code": "TLS_VERIFY_DISABLED",
                    "message": "Device TLS verification is disabled for this runner invocation.",
                },
                output_format,
            )

        op_id = getattr(args, "op_id")
        if op_id == "fw_login_web_management":
            payload = _run_login(args)
        elif op_id == "fw_config_object":
            payload = _run_object(args)
        elif op_id in POLICY_ROUTE_OPS:
            payload = _run_policy_route(args)
        elif op_id in OSPFV2_OPS:
            payload = _run_ospfv2(args)
        elif op_id in OSPFV3_BFD_OPS:
            payload = _run_ospfv3_bfd(args)
        else:
            raise RunnerError(
                "RUNNER_UNSUPPORTED_OP",
                "Runner does not support this operation.",
                {"op_id": op_id, "supported_ops": list(SUPPORTED_OPS)},
                suggestion="Use atomic-ops adapter for unsupported operations, or add a dedicated runner.",
            )
        _write_output(_to_run_envelope(payload), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(
                exc.error_code,
                exc.message,
                exc.details,
                retryable=exc.retryable,
                suggestion=exc.suggestion,
            ),
            output_format,
        )


def _run_login(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.ngfw_login import build_login_dry_run, login
    from atomic_ops.runner.session import session_summary, write_session_file

    session_file = resolve_session_file(getattr(args, "session_file", None))
    username = getattr(args, "username") or "admin"
    if not getattr(args, "execute"):
        return build_login_dry_run(
            base_url=getattr(args, "base_url"),
            username=username,
            session_file=str(session_file),
            change_default_password=bool(getattr(args, "change_default_password")),
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )

    password_value = _read_secret_env(getattr(args, "password_env", None), "password_env")
    replacement_value = None
    if getattr(args, "change_default_password"):
        replacement_value = _read_secret_env(getattr(args, "new_password_env", None), "new_password_env")

    result = login(
        base_url=getattr(args, "base_url"),
        username=username,
        password_value=password_value,
        timeout=float(getattr(args, "timeout")),
        verify_tls=bool(getattr(args, "verify_tls")),
        change_default_password=bool(getattr(args, "change_default_password")),
        replacement_value=replacement_value,
    )
    session_payload = write_session_file(
        session_file,
        base_url=result["base_url"],
        username=username,
        session_value=result["session_value"],
        source_op_id="fw_login_web_management",
    )
    return {
        "op_id": "fw_login_web_management",
        "status": "success",
        "session": session_summary(session_file, session_payload),
    }


def _run_object(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.object import (
        build_address_object_dry_run,
        build_address_object_payload,
        execute_address_object,
    )

    session_file = resolve_session_file(getattr(args, "session_file", None))
    _require_arg(args, "object_name")
    _require_arg(args, "ipaddr")
    _require_arg(args, "mask")
    payload = build_address_object_payload(
        object_name=getattr(args, "object_name"),
        ipaddr=getattr(args, "ipaddr"),
        mask=getattr(args, "mask"),
        object_desc=getattr(args, "object_desc"),
    )
    if not getattr(args, "execute"):
        return build_address_object_dry_run(
            base_url=getattr(args, "base_url"),
            session_file=session_file,
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )
    return execute_address_object(
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout")),
    )


def _run_policy_route(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.policy_route import (
        build_policy_route_delete_payload,
        build_policy_route_dry_run,
        build_policy_route_payload,
        build_policy_route_priority_payload,
        execute_policy_route,
    )

    op_id = getattr(args, "op_id")
    session_file = resolve_session_file(getattr(args, "session_file", None))
    route_type = getattr(args, "policy_route_type")
    payload: dict[str, Any] | None
    if op_id in {"fw_config_policy_route", "fw_update_policy_route"}:
        _require_arg(args, "source_network")
        _require_arg(args, "next_hop_ip")
        _require_arg(args, "in_interface")
        if op_id == "fw_update_policy_route":
            _require_arg(args, "id")
        payload = build_policy_route_payload(
            source_network=getattr(args, "source_network"),
            source_network_is_group=bool(getattr(args, "source_network_is_group")),
            dst_network=getattr(args, "dst_network"),
            dst_network_is_group=bool(getattr(args, "dst_network_is_group")),
            next_hop_ip=getattr(args, "next_hop_ip"),
            in_interface=getattr(args, "in_interface"),
            outgoing_interface=getattr(args, "outgoing_interface"),
            service=getattr(args, "service"),
            service_is_group=bool(getattr(args, "service_is_group")),
            weight=int(getattr(args, "weight")),
            time_obj=getattr(args, "time_obj"),
            route_type=route_type,
            entry_id=getattr(args, "id") if op_id == "fw_update_policy_route" else 0,
            active=bool(getattr(args, "policy_route_active")),
            action=int(getattr(args, "policy_route_action")),
            config_source=int(getattr(args, "config_source")),
        )
    elif op_id == "fw_delete_policy_route":
        _require_arg(args, "id")
        payload = build_policy_route_delete_payload(entry_id=getattr(args, "id"))
    elif op_id == "fw_update_policy_route_priority":
        _require_arg(args, "targetsite")
        _require_arg(args, "targetid")
        _require_arg(args, "moveid")
        payload = build_policy_route_priority_payload(
            targetsite=getattr(args, "targetsite"),
            targetid=getattr(args, "targetid"),
            moveid=getattr(args, "moveid"),
            route_type=route_type,
        )
    else:
        payload = None
    if not getattr(args, "execute"):
        return build_policy_route_dry_run(
            op_id=op_id,
            base_url=getattr(args, "base_url"),
            session_file=session_file,
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            page=int(getattr(args, "page")),
            size=int(getattr(args, "size")),
            route_type=route_type,
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )
    return execute_policy_route(
        op_id=op_id,
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        page=int(getattr(args, "page")),
        size=int(getattr(args, "size")),
        route_type=route_type,
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout")),
    )


def _run_ospfv2(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.ospfv2 import build_ospfv2_dry_run, build_ospfv2_payload, execute_ospfv2

    op_id = getattr(args, "op_id")
    session_file = resolve_session_file(getattr(args, "session_file", None))
    payload = build_ospfv2_payload(
        op_id,
        {
            "id": getattr(args, "id"),
            "enable": getattr(args, "enable"),
            "router_id": getattr(args, "router_id"),
            "originate": getattr(args, "originate"),
            "always": getattr(args, "always"),
            "redistribute": getattr(args, "redistribute"),
            "network": getattr(args, "network"),
            "area": getattr(args, "area"),
            "interface": getattr(args, "interface"),
            "cost": getattr(args, "cost"),
            "priority": getattr(args, "priority"),
            "hello_interval": getattr(args, "hello_interval"),
            "retransmit_interval": getattr(args, "retransmit_interval"),
            "dead_interval": getattr(args, "dead_interval"),
            "transmit_delay": getattr(args, "transmit_delay"),
            "type_network": getattr(args, "type_network"),
            "int_auth_mode": getattr(args, "int_auth_mode"),
            "bfd_enable": getattr(args, "bfd_enable"),
            "detect_multiplier": getattr(args, "detect_multiplier"),
            "min_rx_interval": getattr(args, "min_rx_interval"),
            "min_tx_interval": getattr(args, "min_tx_interval"),
        },
    )
    if not getattr(args, "execute"):
        return build_ospfv2_dry_run(
            op_id=op_id,
            base_url=getattr(args, "base_url"),
            session_file=session_file,
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            page=int(getattr(args, "page")),
            size=int(getattr(args, "size")),
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )
    return execute_ospfv2(
        op_id=op_id,
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        page=int(getattr(args, "page")),
        size=int(getattr(args, "size")),
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout")),
    )


def _run_ospfv3_bfd(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.ospfv3_bfd import (
        build_ospfv3_bfd_dry_run,
        build_ospfv3_bfd_payload,
        execute_ospfv3_bfd,
    )

    op_id = getattr(args, "op_id")
    session_file = resolve_session_file(getattr(args, "session_file", None))
    payload = build_ospfv3_bfd_payload(
        op_id,
        {
            "id": getattr(args, "id"),
            "enable": getattr(args, "enable"),
            "router_id": getattr(args, "router_id"),
            "redistribute": getattr(args, "redistribute"),
            "interface": getattr(args, "interface"),
            "area": getattr(args, "area"),
            "cost": getattr(args, "cost"),
            "priority": getattr(args, "priority"),
            "hello_interval": getattr(args, "hello_interval"),
            "retransmit_interval": getattr(args, "retransmit_interval"),
            "dead_interval": getattr(args, "dead_interval"),
            "transmit_delay": getattr(args, "transmit_delay"),
            "type_network": getattr(args, "type_network"),
        },
    )
    if not getattr(args, "execute"):
        return build_ospfv3_bfd_dry_run(
            op_id=op_id,
            base_url=getattr(args, "base_url"),
            session_file=session_file,
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            page=int(getattr(args, "page")),
            size=int(getattr(args, "size")),
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )
    return execute_ospfv3_bfd(
        op_id=op_id,
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        page=int(getattr(args, "page")),
        size=int(getattr(args, "size")),
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout")),
    )


def _require_arg(args: argparse.Namespace, name: str) -> None:
    value = getattr(args, name)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Missing required runner argument.",
            {"argument": f"--{name.replace('_', '-')}"},
        )


def _read_secret_env(env_name: str | None, field_name: str) -> str:
    if not env_name:
        raise RunnerError(
            "RUNNER_CREDENTIAL_MISSING",
            "Runner credential environment variable name is required.",
            {"missing": field_name},
        )
    value = os.environ.get(env_name)
    if value is None or not value:
        raise RunnerError(
            "RUNNER_CREDENTIAL_MISSING",
            "Runner credential environment variable is not set or is empty.",
            {"env": env_name},
        )
    return value


def _write_output(payload: dict[str, Any], output_format: str) -> None:
    safe_payload = _redact_runner_output(payload)
    if output_format == "json":
        print(json.dumps(safe_payload, ensure_ascii=False, sort_keys=True))
        return
    print(yaml.safe_dump(safe_payload, allow_unicode=True, sort_keys=False), end="")


def _to_run_envelope(payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap runner-specific payloads in the stable operation return envelope."""

    data = dict(payload)
    op_id = data.pop("op_id", None)
    status = data.pop("status", None)
    error_type = data.pop("error_type", "NONE")
    diag_snapshot_ref = data.pop("diag_snapshot_ref", "")

    envelope: dict[str, Any] = {
        "status": status or "success",
        "data": data,
        "error_type": error_type,
        "diag_snapshot_ref": diag_snapshot_ref,
    }
    if op_id is not None:
        envelope["op_id"] = op_id
    return envelope


def _redact_runner_output(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, inner in value.items():
            if key in {"session_value", "passwd", "oldpasswd"}:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_runner_output(inner)
        return redacted
    if isinstance(value, list):
        return [_redact_runner_output(item) for item in value]
    return value
