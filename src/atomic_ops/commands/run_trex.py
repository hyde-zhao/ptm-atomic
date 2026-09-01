"""TRex traffic generator runner commands (tg trex <action>)."""

from __future__ import annotations

import argparse
import json
from typing import Any

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import (
    _to_run_envelope,
    _write_output,
    resolve_run_context,
)
from atomic_ops.errors import CliError, write_error
from atomic_ops.runner.errors import RunnerError


def build_subtree() -> tuple[CommandGroup, ...]:
    return (
        CommandGroup(
            name="tg",
            help="Traffic generator operations.",
            description="Traffic generator (tg) operations.",
            children=(
                CommandGroup(
                    name="trex",
                    help="TRex traffic generator operations.",
                    description="TRex trex-api template and stream lifecycle operations.",
                    children=(
                        CommandSpec(
                            name="acquire-ports",
                            help="Acquire TRex ports for exclusive use by a user.",
                            description="Acquire TRex ports (force=False) and bind them to a user_id until release or timeout.",
                            handler=_run_acquire_ports,
                            add_args=_add_acquire_ports_args,
                        ),
                        CommandSpec(
                            name="config-interface",
                            help="Configure TRex interfaces and learn gateway MACs.",
                            description="Configure TRex IPv4 or IPv6 interfaces and learn gateway MAC addresses.",
                            handler=_run_config_interface,
                            add_args=_add_config_interface_args,
                        ),
                        CommandSpec(
                            name="apply-template",
                            help="Apply a TRex traffic template.",
                            description="Create or update a TRex traffic template YAML on the TG host.",
                            handler=_run_apply_template,
                            add_args=_add_apply_template_args,
                        ),
                        CommandSpec(
                            name="delete-template",
                            help="Delete a TRex traffic template.",
                            description="Delete a TRex traffic template when no runtime stream uses it.",
                            handler=_run_delete_template,
                            add_args=_add_delete_template_args,
                        ),
                        CommandSpec(
                            name="start-stream",
                            help="Start a TRex traffic stream.",
                            description="Start a TRex traffic stream from a predefined traffic template.",
                            handler=_run_start_stream,
                            add_args=_add_start_stream_args,
                        ),
                        CommandSpec(
                            name="stop-stream",
                            help="Stop a TRex traffic stream.",
                            description="Stop a TRex traffic stream and clean its runtime configuration.",
                            handler=_run_stop_stream,
                            add_args=_add_stop_stream_args,
                        ),
                        CommandSpec(
                            name="verify-loss",
                            help="Verify TRex traffic loss.",
                            description="Verify TRex port statistics against a maximum allowed loss ratio.",
                            handler=_run_verify_loss,
                            add_args=_add_verify_loss_args,
                        ),
                        CommandSpec(
                            name="release-ports",
                            help="Release TRex ports previously acquired by a user.",
                            description="Release TRex ports held by a user_id (all or a subset).",
                            handler=_run_release_ports,
                            add_args=_add_release_ports_args,
                        ),
                        CommandSpec(
                            name="verify-ownership",
                            help="Query TRex port ownership across all users.",
                            description="Query the trex-api ownership registry for current port occupation by all users.",
                            handler=_run_verify_ownership,
                            add_args=_add_verify_ownership_args,
                        ),
                        CommandSpec(
                            name="config-stateful-interface",
                            help="Configure ASTF interfaces and learn gateway MACs.",
                            description="Configure ASTF IPv4 or IPv6 interfaces (set_l3_mode) and learn gateway MAC addresses via ARP.",
                            handler=_run_config_stateful_interface,
                            add_args=_add_config_stateful_interface_args,
                        ),
                        CommandSpec(
                            name="apply-stateful-template",
                            help="Load a pre-defined ASTF template.",
                            description="Load an ASTF profile template onto the TRex ASTF instance.",
                            handler=_run_apply_stateful_template,
                            add_args=_add_apply_stateful_template_args,
                        ),
                        CommandSpec(
                            name="start-stateful-stream",
                            help="Start ASTF stateful traffic.",
                            description="Start ASTF stateful traffic from a loaded profile.",
                            handler=_run_start_stateful_stream,
                            add_args=_add_start_stateful_stream_args,
                        ),
                        CommandSpec(
                            name="verify-stateful-metrics",
                            help="Verify ASTF stateful metrics.",
                            description="Query real-time ASTF statistics and optionally verify loss ratio.",
                            handler=_run_verify_stateful_metrics,
                            add_args=_add_verify_stateful_metrics_args,
                        ),
                        CommandSpec(
                            name="stop-stateful-stream",
                            help="Stop ASTF stateful traffic.",
                            description="Stop ASTF stateful traffic and clear runtime state.",
                            handler=_run_stop_stateful_stream,
                            add_args=_add_stop_stateful_stream_args,
                        ),
                        CommandSpec(
                            name="delete-stateful-template",
                            help="Unload ASTF template.",
                            description="Unload the ASTF profile from the TRex ASTF instance.",
                            handler=_run_delete_stateful_template,
                            add_args=_add_delete_stateful_template_args,
                        ),
                    ),
                ),
            ),
        ),
    )


# ── 参数注册 ──────────────────────────────────────────────


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_user_id_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--user-id",
        default="default",
        help="TRex multi-user owner id (default 'default' = legacy force mode; set "
        "dev<ip-suffix>-<seq> like dev171-1 to pair with acquire-ports for owned mode).",
    )


def _add_acquire_ports_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--user-id",
        required=True,
        help="Occupant identifier, format dev<ip-suffix>-<seq> (e.g. dev172-1).",
    )
    parser.add_argument(
        "--ports",
        required=True,
        help="Comma-separated logical port names to acquire, e.g. 2_1,2_2.",
    )
    _add_payload_args(parser)


def _add_release_ports_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--user-id",
        required=True,
        help="Occupant identifier that previously acquired the ports.",
    )
    parser.add_argument(
        "--ports",
        default=None,
        help="Comma-separated logical port names to release. If omitted, releases all ports held by the user-id.",
    )
    _add_payload_args(parser)


def _add_config_interface_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument(
        "--interfaces",
        required=True,
        help="JSON array of interface objects: port, ip, gateway, and optional mac/peer-mac/vlan fields.",
    )
    _add_payload_args(parser)


def _add_apply_template_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--template", required=True, help="Traffic template name (^[a-z0-9_-]+$).")
    parser.add_argument("--tx-port", required=True, help="Default TX port stored in the template.")
    parser.add_argument("--rx-port", required=True, help="Default RX port stored in the template.")
    parser.add_argument(
        "--ip-version",
        choices=("ipv4", "ipv6"),
        default="ipv4",
        help="Network layer packet type. Defaults to ipv4.",
    )
    parser.add_argument("--l4-protocol", choices=("tcp", "udp", "icmp"), required=True, help="Layer 4 protocol (icmp = echo request, no ports).")
    parser.add_argument("--l4-sport", type=int, required=False, default=None, help="Layer 4 source port (tcp/udp only).")
    parser.add_argument("--l4-dport", type=int, required=False, default=None, help="Layer 4 destination port (tcp/udp only).")
    parser.add_argument("--traffic-mode", choices=("count", "continuous"), required=True, help="Traffic mode.")
    parser.add_argument("--rate", required=True, help="TRex-style rate string such as 100pps or 10mbps.")
    parser.add_argument("--count", type=int, default=None, help="Packet count (required when traffic-mode=count except ICMP defaults to 5).")
    parser.add_argument("--frame-size", type=int, default=None, help="Ethernet frame size in bytes (>= 64).")
    parser.add_argument("--vlan", default=None, help="VLAN ID or VLAN stack.")
    parser.add_argument("--src-ip", default=None, help="Optional source IP.")
    parser.add_argument("--dst-ip", default=None, help="Optional destination IP.")
    parser.add_argument("--src-mac", default=None, help="Optional source MAC.")
    parser.add_argument("--dst-mac", default=None, help="Optional destination MAC.")
    _add_user_id_arg(parser)
    _add_payload_args(parser)


def _add_delete_template_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument("--template", required=True, help="Traffic template name to delete.")
    _add_payload_args(parser)


def _add_start_stream_args(parser: argparse.ArgumentParser) -> None:
    _add_stream_args(parser, include_template=True)


def _add_stop_stream_args(parser: argparse.ArgumentParser) -> None:
    _add_stream_args(parser, include_template=False)


def _add_stream_args(parser: argparse.ArgumentParser, *, include_template: bool) -> None:
    _add_user_id_arg(parser)
    parser.add_argument("--ports", required=True, help="Comma-separated TRex port IDs occupied by this operation.")
    parser.add_argument("--txport", required=True, help="TRex port ID that transmits traffic.")
    parser.add_argument("--rxport", required=True, help="TRex port ID that receives traffic.")
    parser.add_argument("--name", required=True, help="Runtime stream instance name.")
    if include_template:
        parser.add_argument("--template", required=True, help="Traffic template name created by apply-template.")
    _add_payload_args(parser)


def _add_verify_loss_args(parser: argparse.ArgumentParser) -> None:
    _add_stream_args(parser, include_template=False)
    parser.add_argument("--max-loss", type=float, required=True, help="Maximum allowed loss ratio (>= 0).")


def _add_verify_ownership_args(parser: argparse.ArgumentParser) -> None:
    _add_payload_args(parser)


def _add_config_stateful_interface_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument(
        "--interfaces",
        required=True,
        help="JSON array of interface objects: port, ip, gateway, and optional mac/peer-mac/vlan fields.",
    )
    _add_payload_args(parser)


def _add_apply_stateful_template_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument(
        "--template",
        required=True,
        help="Pre-defined ASTF template name (http-simple, http-multi, dns-query, ftp-download).",
    )
    parser.add_argument(
        "--tunables",
        default=None,
        help="JSON string of template-specific tunables (e.g. '{\"fsize\": 500}').",
    )
    _add_payload_args(parser)


def _add_start_stateful_stream_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument("--mult", type=int, default=1, help="CPS multiplier (default 1).")
    parser.add_argument("--duration", type=int, default=-1, help="Duration in seconds (-1 = continuous).")
    _add_payload_args(parser)


def _add_verify_stateful_metrics_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument(
        "--max-loss",
        type=float,
        default=None,
        help="Maximum allowed loss ratio. If omitted, only returns stats.",
    )
    _add_payload_args(parser)


def _add_stop_stateful_stream_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    _add_payload_args(parser)


def _add_delete_stateful_template_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    _add_payload_args(parser)


# ── Handler 函数 ──────────────────────────────────────────


def _run_acquire_ports(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_acquire_ports")


def _run_config_interface(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_config_interface")


def _run_apply_template(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_apply_traffic_template")


def _run_delete_template(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_delete_traffic_template")


def _run_start_stream(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_start_traffic_stream")


def _run_stop_stream(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_stop_traffic_stream")


def _run_verify_loss(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_verify_traffic_loss")


def _run_release_ports(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_release_ports")


def _run_verify_ownership(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_verify_ownership")


def _run_config_stateful_interface(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_config_stateful_interface")


def _run_apply_stateful_template(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_apply_stateful_template")


def _run_start_stateful_stream(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_start_stateful_stream")


def _run_verify_stateful_metrics(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_verify_stateful_metrics")


def _run_stop_stateful_stream(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_stop_stateful_stream")


def _run_delete_stateful_template(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_delete_stateful_template")


def _run_trex(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.trex import (
        build_trex_dry_run,
        build_trex_payload,
        execute_trex,
        load_trex_json_payload,
        validate_trex_payload,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        raw_payload = load_trex_json_payload(
            payload_file=getattr(args, "payload_file", None),
            payload_json=getattr(args, "payload_json", None),
        )
        if raw_payload is not None:
            payload = validate_trex_payload(op_id, raw_payload)
        else:
            payload = build_trex_payload(op_id, _params_from_args(args, op_id))

        if not ctx.get("execute"):
            result = build_trex_dry_run(
                op_id=op_id,
                base_url=ctx["base_url"],
                payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_trex(
                op_id=op_id,
                base_url=ctx["base_url"],
                payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _params_from_args(args: argparse.Namespace, op_id: str) -> dict[str, Any]:
    if op_id == "tg_acquire_ports":
        return {"user_id": getattr(args, "user_id", None), "ports": _parse_ports(getattr(args, "ports", ""))}
    if op_id == "tg_release_ports":
        params: dict[str, Any] = {"user_id": getattr(args, "user_id", None)}
        ports_str = getattr(args, "ports", None)
        if ports_str:
            params["ports"] = _parse_ports(ports_str)
        return params
    if op_id == "tg_verify_ownership":
        return {}
    if op_id == "tg_config_interface":
        return {
            "user_id": getattr(args, "user_id", "default"),
            "interfaces": _parse_interfaces(getattr(args, "interfaces", "")),
        }
    if op_id == "tg_apply_traffic_template":
        return {
            "user_id": getattr(args, "user_id", "default"),
            "template": getattr(args, "template", None),
            "tx_port": getattr(args, "tx_port", None),
            "rx_port": getattr(args, "rx_port", None),
            "ip_version": getattr(args, "ip_version", "ipv4"),
            "l4_protocol": getattr(args, "l4_protocol", None),
            "l4_sport": getattr(args, "l4_sport", None),
            "l4_dport": getattr(args, "l4_dport", None),
            "traffic_mode": getattr(args, "traffic_mode", None),
            "rate": getattr(args, "rate", None),
            "count": getattr(args, "count", None),
            "frame_size": getattr(args, "frame_size", None),
            "vlan": getattr(args, "vlan", None),
            "src_ip": getattr(args, "src_ip", None),
            "dst_ip": getattr(args, "dst_ip", None),
            "src_mac": getattr(args, "src_mac", None),
            "dst_mac": getattr(args, "dst_mac", None),
        }
    if op_id in {"tg_start_traffic_stream", "tg_stop_traffic_stream", "tg_verify_traffic_loss"}:
        params = {
            "user_id": getattr(args, "user_id", "default"),
            "ports": _parse_ports(getattr(args, "ports", "")),
            "txport": getattr(args, "txport", None),
            "rxport": getattr(args, "rxport", None),
            "name": getattr(args, "name", None),
        }
        if op_id == "tg_start_traffic_stream":
            params["template"] = getattr(args, "template", None)
        if op_id == "tg_verify_traffic_loss":
            params["max_loss"] = getattr(args, "max_loss", None)
        return params
    if op_id == "tg_delete_traffic_template":
        return {"user_id": getattr(args, "user_id", "default"), "template": getattr(args, "template", None)}
    if op_id == "tg_config_stateful_interface":
        return {
            "user_id": getattr(args, "user_id", "default"),
            "interfaces": _parse_interfaces(getattr(args, "interfaces", "")),
        }
    if op_id == "tg_apply_stateful_template":
        params: dict[str, Any] = {
            "user_id": getattr(args, "user_id", "default"),
            "template": getattr(args, "template", None),
        }
        tunables_str = getattr(args, "tunables", None)
        if tunables_str:
            params["tunables"] = json.loads(tunables_str)
        return params
    if op_id == "tg_start_stateful_stream":
        return {
            "user_id": getattr(args, "user_id", "default"),
            "mult": getattr(args, "mult", 1),
            "duration": getattr(args, "duration", -1),
        }
    if op_id == "tg_verify_stateful_metrics":
        params = {"user_id": getattr(args, "user_id", "default")}
        max_loss = getattr(args, "max_loss", None)
        if max_loss is not None:
            params["max_loss"] = max_loss
        return params
    if op_id in {"tg_stop_stateful_stream", "tg_delete_stateful_template"}:
        return {"user_id": getattr(args, "user_id", "default")}
    return {}


def _parse_ports(value: str) -> list[str]:
    ports = [item.strip() for item in (value or "").split(",") if item.strip()]
    if not ports:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ports must contain at least one port id.",
            {"field": "ports"},
        )
    return ports


def _parse_interfaces(value: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "interfaces must be a JSON array.",
            {"field": "interfaces", "reason": exc.msg},
        ) from exc
    if not isinstance(parsed, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "interfaces must be a JSON array of objects.",
            {"field": "interfaces"},
        )
    return parsed
