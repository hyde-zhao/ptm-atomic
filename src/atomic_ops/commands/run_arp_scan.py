"""ARP scan runner commands."""

from __future__ import annotations

import argparse
from typing import Any

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import (
    _to_run_envelope,
    _write_output,
    resolve_run_context,
)
from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.runner._payload import load_json_payload
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file


def build_subtree() -> tuple[CommandGroup, ...]:
    return (
        CommandGroup(
            name="arp-scan",
            help="ARP scan configuration and trigger operations.",
            description="ARP scan interface/net config and immediate or periodic scan trigger operations.",
            children=(
                CommandSpec(
                    name="config",
                    help="Configure ARP scan interfaces and nets.",
                    description="Configure which interfaces and CIDR nets are ARP-scanned (PUT /api/v1/neighbor/scan/intf).",
                    handler=_run_config,
                    add_args=_add_config_args,
                ),
                CommandSpec(
                    name="trigger",
                    help="Trigger or schedule an ARP scan.",
                    description="Trigger an ARP scan immediately or schedule a periodic scan (PUT /api/v1/neighbor/scan/trigger).",
                    handler=_run_trigger,
                    add_args=_add_trigger_args,
                ),
            ),
        ),
    )


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--interface", help="Interface name to enable ARP scan on (e.g. GE0_6).")
    parser.add_argument("--net", action="append", default=[], help="CIDR net to scan (e.g. 66.1.1.0/24). May be repeated.")
    parser.add_argument(
        "--enable",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Whether the interface is added to ARP scan (default true).",
    )
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_trigger_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--is-periodic",
        action="store_true",
        default=False,
        help="Enable periodic ARP scan instead of one-shot.",
    )
    parser.add_argument(
        "--period-seconds",
        type=int,
        default=300,
        help="Periodic scan interval in seconds (the UI shows minutes).",
    )
    parser.add_argument(
        "--start-at-once",
        action="store_true",
        default=False,
        help="Trigger an ARP scan immediately once.",
    )
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _run_config(args: argparse.Namespace) -> int:
    return _run_arp_scan(args, "fw_config_arp_scan")


def _run_trigger(args: argparse.Namespace) -> int:
    return _run_arp_scan(args, "fw_trigger_arp_scan")


def _run_arp_scan(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.arp_scan import (
        build_arp_scan_config_payload,
        build_arp_scan_dry_run,
        build_arp_scan_trigger_payload,
        execute_arp_scan,
        validate_arp_scan_payload,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        raw_payload = load_json_payload(
            payload_file=getattr(args, "payload_file", None),
            payload_json=getattr(args, "payload_json", None),
        )

        if op_id == "fw_config_arp_scan":
            payload: dict[str, Any] | None = raw_payload or build_arp_scan_config_payload(
                interface=getattr(args, "interface"),
                nets=list(getattr(args, "net") or []),
                enable=bool(getattr(args, "enable", True)),
            )
        else:
            payload = raw_payload or build_arp_scan_trigger_payload(
                is_periodic=bool(getattr(args, "is_periodic", False)),
                period_in_seconds=int(getattr(args, "period_seconds", 300)),
                start_at_once=bool(getattr(args, "start_at_once", False)),
            )
        payload = validate_arp_scan_payload(payload, op_id=op_id)

        if not ctx.get("execute"):
            result = build_arp_scan_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_arp_scan(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
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
