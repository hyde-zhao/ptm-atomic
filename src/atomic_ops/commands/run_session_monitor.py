"""Session-monitor runner commands for NGFW session-table queries."""

from __future__ import annotations

import argparse

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import _to_run_envelope, _write_output, resolve_run_context
from atomic_ops.errors import CliError, write_error
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file


def build_subtree() -> tuple[CommandGroup, ...]:
    return (
        CommandGroup(
            name="session-monitor",
            help="NGFW session-table query operations.",
            description="Session-table query operations for NGFW monitor (/api/v1/monitor/sessioninfo).",
            children=(
                CommandSpec(
                    name="verify",
                    help="Query the NGFW session table (IPv4 or IPv6).",
                    description="Query active sessions with page/size pagination and address-family, protocol, address, port, zone, and interface filters.",
                    handler=_run_verify,
                    add_args=_add_verify_args,
                ),
            ),
        ),
    )


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--isip6",
        type=int,
        choices=(0, 1),
        default=0,
        help="Address family selector; 0 queries IPv4 sessions and 1 queries IPv6 sessions. Defaults to 0.",
    )
    parser.add_argument("--page", type=int, default=1, help="Query page number. Defaults to 1.")
    parser.add_argument("--size", type=int, default=10, help="Query page size. Defaults to 10.")
    parser.add_argument(
        "--proto",
        default="ANY",
        help="Protocol filter (for example ANY, TCP, UDP). Defaults to ANY.",
    )
    parser.add_argument(
        "--src-addr",
        help="Source address filter; defaults to the family zero address (0.0.0.0 for ipv4, 0:0::0 for ipv6).",
    )
    parser.add_argument(
        "--dst-addr",
        help="Destination address filter; defaults to the family zero address.",
    )
    parser.add_argument("--src-port", type=int, default=0, help="Source port filter. Defaults to 0.")
    parser.add_argument("--dst-port", type=int, default=0, help="Destination port filter. Defaults to 0.")
    parser.add_argument(
        "--natsip",
        help="NAT source address filter; defaults to the family zero address.",
    )
    parser.add_argument(
        "--natdip",
        help="NAT destination address filter; defaults to the family zero address.",
    )
    parser.add_argument("--natsport", type=int, default=0, help="NAT source port filter. Defaults to 0.")
    parser.add_argument("--natdport", type=int, default=0, help="NAT destination port filter. Defaults to 0.")
    parser.add_argument("--vlanid", default="", help="VLAN id filter. Defaults to empty (no filter).")
    parser.add_argument("--rx-zone", default="", help="Ingress zone filter. Defaults to empty (no filter).")
    parser.add_argument("--tx-zone", default="", help="Egress zone filter. Defaults to empty (no filter).")
    parser.add_argument(
        "--rx-if",
        default="",
        help="Ingress interface filter (for example TE0_7). Defaults to empty (no filter).",
    )
    parser.add_argument(
        "--tx-if",
        default="",
        help="Egress interface filter (for example TE0_9). Defaults to empty (no filter).",
    )
    parser.add_argument("--policy-id", default="", help="Policy id filter. Defaults to empty (no filter).")
    parser.add_argument("--app-name", default="", help="Application name filter. Defaults to empty (no filter).")
    parser.add_argument(
        "--action",
        default="",
        help="Action filter (permit/deny). Defaults to empty (no filter).",
    )


def _run_verify(args: argparse.Namespace) -> int:
    from atomic_ops.runner.session_monitor import (
        build_verify_session_dry_run,
        execute_verify_session,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        kwargs = {
            "base_url": ctx["base_url"],
            "session_file": session_file,
            "auth_header": ctx.get("auth_header", "Authorization"),
            "isip6": args.isip6,
            "page": args.page,
            "size": args.size,
            "proto": args.proto,
            "src_addr": args.src_addr,
            "dst_addr": args.dst_addr,
            "src_port": args.src_port,
            "dst_port": args.dst_port,
            "natsip": args.natsip,
            "natdip": args.natdip,
            "natsport": args.natsport,
            "natdport": args.natdport,
            "vlanid": args.vlanid,
            "rx_zone": args.rx_zone,
            "tx_zone": args.tx_zone,
            "rx_if": args.rx_if,
            "tx_if": args.tx_if,
            "policy_id": args.policy_id,
            "app_name": args.app_name,
            "action": args.action,
            "verify_tls": ctx.get("verify_tls", False),
            "timeout": float(ctx.get("timeout", 10.0)),
        }
        if not ctx.get("execute"):
            result = build_verify_session_dry_run(**kwargs)
        else:
            result = execute_verify_session(**kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
