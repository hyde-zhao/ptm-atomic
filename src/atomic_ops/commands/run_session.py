"""Session-table runner commands (fw_verify_session / fw_clear_session)."""

from __future__ import annotations

import argparse
from typing import Any

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import _to_run_envelope, _write_output, resolve_run_context
from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file
from atomic_ops.runner.session_table import (
    build_session_clear_dry_run,
    build_session_filters,
    build_session_verify_dry_run,
    execute_session_clear,
    execute_session_verify,
)


def build_subtree() -> tuple[CommandGroup, ...]:
    return (
        CommandGroup(
            name="session",
            help="Session-table monitor operations.",
            description="Query and clear NGFW session table entries.",
            children=(
                CommandSpec(
                    name="verify",
                    help="Verify session table entries.",
                    description="Query NGFW session table entries (IPv4/IPv6) with optional filters.",
                    handler=_run_verify,
                    add_args=_add_verify_args,
                ),
                CommandSpec(
                    name="clear",
                    help="Clear data-plane sessions.",
                    description="Clear all NGFW data-plane session table entries (DELETE /api/v1/monitor/clearsession).",
                    handler=_run_clear,
                    add_args=_add_clear_args,
                ),
            ),
        ),
    )


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--is-ip6", action="store_true", default=False, help="Query IPv6 sessions; default queries IPv4.")
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")
    parser.add_argument("--proto", default="", help="Protocol filter, e.g. ANY / UDP / TCP.")
    parser.add_argument("--src-addr", default="", help="Source address filter.")
    parser.add_argument("--dst-addr", default="", help="Destination address filter.")
    parser.add_argument("--src-port", type=int, default=0, help="Source port filter (0 = no filter).")
    parser.add_argument("--dst-port", type=int, default=0, help="Destination port filter (0 = no filter).")
    parser.add_argument("--rx-zone", default="", help="Ingress (source) security zone filter.")
    parser.add_argument("--tx-zone", default="", help="Egress (destination) security zone filter.")
    parser.add_argument("--rx-if", default="", help="Ingress interface filter.")
    parser.add_argument("--tx-if", default="", help="Egress interface filter.")
    parser.add_argument("--action", default="", help="Session action filter (permit/deny).")
    parser.add_argument("--policy-id", default="", help="Policy id filter.")
    parser.add_argument("--app-name", default="", help="Application name filter.")


def _add_clear_args(parser: argparse.ArgumentParser) -> None:
    """clear 无专属参数（--base-url/--session-file/--timeout/--execute 由 run 共享参数层提供）。"""


def _run_verify(args: argparse.Namespace) -> int:
    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        page = int(getattr(args, "page", 1))
        size = int(getattr(args, "size", 40))
        is_ip6 = bool(getattr(args, "is_ip6", False))
        filters = build_session_filters(
            args={
                "proto": getattr(args, "proto", "ANY"),
                "src_addr": getattr(args, "src_addr", "0:0::0"),
                "dst_addr": getattr(args, "dst_addr", "0:0::0"),
                "src_port": getattr(args, "src_port", 0),
                "dst_port": getattr(args, "dst_port", 0),
                "rxZone": getattr(args, "rx_zone", ""),
                "txZone": getattr(args, "tx_zone", ""),
                "rxIf": getattr(args, "rx_if", ""),
                "txIf": getattr(args, "tx_if", ""),
                "action": getattr(args, "action", ""),
                "policyId": getattr(args, "policy_id", ""),
                "appName": getattr(args, "app_name", ""),
            }
        )

        if not ctx.get("execute"):
            result = build_session_verify_dry_run(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                page=page, size=size, is_ip6=is_ip6, filters=filters,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_session_verify(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                page=page, size=size, is_ip6=is_ip6, filters=filters,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, suggestion=exc.suggestion),
            output_format,
        )


def _run_clear(args: argparse.Namespace) -> int:
    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))

        if not ctx.get("execute"):
            result = build_session_clear_dry_run(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_session_clear(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, suggestion=exc.suggestion),
            output_format,
        )
