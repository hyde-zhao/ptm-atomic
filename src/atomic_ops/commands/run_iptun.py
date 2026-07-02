"""IP tunnel runner commands."""

from __future__ import annotations

import argparse
from typing import Any

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import (
    _arg_list,
    _require_arg,
    _single_arg,
    _to_run_envelope,
    _write_output,
    resolve_run_context,
)
from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file


def build_subtree() -> tuple[CommandGroup, ...]:
    return (
        CommandGroup(
            name="iptun",
            help="IP tunnel operations.",
            description="IP tunnel create, update, delete, batch-delete, and verify operations.",
            children=(
                CommandSpec(name="config", help="Create an IP tunnel.", description="Create a new NGFW IP tunnel entry.", handler=_run_config, add_args=_add_iptun_args),
                CommandSpec(name="update", help="Update an IP tunnel.", description="Update an existing NGFW IP tunnel entry.", handler=_run_update, add_args=_add_iptun_args),
                CommandSpec(name="delete", help="Delete an IP tunnel.", description="Delete a single NGFW IP tunnel entry.", handler=_run_delete, add_args=_add_delete_args),
                CommandSpec(name="delete-batch", help="Delete multiple IP tunnels.", description="Batch-delete NGFW IP tunnel entries.", handler=_run_delete_batch, add_args=_add_delete_args),
                CommandSpec(name="verify", help="Verify IP tunnel entries.", description="Query NGFW IP tunnel entries.", handler=_run_verify, add_args=None),
            ),
        ),
    )


def _add_iptun_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="IP tunnel id and val.name.")
    parser.add_argument(
        "--tunnel-type",
        choices=("4over6", "6over4", "gre"),
        required=True,
        help="IP tunnel variant. 4over6 maps to type 15, 6over4 to type 16, gre to type 11.",
    )
    parser.add_argument("--src-addr", required=True, help="Tunnel source endpoint address.")
    parser.add_argument("--dst-addr", required=True, help="Tunnel destination endpoint address.")
    parser.add_argument("--ip-address", action="append", default=[], help="Tunnel CIDR address. May be repeated for IPv4 and IPv6.")
    enabled_group = parser.add_mutually_exclusive_group()
    enabled_group.add_argument("--enabled", dest="enabled", action="store_true", default=True, help="Enable the IP tunnel (default).")
    enabled_group.add_argument("--disabled", dest="enabled", action="store_false", help="Disable the IP tunnel.")
    parser.add_argument("--level", type=int, default=100, help="IP tunnel level field.")
    parser.add_argument("--gre-tunnel-type", type=int, default=1, help="GRE tunnel_type field (gre only).")
    parser.add_argument("--gre-key", type=int, default=0, help="GRE key field (gre only).")
    parser.add_argument("--gre-check-sum", action="store_true", default=False, help="Enable GRE checksum (gre only).")
    parser.add_argument("--gre-keepalive-enable", action="store_true", default=False, help="Enable GRE keepalive (gre only).")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", help="Entry id. May be repeated for batch operations.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _run_config(args: argparse.Namespace) -> int:
    return _run_iptun(args, "fw_config_iptun")


def _run_update(args: argparse.Namespace) -> int:
    return _run_iptun(args, "fw_update_iptun")


def _run_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_iptun(args, "fw_delete_iptun")


def _run_delete_batch(args: argparse.Namespace) -> int:
    return _run_iptun(args, "fw_delete_batch_iptun")


def _run_verify(args: argparse.Namespace) -> int:
    return _run_iptun(args, "fw_verify_iptun")


def _run_iptun(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.iptun import (
        build_iptun_batch_delete_payload,
        build_iptun_dry_run,
        build_iptun_payload,
        execute_iptun,
        load_json_payload,
        validate_iptun_payload,
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
        payload: dict[str, Any] | None

        if op_id in {"fw_config_iptun", "fw_update_iptun"}:
            payload = raw_payload or build_iptun_payload(
                tunnel_type=getattr(args, "tunnel_type"),
                entry_id=_single_arg(args, "id"),
                ip_addresses=list(getattr(args, "ip_address") or []),
                enabled=bool(getattr(args, "enabled", True)),
                level=int(getattr(args, "level", 100)),
                src_addr=getattr(args, "src_addr"),
                dst_addr=getattr(args, "dst_addr"),
                gre_tunnel_type=int(getattr(args, "gre_tunnel_type", 1)),
                gre_key=int(getattr(args, "gre_key", 0)),
                gre_check_sum=bool(getattr(args, "gre_check_sum", False)),
                gre_keepalive_enable=bool(getattr(args, "gre_keepalive_enable", False)),
            )
            payload = validate_iptun_payload(payload, op_id=op_id)
        elif op_id == "fw_delete_iptun":
            payload = raw_payload or {"id": _single_arg(args, "id")}
            payload = validate_iptun_payload(payload, op_id=op_id)
        elif op_id == "fw_delete_batch_iptun":
            payload = raw_payload or build_iptun_batch_delete_payload(entry_ids=_arg_list(args, "id"))
            payload = validate_iptun_payload(payload, op_id=op_id)
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_iptun_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_iptun(
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
