"""Neighbor (ARP) runner commands."""

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
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file


def build_subtree() -> tuple[CommandGroup, ...]:
    return (
        CommandGroup(
            name="neighbor",
            help="Neighbor (ARP) table operations.",
            description="Neighbor (ARP) table create, update, delete, delete-batch, and verify operations.",
            children=(
                CommandSpec(name="create", help="Create a static ARP entry.", description="Create a new static NGFW neighbor (ARP) entry.", handler=_run_create, add_args=_add_neighbor_args),
                CommandSpec(name="update", help="Update a static ARP entry.", description="Update an existing NGFW neighbor (ARP) entry.", handler=_run_update, add_args=_add_neighbor_args),
                CommandSpec(name="delete", help="Delete a single ARP entry.", description="Delete a single NGFW neighbor (ARP) entry.", handler=_run_delete, add_args=_add_neighbor_args),
                CommandSpec(name="delete-batch", help="Batch-delete ARP entries.", description="Batch-delete multiple NGFW neighbor (ARP) entries.", handler=_run_delete_batch, add_args=_add_batch_delete_args),
                CommandSpec(name="verify", help="Query the ARP table.", description="Query the NGFW neighbor (ARP) table.", handler=_run_verify, add_args=_add_verify_args),
            ),
        ),
    )


def _add_neighbor_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--interface", required=True, help="Neighbor interface name (e.g. GE0_2).")
    parser.add_argument("--ip-address", required=True, help="Neighbor IP address (e.g. 200.1.1.6).")
    parser.add_argument("--phys-address", required=True, help="Neighbor MAC address (e.g. 00:11:32:a7:7f:46).")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_batch_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--interface", action="append", default=[], help="Neighbor interface name. May be repeated for multiple entries.")
    parser.add_argument("--ip-address", action="append", default=[], help="Neighbor IP address. May be repeated for multiple entries.")
    parser.add_argument("--phys-address", action="append", default=[], help="Neighbor MAC address. May be repeated for multiple entries.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")
    parser.add_argument("--keywords", default="", help="Optional search keywords for fuzzy matching.")
    parser.add_argument(
        "--is-ip6",
        type=int,
        choices=(0, 1),
        default=0,
        help="Address family selector; 0 queries the IPv4 ARP table and 1 queries the IPv6 ND table. Defaults to 0.",
    )


def _run_create(args: argparse.Namespace) -> int:
    return _run_neighbor(args, "fw_config_neighbor")


def _run_update(args: argparse.Namespace) -> int:
    return _run_neighbor(args, "fw_update_neighbor")


def _run_delete(args: argparse.Namespace) -> int:
    return _run_neighbor(args, "fw_delete_neighbor")


def _run_delete_batch(args: argparse.Namespace) -> int:
    return _run_neighbor(args, "fw_delete_batch_neighbor")


def _run_verify(args: argparse.Namespace) -> int:
    return _run_neighbor(args, "fw_verify_neighbor")


def _run_neighbor(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.neighbor import (
        build_neighbor_batch_delete_payload,
        build_neighbor_dry_run,
        build_neighbor_payload,
        execute_neighbor,
        load_json_payload,
        validate_neighbor_payload,
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
        page = int(getattr(args, "page", 1))
        size = int(getattr(args, "size", 40))
        keywords = getattr(args, "keywords", "")
        is_ip6 = int(getattr(args, "is_ip6", 0))
        payload: dict[str, Any] | None

        if op_id in {"fw_config_neighbor", "fw_update_neighbor"}:
            payload = raw_payload or build_neighbor_payload(
                interface=getattr(args, "interface"),
                ip_address=getattr(args, "ip_address"),
                phys_address=getattr(args, "phys_address"),
                op_id=op_id,
            )
            payload = validate_neighbor_payload(payload, op_id=op_id)
        elif op_id == "fw_delete_neighbor":
            payload = raw_payload or build_neighbor_payload(
                interface=getattr(args, "interface"),
                ip_address=getattr(args, "ip_address"),
                phys_address=getattr(args, "phys_address"),
                op_id=op_id,
            )
            payload = validate_neighbor_payload(payload, op_id=op_id)
        elif op_id == "fw_delete_batch_neighbor":
            if raw_payload is not None:
                payload = validate_neighbor_payload(raw_payload, op_id=op_id)
            else:
                interfaces = list(getattr(args, "interface") or [])
                ip_addresses = list(getattr(args, "ip_address") or [])
                phys_addresses = list(getattr(args, "phys_address") or [])
                if not interfaces or not ip_addresses or not phys_addresses:
                    raise RunnerError(
                        "RUNNER_VALIDATION_FAILED",
                        "Batch delete requires --interface, --ip-address, and --phys-address.",
                        {"fields": ["interface", "ip_address", "phys_address"]},
                    )
                if len(interfaces) != len(ip_addresses) or len(interfaces) != len(phys_addresses):
                    raise RunnerError(
                        "RUNNER_VALIDATION_FAILED",
                        "Batch delete --interface, --ip-address, and --phys-address must have equal count.",
                        {
                            "interface_count": len(interfaces),
                            "ip_address_count": len(ip_addresses),
                            "phys_address_count": len(phys_addresses),
                        },
                    )
                entries = [
                    {"interface": interfaces[i], "ip_address": ip_addresses[i], "phys_address": phys_addresses[i]}
                    for i in range(len(interfaces))
                ]
                payload = build_neighbor_batch_delete_payload(entries=entries)
                payload = validate_neighbor_payload(payload, op_id=op_id)
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_neighbor_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=page, size=size, keywords=keywords, is_ip6=is_ip6,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_neighbor(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=page, size=size, keywords=keywords, is_ip6=is_ip6,
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
