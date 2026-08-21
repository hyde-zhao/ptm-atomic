"""DNS static entry runner commands."""

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
            name="dns",
            help="DNS configuration operations.",
            description="Static DNS entry and dynamic cache operations.",
            children=(
                CommandSpec(name="static-dns-config", help="Create a static DNS entry.", description="POST /api/v1/dns/cache.", handler=_run_static_dns_config, add_args=_add_static_dns_config_args),
                CommandSpec(name="static-dns-update", help="Update a static DNS entry.", description="PUT /api/v1/dns/cache.", handler=_run_static_dns_update, add_args=_add_static_dns_update_args),
                CommandSpec(name="static-dns-delete", help="Delete a static DNS entry.", description="DELETE /api/v1/dns/cache?id=<domain>.", handler=_run_static_dns_delete, add_args=_add_delete_args),
                CommandSpec(name="static-dns-delete-batch", help="Batch-delete static DNS entries.", description="Batch DELETE /api/v1/dns/cache.", handler=_run_static_dns_delete_batch, add_args=_add_delete_args),
                CommandSpec(name="static-dns-verify", help="Verify static DNS entries.", description="GET /api/v1/dns/cache?type=static.", handler=_run_static_dns_verify, add_args=None),
                CommandSpec(name="dynamic-cache-verify", help="Verify dynamic DNS cache entries.", description="GET /api/v1/dns/cache?page=&size=&type=dynamic.", handler=_run_dynamic_cache_verify, add_args=_add_paged_verify_args),
            ),
        ),
    )


# ── shared arg builders ────────────────────────────────────


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", help="Static DNS entry domain name. May be repeated for batch operations.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_static_dns_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", required=True, help="Static DNS domain name, e.g. www.example.com.")
    parser.add_argument("--ip4addr", required=True, help="IPv4 address the domain resolves to.")
    parser.add_argument("--ip6addr", help="Optional IPv6 address the domain resolves to.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_static_dns_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="Current domain name locating the static entry to update.")
    parser.add_argument("--name", required=True, help="New domain name for the entry (may equal id).")
    parser.add_argument("--ip4addr", required=True, help="IPv4 address the domain resolves to.")
    parser.add_argument("--ip6addr", help="Optional IPv6 address the domain resolves to.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_paged_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")


# ── handlers ───────────────────────────────────────────────


def _run_static_dns_config(args: argparse.Namespace) -> int:
    from atomic_ops.runner.dns_static import build_static_dns_payload, validate_static_dns_payload
    def _build():
        return build_static_dns_payload(
            name=getattr(args, "name"),
            ip4addr=getattr(args, "ip4addr"),
            ip6addr=getattr(args, "ip6addr", None),
        )
    return _run_dns_op(args, "fw_config_static_dns", _build, validate_via=validate_static_dns_payload)


def _run_static_dns_update(args: argparse.Namespace) -> int:
    from atomic_ops.runner.dns_static import build_static_dns_update_payload, validate_static_dns_update_payload
    def _build():
        return build_static_dns_update_payload(
            entry_id=getattr(args, "id"),
            name=getattr(args, "name"),
            ip4addr=getattr(args, "ip4addr"),
            ip6addr=getattr(args, "ip6addr", None),
        )
    return _run_dns_op(args, "fw_update_static_dns", _build, validate_via=validate_static_dns_update_payload)


def _run_static_dns_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_dns_op(args, "fw_delete_static_dns", payload_builder=lambda: {"id": _single_arg(args, "id")})


def _run_static_dns_delete_batch(args: argparse.Namespace) -> int:
    from atomic_ops.runner.dns_static import build_static_dns_batch_delete_payload, validate_batch_payload
    return _run_dns_op(args, "fw_delete_batch_static_dns", payload_builder=lambda: build_static_dns_batch_delete_payload(entry_ids=_arg_list(args, "id")), validate_via=validate_batch_payload)


def _run_static_dns_verify(args: argparse.Namespace) -> int:
    return _run_dns_op(args, "fw_verify_static_dns", payload_builder=None)


def _run_dynamic_cache_verify(args: argparse.Namespace) -> int:
    return _run_dns_op(
        args,
        "fw_verify_dns_cache_entry",
        payload_builder=lambda: {"page": int(getattr(args, "page", 1)), "size": int(getattr(args, "size", 40))},
    )


# ── dispatcher ─────────────────────────────────────────────


def _run_dns_op(args: argparse.Namespace, op_id: str, payload_builder, *, validate_via=None) -> int:
    from atomic_ops.runner.dns_static import build_static_dns_dry_run, execute_static_dns, load_json_payload  # type: ignore

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
        payload = raw_payload if raw_payload is not None else (payload_builder() if payload_builder else None)
        if validate_via is not None and payload is not None:
            payload = validate_via(payload)

        if not ctx.get("execute"):
            result = build_static_dns_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                verify_tls=bool(ctx.get("verify_tls")), timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_static_dns(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                verify_tls=bool(ctx.get("verify_tls")), timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
