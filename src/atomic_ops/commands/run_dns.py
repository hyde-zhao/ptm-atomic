"""DNS static entry runner commands."""

from __future__ import annotations

import argparse
from typing import Any

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import (
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
            description="Static DNS entry create and delete operations.",
            children=(
                CommandSpec(name="static-dns-config", help="Create a static DNS entry.", description="POST /api/v1/dns/cache.", handler=_run_static_dns_config, add_args=_add_static_dns_config_args),
                CommandSpec(name="static-dns-delete", help="Delete a static DNS entry.", description="DELETE /api/v1/dns/cache?id=<domain>.", handler=_run_static_dns_delete, add_args=_add_delete_args),
            ),
        ),
    )


# ── shared arg builders ────────────────────────────────────


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", help="Static DNS entry domain name.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_static_dns_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", required=True, help="Static DNS domain name, e.g. www.example.com.")
    parser.add_argument("--ip4addr", required=True, help="IPv4 address the domain resolves to.")
    parser.add_argument("--ip6addr", help="Optional IPv6 address the domain resolves to.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


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


def _run_static_dns_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_dns_op(args, "fw_delete_static_dns", payload_builder=lambda: {"id": _single_arg(args, "id")})


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
