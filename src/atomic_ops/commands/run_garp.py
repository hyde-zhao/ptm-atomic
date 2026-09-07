"""Gratuitous ARP runner commands."""

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
            name="garp",
            help="Gratuitous ARP rate limit operations.",
            description="Gratuitous ARP rate limit configuration (PUT /api/v1/neighbor/garplimitrate).",
            children=(
                CommandSpec(
                    name="rate-limit",
                    help="Configure gratuitous ARP rate limit.",
                    description="Configure gratuitous ARP send rate limit (PUT /api/v1/neighbor/garplimitrate).",
                    handler=_run_rate_limit,
                    add_args=_add_rate_limit_args,
                ),
            ),
        ),
    )


def _add_rate_limit_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--rate", type=int, help="Gratuitous ARP send rate limit in pps (device range 1-4096).")
    parser.add_argument("--capacity", type=int, default=16, help="Burst capacity (observed default 16).")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _run_rate_limit(args: argparse.Namespace) -> int:
    return _run_garp(args, "fw_config_garp_rate_limit")


def _run_garp(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.garp import (
        build_garp_dry_run,
        build_garp_rate_limit_payload,
        execute_garp,
        validate_garp_payload,
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
        payload: dict[str, Any] | None = raw_payload or build_garp_rate_limit_payload(
            rate=int(getattr(args, "rate", 0)),
            capacity=int(getattr(args, "capacity", 16)),
        )
        payload = validate_garp_payload(payload, op_id=op_id)

        if not ctx.get("execute"):
            result = build_garp_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_garp(
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
