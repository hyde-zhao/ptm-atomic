"""System time runner commands (read-only GET /api/v1/systime)."""

from __future__ import annotations

import argparse

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
            name="system",
            help="System management read-only operations.",
            description="Read-only system management queries such as system time.",
            children=(
                CommandSpec(
                    name="time-verify",
                    help="Read the NGFW system time and optionally assert date/time.",
                    description=(
                        "Read GET /api/v1/systime?id=systime and return vals[0] "
                        "name/enable/date/time/ntp. Optional --expected-date and "
                        "--expected-time produce exact-match flags. Read-only: this "
                        "operation never changes the device clock."
                    ),
                    handler=_run_time_verify,
                    add_args=_add_time_verify_args,
                ),
            ),
        ),
    )


def _add_time_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--expected-date",
        help="Optional expected date in YYYY-MM-DD form for an exact-match assertion.",
    )
    parser.add_argument(
        "--expected-time",
        help="Optional expected time in HH:MM:SS form for an exact-match assertion.",
    )


def _run_time_verify(args: argparse.Namespace) -> int:
    from atomic_ops.runner.system_time import build_system_time_dry_run, execute_system_time

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        expected_date = getattr(args, "expected_date", None)
        expected_time = getattr(args, "expected_time", None)
        if not ctx.get("execute"):
            result = build_system_time_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
                expected_date=expected_date,
                expected_time=expected_time,
            )
        else:
            result = execute_system_time(
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
                expected_date=expected_date,
                expected_time=expected_time,
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
