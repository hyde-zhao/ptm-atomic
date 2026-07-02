"""Operation-log runner commands."""

from __future__ import annotations

import argparse
from typing import Any

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import _to_run_envelope, _write_output, resolve_run_context
from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file


def build_subtree() -> tuple[CommandGroup, ...]:
    return (
        CommandGroup(
            name="operation-log",
            help="Operation-log capture operations.",
            description="Operation-log capture operations for NGFW monitor.",
            children=(
                CommandSpec(
                    name="capture",
                    help="Capture operation-log entries.",
                    description="Query NGFW operation-log entries with a time window.",
                    handler=_run_capture,
                    add_args=_add_capture_args,
                ),
            ),
        ),
    )


def _add_capture_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=10, help="Paginated query page size.")
    parser.add_argument(
        "--timetype",
        choices=("1h", "24h", "7d", "1m", "custom"),
        default="1h",
        help="Time window preset; custom requires --starttime and --endtime.",
    )
    parser.add_argument("--starttime", type=int, help="Unix-second start timestamp (required for custom).")
    parser.add_argument("--endtime", type=int, help="Unix-second end timestamp (required for custom).")


def _run_capture(args: argparse.Namespace) -> int:
    from atomic_ops.runner.operation_log import build_operation_log_dry_run, execute_operation_log

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        page = int(getattr(args, "page", 1))
        size = int(getattr(args, "size", 10))
        timetype = getattr(args, "timetype", "1h")
        starttime: Any = getattr(args, "starttime", None)
        endtime: Any = getattr(args, "endtime", None)

        if not ctx.get("execute"):
            result = build_operation_log_dry_run(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                page=page, size=size, timetype=timetype, starttime=starttime, endtime=endtime,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_operation_log(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                page=page, size=size, timetype=timetype, starttime=starttime, endtime=endtime,
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
