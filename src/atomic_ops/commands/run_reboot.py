"""Device reboot runner commands."""

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
            name="reboot",
            help="Device reboot operations.",
            description="Reboot an NGFW device and invalidate the current session.",
            children=(
                CommandSpec(
                    name="config",
                    help="Reboot the device.",
                    description="Reboot an NGFW device through /api/v1/reboot.",
                    handler=_run_reboot,
                    add_args=_add_reboot_args,
                ),
            ),
        ),
    )


def _add_reboot_args(parser: argparse.ArgumentParser) -> None:
    # P2-39：参数文本从「Informational estimate」提升为显式契约声明。
    parser.add_argument(
        "--expected-unavailable-seconds",
        type=int,
        default=300,
        help="CONTRACT: the runner does NOT wait for the device to recover. Callers MUST wait "
        "this many seconds after the 2xx response before further requests, or the device stays "
        "unreachable (exit 46). Exposed in the envelope as data.caller_must_wait_seconds and "
        "data.device_unavailable_until_epoch.",
    )


def _run_reboot(args: argparse.Namespace) -> int:
    from atomic_ops.runner.reboot import build_reboot_dry_run, execute_reboot

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        expected = int(getattr(args, "expected_unavailable_seconds", 300))
        if not ctx.get("execute"):
            result = build_reboot_dry_run(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                expected_unavailable_seconds=expected,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_reboot(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                expected_unavailable_seconds=expected,
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
