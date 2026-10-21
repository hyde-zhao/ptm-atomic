"""License query runner commands (device identity and module license info)."""

from __future__ import annotations

import argparse

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import _to_run_envelope, _write_output, resolve_run_context
from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file


def build_subtree() -> tuple[CommandGroup, ...]:
    return (
        CommandGroup(
            name="license",
            help="Device license query operations.",
            description="Query device license identity (/api/v1/licensedev) and module license info (/api/v1/license).",
            children=(
                CommandSpec(
                    name="dev",
                    help="Query device license identity.",
                    description="Query devType/devSn/devAuthType/userAuthType/cpuNum/memSize/DeviceTypeName through GET /api/v1/licensedev.",
                    handler=_run_dev,
                    add_args=_add_no_args,
                ),
                CommandSpec(
                    name="verify",
                    help="Query license info and modules.",
                    description="Query info and module[] through GET /api/v1/license; the IPS module is the entry named 入侵防御.",
                    handler=_run_license,
                    add_args=_add_no_args,
                ),
            ),
        ),
    )


def _add_no_args(parser: argparse.ArgumentParser) -> None:
    return None


def _run_dev(args: argparse.Namespace) -> int:
    return _run_license_query(args, "fw_verify_license_dev")


def _run_license(args: argparse.Namespace) -> int:
    return _run_license_query(args, "fw_verify_license")


def _run_license_query(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.license import build_license_dry_run, execute_license

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning(
                {"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."},
                output_format,
            )
        session_file = resolve_session_file(ctx.get("session_file"))
        kwargs = {
            "op_id": op_id,
            "base_url": ctx["base_url"],
            "session_file": session_file,
            "auth_header": ctx.get("auth_header", "Authorization"),
            "verify_tls": bool(ctx.get("verify_tls")),
            "timeout": float(ctx.get("timeout", 10.0)),
        }
        result = execute_license(**kwargs) if ctx.get("execute") else build_license_dry_run(**kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
