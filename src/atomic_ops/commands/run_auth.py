"""Authentication runner commands (auth login)."""

from __future__ import annotations

import argparse
import os
from typing import Any

from atomic_ops.commands import CommandSpec
from atomic_ops.commands.run import _read_secret_env, _to_run_envelope, _write_output, resolve_run_context
from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file


def build_subtree() -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(
            name="login",
            help="Login to NGFW web management and persist a session.",
            description="Login to NGFW web management and persist a session file for subsequent operations.",
            handler=_run_login,
            add_args=_add_login_args,
        ),
    )


def _add_login_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--username", help="NGFW web-management username.")
    parser.add_argument(
        "--password-env",
        help="Environment variable containing the NGFW web-management password.",
    )
    parser.add_argument(
        "--change-default-password",
        action="store_true",
        help="Allow fw_login_web_management to call /api/v1/changeDefPwd when the device requires it.",
    )
    parser.add_argument(
        "--new-password-env",
        help="Environment variable containing the replacement password for --change-default-password.",
    )


def _run_login(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ngfw_login import build_login_dry_run, login
    from atomic_ops.runner.session import session_summary, write_session_file

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning(
                {
                    "warning_code": "TLS_VERIFY_DISABLED",
                    "message": "Device TLS verification is disabled for this runner invocation.",
                },
                output_format,
            )

        session_file = resolve_session_file(ctx.get("session_file"))
        username = getattr(args, "username") or "admin"
        if not ctx.get("execute"):
            payload = build_login_dry_run(
                base_url=ctx["base_url"],
                username=username,
                session_file=str(session_file),
                change_default_password=bool(getattr(args, "change_default_password")),
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            password_value = _read_secret_env(getattr(args, "password_env", None), "password_env")
            replacement_value = None
            if getattr(args, "change_default_password"):
                replacement_value = _read_secret_env(getattr(args, "new_password_env", None), "new_password_env")
            result = login(
                base_url=ctx["base_url"],
                username=username,
                password_value=password_value,
                timeout=float(ctx.get("timeout", 10.0)),
                verify_tls=bool(ctx.get("verify_tls")),
                change_default_password=bool(getattr(args, "change_default_password")),
                replacement_value=replacement_value,
            )
            session_payload = write_session_file(
                session_file,
                base_url=result["base_url"],
                username=username,
                session_value=result["session_value"],
                source_op_id="fw_login_web_management",
            )
            payload = {
                "op_id": "fw_login_web_management",
                "status": "success",
                "session": session_summary(session_file, session_payload),
            }
        _write_output(_to_run_envelope(payload), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
