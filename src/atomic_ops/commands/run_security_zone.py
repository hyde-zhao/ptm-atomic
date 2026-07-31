"""Security-zone runner commands."""

from __future__ import annotations

import argparse
from typing import Any

from atomic_ops.commands import CommandSpec
from atomic_ops.commands.run import (
    _arg_list,
    _read_secret_env,
    _require_arg,
    _single_arg,
    _to_run_envelope,
    _write_output,
    resolve_run_context,
)
from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file


def build_subtree() -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(
            name="config",
            help="Create a new security zone.",
            description="Create a new security zone with optional interface bindings.",
            handler=_run_config,
            add_args=_add_config_args,
        ),
        CommandSpec(
            name="update",
            help="Update an existing security zone.",
            description="Update a security zone description or interface bindings by name.",
            handler=_run_update,
            add_args=_add_update_args,
        ),
        CommandSpec(
            name="delete",
            help="Delete a security zone.",
            description="Delete a security zone by name. Zone must have refcnt equal to 0.",
            handler=_run_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="verify",
            help="Query security zones.",
            description="Query all security zones on the device.",
            handler=_run_verify,
            add_args=_add_verify_args,
        ),
        CommandSpec(
            name="verify-vpp",
            help="Verify security zone VPP data-plane state via SSH.",
            description="SSH into the device, run vppctl show zone, and compare with expected interfaces.",
            handler=_run_verify_vpp,
            add_args=_add_verify_vpp_args,
        ),
    )


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--name", required=True, help="Security-zone name (1-31 chars, letters/digits/Chinese/hyphen/dot)."
    )
    parser.add_argument("--desc", default="", help="Security-zone description.")
    parser.add_argument(
        "--interface", action="append", default=None, dest="interfaces",
        help="Interface name to bind (repeatable).",
    )


def _add_update_args(parser: argparse.ArgumentParser) -> None:
    _add_config_args(parser)
    parser.add_argument("--refcnt", type=int, default=0, help="Reference count from pre-snapshot (used for rollback).")


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", required=True, help="Security-zone name to delete.")


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    # GET /api/v1/sfarea has no pagination or extra parameters.
    pass


def _run_config(args: argparse.Namespace) -> int:
    return _run_security_zone(args, "fw_config_security_zone")


def _run_update(args: argparse.Namespace) -> int:
    _require_arg(args, "name")
    return _run_security_zone(args, "fw_update_security_zone")


def _run_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "name")
    return _run_security_zone(args, "fw_delete_security_zone")


def _run_verify(args: argparse.Namespace) -> int:
    return _run_security_zone(args, "fw_verify_security_zone")


def _run_security_zone(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.security_zone import (
        build_security_zone_create_payload,
        build_security_zone_delete_payload,
        build_security_zone_dry_run,
        build_security_zone_update_payload,
        execute_security_zone,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning(
                {"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."},
                output_format,
            )

        session_file = resolve_session_file(ctx.get("session_file"))
        payload: dict[str, Any] | None

        if op_id == "fw_config_security_zone":
            payload = build_security_zone_create_payload(
                name=getattr(args, "name"),
                desc=getattr(args, "desc", ""),
                interfaces=_arg_list(args, "interfaces"),
            )
        elif op_id == "fw_update_security_zone":
            payload = build_security_zone_update_payload(
                name=getattr(args, "name"),
                desc=getattr(args, "desc", ""),
                interfaces=_arg_list(args, "interfaces"),
                refcnt=int(getattr(args, "refcnt", 0)),
            )
        elif op_id == "fw_delete_security_zone":
            payload = build_security_zone_delete_payload(name=_single_arg(args, "name") or "")
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_security_zone_dry_run(
                op_id=op_id,
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_security_zone(
                op_id=op_id,
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
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


def _add_verify_vpp_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ssh-host", required=True, help="Device SSH hostname or IP.")
    parser.add_argument("--ssh-port", type=int, default=22, help="SSH port (default 22).")
    parser.add_argument("--ssh-user", default="root", help="SSH login user (default root).")
    parser.add_argument("--ssh-password-env", default=None, help="Environment variable containing SSH password.")
    parser.add_argument("--zone-name", default=None, help="Security-zone name to look up in VPP.")
    parser.add_argument("--expected-interfaces", nargs="*", default=None, help="Expected interface names in VPP zone output.")


def _run_verify_vpp(args: argparse.Namespace) -> int:
    from atomic_ops.runner.security_zone import build_vpp_verify_dry_run, execute_vpp_verify

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")

    try:
        if not ctx.get("execute"):
            result = build_vpp_verify_dry_run(
                ssh_host=getattr(args, "ssh_host"),
                ssh_port=int(getattr(args, "ssh_port", 22)),
                ssh_user=getattr(args, "ssh_user", "root"),
                zone_name=getattr(args, "zone_name", None),
                expected_interfaces=_arg_list(args, "expected_interfaces"),
            )
        else:
            ssh_password = _read_secret_env(getattr(args, "ssh_password_env", None), "ssh_password_env")
            result = execute_vpp_verify(
                ssh_host=getattr(args, "ssh_host"),
                ssh_port=int(getattr(args, "ssh_port", 22)),
                ssh_user=getattr(args, "ssh_user", "root"),
                ssh_password=ssh_password,
                zone_name=getattr(args, "zone_name", None),
                expected_interfaces=_arg_list(args, "expected_interfaces"),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
