"""Iplink and linkgroup runner commands."""

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
            name="iplink",
            help="Iplink (link-detection) operations.",
            description="Iplink create, update, delete, batch-delete, and verify operations.",
            children=(
                CommandSpec(name="config", help="Create an iplink.", description="Create a new NGFW iplink entry.", handler=_run_config, add_args=_add_iplink_args),
                CommandSpec(name="update", help="Update an iplink.", description="Update an existing NGFW iplink entry.", handler=_run_update, add_args=_add_iplink_args),
                CommandSpec(name="delete", help="Delete an iplink.", description="Delete a single NGFW iplink entry.", handler=_run_delete, add_args=_add_delete_args),
                CommandSpec(name="delete-batch", help="Delete multiple iplink entries.", description="Batch-delete NGFW iplink entries.", handler=_run_delete_batch, add_args=_add_delete_args),
                CommandSpec(name="verify", help="Verify iplink entries.", description="Query NGFW iplink entries.", handler=_run_verify, add_args=_add_verify_args),
            ),
        ),
        CommandGroup(
            name="linkgroup",
            help="Iplink-group operations.",
            description="Iplink-group create, update, delete, and verify operations.",
            children=(
                CommandSpec(name="config", help="Create an iplink group.", description="Create a new NGFW iplink group.", handler=_run_group_config, add_args=_add_linkgroup_args),
                CommandSpec(name="update", help="Update an iplink group.", description="Update an existing NGFW iplink group.", handler=_run_group_update, add_args=_add_linkgroup_args),
                CommandSpec(name="delete", help="Delete an iplink group.", description="Delete a single NGFW iplink group.", handler=_run_group_delete, add_args=_add_delete_args),
                CommandSpec(name="verify", help="Verify iplink-group entries.", description="Query NGFW iplink-group entries.", handler=_run_group_verify, add_args=_add_verify_args),
            ),
        ),
    )


def _add_iplink_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", required=True, help="Iplink val.name.")
    parser.add_argument("--destination", required=True, help="Iplink detection destination IP address.")
    parser.add_argument("--interface", required=True, help="Iplink detection interface name.")
    parser.add_argument("--port", type=int, default=0, help="Iplink detection destination port.")
    parser.add_argument("--detect-type", type=int, default=0, help="Iplink detectType field.")
    parser.add_argument("--interval", type=int, default=3, help="Iplink detection interval in seconds.")
    parser.add_argument("--retry", type=int, default=1, help="Iplink detection retry count.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_linkgroup_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", required=True, help="Linkgroup val.name.")
    parser.add_argument("--description", default="", help="Linkgroup description.")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--mode-strict", dest="mode_strict", action="store_true", default=True, help="Enable strict mode (default).")
    mode_group.add_argument("--no-mode-strict", dest="mode_strict", action="store_false", help="Disable strict mode.")
    parser.add_argument("--link-name", action="append", default=[], help="Iplink name to aggregate. May be repeated.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", help="Entry id. May be repeated for batch operations.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")
    parser.add_argument("--key", default="", help="Optional name filter for fuzzy search.")


def _run_config(args: argparse.Namespace) -> int:
    return _run_iplink(args, "fw_config_iplink")


def _run_update(args: argparse.Namespace) -> int:
    return _run_iplink(args, "fw_update_iplink")


def _run_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_iplink(args, "fw_delete_iplink")


def _run_delete_batch(args: argparse.Namespace) -> int:
    return _run_iplink(args, "fw_delete_batch_iplink")


def _run_verify(args: argparse.Namespace) -> int:
    return _run_iplink(args, "fw_verify_iplink")


def _run_group_config(args: argparse.Namespace) -> int:
    return _run_linkgroup(args, "fw_config_iplink_group")


def _run_group_update(args: argparse.Namespace) -> int:
    return _run_linkgroup(args, "fw_update_iplink_group")


def _run_group_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_linkgroup(args, "fw_delete_iplink_group")


def _run_group_verify(args: argparse.Namespace) -> int:
    return _run_linkgroup(args, "fw_verify_iplink_group")


def _run_iplink(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.iplink import (
        build_iplink_batch_delete_payload,
        build_iplink_dry_run,
        build_iplink_payload,
        execute_iplink,
        load_json_payload,
        validate_batch_payload,
        validate_iplink_payload,
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
        key = getattr(args, "key", "")
        payload: dict[str, Any] | None

        if op_id in {"fw_config_iplink", "fw_update_iplink"}:
            payload = raw_payload or build_iplink_payload(
                name=getattr(args, "name"),
                destination=getattr(args, "destination"),
                interface=getattr(args, "interface"),
                port=int(getattr(args, "port", 0)),
                detect_type=int(getattr(args, "detect_type", 0)),
                interval=int(getattr(args, "interval", 3)),
                retry=int(getattr(args, "retry", 1)),
            )
            payload = validate_iplink_payload(payload)
        elif op_id == "fw_delete_iplink":
            payload = raw_payload or {"id": _single_arg(args, "id")}
        elif op_id == "fw_delete_batch_iplink":
            payload = raw_payload or build_iplink_batch_delete_payload(entry_ids=_arg_list(args, "id"))
            payload = validate_batch_payload(payload, allowed_resource="/api/v1/iplink")
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_iplink_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=page, size=size, key=key, verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_iplink(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=page, size=size, key=key, verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _run_linkgroup(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.iplink import (
        build_iplink_dry_run,
        build_linkgroup_batch_delete_payload,
        build_linkgroup_payload,
        execute_iplink,
        load_json_payload,
        validate_batch_payload,
        validate_linkgroup_payload,
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
        key = getattr(args, "key", "")
        payload: dict[str, Any] | None

        if op_id in {"fw_config_iplink_group", "fw_update_iplink_group"}:
            payload = raw_payload or build_linkgroup_payload(
                name=getattr(args, "name"),
                description=getattr(args, "description", ""),
                mode_strict=bool(getattr(args, "mode_strict", True)),
                link_name=list(getattr(args, "link_name") or []),
            )
            payload = validate_linkgroup_payload(payload)
        elif op_id == "fw_delete_iplink_group":
            payload = raw_payload or {"id": _single_arg(args, "id")}
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_iplink_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=page, size=size, key=key, verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_iplink(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=page, size=size, key=key, verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
