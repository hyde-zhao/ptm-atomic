"""MAC 地址对象 runner commands (mac-pool config/update/delete/delete-batch/verify)."""

from __future__ import annotations

import argparse
from typing import Any

from atomic_ops.commands import CommandSpec
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


def build_subtree() -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(
            name="config",
            help="Configure a MAC address object on the NGFW device.",
            description="Create an NGFW MAC address object.",
            handler=_run_macpool_config,
            add_args=_add_macpool_args,
        ),
        CommandSpec(
            name="update",
            help="Update a MAC address object.",
            description="Update an existing NGFW MAC address object by name.",
            handler=_run_macpool_update,
            add_args=_add_macpool_update_args,
        ),
        CommandSpec(
            name="delete",
            help="Delete a MAC address object.",
            description="Delete a single NGFW MAC address object by name (DELETE ?id=).",
            handler=_run_macpool_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="delete-batch",
            help="Delete multiple MAC address objects.",
            description="Batch-delete NGFW MAC address objects by name.",
            handler=_run_macpool_delete_batch,
            add_args=_add_delete_batch_args,
        ),
        CommandSpec(
            name="verify",
            help="Verify MAC address objects.",
            description="Query NGFW MAC address objects through /api/v1/macpool.",
            handler=_run_macpool_verify,
            add_args=_add_verify_args,
        ),
    )


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_macpool_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", help="MAC address object name. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--desc", default="", help="Optional description.")
    parser.add_argument(
        "--mac",
        action="append",
        default=[],
        help="MAC address to include (e.g. 02:03:0a:00:53:0c). May be repeated.",
    )
    _add_payload_args(parser)


def _add_macpool_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="MAC address object name to update. Required unless --payload-json/--payload-file is given.")
    _add_macpool_args(parser)


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="Entry name to delete.")


def _add_delete_batch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        action="append",
        required=True,
        help="Entry name to delete. May be repeated for batch operations.",
    )


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")
    parser.add_argument("--keywords", default="", help="Keyword filter for the query.")


def _run_macpool_config(args: argparse.Namespace) -> int:
    return _run_macpool(args, "fw_config_macpool")


def _run_macpool_update(args: argparse.Namespace) -> int:
    return _run_macpool(args, "fw_update_macpool")


def _run_macpool_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_macpool(args, "fw_delete_macpool")


def _run_macpool_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_macpool(args, "fw_delete_batch_macpool")


def _run_macpool_verify(args: argparse.Namespace) -> int:
    return _run_macpool(args, "fw_verify_macpool")


def _run_macpool(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.macpool import (
        build_macpool_batch_delete_payload,
        build_macpool_dry_run,
        build_macpool_payload,
        build_macpool_update_payload,
        execute_macpool,
        validate_macpool_payload,
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
        page = int(getattr(args, "page", 1))
        size = int(getattr(args, "size", 40))
        keywords = getattr(args, "keywords", "") or ""
        types = getattr(args, "type", [])
        payload: dict[str, Any] | None

        if op_id == "fw_config_macpool":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "name")
                payload = build_macpool_payload(
                    name=getattr(args, "name"),
                    desc=getattr(args, "desc", ""),
                    macs=_arg_list(args, "mac"),
                )
        elif op_id == "fw_update_macpool":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "id")
                _require_arg(args, "name")
                payload = build_macpool_update_payload(
                    entry_id=_single_arg(args, "id") or "",
                    name=getattr(args, "name"),
                    desc=getattr(args, "desc", ""),
                    macs=_arg_list(args, "mac"),
                )
        elif op_id == "fw_delete_macpool":
            payload = {"id": _single_arg(args, "id") or ""}
        elif op_id == "fw_delete_batch_macpool":
            entry_ids = _arg_list(args, "id")
            payload = build_macpool_batch_delete_payload(entry_ids=entry_ids)
            payload = validate_macpool_payload(payload, op_id=op_id)
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_macpool_dry_run(
                op_id=op_id,
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                page=page,
                size=size,
                keywords=keywords,
                types=types,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_macpool(
                op_id=op_id,
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                page=page,
                size=size,
                keywords=keywords,
                types=types,
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
