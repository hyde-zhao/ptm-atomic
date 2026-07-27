"""IPv6 地址组 runner commands (ip6pool-group config/update/delete/delete-batch/verify)."""

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
            help="Configure an IPv6 address group on the NGFW device.",
            description="Create an NGFW IPv6 address group.",
            handler=_run_ip6pool_group_config,
            add_args=_add_ip6pool_group_args,
        ),
        CommandSpec(
            name="update",
            help="Update an IPv6 address group.",
            description="Update an existing NGFW IPv6 address group by name.",
            handler=_run_ip6pool_group_update,
            add_args=_add_ip6pool_group_update_args,
        ),
        CommandSpec(
            name="delete",
            help="Delete an IPv6 address group.",
            description="Delete a single NGFW IPv6 address group by name (DELETE ?id=).",
            handler=_run_ip6pool_group_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="delete-batch",
            help="Delete multiple IPv6 address groups.",
            description="Batch-delete NGFW IPv6 address groups by name.",
            handler=_run_ip6pool_group_delete_batch,
            add_args=_add_delete_batch_args,
        ),
        CommandSpec(
            name="verify",
            help="Verify IPv6 address groups.",
            description="Query NGFW IPv6 address groups through /api/v1/ip6pool/group.",
            handler=_run_ip6pool_group_verify,
            add_args=_add_verify_args,
        ),
    )


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_ip6pool_group_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", help="IPv6 address group name. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--desc", default="", help="Optional description.")
    parser.add_argument(
        "--ip6pools",
        action="append",
        default=[],
        help="IPv6 address pool name to include. May be repeated.",
    )
    _add_payload_args(parser)


def _add_ip6pool_group_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="IPv6 address group name to update. Required unless --payload-json/--payload-file is given.")
    _add_ip6pool_group_args(parser)


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
    parser.add_argument(
        "--type",
        action="append",
        default=[],
        help="Address group type filter (e.g. ANY, CUSTOM). May be repeated.",
    )


def _run_ip6pool_group_config(args: argparse.Namespace) -> int:
    return _run_ip6pool_group(args, "fw_config_ip6pool_group")


def _run_ip6pool_group_update(args: argparse.Namespace) -> int:
    return _run_ip6pool_group(args, "fw_update_ip6pool_group")


def _run_ip6pool_group_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_ip6pool_group(args, "fw_delete_ip6pool_group")


def _run_ip6pool_group_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_ip6pool_group(args, "fw_delete_batch_ip6pool_group")


def _run_ip6pool_group_verify(args: argparse.Namespace) -> int:
    return _run_ip6pool_group(args, "fw_verify_ip6pool_group")


def _run_ip6pool_group(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.ip6pool_group import (
        build_ip6pool_group_batch_delete_payload,
        build_ip6pool_group_dry_run,
        build_ip6pool_group_payload,
        build_ip6pool_group_update_payload,
        execute_ip6pool_group,
        validate_ip6pool_group_payload,
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

        if op_id == "fw_config_ip6pool_group":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "name")
                payload = build_ip6pool_group_payload(
                    name=getattr(args, "name"),
                    desc=getattr(args, "desc", ""),
                    ip6pools=_arg_list(args, "ip6pools"),
                )
        elif op_id == "fw_update_ip6pool_group":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "id")
                _require_arg(args, "name")
                payload = build_ip6pool_group_update_payload(
                    entry_id=_single_arg(args, "id") or "",
                    name=getattr(args, "name"),
                    desc=getattr(args, "desc", ""),
                    ip6pools=_arg_list(args, "ip6pools"),
                )
        elif op_id == "fw_delete_ip6pool_group":
            payload = {"id": _single_arg(args, "id") or ""}
        elif op_id == "fw_delete_batch_ip6pool_group":
            entry_ids = _arg_list(args, "id")
            payload = build_ip6pool_group_batch_delete_payload(entry_ids=entry_ids)
            payload = validate_ip6pool_group_payload(payload, op_id=op_id)
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_ip6pool_group_dry_run(
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
            result = execute_ip6pool_group(
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
