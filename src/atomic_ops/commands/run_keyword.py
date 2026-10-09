"""Keyword object runner commands (config/update/verify/delete-batch)."""

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
            help="Create a keyword object.",
            description="Create an NGFW keyword object through /api/v1/keywords.",
            handler=_run_config,
            add_args=_add_config_args,
        ),
        CommandSpec(
            name="update",
            help="Update a keyword object.",
            description="Update an NGFW keyword object by its name through /api/v1/keywords.",
            handler=_run_update,
            add_args=_add_update_args,
        ),
        CommandSpec(
            name="verify",
            help="Query keyword objects.",
            description="Query NGFW keyword objects through /api/v1/keywords.",
            handler=_run_verify,
            add_args=_add_verify_args,
        ),
        CommandSpec(
            name="delete-batch",
            help="Delete multiple keyword objects.",
            description="Batch-delete NGFW keyword objects by name through /api/v1/batch.",
            handler=_run_delete_batch,
            add_args=_add_delete_batch_args,
        ),
    )


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_content_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", help="Keyword object name. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--desc", default="", help="Keyword object description.")
    parser.add_argument(
        "--content",
        action="append",
        default=[],
        help="Keyword content entry. Repeat for multiple entries.",
    )
    _add_payload_args(parser)


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    _add_content_args(parser)


def _add_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="Keyword object name to update. Required unless --payload-json/--payload-file is given.")
    _add_content_args(parser)


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")
    parser.add_argument("--key", default="", help="Keyword filter for the query.")


def _add_delete_batch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        action="append",
        required=True,
        help="Keyword object name to delete. May be repeated for batch operations.",
    )


def _run_config(args: argparse.Namespace) -> int:
    return _run_keyword(args, "fw_config_keyword")


def _run_update(args: argparse.Namespace) -> int:
    return _run_keyword(args, "fw_update_keyword")


def _run_verify(args: argparse.Namespace) -> int:
    return _run_keyword(args, "fw_verify_keyword")


def _run_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_keyword(args, "fw_delete_batch_keyword")


def _run_keyword(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.keyword import (
        build_keyword_batch_delete_payload,
        build_keyword_dry_run,
        build_keyword_payload,
        build_keyword_update_payload,
        execute_keyword,
        validate_keyword_payload,
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
        key = getattr(args, "key", "") or ""
        payload: dict[str, Any] | None

        if op_id in {"fw_config_keyword", "fw_update_keyword"}:
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "name")
                if op_id == "fw_config_keyword":
                    payload = build_keyword_payload(
                        name=getattr(args, "name"),
                        desc=getattr(args, "desc", "") or "",
                        content=_arg_list(args, "content"),
                    )
                else:
                    _require_arg(args, "id")
                    payload = build_keyword_update_payload(
                        entry_id=_single_arg(args, "id") or "",
                        name=getattr(args, "name"),
                        desc=getattr(args, "desc", "") or "",
                        content=_arg_list(args, "content"),
                    )
        elif op_id == "fw_delete_batch_keyword":
            payload = build_keyword_batch_delete_payload(entry_ids=_arg_list(args, "id"))
            payload = validate_keyword_payload(payload, op_id=op_id)
        else:
            payload = None

        runner_kwargs = {
            "op_id": op_id,
            "base_url": ctx["base_url"],
            "session_file": session_file,
            "auth_header": ctx.get("auth_header", "Authorization"),
            "payload": payload,
            "page": page,
            "size": size,
            "key": key,
            "verify_tls": bool(ctx.get("verify_tls")),
            "timeout": float(ctx.get("timeout", 10.0)),
        }
        if not ctx.get("execute"):
            result = build_keyword_dry_run(**runner_kwargs)
        else:
            result = execute_keyword(**runner_kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
