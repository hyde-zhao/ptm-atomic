"""File type object runner commands (filetype config/update/delete + group-config/group-update/group-verify/group-delete-batch)."""

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
            help="Configure a custom file type on the NGFW device.",
            description="Create an NGFW custom file type through /api/v1/appsec/filetype.",
            handler=_run_filetype_config,
            add_args=_add_filetype_args,
        ),
        CommandSpec(
            name="update",
            help="Update a custom file type.",
            description="Update an existing NGFW custom file type.",
            handler=_run_filetype_update,
            add_args=_add_filetype_update_args,
        ),
        CommandSpec(
            name="delete",
            help="Delete a custom file type.",
            description="Delete a single NGFW custom file type by name (DELETE ?id=).",
            handler=_run_filetype_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="group-config",
            help="Configure a file type group on the NGFW device.",
            description="Create an NGFW file type group through /api/v1/appsec/filetypeObj.",
            handler=_run_filetypeobj_config,
            add_args=_add_filetypeobj_args,
        ),
        CommandSpec(
            name="group-update",
            help="Update a file type group.",
            description="Update an existing NGFW file type group.",
            handler=_run_filetypeobj_update,
            add_args=_add_filetypeobj_update_args,
        ),
        CommandSpec(
            name="group-verify",
            help="Verify file type groups.",
            description="Query NGFW file type groups through /api/v1/appsec/filetypeObj.",
            handler=_run_filetypeobj_verify,
            add_args=_add_verify_args,
        ),
        CommandSpec(
            name="group-delete-batch",
            help="Delete multiple file type groups.",
            description="Batch-delete NGFW file type groups by name.",
            handler=_run_filetypeobj_delete_batch,
            add_args=_add_delete_batch_args,
        ),
    )


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_filetype_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", help="Custom file type name. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--description", default="", help="Optional description.")
    _add_payload_args(parser)


def _add_filetype_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="Custom file type name to update. Required unless --payload-json/--payload-file is given.")
    _add_filetype_args(parser)


def _add_filetypeobj_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", help="File type group name. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--des", default="", help="Optional group description.")
    parser.add_argument(
        "--filetype",
        action="append",
        default=[],
        help="File type name to include in the group. May be repeated.",
    )
    _add_payload_args(parser)


def _add_filetypeobj_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="File type group name to update. Required unless --payload-json/--payload-file is given.")
    _add_filetypeobj_args(parser)


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


def _run_filetype_config(args: argparse.Namespace) -> int:
    return _run_filetype(args, "fw_config_filetype")


def _run_filetype_update(args: argparse.Namespace) -> int:
    return _run_filetype(args, "fw_update_filetype")


def _run_filetype_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_filetype(args, "fw_delete_filetype")


def _run_filetypeobj_config(args: argparse.Namespace) -> int:
    return _run_filetype(args, "fw_config_filetypeobj")


def _run_filetypeobj_update(args: argparse.Namespace) -> int:
    return _run_filetype(args, "fw_update_filetypeobj")


def _run_filetypeobj_verify(args: argparse.Namespace) -> int:
    return _run_filetype(args, "fw_verify_filetypeobj")


def _run_filetypeobj_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_filetype(args, "fw_delete_batch_filetypeobj")


def _run_filetype(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.filetype import (
        build_filetype_batch_delete_payload,
        build_filetype_dry_run,
        build_filetype_payload,
        build_filetype_update_payload,
        build_filetypeobj_payload,
        build_filetypeobj_update_payload,
        execute_filetype,
        validate_filetype_payload,
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
        payload: dict[str, Any] | None

        if op_id in {"fw_config_filetype", "fw_update_filetype"}:
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "name")
                if op_id == "fw_config_filetype":
                    payload = build_filetype_payload(
                        name=getattr(args, "name"),
                        description=getattr(args, "description", ""),
                    )
                else:
                    _require_arg(args, "id")
                    payload = build_filetype_update_payload(
                        entry_id=_single_arg(args, "id") or "",
                        name=getattr(args, "name"),
                        description=getattr(args, "description", ""),
                    )
        elif op_id in {"fw_config_filetypeobj", "fw_update_filetypeobj"}:
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "name")
                if op_id == "fw_config_filetypeobj":
                    payload = build_filetypeobj_payload(
                        name=getattr(args, "name"),
                        des=getattr(args, "des", ""),
                        filetypes=_arg_list(args, "filetype"),
                    )
                else:
                    _require_arg(args, "id")
                    payload = build_filetypeobj_update_payload(
                        entry_id=_single_arg(args, "id") or "",
                        name=getattr(args, "name"),
                        des=getattr(args, "des", ""),
                        filetypes=_arg_list(args, "filetype"),
                    )
        elif op_id == "fw_delete_filetype":
            payload = {"id": _single_arg(args, "id") or ""}
        elif op_id == "fw_delete_batch_filetypeobj":
            entry_ids = _arg_list(args, "id")
            payload = build_filetype_batch_delete_payload(entry_ids=entry_ids)
            payload = validate_filetype_payload(payload, op_id=op_id)
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_filetype_dry_run(
                op_id=op_id,
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                page=page,
                size=size,
                keywords=keywords,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_filetype(
                op_id=op_id,
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                page=page,
                size=size,
                keywords=keywords,
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
