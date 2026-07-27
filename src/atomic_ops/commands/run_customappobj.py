"""Custom application-object runner commands (app-obj config/update/delete/delete-batch/verify)."""

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
            help="Configure a custom application object on the NGFW device.",
            description="Create an NGFW custom application object.",
            handler=_run_customappobj_config,
            add_args=_add_customappobj_args,
        ),
        CommandSpec(
            name="update",
            help="Update a custom application object.",
            description="Update an existing NGFW custom application object by id.",
            handler=_run_customappobj_update,
            add_args=_add_customappobj_update_args,
        ),
        CommandSpec(
            name="delete",
            help="Delete a custom application object.",
            description="Delete a single NGFW custom application object by id (via batch endpoint).",
            handler=_run_customappobj_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="delete-batch",
            help="Delete multiple custom application objects.",
            description="Batch-delete NGFW custom application objects by id.",
            handler=_run_customappobj_delete_batch,
            add_args=_add_delete_batch_args,
        ),
        CommandSpec(
            name="verify",
            help="Verify custom application objects.",
            description="Query NGFW application objects through /api/v1/appobjsearch.",
            handler=_run_customappobj_verify,
            add_args=_add_verify_args,
        ),
    )


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_customappobj_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name-cn", help="Custom application-object Chinese name. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--pid", help="Parent category id. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--protocol", help="Protocol, for example TCP or UDP. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--pattern-type", help="Pattern type, for example Ascii or Port. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--pattern", help="Match pattern value. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--platform", default="", help="Platform string joined by 、.")
    parser.add_argument("--ip", default="", help="Optional IP address.")
    parser.add_argument("--path", default="", help="Category path, for example 即时通讯/QQ/xxx.")
    parser.add_argument("--desc", default="", help="Optional description.")
    parser.add_argument(
        "--customflag",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Custom flag (default true). Use --no-customflag to disable.",
    )
    parser.add_argument("--name-en", help="English name; defaults to name_cn when omitted.")
    parser.add_argument("--tcp-offset", default="0", help="tcpudpcfg offset (default 0).")
    parser.add_argument("--tcp-port", default="", help="tcpudpcfg port.")
    parser.add_argument("--tcp-direct", default="client", help="tcpudpcfg direct (default client).")
    _add_payload_args(parser)


def _add_customappobj_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--appid", help="Numeric app id (val.id) returned by create. Required unless --payload-json/--payload-file is given.")
    _add_customappobj_args(parser)


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="Custom application-object id to delete.")


def _add_delete_batch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        action="append",
        required=True,
        help="Custom application-object id to delete. May be repeated for batch operations.",
    )


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--search-keyword", default="", help="Keyword filter; empty returns the full tree.")
    parser.add_argument(
        "--tag-custom",
        type=int,
        default=0,
        help="istagcustom filter, 0 for preset application tree, 1 for custom tags (default 0).",
    )


def _run_customappobj_config(args: argparse.Namespace) -> int:
    return _run_customappobj(args, "fw_config_customappobj")


def _run_customappobj_update(args: argparse.Namespace) -> int:
    return _run_customappobj(args, "fw_update_customappobj")


def _run_customappobj_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_customappobj(args, "fw_delete_customappobj")


def _run_customappobj_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_customappobj(args, "fw_delete_batch_customappobj")


def _run_customappobj_verify(args: argparse.Namespace) -> int:
    return _run_customappobj(args, "fw_verify_customappobj")


def _run_customappobj(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.customappobj import (
        build_customappobj_batch_delete_payload,
        build_customappobj_dry_run,
        build_customappobj_payload,
        build_customappobj_update_payload,
        execute_customappobj,
        validate_customappobj_payload,
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
        search_keyword = getattr(args, "search_keyword", "") or ""
        istagcustom = int(getattr(args, "tag_custom", 0))
        payload: dict[str, Any] | None

        if op_id == "fw_config_customappobj":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "name_cn")
                _require_arg(args, "pid")
                _require_arg(args, "protocol")
                _require_arg(args, "pattern_type")
                _require_arg(args, "pattern")
                payload = build_customappobj_payload(
                    name_cn=getattr(args, "name_cn"),
                    pid=getattr(args, "pid"),
                    protocol=getattr(args, "protocol"),
                    pattern_type=getattr(args, "pattern_type"),
                    pattern=getattr(args, "pattern"),
                    platform=getattr(args, "platform", ""),
                    ip=getattr(args, "ip", ""),
                    path=getattr(args, "path", ""),
                    desc=getattr(args, "desc", ""),
                    customflag=bool(getattr(args, "customflag", True)),
                    name_en=getattr(args, "name_en", None),
                    tcp_offset=getattr(args, "tcp_offset", "0"),
                    tcp_port=getattr(args, "tcp_port", ""),
                    tcp_direct=getattr(args, "tcp_direct", "client"),
                )
        elif op_id == "fw_update_customappobj":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "name_cn")
                _require_arg(args, "appid")
                _require_arg(args, "pid")
                _require_arg(args, "protocol")
                _require_arg(args, "pattern_type")
                _require_arg(args, "pattern")
                payload = build_customappobj_update_payload(
                    name_cn=getattr(args, "name_cn"),
                    appid=_single_arg(args, "appid") or "",
                    pid=getattr(args, "pid"),
                    protocol=getattr(args, "protocol"),
                    pattern_type=getattr(args, "pattern_type"),
                    pattern=getattr(args, "pattern"),
                    platform=getattr(args, "platform", ""),
                    ip=getattr(args, "ip", ""),
                    path=getattr(args, "path", ""),
                    desc=getattr(args, "desc", ""),
                    customflag=bool(getattr(args, "customflag", True)),
                    name_en=getattr(args, "name_en", None),
                    tcp_offset=getattr(args, "tcp_offset", "0"),
                    tcp_port=getattr(args, "tcp_port", ""),
                    tcp_direct=getattr(args, "tcp_direct", "client"),
                )
        elif op_id == "fw_delete_customappobj":
            payload = {"id": _single_arg(args, "id") or ""}
        elif op_id == "fw_delete_batch_customappobj":
            entry_ids = _arg_list(args, "id")
            payload = build_customappobj_batch_delete_payload(entry_ids=entry_ids)
            payload = validate_customappobj_payload(payload, op_id=op_id)
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_customappobj_dry_run(
                op_id=op_id,
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                search_keyword=search_keyword,
                istagcustom=istagcustom,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_customappobj(
                op_id=op_id,
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                search_keyword=search_keyword,
                istagcustom=istagcustom,
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
