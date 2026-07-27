"""Custom application-tag runner commands (app-tag config/update/delete/delete-batch/verify)."""

from __future__ import annotations

import argparse
import json
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
            help="Configure a custom application tag on the NGFW device.",
            description="Create an NGFW custom application tag.",
            handler=_run_customappobjtag_config,
            add_args=_add_customappobjtag_args,
        ),
        CommandSpec(
            name="update",
            help="Update a custom application tag.",
            description="Update an existing NGFW custom application tag by name_cn.",
            handler=_run_customappobjtag_update,
            add_args=_add_customappobjtag_update_args,
        ),
        CommandSpec(
            name="delete",
            help="Delete a custom application tag.",
            description="Delete a single NGFW custom application tag by name (via batch endpoint).",
            handler=_run_customappobjtag_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="delete-batch",
            help="Delete multiple custom application tags.",
            description="Batch-delete NGFW custom application tags by name.",
            handler=_run_customappobjtag_delete_batch,
            add_args=_add_delete_batch_args,
        ),
        CommandSpec(
            name="verify",
            help="Verify custom application tags.",
            description="Query NGFW custom application tags through /api/v1/customappobjtag.",
            handler=_run_customappobjtag_verify,
            add_args=_add_verify_args,
        ),
    )


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_customappobjtag_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name-cn", help="Custom application-tag Chinese name. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--desc", default="", help="Optional description.")
    parser.add_argument(
        "--customflag",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Custom flag (default true). Use --no-customflag to disable.",
    )
    parser.add_argument(
        "--appobj-keys",
        help='JSON list of application keys, e.g. \'[{"appname":"914CG","appid":"4"}]\'.',
    )
    _add_payload_args(parser)


def _add_customappobjtag_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="Custom application-tag name to update. Required unless --payload-json/--payload-file is given.")
    _add_customappobjtag_args(parser)


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="Custom application-tag name to delete.")


def _add_delete_batch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        action="append",
        required=True,
        help="Custom application-tag name to delete. May be repeated for batch operations.",
    )


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")
    parser.add_argument("--keywords", default="", help="Keyword filter for the query.")


def _run_customappobjtag_config(args: argparse.Namespace) -> int:
    return _run_customappobjtag(args, "fw_config_customappobjtag")


def _run_customappobjtag_update(args: argparse.Namespace) -> int:
    return _run_customappobjtag(args, "fw_update_customappobjtag")


def _run_customappobjtag_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_customappobjtag(args, "fw_delete_customappobjtag")


def _run_customappobjtag_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_customappobjtag(args, "fw_delete_batch_customappobjtag")


def _run_customappobjtag_verify(args: argparse.Namespace) -> int:
    return _run_customappobjtag(args, "fw_verify_customappobjtag")


def _parse_appobjkeys(raw: str | None) -> list[dict[str, Any]] | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "--appobj-keys must be valid JSON.",
            {"reason": exc.msg},
        ) from exc
    return parsed


def _run_customappobjtag(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.customappobjtag import (
        build_customappobjtag_batch_delete_payload,
        build_customappobjtag_dry_run,
        build_customappobjtag_payload,
        build_customappobjtag_update_payload,
        execute_customappobjtag,
        validate_customappobjtag_payload,
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

        if op_id == "fw_config_customappobjtag":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "name_cn")
                payload = build_customappobjtag_payload(
                    name_cn=getattr(args, "name_cn"),
                    desc=getattr(args, "desc", ""),
                    customflag=bool(getattr(args, "customflag", True)),
                    appobjkeys=_parse_appobjkeys(getattr(args, "appobj_keys", None)),
                )
        elif op_id == "fw_update_customappobjtag":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "id")
                _require_arg(args, "name_cn")
                payload = build_customappobjtag_update_payload(
                    entry_id=_single_arg(args, "id") or "",
                    name_cn=getattr(args, "name_cn"),
                    desc=getattr(args, "desc", ""),
                    customflag=bool(getattr(args, "customflag", True)),
                    appobjkeys=_parse_appobjkeys(getattr(args, "appobj_keys", None)),
                )
        elif op_id == "fw_delete_customappobjtag":
            payload = {"id": _single_arg(args, "id") or ""}
        elif op_id == "fw_delete_batch_customappobjtag":
            entry_ids = _arg_list(args, "id")
            payload = build_customappobjtag_batch_delete_payload(entry_ids=entry_ids)
            payload = validate_customappobjtag_payload(payload, op_id=op_id)
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_customappobjtag_dry_run(
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
            result = execute_customappobjtag(
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
