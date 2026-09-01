"""时间对象 runner commands (time-object config/update/delete/delete-batch/verify)."""

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
            help="Configure a time object on the NGFW device.",
            description="Create an NGFW time object (oneshot/day/week/month scheduletype).",
            handler=_run_timeobject_config,
            add_args=_add_timeobject_args,
        ),
        CommandSpec(
            name="update",
            help="Update a time object.",
            description="Update an existing NGFW time object by name.",
            handler=_run_timeobject_update,
            add_args=_add_timeobject_update_args,
        ),
        CommandSpec(
            name="delete",
            help="Delete a time object.",
            description="Delete a single NGFW time object by name (DELETE ?id=).",
            handler=_run_timeobject_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="delete-batch",
            help="Delete multiple time objects.",
            description="Batch-delete NGFW time objects by name.",
            handler=_run_timeobject_delete_batch,
            add_args=_add_delete_batch_args,
        ),
        CommandSpec(
            name="verify",
            help="Verify time objects.",
            description="Query NGFW time objects through /api/v1/timeobject.",
            handler=_run_timeobject_verify,
            add_args=_add_verify_args,
        ),
    )


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_timeobject_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", help="Time object name. Required unless --payload-json/--payload-file is given.")
    parser.add_argument(
        "--scheduletype",
        help="Schedule type: oneshot/day/week/month. Required unless --payload-json/--payload-file is given.",
    )
    parser.add_argument(
        "--start-time",
        default="",
        help="Start time for oneshot (YYYY-MM-DD HH:MM:SS) or day/week (HH:MM:SS).",
    )
    parser.add_argument(
        "--end-time",
        default="",
        help="End time for oneshot (YYYY-MM-DD HH:MM:SS) or day/week (HH:MM:SS).",
    )
    parser.add_argument(
        "--weekday",
        help="Weekday integer (1-7) for week scheduletype. Same value applied to start and end.",
    )
    parser.add_argument(
        "--month-time",
        help="Month time integer for month scheduletype (e.g. 24).",
    )
    parser.add_argument(
        "--planday",
        default="",
        help="Plan day string for month scheduletype (e.g. 11).",
    )
    _add_payload_args(parser)


def _add_timeobject_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="Time object name to update. Required unless --payload-json/--payload-file is given.")
    _add_timeobject_args(parser)


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


def _run_timeobject_config(args: argparse.Namespace) -> int:
    return _run_timeobject(args, "fw_config_timeobject")


def _run_timeobject_update(args: argparse.Namespace) -> int:
    return _run_timeobject(args, "fw_update_timeobject")


def _run_timeobject_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_timeobject(args, "fw_delete_timeobject")


def _run_timeobject_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_timeobject(args, "fw_delete_batch_timeobject")


def _run_timeobject_verify(args: argparse.Namespace) -> int:
    return _run_timeobject(args, "fw_verify_timeobject")


def _run_timeobject(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.timeobject import (
        build_timeobject_batch_delete_payload,
        build_timeobject_dry_run,
        build_timeobject_payload,
        build_timeobject_update_payload,
        execute_timeobject,
        validate_timeobject_payload,
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

        if op_id == "fw_config_timeobject":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "name")
                _require_arg(args, "scheduletype")
                payload = build_timeobject_payload(
                    name=getattr(args, "name"),
                    scheduletype=getattr(args, "scheduletype"),
                    start_time=getattr(args, "start_time", ""),
                    end_time=getattr(args, "end_time", ""),
                    weekday=getattr(args, "weekday", None),
                    month_time=getattr(args, "month_time", None),
                    planday=getattr(args, "planday", ""),
                )
        elif op_id == "fw_update_timeobject":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                # 设备 PUT 信封要求 {"id":<name>,"val":{...}}。--payload-json 逃生口若只携带
                # {"val":...} 而未带 id, 从 --id 注入, 否则设备 400 "请求中没有id字段"。
                if isinstance(raw_payload, dict) and "val" in raw_payload and "id" not in raw_payload:
                    _require_arg(args, "id")
                    payload = {"id": _single_arg(args, "id") or "", "val": raw_payload["val"]}
                else:
                    payload = raw_payload
            else:
                _require_arg(args, "id")
                _require_arg(args, "name")
                _require_arg(args, "scheduletype")
                payload = build_timeobject_update_payload(
                    entry_id=_single_arg(args, "id") or "",
                    name=getattr(args, "name"),
                    scheduletype=getattr(args, "scheduletype"),
                    start_time=getattr(args, "start_time", ""),
                    end_time=getattr(args, "end_time", ""),
                    weekday=getattr(args, "weekday", None),
                    month_time=getattr(args, "month_time", None),
                    planday=getattr(args, "planday", ""),
                )
        elif op_id == "fw_delete_timeobject":
            payload = {"id": _single_arg(args, "id") or ""}
        elif op_id == "fw_delete_batch_timeobject":
            entry_ids = _arg_list(args, "id")
            payload = build_timeobject_batch_delete_payload(entry_ids=entry_ids)
            payload = validate_timeobject_payload(payload, op_id=op_id)
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_timeobject_dry_run(
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
            result = execute_timeobject(
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
