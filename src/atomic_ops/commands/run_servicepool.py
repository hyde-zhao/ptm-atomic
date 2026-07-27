"""Service pool and service group runner commands (service-pool config/update/delete/.../group-*)."""

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
        # 服务对象
        CommandSpec(
            name="config",
            help="Configure a custom service pool on the NGFW device.",
            description="Create an NGFW custom service pool.",
            handler=_run_servicepool_config,
            add_args=_add_servicepool_args,
        ),
        CommandSpec(
            name="update",
            help="Update a custom service pool.",
            description="Update an existing NGFW custom service pool by name.",
            handler=_run_servicepool_update,
            add_args=_add_servicepool_update_args,
        ),
        CommandSpec(
            name="delete",
            help="Delete a custom service pool.",
            description="Delete a single NGFW custom service pool by name (via batch endpoint).",
            handler=_run_servicepool_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="delete-batch",
            help="Delete multiple custom service pools.",
            description="Batch-delete NGFW custom service pools by name.",
            handler=_run_servicepool_delete_batch,
            add_args=_add_delete_batch_args,
        ),
        CommandSpec(
            name="verify",
            help="Verify custom service pools (type CUSTOM).",
            description="Query NGFW custom service pools through /api/v1/servicepool?type=CUSTOM.",
            handler=_run_servicepool_verify,
            add_args=_add_verify_args,
        ),
        CommandSpec(
            name="verify-preset",
            help="Verify preset service pools (type PRESET).",
            description="Query NGFW preset service pools through /api/v1/servicepool?type=PRESET.",
            handler=_run_servicepool_verify_preset,
            add_args=_add_verify_preset_args,
        ),
        # 服务组
        CommandSpec(
            name="group-config",
            help="Configure a service pool group on the NGFW device.",
            description="Create an NGFW service pool group.",
            handler=_run_servicepool_group_config,
            add_args=_add_servicepool_group_args,
        ),
        CommandSpec(
            name="group-update",
            help="Update a service pool group.",
            description="Update an existing NGFW service pool group by name.",
            handler=_run_servicepool_group_update,
            add_args=_add_servicepool_group_update_args,
        ),
        CommandSpec(
            name="group-delete",
            help="Delete a service pool group.",
            description="Delete a single NGFW service pool group by name (via batch endpoint).",
            handler=_run_servicepool_group_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="group-delete-batch",
            help="Delete multiple service pool groups.",
            description="Batch-delete NGFW service pool groups by name.",
            handler=_run_servicepool_group_delete_batch,
            add_args=_add_delete_batch_args,
        ),
        CommandSpec(
            name="group-verify",
            help="Verify service pool groups.",
            description="Query NGFW service pool groups through /api/v1/servicepool/group.",
            handler=_run_servicepool_group_verify,
            add_args=_add_verify_args,
        ),
    )


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_servicepool_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", help="Custom service pool name. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--desc", default="", help="Optional description.")
    parser.add_argument("--ranges", help='JSON list of ranges, e.g. \'[{"proto":6,"s_start":0,"s_end":65535,"d_start":0,"d_end":65535}]\'.')
    _add_payload_args(parser)


def _add_servicepool_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="Custom service pool name to update. Required unless --payload-json/--payload-file is given.")
    _add_servicepool_args(parser)


def _add_servicepool_group_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", help="Service pool group name. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--desc", default="", help="Optional description.")
    parser.add_argument(
        "--servicepools",
        action="append",
        default=[],
        help="Service pool name to include. May be repeated.",
    )
    _add_payload_args(parser)


def _add_servicepool_group_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="Service pool group name to update. Required unless --payload-json/--payload-file is given.")
    _add_servicepool_group_args(parser)


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


def _add_verify_preset_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")


def _run_servicepool_config(args: argparse.Namespace) -> int:
    return _run_servicepool(args, "fw_config_servicepool")


def _run_servicepool_update(args: argparse.Namespace) -> int:
    return _run_servicepool(args, "fw_update_servicepool")


def _run_servicepool_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_servicepool(args, "fw_delete_servicepool")


def _run_servicepool_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_servicepool(args, "fw_delete_batch_servicepool")


def _run_servicepool_verify(args: argparse.Namespace) -> int:
    return _run_servicepool(args, "fw_verify_servicepool")


def _run_servicepool_verify_preset(args: argparse.Namespace) -> int:
    return _run_servicepool(args, "fw_verify_servicepool_preset")


def _run_servicepool_group_config(args: argparse.Namespace) -> int:
    return _run_servicepool(args, "fw_config_servicepool_group")


def _run_servicepool_group_update(args: argparse.Namespace) -> int:
    return _run_servicepool(args, "fw_update_servicepool_group")


def _run_servicepool_group_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_servicepool(args, "fw_delete_servicepool_group")


def _run_servicepool_group_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_servicepool(args, "fw_delete_batch_servicepool_group")


def _run_servicepool_group_verify(args: argparse.Namespace) -> int:
    return _run_servicepool(args, "fw_verify_servicepool_group")


def _parse_ranges(raw: str | None) -> list[dict[str, Any]] | None:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "--ranges must be valid JSON.",
            {"reason": exc.msg},
        ) from exc


def _run_servicepool(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.servicepool import (
        build_servicepool_batch_delete_payload,
        build_servicepool_dry_run,
        build_servicepool_group_batch_delete_payload,
        build_servicepool_group_payload,
        build_servicepool_group_update_payload,
        build_servicepool_payload,
        build_servicepool_update_payload,
        execute_servicepool,
        validate_servicepool_payload,
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

        if op_id == "fw_config_servicepool":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "name")
                payload = build_servicepool_payload(
                    name=getattr(args, "name"),
                    desc=getattr(args, "desc", ""),
                    ranges=_parse_ranges(getattr(args, "ranges", None)),
                )
        elif op_id == "fw_update_servicepool":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "id")
                _require_arg(args, "name")
                payload = build_servicepool_update_payload(
                    entry_id=_single_arg(args, "id") or "",
                    name=getattr(args, "name"),
                    desc=getattr(args, "desc", ""),
                    ranges=_parse_ranges(getattr(args, "ranges", None)),
                )
        elif op_id == "fw_config_servicepool_group":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "name")
                payload = build_servicepool_group_payload(
                    name=getattr(args, "name"),
                    desc=getattr(args, "desc", ""),
                    servicepools=_arg_list(args, "servicepools"),
                )
        elif op_id == "fw_update_servicepool_group":
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "id")
                _require_arg(args, "name")
                payload = build_servicepool_group_update_payload(
                    entry_id=_single_arg(args, "id") or "",
                    name=getattr(args, "name"),
                    desc=getattr(args, "desc", ""),
                    servicepools=_arg_list(args, "servicepools"),
                )
        elif op_id == "fw_delete_servicepool":
            payload = {"id": _single_arg(args, "id") or ""}
        elif op_id == "fw_delete_batch_servicepool":
            entry_ids = _arg_list(args, "id")
            payload = build_servicepool_batch_delete_payload(entry_ids=entry_ids)
            payload = validate_servicepool_payload(payload, op_id=op_id)
        elif op_id == "fw_delete_servicepool_group":
            payload = {"id": _single_arg(args, "id") or ""}
        elif op_id == "fw_delete_batch_servicepool_group":
            entry_ids = _arg_list(args, "id")
            payload = build_servicepool_group_batch_delete_payload(entry_ids=entry_ids)
            payload = validate_servicepool_payload(payload, op_id=op_id)
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_servicepool_dry_run(
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
            result = execute_servicepool(
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
