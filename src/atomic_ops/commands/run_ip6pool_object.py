"""IPv6 地址对象 runner commands (ip6pool-object config/update/delete/delete-batch/verify)."""

from __future__ import annotations

import argparse
import json
from typing import Any

from atomic_ops.commands import CommandSpec
from atomic_ops.commands.run import (
    _arg_list,
    _require_arg,
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
            help="Configure an IPv6 address object on the NGFW device.",
            description="Create an NGFW IPv6 address object.",
            handler=_run_ip6pool_object_config,
            add_args=_add_object_args,
        ),
        CommandSpec(
            name="update",
            help="Update an IPv6 address object.",
            description="Update an existing NGFW IPv6 address object.",
            handler=_run_ip6pool_object_update,
            add_args=_add_object_args,
        ),
        CommandSpec(
            name="delete",
            help="Delete an IPv6 address object.",
            description="Delete a single NGFW IPv6 address object by name.",
            handler=_run_ip6pool_object_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="delete-batch",
            help="Delete multiple IPv6 address objects.",
            description="Batch-delete NGFW IPv6 address objects by name.",
            handler=_run_ip6pool_object_delete_batch,
            add_args=_add_delete_batch_args,
        ),
        CommandSpec(
            name="verify",
            help="Verify IPv6 address objects.",
            description="Query NGFW IPv6 address objects through /api/v1/ip6pool.",
            handler=_run_ip6pool_object_verify,
            add_args=_add_verify_args,
        ),
    )


def _add_object_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--object-name", required=True, help="IPv6 address-object name.")
    parser.add_argument("--ipaddr", required=True, help="IPv6 address or network address.")
    parser.add_argument("--mask", required=True, help="IPv6 mask length, for example 64 or 128.")
    parser.add_argument("--object-desc", help="Optional address-object description.")
    parser.add_argument(
        "--excl-ranges",
        help='JSON list of excluded ranges, for example \'[{"s_start":1,"s_end":10}]\'.',
    )
    parser.add_argument(
        "--excl-networks",
        help='JSON list of excluded networks, for example \'[{"ipaddr":"2001::1","mask":""}]\'.',
    )


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--object-name", required=True, help="IPv6 address-object name to delete.")


def _add_delete_batch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--object-name",
        action="append",
        required=True,
        help="IPv6 address-object name to delete. May be repeated for batch operations.",
    )


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")
    parser.add_argument("--keywords", default="", help="Keyword filter for the query.")
    parser.add_argument(
        "--type",
        action="append",
        default=[],
        help="Address object type filter (e.g. ANY, CUSTOM). May be repeated.",
    )


def _parse_json_list(raw: str | None) -> list[dict[str, Any]] | None:
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "JSON list argument must be valid JSON.",
            {"reason": exc.msg},
        ) from exc
    if not isinstance(parsed, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "JSON list argument must decode to a JSON array.",
        )
    return parsed


def _run_ip6pool_object_config(args: argparse.Namespace) -> int:
    return _run_ip6pool_object(args, "fw_config_ip6pool_object")


def _run_ip6pool_object_update(args: argparse.Namespace) -> int:
    return _run_ip6pool_object(args, "fw_update_ip6pool_object")


def _run_ip6pool_object_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "object_name")
    return _run_ip6pool_object(args, "fw_delete_ip6pool_object")


def _run_ip6pool_object_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "object_name")
    return _run_ip6pool_object(args, "fw_delete_batch_ip6pool_object")


def _run_ip6pool_object_verify(args: argparse.Namespace) -> int:
    return _run_ip6pool_object(args, "fw_verify_ip6pool_object")


def _run_ip6pool_object(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.object import (
        IP6POOL_OBJECT_RESOURCE,
        build_address_object_payload,
        build_address_object_update_payload,
        build_object_batch_delete_payload,
        build_object_dry_run,
        execute_object,
        validate_object_payload,
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
        exclranges = _parse_json_list(getattr(args, "excl_ranges", None))
        exclnetworks = _parse_json_list(getattr(args, "excl_networks", None))
        payload: dict[str, Any] | None
        if op_id == "fw_config_ip6pool_object":
            payload = build_address_object_payload(
                object_name=getattr(args, "object_name"),
                ipaddr=getattr(args, "ipaddr"),
                mask=getattr(args, "mask"),
                object_desc=getattr(args, "object_desc"),
                ip_version=6,
                exclranges=exclranges,
                exclnetworks=exclnetworks,
            )
        elif op_id == "fw_update_ip6pool_object":
            payload = build_address_object_update_payload(
                object_name=getattr(args, "object_name"),
                ipaddr=getattr(args, "ipaddr"),
                mask=getattr(args, "mask"),
                object_desc=getattr(args, "object_desc"),
                ip_version=6,
                exclranges=exclranges,
                exclnetworks=exclnetworks,
            )
        elif op_id == "fw_delete_ip6pool_object":
            payload = {"id": getattr(args, "object_name")}
        elif op_id == "fw_delete_batch_ip6pool_object":
            payload = build_object_batch_delete_payload(
                entry_ids=_arg_list(args, "object_name"),
                resource=IP6POOL_OBJECT_RESOURCE,
            )
            payload = validate_object_payload(payload, op_id=op_id)
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_object_dry_run(
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
            result = execute_object(
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
