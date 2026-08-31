"""Geoip (custom region object) runner commands.

Custom region objects map an IP range to a country/province/city. A geoip
object has no name — it is identified by the numeric id returned on create
and queried by IP. Subcommands mirror the family convention:

  config        POST   /api/v1/geoip/custom
  update        PUT    /api/v1/geoip/custom
  delete        DELETE /api/v1/geoip/custom?id=<numeric id>
  delete-batch  POST   /api/v1/batch  (resource /api/v1/geoip/custom, string ids)
  verify        GET    /api/v1/geoip/custom?page=&size=&keywords=

The default region fields follow geoip.txt; accuracy pins the mapping
precision (default 2 = country/province/city).
"""

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
            help="Create a custom geoip region object.",
            description="Create an NGFW custom region object mapping an IP range to a country/province/city.",
            handler=_run_geoip_config,
            add_args=_add_geoip_args,
        ),
        CommandSpec(
            name="update",
            help="Update a custom geoip region object.",
            description="Update an existing NGFW custom geoip object.",
            handler=_run_geoip_update,
            add_args=_add_geoip_update_args,
        ),
        CommandSpec(
            name="delete",
            help="Delete a custom geoip region object.",
            description="Delete a single NGFW custom geoip object by numeric id.",
            handler=_run_geoip_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="delete-batch",
            help="Delete multiple custom geoip region objects.",
            description="Batch-delete NGFW custom geoip objects by numeric id.",
            handler=_run_geoip_delete_batch,
            add_args=_add_delete_batch_args,
        ),
        CommandSpec(
            name="verify",
            help="List custom geoip region objects.",
            description="Query NGFW custom geoip objects with pagination.",
            handler=_run_geoip_verify,
            add_args=_add_verify_args,
        ),
    )


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_region_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--ip",
        help="IP address or range (e.g. 192.0.2.1-192.0.2.9). Required unless --payload-json/--payload-file is given.",
    )
    parser.add_argument("--country", help="Country code or name, e.g. CN. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--province", help="Province name the device region database recognizes, e.g. Hunan. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--city", help="City name the device region database recognizes, e.g. Changsha. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--accuracy", type=int, default=2, help="Geographic precision (default 2 = country/province/city).")
    parser.add_argument("--desc", default="", help="Optional description.")
    _add_payload_args(parser)


def _add_geoip_args(parser: argparse.ArgumentParser) -> None:
    _add_region_args(parser)


def _add_geoip_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="Geoip object numeric id to update. Required unless --payload-json/--payload-file is given.")
    _add_region_args(parser)


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="Geoip object numeric id to delete.")


def _add_delete_batch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        action="append",
        required=True,
        help="Geoip object numeric id to delete. May be repeated for batch operations.",
    )


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")
    parser.add_argument("--keywords", default="", help="Keyword filter for the query (e.g. a description fragment).")


def _run_geoip_config(args: argparse.Namespace) -> int:
    return _run_geoip(args, "fw_config_geoip")


def _run_geoip_update(args: argparse.Namespace) -> int:
    return _run_geoip(args, "fw_update_geoip")


def _run_geoip_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_geoip(args, "fw_delete_geoip")


def _run_geoip_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_geoip(args, "fw_delete_batch_geoip")


def _run_geoip_verify(args: argparse.Namespace) -> int:
    return _run_geoip(args, "fw_verify_geoip")


def _run_geoip(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.geoip import (
        build_geoip_batch_delete_payload,
        build_geoip_delete_payload,
        build_geoip_dry_run,
        build_geoip_payload,
        build_geoip_update_payload,
        execute_geoip,
        validate_geoip_payload,
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

        if op_id == "fw_config_geoip":
            payload = _geoip_payload(args, build_geoip_payload)
        elif op_id == "fw_update_geoip":
            payload = _geoip_payload(args, build_geoip_update_payload, update=True)
        elif op_id == "fw_delete_geoip":
            payload = build_geoip_delete_payload(entry_id=_single_arg(args, "id") or "")
        elif op_id == "fw_delete_batch_geoip":
            entry_ids = _arg_list(args, "id")
            payload = build_geoip_batch_delete_payload(entry_ids=entry_ids)
            payload = validate_geoip_payload(payload, op_id=op_id)
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_geoip_dry_run(
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
            result = execute_geoip(
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


def _geoip_payload(args: argparse.Namespace, builder: Any, *, update: bool = False) -> dict[str, Any]:
    """Build a geoip config/update payload from CLI args or a payload escape hatch."""
    from atomic_ops.runner._payload import load_json_payload

    raw_payload = load_json_payload(
        payload_file=getattr(args, "payload_file", None),
        payload_json=getattr(args, "payload_json", None),
    )
    if raw_payload is not None:
        return raw_payload
    _require_arg(args, "ip")
    _require_arg(args, "country")
    _require_arg(args, "province")
    _require_arg(args, "city")
    if update:
        _require_arg(args, "id")
    kwargs: dict[str, Any] = {
        "ip": getattr(args, "ip"),
        "country": getattr(args, "country") or "",
        "province": getattr(args, "province", "") or "",
        "city": getattr(args, "city", "") or "",
        "accuracy": int(getattr(args, "accuracy", 2)),
        "desc": getattr(args, "desc", "") or "",
    }
    if update:
        kwargs["entry_id"] = _single_arg(args, "id") or ""
    return builder(**kwargs)
