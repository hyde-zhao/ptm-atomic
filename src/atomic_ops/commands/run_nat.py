"""NAT runner commands."""

from __future__ import annotations

import argparse
from typing import Any

from atomic_ops.commands import CommandGroup, CommandSpec
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


# 转换族与动作的笛卡尔积；族不同即端点不同，因此每族是独立的原子操作。
_NAT_FAMILIES: tuple[str, ...] = ("snat", "dnat", "static")


def build_subtree() -> tuple[CommandGroup, ...]:
    children: list[CommandSpec] = []
    for family in _NAT_FAMILIES:
        suffix = family.upper()
        children.append(
            CommandSpec(
                name=f"config-{family}",
                help=f"Create a {suffix} rule.",
                description=f"Create a new NGFW {suffix} rule.",
                handler=_make_handler(f"fw_config_nat_{family}"),
                add_args=_add_nat_rule_args,
            )
        )
        children.append(
            CommandSpec(
                name=f"update-{family}",
                help=f"Update a {suffix} rule.",
                description=f"Update an existing NGFW {suffix} rule by id.",
                handler=_make_handler(f"fw_update_nat_{family}"),
                add_args=_add_nat_update_args,
            )
        )
        children.append(
            CommandSpec(
                name=f"delete-{family}",
                help=f"Delete a {suffix} rule.",
                description=f"Delete a single NGFW {suffix} rule by id.",
                handler=_make_handler(f"fw_delete_nat_{family}"),
                add_args=_add_nat_delete_args,
            )
        )
        children.append(
            CommandSpec(
                name=f"verify-{family}",
                help=f"Query {suffix} rules.",
                description=f"Query NGFW {suffix} rules with pagination.",
                handler=_make_handler(f"fw_verify_nat_{family}"),
                add_args=_add_nat_verify_args,
            )
        )
    children.append(
        CommandSpec(
            name="update-hitcount",
            help="Clear NAT rule hit counters.",
            description="Clear the hit counters of source, destination, or static NAT rules.",
            handler=_make_handler("fw_update_nat_hitcount"),
            add_args=_add_nat_hitcount_args,
        )
    )
    children.append(
        CommandSpec(
            name="delete-batch",
            help="Delete multiple NAT rules.",
            description="Batch-delete NAT rules of one family inside a single device.",
            handler=_make_handler("fw_delete_batch_nat"),
            add_args=_add_nat_batch_args,
        )
    )
    return (
        CommandGroup(
            name="nat",
            help="NAT rule operations.",
            description="Source, destination, and static NAT rule create, update, delete, batch-delete, and verify operations.",
            children=tuple(children),
        ),
    )


def _make_handler(op_id: str):
    def handler(args: argparse.Namespace) -> int:
        return _run_nat(args, op_id)

    return handler


def _add_nat_type_arg(parser: argparse.ArgumentParser) -> None:
    # 协议是参数而非 op：当前设备只暴露 nat44，新增 nat66/nat46/nat64 时仅扩展 runner 白名单。
    parser.add_argument(
        "--nat-type",
        default="nat44",
        help="NAT protocol type. nat44 is the only value the captured device contract exposes.",
    )


def _add_val_source_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--val-file", help="Path to a JSON file holding only the val object.")
    parser.add_argument("--val-json", help="JSON string holding only the val object.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload (overrides val sources).")
    parser.add_argument("--payload-json", help="Complete JSON request payload (overrides val sources).")


def _add_nat_rule_args(parser: argparse.ArgumentParser) -> None:
    _add_nat_type_arg(parser)
    _add_val_source_args(parser)


def _add_nat_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        help="Rule id. Sent as an integer, matching the captured PUT body. "
        "Required unless --payload-json/--payload-file is given.",
    )
    _add_nat_type_arg(parser)
    _add_val_source_args(parser)


def _add_nat_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        required=True,
        help="Rule id. Sent as a string in the id query parameter (?id=<id>), with no JSON body.",
    )


def _add_nat_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Page number (default 1).")
    parser.add_argument("--size", type=int, default=10, help="Page size (default 10).")
    _add_nat_type_arg(parser)


def _add_nat_hitcount_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--nat-family", choices=_NAT_FAMILIES, required=True, help="NAT family whose counters are cleared.")
    _add_nat_type_arg(parser)
    parser.add_argument("--rule-id", action="append", default=[], help="Rule id to narrow the clear. May be repeated.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_nat_batch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--nat-family", choices=_NAT_FAMILIES, required=True, help="NAT family of the rules being deleted.")
    parser.add_argument("--id", action="append", default=[], help="Rule id. May be repeated.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _run_nat(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.nat import (
        BATCH_OPS,
        CONFIG_OPS,
        DELETE_OPS,
        GET_OPS,
        HITCOUNT_OP,
        UPDATE_OPS,
        build_nat_batch_delete_payload,
        build_nat_delete_payload,
        build_nat_dry_run,
        build_nat_hitcount_payload,
        build_nat_rule_payload,
        execute_nat,
        validate_nat_payload,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        raw_payload = load_json_payload(
            payload_file=getattr(args, "payload_file", None),
            payload_json=getattr(args, "payload_json", None),
        )
        nat_type = str(getattr(args, "nat_type", "nat44"))
        payload: dict[str, Any] | None = None

        if op_id in CONFIG_OPS or op_id in UPDATE_OPS:
            if raw_payload is not None:
                # 直传 payload 优先。设备 PUT 信封要求 {"id":...,"val":{...}}：payload 自带
                # id 时不再要求 --id（回滚重放走此路径，op_mapper 只给 payload_json）。
                if (
                    op_id in UPDATE_OPS
                    and isinstance(raw_payload, dict)
                    and "val" in raw_payload
                    and raw_payload.get("id") in (None, "")
                ):
                    _require_arg(args, "id")
                    raw_payload = dict(raw_payload)
                    raw_payload["id"] = _single_arg(args, "id")
                payload = raw_payload
            else:
                if op_id in UPDATE_OPS:
                    _require_arg(args, "id")
                payload = build_nat_rule_payload(
                    op_id=op_id,
                    val=load_json_payload(
                        payload_file=getattr(args, "val_file", None),
                        payload_json=getattr(args, "val_json", None),
                    ),
                    nat_type=nat_type,
                    entry_id=_single_arg(args, "id") if op_id in UPDATE_OPS else None,
                )
            payload = validate_nat_payload(payload, op_id=op_id)
        elif op_id in DELETE_OPS:
            payload = raw_payload or {"id": _single_arg(args, "id")}
            payload = validate_nat_payload(payload, op_id=op_id)
        elif op_id == HITCOUNT_OP:
            payload = raw_payload or build_nat_hitcount_payload(
                family=getattr(args, "nat_family"),
                nat_type=nat_type,
                rule_ids=list(getattr(args, "rule_id") or []),
            )
            payload = validate_nat_payload(payload, op_id=op_id)
        elif op_id in BATCH_OPS:
            payload = raw_payload or build_nat_batch_delete_payload(
                family=getattr(args, "nat_family"),
                entry_ids=_arg_list(args, "id"),
            )
            payload = validate_nat_payload(payload, op_id=op_id)
        elif op_id in GET_OPS:
            payload = None

        runner_kwargs: dict[str, Any] = {
            "op_id": op_id,
            "base_url": ctx["base_url"],
            "session_file": session_file,
            "auth_header": ctx.get("auth_header", "Authorization"),
            "payload": payload,
            "verify_tls": bool(ctx.get("verify_tls")),
            "timeout": float(ctx.get("timeout", 10.0)),
            "page": int(getattr(args, "page")) if op_id in GET_OPS else None,
            "size": int(getattr(args, "size")) if op_id in GET_OPS else None,
            "nat_type": nat_type,
        }
        if not ctx.get("execute"):
            result = build_nat_dry_run(**runner_kwargs)
        else:
            result = execute_nat(**runner_kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
