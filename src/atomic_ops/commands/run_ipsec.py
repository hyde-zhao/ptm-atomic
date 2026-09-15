"""IPsec runner commands."""

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


def build_subtree() -> tuple[CommandGroup, ...]:
    children: tuple[CommandSpec, ...] = (
        CommandSpec(
            name="config-policy",
            help="Create or modify an IPsec policy.",
            description=(
                "Create or modify an NGFW IPsec policy. PUT /api/v1/ipsec is an upsert: "
                "--id is the policy name and decides which object the device writes."
            ),
            handler=_make_handler("fw_config_ipsec_policy"),
            add_args=_add_ipsec_policy_args,
        ),
        CommandSpec(
            name="delete-policy",
            help="Delete an IPsec policy by name.",
            description="Delete a single NGFW IPsec policy. The name is sent as the id query value.",
            handler=_make_handler("fw_delete_ipsec_policy"),
            add_args=_add_ipsec_delete_args,
        ),
        CommandSpec(
            name="verify-policy",
            help="Query IPsec policies.",
            description="Query NGFW IPsec policies. The request carries no body and no query parameters.",
            handler=_make_handler("fw_verify_ipsec_policy"),
            add_args=_add_no_args,
        ),
        CommandSpec(
            name="update-port",
            help="Update IPsec port and NAT-T settings.",
            description="Update NGFW IPsec port and NAT-T settings. The device fixes the envelope id at 0.",
            handler=_make_handler("fw_update_ipsec_port"),
            add_args=_add_ipsec_port_args,
        ),
        CommandSpec(
            name="verify-port",
            help="Query IPsec port and NAT-T settings.",
            description="Query NGFW IPsec port and NAT-T settings. The request carries no body and no query parameters.",
            handler=_make_handler("fw_verify_ipsec_port"),
            add_args=_add_no_args,
        ),
        CommandSpec(
            name="verify-ikesa",
            help="Query IKE SAs.",
            description="Query NGFW IKE security associations with pagination.",
            handler=_make_handler("fw_verify_ipsec_ikesa"),
            add_args=_add_paging_args,
        ),
        CommandSpec(
            name="verify-sa",
            help="Query IPsec child SAs.",
            description="Query NGFW IPsec child security associations with pagination.",
            handler=_make_handler("fw_verify_ipsec_sa"),
            add_args=_add_paging_args,
        ),
        CommandSpec(
            name="delete-batch",
            help="Delete multiple IPsec policies.",
            description="Batch-delete IPsec policies inside a single device through /api/v1/batch.",
            handler=_make_handler("fw_delete_batch_ipsec"),
            add_args=_add_ipsec_batch_args,
        ),
    )
    return (
        CommandGroup(
            name="ipsec",
            help="IPsec policy and tunnel operations.",
            description=(
                "IPsec policy upsert, delete, batch-delete, port/NAT-T update, and policy / port / "
                "IKE SA / IPsec SA query operations."
            ),
            children=children,
        ),
    )


def _make_handler(op_id: str):
    def handler(args: argparse.Namespace) -> int:
        return _run_ipsec(args, op_id)

    return handler


def _add_no_args(parser: argparse.ArgumentParser) -> None:
    """策略与端口的查询在抓包里既无 body 也无查询参数 —— 故意不注册任何参数。"""
    return None


def _add_paging_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Page number (default 1).")
    parser.add_argument("--size", type=int, default=10, help="Page size (default 10).")


def _add_val_source_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--val-file", help="Path to a JSON file holding only the val object.")
    parser.add_argument("--val-json", help="JSON string holding only the val object.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload (overrides val sources).")
    parser.add_argument("--payload-json", help="Complete JSON request payload (overrides val sources).")


def _add_ipsec_policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        help="Policy name. Also the upsert key. Required unless --payload-json/--payload-file is given.",
    )
    _add_val_source_args(parser)


def _add_ipsec_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="Policy name. Sent as the id query value.")


def _add_ipsec_port_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--local-port", type=int, help="Local port, e.g. 500.")
    parser.add_argument("--remote-port", type=int, help="Remote port, e.g. 500.")
    parser.add_argument("--ip-protocol", help="Protocol record this update rewrites: ipv4 or ipv6.")
    parser.add_argument("--nat-t", choices=("enable", "disable"), help="NAT traversal state.")
    _add_val_source_args(parser)


def _add_ipsec_batch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", default=[], help="Policy name. May be repeated.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _build_port_val(args: argparse.Namespace) -> dict[str, Any] | None:
    """从扁平 flag 组装 val；四个 flag 全缺时返回 None 交给 val 逃生口。"""
    val: dict[str, Any] = {}
    if getattr(args, "local_port", None) is not None:
        val["local_port"] = int(args.local_port)
    if getattr(args, "remote_port", None) is not None:
        val["remote_port"] = int(args.remote_port)
    if getattr(args, "ip_protocol", None) is not None:
        val["ip_protocol"] = str(args.ip_protocol)
    if getattr(args, "nat_t", None) is not None:
        val["nat_t"] = str(args.nat_t)
    return val or None


def _run_ipsec(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.ipsec import (
        BATCH_OPS,
        DELETE_OPS,
        GET_OPS,
        PAGED_GET_OPS,
        PORT_UPDATE_OPS,
        UPSERT_OPS,
        build_ipsec_batch_delete_payload,
        build_ipsec_dry_run,
        build_ipsec_policy_payload,
        build_ipsec_port_payload,
        execute_ipsec,
        validate_ipsec_payload,
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
        payload: dict[str, Any] | None = None
        entry_id: str | None = None

        if op_id in UPSERT_OPS:
            if raw_payload is not None:
                # 直传 payload 优先。信封要求 {"id":...,"val":{...}}：payload 自带 id 时不再
                # 要求 --id（回滚重放走此路径，op_mapper 只给 payload_json）。
                if isinstance(raw_payload, dict) and raw_payload.get("id") in (None, ""):
                    _require_arg(args, "id")
                    raw_payload = dict(raw_payload)
                    raw_payload["id"] = _single_arg(args, "id")
                payload = build_ipsec_policy_payload(op_id=op_id, envelope=raw_payload)
            else:
                _require_arg(args, "id")
                payload = build_ipsec_policy_payload(
                    op_id=op_id,
                    envelope={
                        "id": _single_arg(args, "id"),
                        "val": load_json_payload(
                            payload_file=getattr(args, "val_file", None),
                            payload_json=getattr(args, "val_json", None),
                        ),
                    },
                )
        elif op_id in PORT_UPDATE_OPS:
            if raw_payload is not None:
                payload = raw_payload
            else:
                val = load_json_payload(
                    payload_file=getattr(args, "val_file", None),
                    payload_json=getattr(args, "val_json", None),
                )
                if val is None:
                    val = _build_port_val(args)
                payload = build_ipsec_port_payload(val=val)
            payload = validate_ipsec_payload(payload, op_id=op_id)
        elif op_id in DELETE_OPS:
            # id 走查询串，不下发 body。
            entry_id = _single_arg(args, "id")
        elif op_id in BATCH_OPS:
            policy_names = [str(name) for name in _arg_list(args, "id")]
            payload = raw_payload or build_ipsec_batch_delete_payload(policy_names=policy_names)
            payload = validate_ipsec_payload(payload, op_id=op_id)
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
            "page": int(getattr(args, "page")) if op_id in PAGED_GET_OPS else None,
            "size": int(getattr(args, "size")) if op_id in PAGED_GET_OPS else None,
            "entry_id": entry_id,
        }
        if not ctx.get("execute"):
            result = build_ipsec_dry_run(**runner_kwargs)
        else:
            result = execute_ipsec(**runner_kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
