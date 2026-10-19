"""Static-route runner commands."""

from __future__ import annotations

import argparse
from typing import Any

from atomic_ops.commands import CommandSpec
from atomic_ops.commands.run import (
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
            help="Create a new static route.",
            description="Create a new static route with destination network and next-hop.",
            handler=_run_config,
            add_args=_add_config_args,
        ),
        CommandSpec(
            name="update",
            help="Update an existing static route.",
            description="Update a static route by id.",
            handler=_run_update,
            add_args=_add_update_args,
        ),
        CommandSpec(
            name="delete",
            help="Delete a static route.",
            description="Delete a static route by id.",
            handler=_run_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="verify",
            help="Query static routes.",
            description="Query the static route list from the device.",
            handler=_run_verify,
            add_args=_add_verify_args,
        ),
    )


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--dst-network", required=True, help="Destination network in CIDR notation (e.g. 1.1.1.0/24)."
    )
    parser.add_argument(
        "--next-hop-addr", required=True, help="Next-hop IP address."
    )
    parser.add_argument(
        "--preference", type=int, default=1, help="Route preference (default: 1)."
    )
    parser.add_argument(
        "--weight", type=int, default=0, help="Route weight (default: 0)."
    )
    parser.add_argument(
        "--outgoing-interface", default="", help="Outgoing interface (default: empty)."
    )
    parser.add_argument(
        "--route-type", choices=("ipv4", "ipv6"), default="ipv4", help="Static-route address family."
    )
    route_enable_group = parser.add_mutually_exclusive_group()
    route_enable_group.add_argument(
        "--enable", dest="enable", action="store_true", default=True, help="Enable the static route (default)."
    )
    route_enable_group.add_argument(
        "--disable", dest="enable", action="store_false", help="Disable the static route."
    )
    # 2026-10-19 houjialin：完整 payload 直传通道（与 iplink config 同型）。结构化参数
    # 无法表达内联 health_check（静态路由引用 IP-Link 的健康检查，17220/17233）——
    # 用例经 payload_json 下发 {"val": {..., "health_check": {...}}}。payload 模式下
    # payload 为完整请求体，结构化参数仅作 argparse 满足（不合并进 payload）。
    parser.add_argument(
        "--payload-json", help="Complete JSON request payload (e.g. inline health_check); overrides structured args."
    )
    parser.add_argument(
        "--payload-file", help="Path to a complete JSON request payload; overrides structured args."
    )


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    _add_common_args(parser)


def _add_update_args(parser: argparse.ArgumentParser) -> None:
    _add_common_args(parser)
    parser.add_argument("--id", required=True, type=int, help="Static-route entry id to update.")


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, type=int, help="Static-route entry id to delete.")
    # P2 delete 未就绪缺口：可选内部重试（默认 0 关闭，向后兼容）；仅对「根本没拿到
    # 响应」（46）重试，设备拒绝（48）不重试。
    parser.add_argument("--retry", type=int, default=0, help="Optional internal retries when the device is unreachable (exit 46: no response at all). Default 0 (no retry).")
    parser.add_argument("--retry-backoff", type=float, default=1.0, help="Seconds to wait between delete retries. Default 1.0.")


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--route-type", choices=("ipv4", "ipv6"), default="ipv4", help="Static-route address family.")
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")
    # P2 大批量 verify 缺口：--page-size 开启内部翻页聚合（默认不传行为不变）。
    parser.add_argument("--page-size", type=int, help="Aggregate mode: fetch ALL entries with internal pagination of this page size instead of one oversized query.")


def _run_config(args: argparse.Namespace) -> int:
    return _run_static_route(args, "fw_config_static_route")


def _run_update(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_static_route(args, "fw_update_static_route")


def _run_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_static_route(args, "fw_delete_static_route")


def _run_verify(args: argparse.Namespace) -> int:
    return _run_static_route(args, "fw_verify_static_route")


def _run_static_route(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.static_route import (
        build_static_route_dry_run,
        build_static_route_payload,
        execute_static_route,
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
        route_type = getattr(args, "route_type", "ipv4")
        payload: dict[str, Any] | None

        if op_id in {"fw_config_static_route", "fw_update_static_route"}:
            # 2026-10-19 houjialin：payload_json/payload_file 直传优先（完整请求体，
            # 含结构化参数表达不了的内联 health_check）；两者互斥，JSON 解析失败报
            # PARAM_INVALID。未提供时走结构化参数组装（原路径不变）。
            payload_json_text = getattr(args, "payload_json", None)
            payload_file = getattr(args, "payload_file", None)
            if payload_json_text and payload_file:
                return write_error(
                    CliError(
                        "PARAM_INVALID",
                        "payload_json and payload_file are mutually exclusive.",
                        {"op_id": op_id},
                    ),
                    output_format,
                )
            if payload_json_text or payload_file:
                import json as _json

                try:
                    if payload_file:
                        with open(payload_file, "r", encoding="utf-8") as fh:
                            payload = _json.load(fh)
                    else:
                        payload = _json.loads(payload_json_text)
                except (OSError, ValueError) as exc:
                    return write_error(
                        CliError(
                            "PARAM_INVALID",
                            f"Static-route payload is not valid JSON: {exc}",
                            {"op_id": op_id},
                        ),
                        output_format,
                    )
            else:
                entry_id = int(getattr(args, "id", 0) or 0)
                payload = build_static_route_payload(
                    dst_network=getattr(args, "dst_network"),
                    next_hop_addr=getattr(args, "next_hop_addr"),
                    enable=bool(getattr(args, "enable", True)),
                    preference=int(getattr(args, "preference", 1)),
                    weight=int(getattr(args, "weight", 0)),
                    outgoing_interface=getattr(args, "outgoing_interface", "") or "",
                    route_type=route_type,
                    entry_id=entry_id,
                )
        elif op_id == "fw_delete_static_route":
            payload = {"id": int(getattr(args, "id"))}
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_static_route_dry_run(
                op_id=op_id,
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                page=int(getattr(args, "page", 1)),
                size=int(getattr(args, "size", 40)),
                route_type=route_type,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_static_route(
                op_id=op_id,
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                page=int(getattr(args, "page", 1)),
                size=int(getattr(args, "size", 40)),
                route_type=route_type,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
                # P2 delete 未就绪缺口：删除类 op 可选内部重试（默认 0）
                retries=int(getattr(args, "retry", 0) or 0),
                retry_backoff_seconds=float(getattr(args, "retry_backoff", 1.0)),
                # P2 大批量 verify 缺口：--page-size 聚合模式（默认 None 行为不变）
                aggregate_page_size=getattr(args, "page_size", None),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
