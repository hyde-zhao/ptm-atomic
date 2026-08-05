"""Policy-route runner commands."""

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
        CommandSpec(name="config", help="Create a new policy route.", description="Create a new policy route.", handler=_run_config, add_args=_add_common_args),
        CommandSpec(name="config-batch", help="Create multiple policy routes in a loop.", description="Loop-create multiple policy routes by repeated POST /api/v1/policyroute.", handler=_run_config_batch, add_args=_add_config_batch_args),
        CommandSpec(name="update", help="Update an existing policy route.", description="Update an existing policy route by id.", handler=_run_update, add_args=_add_update_args),
        CommandSpec(name="delete", help="Delete a policy route.", description="Delete a policy route by id.", handler=_run_delete, add_args=_add_delete_args),
        CommandSpec(name="delete-batch", help="Delete multiple policy routes.", description="Batch-delete NGFW policy routes by id.", handler=_run_delete_batch, add_args=_add_delete_args),
        CommandSpec(name="verify", help="Verify a policy route.", description="Verify a policy route.", handler=_run_verify, add_args=_add_verify_args),
        CommandSpec(name="reset-hitcount", help="Reset a policy-route hit count.", description="Reset a policy-route hit count to zero by id.", handler=_run_reset_hitcount, add_args=_add_delete_args),
        CommandSpec(name="verify-hitcount", help="Verify a policy-route hit count.", description="Query a policy-route hit count.", handler=_run_verify_hitcount, add_args=_add_verify_args),
        CommandSpec(name="priority", help="Update policy route priority.", description="Update policy route priority ordering.", handler=_run_priority, add_args=_add_priority_args),
    )


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--source-network", required=False, default="any", help="Policy-route source address object or address-group name (default: any; empty normalized to any)."
    )
    parser.add_argument("--source-network-is-group", action="store_true", help="Treat --source-network as an address-group name.")
    parser.add_argument("--dst-network", default="any", help="Policy-route destination address object or address-group name (default: any; empty normalized to any).")
    parser.add_argument("--dst-network-is-group", action="store_true", help="Treat --dst-network as an address-group name.")
    parser.add_argument("--next-hop-ip", help="Policy-route forwarding next-hop IP address.")
    parser.add_argument("--in-interface", required=False, default="any", help="Policy-route incoming interface (default: any; empty normalized to any).")
    parser.add_argument("--outgoing-interface", default="", help="Policy-route outgoing interface.")
    parser.add_argument("--service", default="any", help="Policy-route service object/name.")
    parser.add_argument("--service-is-group", action="store_true", help="Treat --service as a service-group name.")
    parser.add_argument("--weight", type=int, default=100, help="Policy-route forwarding path weight.")
    parser.add_argument("--time-obj", default="", help="Policy-route time object.")
    parser.add_argument("--policy-route-type", choices=("ipv4", "ipv6"), default="ipv4", help="Policy-route address family.")
    policy_route_active_group = parser.add_mutually_exclusive_group()
    policy_route_active_group.add_argument("--policy-route-active", dest="policy_route_active", action="store_true", default=True, help="Enable the policy route.")
    policy_route_active_group.add_argument("--policy-route-inactive", dest="policy_route_active", action="store_false", help="Disable the policy route.")
    parser.add_argument("--policy-route-action", type=int, default=1, help="Policy-route action value.")
    parser.add_argument("--config-source", type=int, default=0, help="Policy-route config_source value.")
    parser.add_argument(
        "--app-list",
        help='JSON list of matched applications, e.g. \'[{"appname":"UDP应用","appid":"479"}]\'. Omit to match no application.',
    )
    parser.add_argument(
        "--app-tag-name",
        help='JSON list of matched application tag names, e.g. \'["限速应用"]\'. Omit to match no application tag.',
    )
    parser.add_argument(
        "--ip-link-name",
        help="IP-link object name to associate with the forwarding path health check (health_check={type:iplink,name}). Omit to keep health_check empty.",
    )


def _add_update_args(parser: argparse.ArgumentParser) -> None:
    _add_common_args(parser)
    parser.add_argument("--id", required=True, help="Policy-route entry id to update.")


def _add_config_batch_args(parser: argparse.ArgumentParser) -> None:
    _add_common_args(parser)
    parser.add_argument(
        "--count",
        type=int,
        required=True,
        help="Number of policy routes to create in a loop.",
    )
    parser.add_argument(
        "--increment",
        action="store_true",
        help="Increment string parameters per entry (IPv4 host +carry, trailing digits, or 0001-padded name); default keeps all parameters unchanged.",
    )


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, action="append", help="Entry id to delete.")
    parser.add_argument("--policy-route-type", choices=("ipv4", "ipv6"), default="ipv4", help="Policy-route address family.")


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--policy-route-type", choices=("ipv4", "ipv6"), default="ipv4", help="Policy-route address family.")
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")


def _add_priority_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--targetsite", choices=("before", "after", "first", "last"), required=True, help="Policy-route priority target site.")
    parser.add_argument("--targetid", required=True, help="Policy-route priority target id.")
    parser.add_argument("--moveid", required=True, help="Policy-route priority moving route id.")
    parser.add_argument("--policy-route-type", choices=("ipv4", "ipv6"), default="ipv4", help="Policy-route address family.")


def _parse_json_arg(raw: str | None, *, flag: str) -> Any | None:
    """将 --app-list / --app-tag-name 的 JSON 字符串参数解析为对象。

    省略时返回 None（runner 保持默认空数组）；非法 JSON 直接报 RUNNER_VALIDATION_FAILED，
    与 service-pool 的 --ranges 解析惯例保持一致。
    """
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{flag} must be valid JSON.",
            {"reason": exc.msg},
        ) from exc


def _run_config(args: argparse.Namespace) -> int:
    return _run_policy_route(args, "fw_config_policy_route")


def _run_config_batch(args: argparse.Namespace) -> int:
    from atomic_ops.runner.policy_route import (
        build_policy_route_batch_config_dry_run,
        build_policy_route_batch_config_payloads,
        execute_policy_route_batch_config,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        route_type = getattr(args, "policy_route_type", "ipv4")
        count = int(getattr(args, "count", 1))
        increment = bool(getattr(args, "increment", False))
        base_params: dict[str, Any] = {
            "source_network": getattr(args, "source_network"),
            "source_network_is_group": bool(getattr(args, "source_network_is_group")),
            "dst_network": getattr(args, "dst_network", "any"),
            "dst_network_is_group": bool(getattr(args, "dst_network_is_group")),
            "next_hop_ip": getattr(args, "next_hop_ip") or "",
            "in_interface": getattr(args, "in_interface"),
            "outgoing_interface": getattr(args, "outgoing_interface") or "",
            "service": getattr(args, "service", "any"),
            "service_is_group": bool(getattr(args, "service_is_group")),
            "weight": int(getattr(args, "weight", 100)),
            "time_obj": getattr(args, "time_obj", ""),
            "route_type": route_type,
            "active": bool(getattr(args, "policy_route_active", True)),
            "action": int(getattr(args, "policy_route_action", 1)),
            "config_source": int(getattr(args, "config_source", 0)),
            "applist": _parse_json_arg(getattr(args, "app_list", None), flag="--app-list"),
            "app_tag_name": _parse_json_arg(getattr(args, "app_tag_name", None), flag="--app-tag-name"),
            "ip_link_name": getattr(args, "ip_link_name", None) or None,
        }
        payloads = build_policy_route_batch_config_payloads(count=count, increment=increment, **base_params)

        if not ctx.get("execute"):
            result = build_policy_route_batch_config_dry_run(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payloads=payloads,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_policy_route_batch_config(
                op_id="fw_config_policy_route", base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payloads=payloads,
                page=int(getattr(args, "page", 1)), size=int(getattr(args, "size", 40)),
                route_type=route_type, verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _run_update(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_policy_route(args, "fw_update_policy_route")


def _run_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_policy_route(args, "fw_delete_policy_route")


def _run_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_policy_route(args, "fw_delete_batch_policy_route")


def _run_verify(args: argparse.Namespace) -> int:
    return _run_policy_route(args, "fw_verify_policy_route")


def _run_reset_hitcount(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_policy_route(args, "fw_reset_policy_route_hitcount")


def _run_verify_hitcount(args: argparse.Namespace) -> int:
    return _run_policy_route(args, "fw_verify_policy_route_hitcount")


def _run_priority(args: argparse.Namespace) -> int:
    return _run_policy_route(args, "fw_update_policy_route_priority")


def _run_policy_route(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.policy_route import (
        build_policy_route_batch_delete_payload,
        build_policy_route_delete_payload,
        build_policy_route_dry_run,
        build_policy_route_payload,
        build_policy_route_priority_payload,
        execute_policy_route,
        validate_policy_route_payload,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        route_type = getattr(args, "policy_route_type", "ipv4")
        payload: dict[str, Any] | None

        if op_id in {"fw_config_policy_route", "fw_update_policy_route"}:
            payload = build_policy_route_payload(
                source_network=getattr(args, "source_network"),
                source_network_is_group=bool(getattr(args, "source_network_is_group")),
                dst_network=getattr(args, "dst_network", "any"),
                dst_network_is_group=bool(getattr(args, "dst_network_is_group")),
                next_hop_ip=getattr(args, "next_hop_ip") or "",
                in_interface=getattr(args, "in_interface"),
                outgoing_interface=getattr(args, "outgoing_interface") or "",
                service=getattr(args, "service", "any"),
                service_is_group=bool(getattr(args, "service_is_group")),
                weight=int(getattr(args, "weight", 100)),
                time_obj=getattr(args, "time_obj", ""),
                route_type=route_type,
                entry_id=_single_arg(args, "id") if op_id == "fw_update_policy_route" else 0,
                active=bool(getattr(args, "policy_route_active", True)),
                action=int(getattr(args, "policy_route_action", 1)),
                config_source=int(getattr(args, "config_source", 0)),
                applist=_parse_json_arg(getattr(args, "app_list", None), flag="--app-list"),
                app_tag_name=_parse_json_arg(getattr(args, "app_tag_name", None), flag="--app-tag-name"),
                ip_link_name=getattr(args, "ip_link_name", None) or None,
            )
        elif op_id == "fw_delete_policy_route":
            payload = build_policy_route_delete_payload(entry_id=_single_arg(args, "id"))
        elif op_id == "fw_delete_batch_policy_route":
            payload = build_policy_route_batch_delete_payload(
                entry_ids=_arg_list(args, "id"),
                route_type=route_type,
            )
            payload = validate_policy_route_payload(payload, op_id=op_id)
        elif op_id == "fw_reset_policy_route_hitcount":
            payload = build_policy_route_delete_payload(entry_id=_single_arg(args, "id"))
        elif op_id == "fw_update_policy_route_priority":
            payload = build_policy_route_priority_payload(
                targetsite=getattr(args, "targetsite"),
                targetid=getattr(args, "targetid"),
                moveid=getattr(args, "moveid"),
                route_type=route_type,
            )
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_policy_route_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=int(getattr(args, "page", 1)), size=int(getattr(args, "size", 40)),
                route_type=route_type, verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_policy_route(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=int(getattr(args, "page", 1)), size=int(getattr(args, "size", 40)),
                route_type=route_type, verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
