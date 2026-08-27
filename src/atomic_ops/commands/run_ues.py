"""UES runner commands."""

from __future__ import annotations

import argparse
import json
from typing import Any

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import (
    _single_arg,
    _to_run_envelope,
    _write_output,
    resolve_run_context,
)
from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file


def build_subtree() -> tuple[CommandGroup, ...]:
    return (
        CommandGroup(
            name="ues",
            help="UES (unified experience system) operations.",
            description="UES access config, global config, promotion-policy CRUD, connection test, and priority operations.",
            children=(
                CommandSpec(name="access", help="Save the UES access config.", description="Save the UES access config by PUT /api/v1/uesaccess.", handler=_run_config_access, add_args=_add_access_args),
                CommandSpec(name="access-verify", help="Query the UES access config.", description="Query the UES access config by GET /api/v1/uesaccess.", handler=_run_verify_access),
                CommandSpec(name="connection", help="Test UES connectivity.", description="Test NGFW connectivity to the UES platform by POST /api/v1/uesaccess/state.", handler=_run_check_connection, add_args=_add_connection_args),
                CommandSpec(name="global", help="Save the UES global config.", description="Save the UES global config by PUT /api/v1/uesglobal.", handler=_run_config_global, add_args=_add_global_args),
                CommandSpec(name="global-verify", help="Query the UES global config.", description="Query the UES global config by GET /api/v1/uesglobal.", handler=_run_verify_global),
                CommandSpec(name="policy", help="Create a UES promotion policy.", description="Create a UES IP promotion policy by POST /api/v1/uesippolicy.", handler=_run_config_policy, add_args=_add_policy_args),
                CommandSpec(name="policy-update", help="Update a UES promotion policy.", description="Update a UES IP promotion policy by PUT /api/v1/uesippolicy.", handler=_run_update_policy, add_args=_add_update_policy_args),
                CommandSpec(name="policy-delete", help="Delete a UES promotion policy.", description="Delete a UES IP promotion policy by DELETE /api/v1/uesippolicy?id.", handler=_run_delete_policy, add_args=_add_delete_args),
                CommandSpec(name="policy-verify", help="Query UES promotion policies.", description="Query UES IP promotion policies by GET /api/v1/uesippolicy.", handler=_run_verify_policy, add_args=_add_verify_args),
                CommandSpec(name="order", help="Query UES policy priority order.", description="Query the UES promotion-policy priority order by GET /api/v1/uesippolicyorder.", handler=_run_verify_order, add_args=_add_order_args),
                CommandSpec(name="priority", help="Move a UES promotion policy priority.", description="Move a UES promotion-policy priority by POST /api/v1/uesippolicyorder.", handler=_run_priority, add_args=_add_priority_args),
            ),
        ),
    )


def _add_access_args(parser: argparse.ArgumentParser) -> None:
    ues_switch_group = parser.add_mutually_exclusive_group()
    ues_switch_group.add_argument("--ues-switch", dest="ues_switch", action="store_true", default=True, help="Enable UES access.")
    ues_switch_group.add_argument("--ues-off", dest="ues_switch", action="store_false", help="Disable UES access.")
    _add_connection_args(parser)


def _add_connection_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--ues-ip", required=True, help="UES platform IP address (e.g. <UES_IP>).")
    parser.add_argument("--ues-port", required=True, help="UES platform port (e.g. 53443).")
    parser.add_argument("--ues-security-key", default="", help="UES security key (optional; may be empty).")
    parser.add_argument("--ues-thirdparty-code", default="tgfw", help="UES third-party code (e.g. tgfw).")


def _add_global_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--http-dst-port",
        default="[80]",
        help='HTTP destination port list, e.g. \'[80, 8080]\'.',
    )
    parser.add_argument(
        "--https-dst-port",
        default="[443]",
        help='HTTPS destination port list, e.g. \'[443]\'.',
    )
    parser.add_argument(
        "--open-service",
        default='["DNS", "DHCP"]',
        help='UES open service name list, e.g. \'["DNS", "DHCP"]\'.',
    )
    parser.add_argument("--blocktime", type=int, default=300, help="Blacklist block time in seconds.")
    ues_blackadd_group = parser.add_mutually_exclusive_group()
    ues_blackadd_group.add_argument("--blackadd", dest="ues_blackadd", action="store_true", default=True, help="Enable blacklist auto-add.")
    ues_blackadd_group.add_argument("--no-blackadd", dest="ues_blackadd", action="store_false", help="Disable blacklist auto-add.")
    ues_hashadd_group = parser.add_mutually_exclusive_group()
    ues_hashadd_group.add_argument("--hashadd", dest="ues_hashadd", action="store_true", default=True, help="Enable hashed add.")
    ues_hashadd_group.add_argument("--no-hashadd", dest="ues_hashadd", action="store_false", help="Disable hashed add.")
    parser.add_argument("--ues-url", required=True, help="UES page URL echoed from GET /api/v1/uesglobal (PUT replaces the whole config).")
    ues_notipstate_group = parser.add_mutually_exclusive_group()
    ues_notipstate_group.add_argument("--notipstate", dest="ues_notipstate", action="store_true", default=True, help="Enable no-tip state.")
    ues_notipstate_group.add_argument("--no-notipstate", dest="ues_notipstate", action="store_false", help="Disable no-tip state.")


def _add_policy_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", required=True, help="UES promotion-policy name.")
    ues_enable_group = parser.add_mutually_exclusive_group()
    ues_enable_group.add_argument("--enable", dest="ues_enable", action="store_true", default=True, help="Enable the policy.")
    ues_enable_group.add_argument("--disable", dest="ues_enable", action="store_false", help="Disable the policy.")
    parser.add_argument("--action", type=int, default=0, help="Policy action: 0=permit, 1=permit and log, 2=permit and push promotion.")
    ues_log_group = parser.add_mutually_exclusive_group()
    ues_log_group.add_argument("--log", dest="ues_log", action="store_true", default=False, help="Enable logging.")
    ues_log_group.add_argument("--no-log", dest="ues_log", action="store_false", help="Disable logging.")
    parser.add_argument("--cycletime", type=int, default=0, help="Promotion push interval (cycles).")
    parser.add_argument("--desc", default="", help="Policy description.")
    parser.add_argument("--src-ip", default="any", help="Source address object or address-group name (default: any; empty normalized to any).")
    parser.add_argument("--src-ip-is-group", action="store_true", help="Treat --src-ip as an address-group name.")
    parser.add_argument("--dst-ip", default="any", help="Destination address object or address-group name (default: any; empty normalized to any).")
    parser.add_argument("--dst-ip-is-group", action="store_true", help="Treat --dst-ip as an address-group name.")


def _add_update_policy_args(parser: argparse.ArgumentParser) -> None:
    _add_policy_args(parser)
    parser.add_argument("--id", required=True, help="UES promotion-policy id to update.")


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="UES promotion-policy id to delete.")


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")


def _add_order_args(parser: argparse.ArgumentParser) -> None:
    _add_verify_args(parser)
    parser.add_argument("--config-source", type=int, default=0, help="Configuration source selector (0 = local configuration).")


def _add_priority_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--targetsite", choices=("first", "before", "after", "last"), default="first", help="Priority target site (only first recorded; before/after/last need device confirmation).")
    parser.add_argument("--moveid", required=True, help="UES promotion-policy id to move.")
    parser.add_argument("--targetid", help="Optional anchor policy id used with before/after targetsite.")


def _parse_json_list(raw: str | None, *, flag: str) -> list[Any]:
    """将 --http-dst-port / --open-service 等 JSON 列表参数解析为对象。"""
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{flag} must be valid JSON.",
            {"reason": exc.msg},
        ) from exc
    if not isinstance(parsed, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{flag} must be a JSON list.",
            {"value": parsed},
        )
    return parsed


def _run_config_access(args: argparse.Namespace) -> int:
    return _run_ues(args, "fw_config_ues_access")


def _run_verify_access(args: argparse.Namespace) -> int:
    return _run_ues(args, "fw_verify_ues_access")


def _run_check_connection(args: argparse.Namespace) -> int:
    return _run_ues(args, "fw_check_ues_connection")


def _run_config_global(args: argparse.Namespace) -> int:
    return _run_ues(args, "fw_config_ues_global")


def _run_verify_global(args: argparse.Namespace) -> int:
    return _run_ues(args, "fw_verify_ues_global")


def _run_config_policy(args: argparse.Namespace) -> int:
    return _run_ues(args, "fw_config_ues_ip_policy")


def _run_update_policy(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_ues(args, "fw_update_ues_ip_policy")


def _run_delete_policy(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_ues(args, "fw_delete_ues_ip_policy")


def _run_verify_policy(args: argparse.Namespace) -> int:
    return _run_ues(args, "fw_verify_ues_ip_policy")


def _run_verify_order(args: argparse.Namespace) -> int:
    return _run_ues(args, "fw_verify_ues_ip_policy_order")


def _run_priority(args: argparse.Namespace) -> int:
    return _run_ues(args, "fw_update_ues_ip_policy_priority")


def _require_arg(args: argparse.Namespace, name: str) -> None:
    if not getattr(args, name, None):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"Missing required argument --{name.replace('_', '-')}.",
            {"field": name},
        )


def _run_ues(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.ues import (
        build_ues_access_payload,
        build_ues_connection_payload,
        build_ues_delete_payload,
        build_ues_dry_run,
        build_ues_global_payload,
        build_ues_ip_policy_payload,
        build_ues_priority_payload,
        execute_ues,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        page = int(getattr(args, "page", 1))
        size = int(getattr(args, "size", 40))
        config_source = int(getattr(args, "config_source", 0))
        payload: dict[str, Any] | None

        if op_id == "fw_config_ues_access":
            payload = build_ues_access_payload(
                uesswitch=bool(getattr(args, "ues_switch", True)),
                uesip=getattr(args, "ues_ip"),
                port=getattr(args, "ues_port"),
                securitykey=getattr(args, "ues_security_key", ""),
                thirdpartycode=getattr(args, "ues_thirdparty_code", "tgfw"),
            )
        elif op_id == "fw_check_ues_connection":
            payload = build_ues_connection_payload(
                uesip=getattr(args, "ues_ip"),
                port=getattr(args, "ues_port"),
                securitykey=getattr(args, "ues_security_key", ""),
                thirdpartycode=getattr(args, "ues_thirdparty_code", "tgfw"),
            )
        elif op_id == "fw_config_ues_global":
            payload = build_ues_global_payload(
                httpdstport=_parse_json_list(getattr(args, "http_dst_port", "[80]"), flag="--http-dst-port"),
                httpsdstport=_parse_json_list(getattr(args, "https_dst_port", "[443]"), flag="--https-dst-port"),
                blackadd=bool(getattr(args, "ues_blackadd", True)),
                blocktime=int(getattr(args, "blocktime", 300)),
                hashadd=bool(getattr(args, "ues_hashadd", True)),
                uesurl=getattr(args, "ues_url"),
                notipstate=bool(getattr(args, "ues_notipstate", True)),
                open_service=_parse_json_list(getattr(args, "open_service", '["DNS", "DHCP"]'), flag="--open-service"),
            )
        elif op_id in {"fw_config_ues_ip_policy", "fw_update_ues_ip_policy"}:
            payload = build_ues_ip_policy_payload(
                entry_id=_single_arg(args, "id") if op_id == "fw_update_ues_ip_policy" else 0,
                name=getattr(args, "name"),
                enable=bool(getattr(args, "ues_enable", True)),
                action=int(getattr(args, "action", 0)),
                log=bool(getattr(args, "ues_log", False)),
                cycletime=int(getattr(args, "cycletime", 0)),
                desc=getattr(args, "desc", ""),
                srcip=getattr(args, "src_ip", "any"),
                srcipisgroup=bool(getattr(args, "src_ip_is_group", False)),
                dstip=getattr(args, "dst_ip", "any"),
                dstipisgroup=bool(getattr(args, "dst_ip_is_group", False)),
            )
        elif op_id == "fw_delete_ues_ip_policy":
            payload = build_ues_delete_payload(entry_id=_single_arg(args, "id"))
        elif op_id == "fw_update_ues_ip_policy_priority":
            payload = build_ues_priority_payload(
                targetsite=getattr(args, "targetsite", "first"),
                moveid=getattr(args, "moveid"),
                targetid=getattr(args, "targetid", None),
            )
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_ues_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=page, size=size, config_source=config_source,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_ues(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=page, size=size, config_source=config_source,
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
