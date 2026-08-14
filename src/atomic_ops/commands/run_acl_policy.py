"""Control-policy (acl_policy) runner commands (config/update/delete/delete-batch/verify).

控制策略覆盖 IPv4 与 IPv6，由叶子命令的 --policy-type 选择请求路径前缀。
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
        CommandSpec(name="config", help="Create a control policy.", description="Create an NGFW IPv4 or IPv6 control policy.", handler=_run_config, add_args=_add_common_args),
        CommandSpec(name="update", help="Update a control policy.", description="Update an NGFW control policy by id.", handler=_run_update, add_args=_add_update_args),
        CommandSpec(name="delete", help="Delete a control policy.", description="Delete a control policy by id.", handler=_run_delete, add_args=_add_delete_args),
        CommandSpec(name="delete-batch", help="Delete multiple control policies.", description="Batch-delete control policies by id.", handler=_run_delete_batch, add_args=_add_delete_args),
        CommandSpec(name="verify", help="Verify control policies.", description="Query NGFW control policies.", handler=_run_verify, add_args=_add_verify_args),
    )


def _add_policy_type(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--policy-type",
        choices=("ipv4", "ipv6"),
        default="ipv4",
        help="Control-policy address family; selects the ip4policy or ip6policy request path.",
    )


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    _add_policy_type(parser)
    parser.add_argument("--name", required=True, help="Control-policy name.")
    enable_group = parser.add_mutually_exclusive_group()
    enable_group.add_argument("--enable", dest="acl_policy_enable", action="store_true", default=True, help="Enable the control policy (default).")
    enable_group.add_argument("--disable", dest="acl_policy_enable", action="store_false", help="Disable the control policy.")
    parser.add_argument("--action", type=int, default=1, help="Control-policy action value (1=permit, 0=deny).")
    parser.add_argument("--log", action="store_true", help="Enable session logging for the control policy.")
    parser.add_argument("--szone", default="any", help="Source security zone name.")
    parser.add_argument("--dzone", default="any", help="Destination security zone name.")
    parser.add_argument("--policy-group", default="全部", help="Control-policy group name (default 全部).")
    parser.add_argument("--desc", default="", help="Control-policy description.")
    parser.add_argument("--src-addr", default="any", help="Source address object or address-group name.")
    parser.add_argument("--src-addr-is-group", action="store_true", help="Treat --src-addr as an address-group name.")
    parser.add_argument("--dst-addr", default="any", help="Destination address object or address-group name.")
    parser.add_argument("--dst-addr-is-group", action="store_true", help="Treat --dst-addr as an address-group name.")
    parser.add_argument("--service", default="any", help="Service object or service-group name.")
    parser.add_argument("--service-is-group", action="store_true", help="Treat --service as a service-group name.")


def _add_update_args(parser: argparse.ArgumentParser) -> None:
    _add_common_args(parser)
    parser.add_argument("--id", required=True, help="Control-policy id to update (resolve via verify by policy_name).")


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    _add_policy_type(parser)
    parser.add_argument("--id", required=True, action="append", help="Control-policy id to delete. May be repeated for batch operations.")


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    _add_policy_type(parser)
    parser.add_argument("--page", type=int, default=1, help="Paginated query page (filter mode).")
    parser.add_argument("--size", type=int, default=10, help="Paginated query page size (filter mode).")
    parser.add_argument("--policy-id", type=int, default=None, help="Single-policy lookup id; 0 returns the default policy. Switches to the ?id mode when set.")
    parser.add_argument("--content", default="", help="Free-text content filter (filter mode).")
    parser.add_argument("--policy-name", default="", help="Policy-name filter (filter mode); resolves the id for update.")
    parser.add_argument("--source", default="", help="Source-address filter (filter mode).")
    parser.add_argument("--destination", default="", help="Destination-address filter (filter mode).")
    parser.add_argument("--service", default="", help="Service filter (filter mode).")
    parser.add_argument("--policy-group", default="全部", help="Policy-group filter (filter mode, default 全部).")


def _run_config(args: argparse.Namespace) -> int:
    return _run_acl_policy(args, "fw_config_acl_policy")


def _run_update(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_acl_policy(args, "fw_update_acl_policy")


def _run_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_acl_policy(args, "fw_delete_acl_policy")


def _run_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_acl_policy(args, "fw_delete_batch_acl_policy")


def _run_verify(args: argparse.Namespace) -> int:
    return _run_acl_policy(args, "fw_verify_acl_policy")


def _run_acl_policy(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.acl_policy import (
        build_acl_policy_batch_delete_payload,
        build_acl_policy_delete_payload,
        build_acl_policy_dry_run,
        build_acl_policy_payload,
        execute_acl_policy,
        validate_acl_policy_payload,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        policy_type = getattr(args, "policy_type", "ipv4")
        page = int(getattr(args, "page", 1))
        size = int(getattr(args, "size", 10))
        policy_id = getattr(args, "policy_id", None)
        payload: dict[str, Any] | None

        if op_id in {"fw_config_acl_policy", "fw_update_acl_policy"}:
            entry_id = _single_arg(args, "id") if op_id == "fw_update_acl_policy" else None
            payload = build_acl_policy_payload(
                policy_type=policy_type,
                name=getattr(args, "name"),
                enable=bool(getattr(args, "acl_policy_enable", True)),
                action=int(getattr(args, "action", 1)),
                log=bool(getattr(args, "log", False)),
                szone=getattr(args, "szone", "any"),
                dzone=getattr(args, "dzone", "any"),
                policy_group=getattr(args, "policy_group", "全部"),
                desc=getattr(args, "desc", ""),
                src_addr=getattr(args, "src_addr", "any"),
                src_addr_is_group=bool(getattr(args, "src_addr_is_group", False)),
                dst_addr=getattr(args, "dst_addr", "any"),
                dst_addr_is_group=bool(getattr(args, "dst_addr_is_group", False)),
                service=getattr(args, "service", "any"),
                service_is_group=bool(getattr(args, "service_is_group", False)),
                entry_id=entry_id,
            )
        elif op_id == "fw_delete_acl_policy":
            payload = build_acl_policy_delete_payload(entry_id=_single_arg(args, "id"))
        elif op_id == "fw_delete_batch_acl_policy":
            payload = build_acl_policy_batch_delete_payload(
                entry_ids=_arg_list(args, "id"),
                policy_type=policy_type,
            )
            payload = validate_acl_policy_payload(payload, op_id=op_id)
        else:
            payload = None

        common_kwargs: dict[str, Any] = {
            "op_id": op_id,
            "base_url": ctx["base_url"],
            "session_file": session_file,
            "auth_header": ctx.get("auth_header", "Authorization"),
            "payload": payload,
            "policy_type": policy_type,
            "page": page,
            "size": size,
            "policy_id": policy_id,
            "content": getattr(args, "content", ""),
            "policy_name": getattr(args, "policy_name", ""),
            "source": getattr(args, "source", ""),
            "destination": getattr(args, "destination", ""),
            "service": getattr(args, "service", ""),
            "policy_group": getattr(args, "policy_group", "全部"),
            "verify_tls": bool(ctx.get("verify_tls")),
            "timeout": float(ctx.get("timeout", 10.0)),
        }

        if not ctx.get("execute"):
            result = build_acl_policy_dry_run(**common_kwargs)
        else:
            result = execute_acl_policy(**common_kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
