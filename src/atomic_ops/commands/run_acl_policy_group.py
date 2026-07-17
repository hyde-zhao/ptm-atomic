"""Control-policy group (acl_policy_group) runner commands (config/update/delete/verify).

策略组覆盖 IPv4 与 IPv6，由叶子命令的 --policy-type 选择请求路径前缀。
update 是重命名语义，delete 按 name 查询。
"""

from __future__ import annotations

import argparse
from typing import Any

from atomic_ops.commands import CommandSpec
from atomic_ops.commands.run import (
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
        CommandSpec(name="config", help="Create a control-policy group.", description="Create an NGFW control-policy group.", handler=_run_config, add_args=_add_config_args),
        CommandSpec(name="update", help="Rename a control-policy group.", description="Rename an NGFW control-policy group.", handler=_run_update, add_args=_add_update_args),
        CommandSpec(name="delete", help="Delete a control-policy group.", description="Delete a control-policy group by name.", handler=_run_delete, add_args=_add_delete_args),
        CommandSpec(name="verify", help="Verify control-policy groups.", description="Query NGFW control-policy groups.", handler=_run_verify, add_args=_add_verify_args),
    )


def _add_policy_type(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--policy-type",
        choices=("ipv4", "ipv6"),
        default="ipv4",
        help="Control-policy-group address family; selects the ip4policy or ip6policy request path.",
    )


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    _add_policy_type(parser)
    parser.add_argument("--name", required=True, help="Control-policy group name.")


def _add_update_args(parser: argparse.ArgumentParser) -> None:
    _add_policy_type(parser)
    parser.add_argument("--old-name", required=True, help="Existing control-policy group name to rename from.")
    parser.add_argument("--new-name", required=True, help="New control-policy group name to rename to.")


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    _add_policy_type(parser)
    parser.add_argument("--name", required=True, help="Control-policy group name to delete.")


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    _add_policy_type(parser)


def _run_config(args: argparse.Namespace) -> int:
    return _run_acl_policy_group(args, "fw_config_acl_policy_group")


def _run_update(args: argparse.Namespace) -> int:
    _require_arg(args, "old_name")
    _require_arg(args, "new_name")
    return _run_acl_policy_group(args, "fw_update_acl_policy_group")


def _run_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "name")
    return _run_acl_policy_group(args, "fw_delete_acl_policy_group")


def _run_verify(args: argparse.Namespace) -> int:
    return _run_acl_policy_group(args, "fw_verify_acl_policy_group")


def _run_acl_policy_group(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.acl_policy_group import (
        build_acl_policy_group_delete_payload,
        build_acl_policy_group_dry_run,
        build_acl_policy_group_payload,
        build_acl_policy_group_update_payload,
        execute_acl_policy_group,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        policy_type = getattr(args, "policy_type", "ipv4")
        payload: dict[str, Any] | None

        if op_id == "fw_config_acl_policy_group":
            payload = build_acl_policy_group_payload(name=getattr(args, "name"))
        elif op_id == "fw_update_acl_policy_group":
            payload = build_acl_policy_group_update_payload(
                old_name=getattr(args, "old_name"),
                new_name=getattr(args, "new_name"),
            )
        elif op_id == "fw_delete_acl_policy_group":
            payload = build_acl_policy_group_delete_payload(name=getattr(args, "name"))
        else:
            payload = None

        common_kwargs: dict[str, Any] = {
            "op_id": op_id,
            "base_url": ctx["base_url"],
            "session_file": session_file,
            "auth_header": ctx.get("auth_header", "Authorization"),
            "payload": payload,
            "policy_type": policy_type,
            "verify_tls": bool(ctx.get("verify_tls")),
            "timeout": float(ctx.get("timeout", 10.0)),
        }

        if not ctx.get("execute"):
            result = build_acl_policy_group_dry_run(**common_kwargs)
        else:
            result = execute_acl_policy_group(**common_kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
