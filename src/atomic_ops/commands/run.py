"""Implementation for the ptm-atomic run command.

提供共享参数注册和操作族子命令树。各操作族的 runner 逻辑位于独立的
run_<family>.py 模块中。
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

import yaml

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.repository import Repository
from atomic_ops.rollback import run_rollback_context
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import DEFAULT_SESSION_FILE

# ── 受支持操作列表（维护旧格式兼容映射） ─────────────────

OSPFV2_OPS = (
    "fw_config_ospfv2_global",
    "fw_verify_ospfv2_global",
    "fw_config_ospfv2_redistribution",
    "fw_verify_ospfv2_redistribution",
    "fw_config_ospfv2_network",
    "fw_config_ospfv2_network_update",
    "fw_delete_ospfv2_network",
    "fw_verify_ospfv2_network",
    "fw_config_ospfv2_interface",
    "fw_config_ospfv2_interface_update",
    "fw_delete_ospfv2_interface",
    "fw_verify_ospfv2_interface",
    "fw_verify_ospfv2_neighbor",
    "fw_capture_ospfv2_log",
)
OSPFV3_BFD_OPS = (
    "fw_config_ospfv3_global",
    "fw_verify_ospfv3_global",
    "fw_config_ospfv3_redistribution",
    "fw_verify_ospfv3_redistribution",
    "fw_config_ospfv3_network",
    "fw_config_ospfv3_network_update",
    "fw_delete_ospfv3_network",
    "fw_verify_ospfv3_network",
    "fw_config_ospfv3_interface",
    "fw_config_ospfv3_interface_update",
    "fw_delete_ospfv3_interface",
    "fw_verify_ospfv3_interface",
    "fw_verify_ospfv3_neighbor",
    "fw_capture_ospfv3_log",
    "fw_config_bfd_global",
    "fw_verify_bfd_global",
    "fw_verify_bfd_session",
    "fw_capture_bfd_log",
)
POLICY_ROUTE_OPS = (
    "fw_config_policy_route",
    "fw_update_policy_route",
    "fw_delete_policy_route",
    "fw_verify_policy_route",
    "fw_update_policy_route_priority",
)
STATIC_ROUTE_OPS = (
    "fw_config_static_route",
    "fw_update_static_route",
    "fw_delete_static_route",
    "fw_verify_static_route",
)
INTERFACE_OPS = (
    "fw_config_interface",
    "fw_update_interface",
    "fw_verify_interface",
    "fw_delete_interface",
    "fw_delete_batch_interface",
)
SECURITY_ZONE_OPS = (
    "fw_config_security_zone",
    "fw_update_security_zone",
    "fw_delete_security_zone",
    "fw_verify_security_zone",
    "fw_verify_security_zone_vpp",
)
CUSTOMAPPOBJ_OPS = (
    "fw_config_customappobj",
    "fw_update_customappobj",
    "fw_delete_customappobj",
    "fw_delete_batch_customappobj",
    "fw_verify_customappobj",
)
CUSTOMAPPOBJTAG_OPS = (
    "fw_config_customappobjtag",
    "fw_update_customappobjtag",
    "fw_delete_customappobjtag",
    "fw_delete_batch_customappobjtag",
    "fw_verify_customappobjtag",
)
SERVICEPOOL_OPS = (
    "fw_config_servicepool",
    "fw_update_servicepool",
    "fw_delete_servicepool",
    "fw_delete_batch_servicepool",
    "fw_verify_servicepool",
    "fw_verify_servicepool_preset",
    "fw_config_servicepool_group",
    "fw_update_servicepool_group",
    "fw_delete_servicepool_group",
    "fw_delete_batch_servicepool_group",
    "fw_verify_servicepool_group",
)
IPPOOL_GROUP_OPS = (
    "fw_config_ippool_group",
    "fw_update_ippool_group",
    "fw_delete_ippool_group",
    "fw_delete_batch_ippool_group",
    "fw_verify_ippool_group",
)
IP6POOL_GROUP_OPS = (
    "fw_config_ip6pool_group",
    "fw_update_ip6pool_group",
    "fw_delete_ip6pool_group",
    "fw_delete_batch_ip6pool_group",
    "fw_verify_ip6pool_group",
)
TIMEOBJECT_OPS = (
    "fw_config_timeobject",
    "fw_update_timeobject",
    "fw_delete_timeobject",
    "fw_delete_batch_timeobject",
    "fw_verify_timeobject",
)
NEIGHBOR_OPS = (
    "fw_config_neighbor",
    "fw_update_neighbor",
    "fw_verify_neighbor",
    "fw_delete_neighbor",
    "fw_delete_batch_neighbor",
)
SUPPORTED_OPS = (
    "fw_login_web_management",
    "fw_logout_web_management",
    "fw_config_object",
    *POLICY_ROUTE_OPS,
    *STATIC_ROUTE_OPS,
    *INTERFACE_OPS,
    *OSPFV2_OPS,
    *OSPFV3_BFD_OPS,
    "fw_verify_system_version",
    "fw_check_bvi_interface_config",
    "fw_check_bridge_domain",
    *SECURITY_ZONE_OPS,
    *CUSTOMAPPOBJ_OPS,
    *CUSTOMAPPOBJTAG_OPS,
    *SERVICEPOOL_OPS,
    *IPPOOL_GROUP_OPS,
    *IP6POOL_GROUP_OPS,
    *TIMEOBJECT_OPS,
    *NEIGHBOR_OPS,
)

# ── 旧 op_id → 新子命令路径映射 ──────────────────────────

DEPRECATED_OP_MAP: dict[str, tuple[str, ...]] = {
    "fw_login_web_management": ("auth", "login"),
    "fw_logout_web_management": ("auth", "logout"),
    "fw_config_object": ("object", "config"),
    "fw_config_policy_route": ("policy-route", "config"),
    "fw_update_policy_route": ("policy-route", "update"),
    "fw_delete_policy_route": ("policy-route", "delete"),
    "fw_verify_policy_route": ("policy-route", "verify"),
    "fw_update_policy_route_priority": ("policy-route", "priority"),
    "fw_config_static_route": ("static-route", "config"),
    "fw_update_static_route": ("static-route", "update"),
    "fw_delete_static_route": ("static-route", "delete"),
    "fw_verify_static_route": ("static-route", "verify"),
    "fw_config_interface": ("interface", "create"),
    "fw_update_interface": ("interface", "update"),
    "fw_verify_interface": ("interface", "verify"),
    "fw_delete_interface": ("interface", "delete"),
    "fw_delete_batch_interface": ("interface", "delete-batch"),
    "fw_config_ospfv2_global": ("ospf", "config", "global"),
    "fw_verify_ospfv2_global": ("ospf", "verify", "global"),
    "fw_config_ospfv2_redistribution": ("ospf", "config", "redistribution"),
    "fw_verify_ospfv2_redistribution": ("ospf", "verify", "redistribution"),
    "fw_config_ospfv2_network": ("ospf", "config", "network"),
    "fw_config_ospfv2_network_update": ("ospf", "config", "network-update"),
    "fw_delete_ospfv2_network": ("ospf", "delete", "network"),
    "fw_verify_ospfv2_network": ("ospf", "verify", "network"),
    "fw_config_ospfv2_interface": ("ospf", "config", "interface"),
    "fw_config_ospfv2_interface_update": ("ospf", "config", "interface-update"),
    "fw_delete_ospfv2_interface": ("ospf", "delete", "interface"),
    "fw_verify_ospfv2_interface": ("ospf", "verify", "interface"),
    "fw_verify_ospfv2_neighbor": ("ospf", "verify", "neighbor"),
    "fw_capture_ospfv2_log": ("ospf", "verify", "neighbor"),
    "fw_config_ospfv3_global": ("ospfv3", "config", "global"),
    "fw_verify_ospfv3_global": ("ospfv3", "verify", "global"),
    "fw_config_ospfv3_redistribution": ("ospfv3", "config", "redistribution"),
    "fw_verify_ospfv3_redistribution": ("ospfv3", "verify", "redistribution"),
    "fw_config_ospfv3_network": ("ospfv3", "config", "network"),
    "fw_config_ospfv3_network_update": ("ospfv3", "config", "network-update"),
    "fw_delete_ospfv3_network": ("ospfv3", "delete", "network"),
    "fw_verify_ospfv3_network": ("ospfv3", "verify", "network"),
    "fw_config_ospfv3_interface": ("ospfv3", "config", "interface"),
    "fw_config_ospfv3_interface_update": ("ospfv3", "config", "interface-update"),
    "fw_delete_ospfv3_interface": ("ospfv3", "delete", "interface"),
    "fw_verify_ospfv3_interface": ("ospfv3", "verify", "interface"),
    "fw_verify_ospfv3_neighbor": ("ospfv3", "verify", "neighbor"),
    "fw_capture_ospfv3_log": ("ospfv3", "verify", "neighbor"),
    "fw_config_bfd_global": ("ospfv3", "bfd", "config"),
    "fw_verify_bfd_global": ("ospfv3", "bfd", "verify-global"),
    "fw_verify_bfd_session": ("ospfv3", "bfd", "verify-session"),
    "fw_capture_bfd_log": ("ospfv3", "bfd", "verify-session"),
    "fw_verify_system_version": ("cli", "verify-system-version"),
    "fw_check_bvi_interface_config": ("cli", "check-bvi-interface-config"),
    "fw_check_bridge_domain": ("cli", "check-bridge-domain"),
    # Deprecated legacy op_id aliases (merged into the unified transport op)
    "fw_verify_system_version_cli": ("cli", "verify-system-version"),
    "fw_verify_system_version_telnet": ("cli", "verify-system-version"),
    "fw_check_bvi_interface_config_telnet": ("cli", "check-bvi-interface-config"),
    "fw_check_bridge_domain_telnet": ("cli", "check-bridge-domain"),
    "fw_config_security_zone": ("security-zone", "config"),
    "fw_update_security_zone": ("security-zone", "update"),
    "fw_delete_security_zone": ("security-zone", "delete"),
    "fw_verify_security_zone": ("security-zone", "verify"),
    "fw_config_neighbor": ("neighbor", "create"),
    "fw_update_neighbor": ("neighbor", "update"),
    "fw_verify_neighbor": ("neighbor", "verify"),
    "fw_delete_neighbor": ("neighbor", "delete"),
    "fw_delete_batch_neighbor": ("neighbor", "delete-batch"),
}

# 共享参数名列表（子命令通过 getattr 从父解析器结果中读取）
SHARED_ARG_NAMES = (
    "base_url",
    "session_file",
    "timeout",
    "verify_tls",
    "output_format",
    "execute",
    "auth_header",
)

# ── 共享参数注册 ──────────────────────────────────────────


def add_shared_arguments(parser: argparse.ArgumentParser) -> None:
    """注册所有 run 子命令共享的参数。"""
    parser.add_argument(
        "--base-url",
        required=True,
        help="Device management base URL, for example https://10.0.0.1.",
    )
    parser.add_argument(
        "--session-file",
        default=str(DEFAULT_SESSION_FILE),
        help="Session file path. Defaults to ~/.local/state/ptm-atomic/ngfw/session.json.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify the device TLS certificate. Disabled by default for lab NGFW devices.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "yaml"),
        default="yaml",
        dest="output_format",
        help="Output format.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Perform live device requests. Omit for dry-run.",
    )
    parser.add_argument(
        "--auth-header",
        choices=("Authorization", "AuthorizationToken"),
        default="Authorization",
        help="Authentication header used for object and policy-route execution.",
    )


def resolve_run_context(args: argparse.Namespace) -> dict[str, Any]:
    """从解析结果中提取共享参数，返回 dict 供 runner 使用。"""
    ctx: dict[str, Any] = {}
    for name in SHARED_ARG_NAMES:
        value = getattr(args, name, None)
        if value is not None:
            ctx[name] = value
    return ctx


# ── 子命令树构建 ──────────────────────────────────────────


def build_run_subtree() -> tuple[CommandGroup | CommandSpec, ...]:
    """构建 run 子命令树。每个操作族为一个 CommandGroup。"""
    from atomic_ops.commands import run_auth as run_auth
    from atomic_ops.commands import run_object as run_object
    from atomic_ops.commands import run_ip6pool_object as run_ip6pool_object
    from atomic_ops.commands import run_customappobj as run_customappobj
    from atomic_ops.commands import run_customappobjtag as run_customappobjtag
    from atomic_ops.commands import run_servicepool as run_servicepool
    from atomic_ops.commands import run_ippool_group as run_ippool_group
    from atomic_ops.commands import run_ip6pool_group as run_ip6pool_group
    from atomic_ops.commands import run_timeobject as run_timeobject
    from atomic_ops.commands import run_policy_route as run_policy_route
    from atomic_ops.commands import run_static_route as run_static_route
    from atomic_ops.commands import run_security_zone as run_security_zone
    from atomic_ops.commands import run_acl_policy as run_acl_policy
    from atomic_ops.commands import run_acl_policy_group as run_acl_policy_group
    from atomic_ops.commands import run_interface as run_interface
    from atomic_ops.commands import run_ospf as run_ospf
    from atomic_ops.commands import run_ospfv3 as run_ospfv3
    from atomic_ops.commands import run_iplink as run_iplink
    from atomic_ops.commands import run_iptun as run_iptun
    from atomic_ops.commands import run_operation_log as run_operation_log
    from atomic_ops.commands import run_config_transfer as run_config_transfer
    from atomic_ops.commands import run_reboot as run_reboot
    from atomic_ops.commands import run_ha as run_ha
    from atomic_ops.commands import run_trex as run_trex
    from atomic_ops.commands import run_neighbor as run_neighbor
    from atomic_ops.commands import run_cli as run_cli

    return (
        CommandGroup(
            name="auth",
            help="Authentication operations (login).",
            description="Authentication operations for NGFW device login.",
            children=run_auth.build_subtree(),
        ),
        CommandGroup(
            name="object",
            help="Address object operations.",
            description="Address object configuration operations.",
            children=run_object.build_subtree(),
        ),
        CommandGroup(
            name="ip6pool-object",
            help="IPv6 address object operations.",
            description="IPv6 address object configuration, update, delete, batch-delete, and verify operations.",
            children=run_ip6pool_object.build_subtree(),
        ),
        CommandGroup(
            name="app-obj",
            help="Custom application object operations.",
            description="Custom application object configuration, update, delete, and query operations.",
            children=run_customappobj.build_subtree(),
        ),
        CommandGroup(
            name="app-tag",
            help="Custom application tag operations.",
            description="Custom application tag configuration, update, delete, and query operations.",
            children=run_customappobjtag.build_subtree(),
        ),
        CommandGroup(
            name="service-pool",
            help="Service pool and group operations.",
            description="Service pool and service group configuration, update, delete, and query operations.",
            children=run_servicepool.build_subtree(),
        ),
        CommandGroup(
            name="ippool-group",
            help="IPv4 address group operations.",
            description="IPv4 address group configuration, update, delete, batch-delete, and verify operations.",
            children=run_ippool_group.build_subtree(),
        ),
        CommandGroup(
            name="ip6pool-group",
            help="IPv6 address group operations.",
            description="IPv6 address group configuration, update, delete, batch-delete, and verify operations.",
            children=run_ip6pool_group.build_subtree(),
        ),
        CommandGroup(
            name="time-object",
            help="Time object operations.",
            description="Time object configuration, update, delete, batch-delete, and verify operations.",
            children=run_timeobject.build_subtree(),
        ),
        CommandGroup(
            name="policy-route",
            help="Policy-based routing operations.",
            description="Policy-route configuration, update, delete, verify, and priority operations.",
            children=run_policy_route.build_subtree(),
        ),
        CommandGroup(
            name="static-route",
            help="Static route operations.",
            description="Static route configuration, update, delete, and verify operations.",
            children=run_static_route.build_subtree(),
        ),
        CommandGroup(
            name="security-zone",
            help="Security zone operations.",
            description="Security zone configuration, update, delete, and verify operations.",
            children=run_security_zone.build_subtree(),
        ),
        CommandGroup(
            name="acl-policy",
            help="Control-policy operations.",
            description="Control-policy (acl_policy) configuration, update, delete, batch-delete, and verify operations over IPv4 and IPv6.",
            children=run_acl_policy.build_subtree(),
        ),
        CommandGroup(
            name="acl-policy-group",
            help="Control-policy group operations.",
            description="Control-policy group (acl_policy_group) configuration, rename, delete, and verify operations over IPv4 and IPv6.",
            children=run_acl_policy_group.build_subtree(),
        ),
        CommandGroup(
            name="interface",
            help="Network interface operations.",
            description="Interface create, update, delete, delete-batch, and verify operations.",
            children=run_interface.build_subtree(),
        ),
        CommandGroup(
            name="ospf",
            help="OSPFv2 routing operations.",
            description="OSPFv2 global, network, interface, and redistribution config/delete/verify operations.",
            children=run_ospf.build_subtree(),
        ),
        CommandGroup(
            name="ospfv3",
            help="OSPFv3 and BFD routing operations.",
            description="OSPFv3 and BFD config, delete, verify operations.",
            children=run_ospfv3.build_subtree(),
        ),
        *run_iplink.build_subtree(),
        *run_iptun.build_subtree(),
        *run_operation_log.build_subtree(),
        *run_config_transfer.build_subtree(),
        *run_reboot.build_subtree(),
        *run_ha.build_subtree(),
        *run_trex.build_subtree(),
        *run_neighbor.build_subtree(),
        CommandGroup(
            name="cli",
            help="SSH/Telnet shell verification operations.",
            description="Read-only device shell operations executed over SSH/Telnet transports.",
            children=run_cli.build_subtree(),
        ),
    )


# ── 旧格式兼容 ────────────────────────────────────────────


def run_legacy(args: argparse.Namespace) -> int:
    """处理旧格式 'ptm-atomic run <op_id> [--params]'。

    检测到 op_id 时输出 deprecation warning，映射到对应的新子命令路径。
    此兼容入口将在 1-2 个版本后移除。
    """
    op_id = getattr(args, "op_id", None)
    if op_id and op_id in DEPRECATED_OP_MAP:
        path = DEPRECATED_OP_MAP[op_id]
        new_cmd = " ".join(path)
        print(
            f"warning: '{op_id}' is deprecated, "
            f"use 'ptm-atomic run {new_cmd}' instead.",
            file=sys.stderr,
        )
        # 将参数转发到对应的操作族 handler
        return _dispatch_legacy(op_id, args)

    if op_id and op_id not in SUPPORTED_OPS:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this operation.",
            {"op_id": op_id, "supported_ops": list(SUPPORTED_OPS)},
            suggestion="Use ptm-atomic adapter for unsupported operations, or add a dedicated runner.",
        )

    # 不应到达此处：正常的 run 子命令已在 cli.py 被子命令解析器捕获
    return _dispatch_legacy(op_id, args) if op_id else 2


def _dispatch_legacy(op_id: str, args: argparse.Namespace) -> int:
    """将旧格式 op_id 分发到对应的操作族 handler。"""
    from atomic_ops.runner.session import DEFAULT_SESSION_FILE, resolve_session_file

    output_format = getattr(args, "output_format", "yaml")
    try:
        if not getattr(args, "verify_tls", False):
            write_warning(
                {
                    "warning_code": "TLS_VERIFY_DISABLED",
                    "message": "Device TLS verification is disabled for this runner invocation.",
                },
                output_format,
            )

        if op_id == "fw_login_web_management":
            payload = _run_login_legacy(args)
        elif op_id == "fw_logout_web_management":
            payload = _run_logout_legacy(args)
        elif op_id == "fw_config_object":
            payload = _run_object_legacy(args)
        elif op_id in POLICY_ROUTE_OPS:
            payload = _run_policy_route_legacy(args)
        elif op_id in STATIC_ROUTE_OPS:
            payload = _run_static_route_legacy(args)
        elif op_id in INTERFACE_OPS:
            payload = _run_interface_legacy(args)
        elif op_id in SECURITY_ZONE_OPS:
            payload = _run_security_zone_legacy(args)
        elif op_id in OSPFV2_OPS:
            payload = _run_ospfv2_legacy(args)
        elif op_id in OSPFV3_BFD_OPS:
            payload = _run_ospfv3_bfd_legacy(args)
        else:
            raise RunnerError(
                "RUNNER_UNSUPPORTED_OP",
                "Runner does not support this operation.",
                {"op_id": op_id, "supported_ops": list(SUPPORTED_OPS)},
                suggestion="Use ptm-atomic adapter for unsupported operations, or add a dedicated runner.",
            )
        _write_output(_to_run_envelope(payload), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(
                exc.error_code,
                exc.message,
                exc.details,
                retryable=exc.retryable,
                suggestion=exc.suggestion,
            ),
            output_format,
        )


# ── 旧格式 runner 函数（保持原有实现） ──────────────────


def _run_login_legacy(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.ngfw_login import build_login_dry_run, login
    from atomic_ops.runner.session import session_summary, write_session_file

    session_file = resolve_session_file(getattr(args, "session_file", None))
    username = getattr(args, "username") or "admin"
    if not getattr(args, "execute"):
        return build_login_dry_run(
            base_url=getattr(args, "base_url"),
            username=username,
            session_file=str(session_file),
            change_default_password=bool(getattr(args, "change_default_password")),
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )

    password_value = _read_secret_env(getattr(args, "password_env", None), "password_env")
    replacement_value = None
    if getattr(args, "change_default_password"):
        replacement_value = _read_secret_env(getattr(args, "new_password_env", None), "new_password_env")

    result = login(
        base_url=getattr(args, "base_url"),
        username=username,
        password_value=password_value,
        timeout=float(getattr(args, "timeout")),
        verify_tls=bool(getattr(args, "verify_tls")),
        change_default_password=bool(getattr(args, "change_default_password")),
        replacement_value=replacement_value,
    )
    session_payload = write_session_file(
        session_file,
        base_url=result["base_url"],
        username=username,
        session_value=result["session_value"],
        source_op_id="fw_login_web_management",
    )
    return {
        "op_id": "fw_login_web_management",
        "status": "success",
        "session": session_summary(session_file, session_payload),
    }


def _run_logout_legacy(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.ngfw_login import build_logout_dry_run, logout

    session_file = resolve_session_file(getattr(args, "session_file", None))
    if not getattr(args, "execute"):
        return build_logout_dry_run(
            base_url=getattr(args, "base_url"),
            session_file=str(session_file),
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout", 10.0)),
        )
    return logout(
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header", "Authorization"),
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout", 10.0)),
    )


def _run_object_legacy(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.object import (
        build_address_object_dry_run,
        build_address_object_payload,
        execute_address_object,
    )

    _require_arg(args, "object_name")
    _require_arg(args, "ipaddr")
    _require_arg(args, "mask")
    payload = build_address_object_payload(
        object_name=getattr(args, "object_name"),
        ipaddr=getattr(args, "ipaddr"),
        mask=getattr(args, "mask"),
        object_desc=getattr(args, "object_desc"),
    )
    if not getattr(args, "execute"):
        return build_address_object_dry_run(
            base_url=getattr(args, "base_url"),
            session_file=resolve_session_file(getattr(args, "session_file", None)),
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )
    return execute_address_object(
        base_url=getattr(args, "base_url"),
        session_file=resolve_session_file(getattr(args, "session_file", None)),
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout")),
    )


def _run_policy_route_legacy(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.policy_route import (
        build_policy_route_delete_payload,
        build_policy_route_dry_run,
        build_policy_route_payload,
        build_policy_route_priority_payload,
        execute_policy_route,
    )

    op_id = getattr(args, "op_id")
    session_file = resolve_session_file(getattr(args, "session_file", None))
    route_type = getattr(args, "policy_route_type")
    payload: dict[str, Any] | None
    if op_id in {"fw_config_policy_route", "fw_update_policy_route"}:
        _require_arg(args, "source_network")
        _require_arg(args, "in_interface")
        if op_id == "fw_update_policy_route":
            _require_arg(args, "id")
        payload = build_policy_route_payload(
            source_network=getattr(args, "source_network"),
            source_network_is_group=bool(getattr(args, "source_network_is_group")),
            dst_network=getattr(args, "dst_network"),
            dst_network_is_group=bool(getattr(args, "dst_network_is_group")),
            next_hop_ip=getattr(args, "next_hop_ip") or "",
            in_interface=getattr(args, "in_interface"),
            outgoing_interface=getattr(args, "outgoing_interface") or "",
            service=getattr(args, "service"),
            service_is_group=bool(getattr(args, "service_is_group")),
            weight=int(getattr(args, "weight")),
            time_obj=getattr(args, "time_obj"),
            route_type=route_type,
            entry_id=_single_arg(args, "id") if op_id == "fw_update_policy_route" else 0,
            active=bool(getattr(args, "policy_route_active")),
            action=int(getattr(args, "policy_route_action")),
            config_source=int(getattr(args, "config_source")),
        )
    elif op_id == "fw_delete_policy_route":
        _require_arg(args, "id")
        payload = build_policy_route_delete_payload(entry_id=_single_arg(args, "id"))
    elif op_id == "fw_update_policy_route_priority":
        _require_arg(args, "targetsite")
        _require_arg(args, "targetid")
        _require_arg(args, "moveid")
        payload = build_policy_route_priority_payload(
            targetsite=getattr(args, "targetsite"),
            targetid=getattr(args, "targetid"),
            moveid=getattr(args, "moveid"),
            route_type=route_type,
        )
    else:
        payload = None
    if not getattr(args, "execute"):
        return build_policy_route_dry_run(
            op_id=op_id,
            base_url=getattr(args, "base_url"),
            session_file=session_file,
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            page=int(getattr(args, "page")),
            size=int(getattr(args, "size")),
            route_type=route_type,
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )
    return execute_policy_route(
        op_id=op_id,
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        page=int(getattr(args, "page")),
        size=int(getattr(args, "size")),
        route_type=route_type,
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout")),
    )


def _run_static_route_legacy(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.static_route import (
        build_static_route_dry_run,
        build_static_route_payload,
        execute_static_route,
    )

    op_id = getattr(args, "op_id")
    session_file = resolve_session_file(getattr(args, "session_file", None))
    route_type = getattr(args, "route_type", "ipv4")
    payload: dict[str, Any] | None
    if op_id in {"fw_config_static_route", "fw_update_static_route"}:
        _require_arg(args, "dst_network")
        _require_arg(args, "next_hop_addr")
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
        _require_arg(args, "id")
        payload = {"id": int(getattr(args, "id"))}
    else:
        payload = None
    if not getattr(args, "execute"):
        return build_static_route_dry_run(
            op_id=op_id,
            base_url=getattr(args, "base_url"),
            session_file=session_file,
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            page=int(getattr(args, "page", 1)),
            size=int(getattr(args, "size", 40)),
            route_type=route_type,
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout", 10.0)),
        )
    return execute_static_route(
        op_id=op_id,
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        page=int(getattr(args, "page", 1)),
        size=int(getattr(args, "size", 40)),
        route_type=route_type,
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout", 10.0)),
    )


def _run_interface_legacy(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.interface import (
        build_interface_batch_delete_payload,
        build_interface_dry_run,
        build_interface_payload,
        execute_interface,
        load_json_payload,
        validate_delete_payload,
        validate_interface_payload,
    )

    op_id = getattr(args, "op_id")
    session_file = resolve_session_file(getattr(args, "session_file", None))
    raw_payload = load_json_payload(
        payload_file=getattr(args, "payload_file"),
        payload_json=getattr(args, "payload_json"),
    )
    payload: dict[str, Any] | None
    if op_id == "fw_verify_interface":
        payload = None
    elif op_id == "fw_delete_interface":
        payload = raw_payload or {"id": _single_arg(args, "id")}
        payload = validate_delete_payload(payload)
    elif op_id == "fw_delete_batch_interface":
        payload = raw_payload or build_interface_batch_delete_payload(entry_ids=_arg_list(args, "id"))
        payload = validate_interface_payload(payload, op_id=op_id)
    else:
        if raw_payload is not None:
            payload = validate_interface_payload(raw_payload, op_id=op_id)
        else:
            _require_arg(args, "interface_kind")
            _require_arg(args, "id")
            payload = build_interface_payload(
                interface_kind=getattr(args, "interface_kind"),
                entry_id=_single_arg(args, "id"),
                mode=getattr(args, "mode"),
                ip_addresses=list(getattr(args, "ip_address") or []),
                name=getattr(args, "name"),
                desc=getattr(args, "desc"),
                enabled=bool(getattr(args, "interface_enabled")),
                parent_name=getattr(args, "parent_name"),
                sub_id=getattr(args, "sub_id"),
                bvi_instance=getattr(args, "bvi_instance"),
                bond_id=getattr(args, "bond_id"),
                bond_members=list(getattr(args, "bond_member") or []),
                bond_mode=int(getattr(args, "bond_mode")),
                bond_lb=int(getattr(args, "bond_lb")),
                link_type=getattr(args, "link_type"),
                pvid=int(getattr(args, "pvid")),
                allow_pass=getattr(args, "allow_pass"),
            )
        payload = validate_interface_payload(payload, op_id=op_id)
    if not getattr(args, "execute"):
        return build_interface_dry_run(
            op_id=op_id,
            base_url=getattr(args, "base_url"),
            session_file=session_file,
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )
    return execute_interface(
        op_id=op_id,
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout")),
    )


def _run_security_zone_legacy(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.security_zone import (
        build_security_zone_create_payload,
        build_security_zone_delete_payload,
        build_security_zone_dry_run,
        build_security_zone_update_payload,
        execute_security_zone,
    )

    op_id = getattr(args, "op_id")
    session_file = resolve_session_file(getattr(args, "session_file", None))
    payload: dict[str, Any] | None

    if op_id == "fw_config_security_zone":
        _require_arg(args, "name")
        payload = build_security_zone_create_payload(
            name=getattr(args, "name"),
            desc=getattr(args, "desc", ""),
            interfaces=_arg_list(args, "interfaces"),
        )
    elif op_id == "fw_update_security_zone":
        _require_arg(args, "name")
        payload = build_security_zone_update_payload(
            name=getattr(args, "name"),
            desc=getattr(args, "desc", ""),
            interfaces=_arg_list(args, "interfaces"),
            refcnt=int(getattr(args, "refcnt", 0)),
        )
    elif op_id == "fw_delete_security_zone":
        _require_arg(args, "name")
        payload = build_security_zone_delete_payload(name=_single_arg(args, "name") or "")
    else:
        payload = None

    if not getattr(args, "execute"):
        return build_security_zone_dry_run(
            op_id=op_id,
            base_url=getattr(args, "base_url"),
            session_file=session_file,
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )
    return execute_security_zone(
        op_id=op_id,
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout")),
    )


def _run_ospfv2_legacy(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.ospfv2 import build_ospfv2_dry_run, build_ospfv2_payload, execute_ospfv2

    op_id = getattr(args, "op_id")
    session_file = resolve_session_file(getattr(args, "session_file", None))
    payload = build_ospfv2_payload(
        op_id,
        {
            "id": _single_arg(args, "id"),
            "enable": getattr(args, "enable"),
            "router_id": getattr(args, "router_id"),
            "originate": getattr(args, "originate"),
            "always": getattr(args, "always"),
            "redistribute": getattr(args, "redistribute"),
            "network": getattr(args, "network"),
            "area": getattr(args, "area"),
            "interface": getattr(args, "interface"),
            "cost": getattr(args, "cost"),
            "priority": getattr(args, "priority"),
            "hello_interval": getattr(args, "hello_interval"),
            "retransmit_interval": getattr(args, "retransmit_interval"),
            "dead_interval": getattr(args, "dead_interval"),
            "transmit_delay": getattr(args, "transmit_delay"),
            "type_network": getattr(args, "type_network"),
            "int_auth_mode": getattr(args, "int_auth_mode"),
            "bfd_enable": getattr(args, "bfd_enable"),
            "detect_multiplier": getattr(args, "detect_multiplier"),
            "min_rx_interval": getattr(args, "min_rx_interval"),
            "min_tx_interval": getattr(args, "min_tx_interval"),
        },
    )
    if not getattr(args, "execute"):
        return build_ospfv2_dry_run(
            op_id=op_id,
            base_url=getattr(args, "base_url"),
            session_file=session_file,
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            page=int(getattr(args, "page")),
            size=int(getattr(args, "size")),
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )
    return execute_ospfv2(
        op_id=op_id,
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        page=int(getattr(args, "page")),
        size=int(getattr(args, "size")),
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout")),
    )


def _run_ospfv3_bfd_legacy(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.ospfv3_bfd import (
        build_ospfv3_bfd_dry_run,
        build_ospfv3_bfd_payload,
        execute_ospfv3_bfd,
    )

    op_id = getattr(args, "op_id")
    session_file = resolve_session_file(getattr(args, "session_file", None))
    payload = build_ospfv3_bfd_payload(
        op_id,
        {
            "id": _single_arg(args, "id"),
            "enable": getattr(args, "enable"),
            "router_id": getattr(args, "router_id"),
            "redistribute": getattr(args, "redistribute"),
            "interface": getattr(args, "interface"),
            "area": getattr(args, "area"),
            "cost": getattr(args, "cost"),
            "priority": getattr(args, "priority"),
            "hello_interval": getattr(args, "hello_interval"),
            "retransmit_interval": getattr(args, "retransmit_interval"),
            "dead_interval": getattr(args, "dead_interval"),
            "transmit_delay": getattr(args, "transmit_delay"),
            "type_network": getattr(args, "type_network"),
        },
    )
    if not getattr(args, "execute"):
        return build_ospfv3_bfd_dry_run(
            op_id=op_id,
            base_url=getattr(args, "base_url"),
            session_file=session_file,
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            page=int(getattr(args, "page")),
            size=int(getattr(args, "size")),
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )
    return execute_ospfv3_bfd(
        op_id=op_id,
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        page=int(getattr(args, "page")),
        size=int(getattr(args, "size")),
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout")),
    )


# ── 辅助函数 ──────────────────────────────────────────────


def _require_arg(args: argparse.Namespace, name: str) -> None:
    value = getattr(args, name)
    if isinstance(value, list):
        value = [item for item in value if isinstance(item, str) and item.strip()]
    if value is None or value == [] or (isinstance(value, str) and not value.strip()):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Missing required runner argument.",
            {"argument": f"--{name.replace('_', '-')}"},
        )


def _single_arg(args: argparse.Namespace, name: str) -> str | None:
    value = getattr(args, name)
    if isinstance(value, list):
        if not value:
            return None
        if len(value) > 1:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Runner argument can only be provided once for this operation.",
                {"argument": f"--{name.replace('_', '-')}"},
            )
        return value[0]
    return value


def _arg_list(args: argparse.Namespace, name: str) -> list[str]:
    value = getattr(args, name)
    if isinstance(value, list):
        return [item for item in value if item]
    if value:
        return [value]
    return []


def _read_secret_env(env_name: str | None, field_name: str) -> str:
    if not env_name:
        raise RunnerError(
            "RUNNER_CREDENTIAL_MISSING",
            "Runner credential environment variable name is required.",
            {"missing": field_name},
        )
    value = os.environ.get(env_name)
    if value is None or not value:
        raise RunnerError(
            "RUNNER_CREDENTIAL_MISSING",
            "Runner credential environment variable is not set or is empty.",
            {"env": env_name},
        )
    return value


def _write_output(payload: dict[str, Any], output_format: str) -> None:
    safe_payload = _redact_runner_output(payload)
    if output_format == "json":
        print(json.dumps(safe_payload, ensure_ascii=False, sort_keys=True))
        return
    print(yaml.safe_dump(safe_payload, allow_unicode=True, sort_keys=False), end="")


def _to_run_envelope(payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap runner-specific payloads in the stable operation return envelope."""
    data = dict(payload)
    op_id = data.pop("op_id", None)
    status = data.pop("status", None)
    error_type = data.pop("error_type", "NONE")
    diag_snapshot_ref = data.pop("diag_snapshot_ref", "")
    metadata = data.pop("metadata", {})

    envelope: dict[str, Any] = {
        "status": status or "success",
        "data": data,
        "error_type": error_type,
        "diag_snapshot_ref": diag_snapshot_ref,
    }
    if op_id is not None:
        envelope["op_id"] = op_id
        rollback_context = _load_rollback_context(str(op_id), data)
        if rollback_context is not None:
            metadata = dict(metadata) if isinstance(metadata, dict) else {}
            metadata["rollback_context"] = rollback_context
    if metadata:
        envelope["metadata"] = metadata
    _record_exec_log(envelope, op_id, status, data)
    return envelope


def _record_exec_log(
    envelope: dict[str, Any],
    op_id: str | None,
    status: str | None,
    data: dict[str, Any],
) -> None:
    """execute 且成功时写 exec-log，envelope 输出 run_id/path 供调用方获取。

    dry-run 不记；错误由 write_error 记录，不在此重复。
    """
    from atomic_ops.runner.exec_log import current_run, run_log_path, write_exec_log

    ctx = current_run()
    if ctx is None or ctx.mode != "execute":
        return
    if status != "success":
        return
    path = write_exec_log(
        run_id=ctx.run_id,
        op_id=op_id,
        mode=ctx.mode,
        status="success",
        status_code=data.get("status_code"),
    )
    metadata = envelope.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        envelope["metadata"] = metadata
    metadata["exec_log"] = {"run_id": ctx.run_id, "path": str(path)}


def _load_rollback_context(op_id: str, result_data: dict[str, Any]) -> dict[str, Any] | None:
    try:
        repo = Repository.from_default_cache()
        document = repo.read_operation(op_id)
    except Exception:
        return None
    return run_rollback_context(op_id, document.data, result_data)


def _redact_runner_output(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, inner in value.items():
            if key in {"session_value", "passwd", "oldpasswd"}:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_runner_output(inner)
        return redacted
    if isinstance(value, list):
        return [_redact_runner_output(item) for item in value]
    return value
