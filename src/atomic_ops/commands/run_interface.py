"""Network interface runner commands."""

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


class _RemovedPppoePasswordAction(argparse.Action):
    # 2026-09：--pppoe-password 明文入口已删除（明文不进入 CLI 参数/进程列表/payload
    # 构造，安全口径对齐 pppoe-config）。保留参数名仅为让既有调用获得可诊断错误并
    # 指路环境变量注入方式；传值即 argparse error（exit 2），不静默忽略。
    def __call__(self, parser, namespace, values, option_string=None):
        parser.error(
            f"{option_string} is removed: plaintext PPPoE passwords are not accepted. "
            "Supply the dial password through an environment variable and rerun with "
            "--pppoe-password-env <ENV> --execute."
        )


def build_subtree() -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(name="create", help="Create a new network interface.", description="Create a new NGFW network interface.", handler=_run_create, add_args=_add_interface_args),
        CommandSpec(name="update", help="Update an existing network interface.", description="Update an existing NGFW network interface.", handler=_run_update, add_args=_add_interface_args),
        CommandSpec(name="delete", help="Delete a network interface.", description="Delete a single NGFW network interface.", handler=_run_delete, add_args=_add_delete_args),
        CommandSpec(name="delete-batch", help="Delete multiple network interfaces.", description="Batch-delete NGFW network interfaces.", handler=_run_delete_batch, add_args=_add_delete_args),
        CommandSpec(name="verify", help="Verify a network interface.", description="Verify a NGFW network interface.", handler=_run_verify, add_args=_add_verify_args),
        CommandSpec(name="pppoe-config", help="Configure a PPPoE dial interface.", description="PUT /api/v1/intf with an RSA-encrypted PPPoE password.", handler=_run_pppoe_config, add_args=_add_pppoe_args),
    )


def _add_interface_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, action="append", help="Entry id. May be repeated for batch operations.")
    parser.add_argument("--interface-kind", choices=("bvi", "sub", "physical", "bond", "tunnel", "pppoe"), required=True, help="NGFW interface kind. Tunnel interfaces support PUT and GET only.")
    parser.add_argument("--mode", choices=("Route", "Switch", "Pair", "Monitor"), default="Route", help="NGFW interface mode.")
    parser.add_argument("--name", help="Interface val.name. Defaults to --id.")
    parser.add_argument("--desc", default="", help="Interface description.")
    interface_enabled_group = parser.add_mutually_exclusive_group()
    interface_enabled_group.add_argument("--interface-enabled", dest="interface_enabled", action="store_true", default=True, help="Enable the NGFW interface.")
    interface_enabled_group.add_argument("--interface-disabled", dest="interface_enabled", action="store_false", help="Disable the NGFW interface.")
    parser.add_argument("--ip-address", action="append", default=[], help="Interface CIDR address. May be repeated for IPv4 and IPv6.")
    parser.add_argument("--parent-name", help="Subinterface parent interface name, or optional BVI bridge member interface name (bvi kind). When given, the member port must be Switch mode with pvid equal to the BVI instance and linkType 1; prepare it with 'interface update' first.")
    parser.add_argument("--sub-id", type=int, help="Subinterface VLAN/sub id.")
    parser.add_argument("--bvi-instance", type=int, help="BVI instance id. Member port pvid must equal this value.")
    parser.add_argument("--bond-id", type=int, help="Bond id.")
    parser.add_argument("--bond-member", action="append", default=[], help="Physical interface member for a bond. May be repeated.")
    parser.add_argument("--bond-mode", type=int, default=5, help="Bond mode field.")
    parser.add_argument("--bond-lb", type=int, default=0, help="Bond load-balance field.")
    parser.add_argument("--pppoe-username", help="PPPoE username (pppoe kind only).")
    parser.add_argument(
        "--pppoe-password", action=_RemovedPppoePasswordAction,
        metavar="PASSWORD",
        help="[REMOVED] Plaintext PPPoE passwords are not accepted; use --pppoe-password-env.",
    )
    parser.add_argument(
        "--pppoe-password-env",
        help="Name of the environment variable holding the PPPoE dial password "
        "(pppoe kind only). Required for --execute; the runner RSA-encrypts the "
        "value with the login public key before sending.",
    )
    parser.add_argument("--link-type", type=int, help="Interface linkType field. BVI bridge member ports require 1 (access); the device defaults to 2 (trunk) when omitted, which is rejected as a BVI member.")
    parser.add_argument("--pvid", type=int, default=1, help="Switch/Pair/Monitor mode PVID.")
    parser.add_argument("--allow-pass", help="Switch/Pair/Monitor mode allowPass field.")
    parser.add_argument("--tunnel-type", choices=("4over6", "6over4", "gre"), help="IP tunnel variant (tunnel kind only). 4over6 maps to type 15, 6over4 to type 16, gre to type 11.")
    parser.add_argument("--src-addr", help="Tunnel source endpoint address (tunnel kind only).")
    parser.add_argument("--dst-addr", help="Tunnel destination endpoint address (tunnel kind only).")
    parser.add_argument("--gre-tunnel-type", type=int, default=1, help="GRE tunnel_type field (gre only).")
    parser.add_argument("--gre-key", type=int, default=0, help="GRE key field (gre only).")
    parser.add_argument("--gre-check-sum", action="store_true", default=False, help="Enable GRE checksum (gre only).")
    parser.add_argument("--gre-keepalive-enable", action="store_true", default=False, help="Enable GRE keepalive (gre only).")
    parser.add_argument("--ip6-nd-prefix", action="append", default=None, help="IPv6 ND prefix for val.ip6_nd.ip_prefix (bvi/sub only), e.g. 66::/96. May be repeated. Omitted from the payload when not set.")
    parser.add_argument("--ip6-racfg-suppress", type=int, help="val.ip6_racfg.suppress flag, 0 or 1 (bvi/sub only). Omitted from the payload when not set.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", help="Entry id. May be repeated for fw_delete_batch_interface.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", help="Entry id.")
    parser.add_argument("--page", type=int, help="Page number for the paginated interface query (fw_verify_interface).")
    parser.add_argument("--size", type=int, help="Page size for the paginated interface query (fw_verify_interface).")


def _add_pppoe_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="PPPoE interface id, e.g. TE0_21.")
    parser.add_argument("--username", required=True, help="PPPoE dial username.")
    parser.add_argument("--password-env", help="Name of the environment variable holding the PPPoE password. Required for --execute.")


def _run_pppoe_config(args: argparse.Namespace) -> int:
    from atomic_ops.runner.pppoe import build_pppoe_config_dry_run, execute_pppoe_config

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        intf_id = getattr(args, "id")
        username = getattr(args, "username")
        if not ctx.get("execute"):
            result = build_pppoe_config_dry_run(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                intf_id=intf_id, username=username,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            password_env = getattr(args, "password_env", None)
            if not password_env:
                raise RunnerError(
                    "RUNNER_CREDENTIAL_MISSING",
                    "--password-env is required when using --execute.",
                    {"missing": "password_env"},
                )
            result = execute_pppoe_config(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                intf_id=intf_id, username=username, password_env=password_env,
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


def _run_create(args: argparse.Namespace) -> int:
    return _run_interface(args, "fw_config_interface")


def _run_update(args: argparse.Namespace) -> int:
    return _run_interface(args, "fw_update_interface")


def _run_delete(args: argparse.Namespace) -> int:
    return _run_interface(args, "fw_delete_interface")


def _run_delete_batch(args: argparse.Namespace) -> int:
    return _run_interface(args, "fw_delete_batch_interface")


def _run_verify(args: argparse.Namespace) -> int:
    return _run_interface(args, "fw_verify_interface")


def _verify_query(args: argparse.Namespace, op_id: str) -> dict[str, int] | None:
    if op_id != "fw_verify_interface":
        return None
    page = getattr(args, "page", None)
    size = getattr(args, "size", None)
    if page is None and size is None:
        return None
    query: dict[str, int] = {}
    for name, value in (("page", page), ("size", size)):
        if value is None:
            continue
        if value < 1:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Interface pagination parameter must be a positive integer.",
                {"field": name, "value": value},
            )
        query[name] = value
    return query


def _run_interface(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.interface import (
        build_interface_batch_delete_payload,
        build_interface_dry_run,
        build_interface_payload,
        execute_interface,
        load_json_payload,
        validate_delete_payload,
        validate_interface_payload,
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
                    mode=getattr(args, "mode", "Route"),
                    ip_addresses=_arg_list(args, "ip_address"),
                    name=getattr(args, "name"),
                    desc=getattr(args, "desc", ""),
                    enabled=bool(getattr(args, "interface_enabled", True)),
                    parent_name=getattr(args, "parent_name"),
                    sub_id=getattr(args, "sub_id"),
                    bvi_instance=getattr(args, "bvi_instance"),
                    bond_id=getattr(args, "bond_id"),
                    bond_members=_arg_list(args, "bond_member"),
                    bond_mode=int(getattr(args, "bond_mode", 5)),
                    bond_lb=int(getattr(args, "bond_lb", 0)),
                    pppoe_username=getattr(args, "pppoe_username"),
                    link_type=getattr(args, "link_type"),
                    pvid=int(getattr(args, "pvid", 1)),
                    allow_pass=getattr(args, "allow_pass"),
                    tunnel_type=getattr(args, "tunnel_type"),
                    src_addr=getattr(args, "src_addr"),
                    dst_addr=getattr(args, "dst_addr"),
                    gre_tunnel_type=int(getattr(args, "gre_tunnel_type", 1)),
                    gre_key=int(getattr(args, "gre_key", 0)),
                    gre_check_sum=bool(getattr(args, "gre_check_sum", False)),
                    gre_keepalive_enable=bool(getattr(args, "gre_keepalive_enable", False)),
                    ip6_nd_prefixes=list(getattr(args, "ip6_nd_prefix") or []) or None,
                    ip6_racfg_suppress=getattr(args, "ip6_racfg_suppress"),
                )
            payload = validate_interface_payload(payload, op_id=op_id)

        if not ctx.get("execute"):
            result = build_interface_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
                query=_verify_query(args, op_id),
            )
        else:
            result = execute_interface(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
                query=_verify_query(args, op_id),
                pppoe_password_env=getattr(args, "pppoe_password_env", None),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
