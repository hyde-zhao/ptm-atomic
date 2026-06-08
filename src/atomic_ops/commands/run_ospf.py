"""OSPFv2 runner commands (ospf config/delete/verify)."""

from __future__ import annotations

import argparse
from typing import Any

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import _single_arg, _to_run_envelope, _write_output, resolve_run_context
from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file


def build_subtree() -> tuple[CommandGroup, ...]:
    return (
        CommandGroup(name="config", help="OSPFv2 configuration operations.", description="OSPFv2 configuration operations.", children=(
            CommandSpec(name="global", help="Configure OSPFv2 global settings.", description="Configure OSPFv2 global settings.", handler=_run_global_config, add_args=_add_global_args),
            CommandSpec(name="network", help="Configure OSPFv2 network.", description="Configure OSPFv2 network.", handler=_run_network_config, add_args=_add_network_args),
            CommandSpec(name="network-update", help="Update OSPFv2 network.", description="Update OSPFv2 network configuration.", handler=_run_network_update, add_args=_add_network_args),
            CommandSpec(name="interface", help="Configure OSPFv2 interface.", description="Configure OSPFv2 interface settings.", handler=_run_interface_config, add_args=_add_interface_args),
            CommandSpec(name="interface-update", help="Update OSPFv2 interface.", description="Update OSPFv2 interface settings.", handler=_run_interface_update, add_args=_add_interface_args),
            CommandSpec(name="redistribution", help="Configure OSPFv2 redistribution.", description="Configure OSPFv2 route redistribution.", handler=_run_redist_config, add_args=_add_redist_args),
        )),
        CommandGroup(name="delete", help="OSPFv2 delete operations.", description="OSPFv2 delete operations.", children=(
            CommandSpec(name="network", help="Delete OSPFv2 network.", description="Delete OSPFv2 network.", handler=_run_network_delete, add_args=_add_delete_network_args),
            CommandSpec(name="interface", help="Delete OSPFv2 interface.", description="Delete OSPFv2 interface.", handler=_run_interface_delete, add_args=_add_delete_interface_args),
        )),
        CommandGroup(name="verify", help="OSPFv2 verify operations.", description="OSPFv2 verify operations.", children=(
            CommandSpec(name="global", help="Verify OSPFv2 global configuration.", description="Verify OSPFv2 global configuration.", handler=_run_verify_global, add_args=_add_verify_args),
            CommandSpec(name="network", help="Verify OSPFv2 network.", description="Verify OSPFv2 network.", handler=_run_verify_network, add_args=_add_verify_args),
            CommandSpec(name="interface", help="Verify OSPFv2 interface.", description="Verify OSPFv2 interface.", handler=_run_verify_interface, add_args=_add_verify_args),
            CommandSpec(name="neighbor", help="Verify OSPFv2 neighbor.", description="Verify OSPFv2 neighbor adjacency.", handler=_run_verify_neighbor, add_args=_add_verify_args),
            CommandSpec(name="redistribution", help="Verify OSPFv2 redistribution.", description="Verify OSPFv2 route redistribution.", handler=_run_verify_redist, add_args=_add_verify_args),
        )),
    )


def _add_global_args(parser: argparse.ArgumentParser) -> None:
    enable_group = parser.add_mutually_exclusive_group()
    enable_group.add_argument("--enable", dest="enable", action="store_true", default=None, help="Enable OSPFv2 globally.")
    enable_group.add_argument("--disable", dest="enable", action="store_false", help="Disable OSPFv2 globally.")
    parser.add_argument("--router-id", help="OSPFv2 router ID IPv4 address.")
    originate_group = parser.add_mutually_exclusive_group()
    originate_group.add_argument("--originate", dest="originate", action="store_true", default=None, help="Enable default route origination.")
    originate_group.add_argument("--no-originate", dest="originate", action="store_false", help="Disable default route origination.")
    always_group = parser.add_mutually_exclusive_group()
    always_group.add_argument("--always", dest="always", action="store_true", default=None, help="Always originate the default route.")
    always_group.add_argument("--no-always", dest="always", action="store_false", help="Do not always originate the default route.")
    parser.add_argument("--redistribute", action="append", default=[], help="Protocol=metric mapping. May be repeated.")


def _add_network_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--network", help="OSPFv2 network in IPv4 CIDR form.")
    parser.add_argument("--area", help="OSPFv2 area id.")
    parser.add_argument("--id", action="append", help="Entry id for update operations.")


def _add_interface_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--interface", help="OSPFv2 interface name.")
    parser.add_argument("--cost", help="OSPFv2 interface cost.")
    parser.add_argument("--priority", help="OSPFv2 interface priority.")
    parser.add_argument("--hello-interval", help="OSPFv2 hello interval.")
    parser.add_argument("--retransmit-interval", help="OSPFv2 retransmit interval.")
    parser.add_argument("--dead-interval", help="OSPFv2 dead interval.")
    parser.add_argument("--transmit-delay", help="OSPFv2 transmit delay.")
    parser.add_argument("--type-network", type=int, help="OSPFv2 interface network type.")
    parser.add_argument("--int-auth-mode", type=int, help="OSPFv2 interface authentication mode.")
    bfd_group = parser.add_mutually_exclusive_group()
    bfd_group.add_argument("--bfd-enable", dest="bfd_enable", action="store_true", default=None, help="Enable BFD.")
    bfd_group.add_argument("--bfd-disable", dest="bfd_enable", action="store_false", help="Disable BFD.")
    parser.add_argument("--detect-multiplier", type=int, help="OSPFv2 BFD detect multiplier.")
    parser.add_argument("--min-rx-interval", type=int, help="OSPFv2 BFD minimum receive interval.")
    parser.add_argument("--min-tx-interval", type=int, help="OSPFv2 BFD minimum transmit interval.")
    parser.add_argument("--id", action="append", help="Entry id for update operations.")


def _add_redist_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--redistribute", action="append", default=[], help="Protocol=metric mapping. May be repeated.")


def _add_delete_network_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", help="Entry id.")


def _add_delete_interface_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", help="Entry id.")


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")


# ── Handler 函数 ──────────────────────────────────────────

def _run_global_config(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_config_ospfv2_global")


def _run_network_config(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_config_ospfv2_network")


def _run_network_update(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_config_ospfv2_network_update")


def _run_interface_config(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_config_ospfv2_interface")


def _run_interface_update(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_config_ospfv2_interface_update")


def _run_redist_config(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_config_ospfv2_redistribution")


def _run_network_delete(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_delete_ospfv2_network")


def _run_interface_delete(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_delete_ospfv2_interface")


def _run_verify_global(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_verify_ospfv2_global")


def _run_verify_network(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_verify_ospfv2_network")


def _run_verify_interface(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_verify_ospfv2_interface")


def _run_verify_neighbor(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_verify_ospfv2_neighbor")


def _run_verify_redist(args: argparse.Namespace) -> int:
    return _run_ospf(args, "fw_verify_ospfv2_redistribution")


def _run_ospf(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.ospfv2 import build_ospfv2_dry_run, build_ospfv2_payload, execute_ospfv2

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        payload = build_ospfv2_payload(
            op_id,
            {
                "id": _single_arg(args, "id") if hasattr(args, "id") else None,
                "enable": getattr(args, "enable", None),
                "router_id": getattr(args, "router_id", None),
                "originate": getattr(args, "originate", None),
                "always": getattr(args, "always", None),
                "redistribute": getattr(args, "redistribute", []),
                "network": getattr(args, "network", None),
                "area": getattr(args, "area", None),
                "interface": getattr(args, "interface", None),
                "cost": getattr(args, "cost", None),
                "priority": getattr(args, "priority", None),
                "hello_interval": getattr(args, "hello_interval", None),
                "retransmit_interval": getattr(args, "retransmit_interval", None),
                "dead_interval": getattr(args, "dead_interval", None),
                "transmit_delay": getattr(args, "transmit_delay", None),
                "type_network": getattr(args, "type_network", None),
                "int_auth_mode": getattr(args, "int_auth_mode", None),
                "bfd_enable": getattr(args, "bfd_enable", None),
                "detect_multiplier": getattr(args, "detect_multiplier", None),
                "min_rx_interval": getattr(args, "min_rx_interval", None),
                "min_tx_interval": getattr(args, "min_tx_interval", None),
            },
        )
        if not ctx.get("execute"):
            result = build_ospfv2_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=int(getattr(args, "page", 1)), size=int(getattr(args, "size", 40)),
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_ospfv2(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=int(getattr(args, "page", 1)), size=int(getattr(args, "size", 40)),
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
