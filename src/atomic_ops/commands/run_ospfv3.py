"""OSPFv3 and BFD runner commands (ospfv3 config/delete/verify/bfd)."""

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
        CommandGroup(name="config", help="OSPFv3 configuration operations.", description="OSPFv3 configuration operations.", children=(
            CommandSpec(name="global", help="Configure OSPFv3 global settings.", description="Configure OSPFv3 global settings.", handler=_run_global_config, add_args=_add_global_args),
            CommandSpec(name="network", help="Configure OSPFv3 network.", description="Configure OSPFv3 network.", handler=_run_network_config, add_args=_add_network_args),
            CommandSpec(name="network-update", help="Update OSPFv3 network.", description="Update OSPFv3 network configuration.", handler=_run_network_update, add_args=_add_network_args),
            CommandSpec(name="interface", help="Configure OSPFv3 interface.", description="Configure OSPFv3 interface settings.", handler=_run_interface_config, add_args=_add_interface_args),
            CommandSpec(name="interface-update", help="Update OSPFv3 interface.", description="Update OSPFv3 interface settings.", handler=_run_interface_update, add_args=_add_interface_args),
            CommandSpec(name="redistribution", help="Configure OSPFv3 redistribution.", description="Configure OSPFv3 route redistribution.", handler=_run_redist_config, add_args=_add_redist_args),
        )),
        CommandGroup(name="delete", help="OSPFv3 delete operations.", description="OSPFv3 delete operations.", children=(
            CommandSpec(name="network", help="Delete OSPFv3 network.", description="Delete OSPFv3 network.", handler=_run_network_delete, add_args=_add_delete_network_args),
            CommandSpec(name="interface", help="Delete OSPFv3 interface.", description="Delete OSPFv3 interface.", handler=_run_interface_delete, add_args=_add_delete_interface_args),
        )),
        CommandGroup(name="verify", help="OSPFv3 verify operations.", description="OSPFv3 verify operations.", children=(
            CommandSpec(name="global", help="Verify OSPFv3 global configuration.", description="Verify OSPFv3 global configuration.", handler=_run_verify_global, add_args=_add_verify_args),
            CommandSpec(name="network", help="Verify OSPFv3 network.", description="Verify OSPFv3 network.", handler=_run_verify_network, add_args=_add_verify_args),
            CommandSpec(name="interface", help="Verify OSPFv3 interface.", description="Verify OSPFv3 interface.", handler=_run_verify_interface, add_args=_add_verify_args),
            CommandSpec(name="neighbor", help="Verify OSPFv3 neighbor.", description="Verify OSPFv3 neighbor adjacency.", handler=_run_verify_neighbor, add_args=_add_verify_args),
        )),
        CommandGroup(name="bfd", help="BFD operations.", description="BFD configuration and verification.", children=(
            CommandSpec(name="config", help="Configure BFD global settings.", description="Configure BFD global settings.", handler=_run_bfd_config, add_args=_add_bfd_config_args),
            CommandSpec(name="verify-global", help="Verify BFD global configuration.", description="Verify BFD global configuration.", handler=_run_bfd_verify_global, add_args=_add_verify_args),
            CommandSpec(name="verify-session", help="Verify BFD session.", description="Verify BFD session status.", handler=_run_bfd_verify_session, add_args=_add_verify_args),
        )),
    )


def _add_global_args(parser: argparse.ArgumentParser) -> None:
    enable_group = parser.add_mutually_exclusive_group()
    enable_group.add_argument("--enable", dest="enable", action="store_true", default=None, help="Enable OSPFv3 globally.")
    enable_group.add_argument("--disable", dest="enable", action="store_false", help="Disable OSPFv3 globally.")
    parser.add_argument("--router-id", help="OSPFv3 router ID IPv4 address.")
    parser.add_argument("--redistribute", action="append", default=[], help="Protocol=metric mapping. May be repeated.")


def _add_network_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--network", help="OSPFv3 network in IPv4 CIDR form.")
    parser.add_argument("--area", help="OSPFv3 area id.")
    parser.add_argument("--id", action="append", help="Entry id for update operations.")


def _add_interface_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--interface", help="OSPFv3 interface name.")
    parser.add_argument("--area", help="OSPFv3 area id.")
    parser.add_argument("--cost", help="OSPFv3 interface cost.")
    parser.add_argument("--priority", help="OSPFv3 interface priority.")
    parser.add_argument("--hello-interval", help="OSPFv3 hello interval.")
    parser.add_argument("--retransmit-interval", help="OSPFv3 retransmit interval.")
    parser.add_argument("--dead-interval", help="OSPFv3 dead interval.")
    parser.add_argument("--transmit-delay", help="OSPFv3 transmit delay.")
    parser.add_argument("--type-network", type=int, help="OSPFv3 interface network type.")
    parser.add_argument("--id", action="append", help="Entry id for update operations.")


def _add_redist_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--redistribute", action="append", default=[], help="Protocol=metric mapping. May be repeated.")


def _add_delete_network_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", help="Entry id.")


def _add_delete_interface_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", help="Entry id.")


def _add_bfd_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--detect-multiplier", type=int, help="BFD detect multiplier.")
    parser.add_argument("--min-rx-interval", type=int, help="BFD minimum receive interval.")
    parser.add_argument("--min-tx-interval", type=int, help="BFD minimum transmit interval.")


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")


# ── Handler 函数 ──────────────────────────────────────────

def _run_global_config(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_config_ospfv3_global")


def _run_network_config(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_config_ospfv3_network")


def _run_network_update(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_config_ospfv3_network_update")


def _run_interface_config(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_config_ospfv3_interface")


def _run_interface_update(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_config_ospfv3_interface_update")


def _run_redist_config(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_verify_ospfv3_redistribution")


def _run_network_delete(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_delete_ospfv3_network")


def _run_interface_delete(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_delete_ospfv3_interface")


def _run_verify_global(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_verify_ospfv3_global")


def _run_verify_network(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_verify_ospfv3_network")


def _run_verify_interface(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_verify_ospfv3_interface")


def _run_verify_neighbor(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_verify_ospfv3_neighbor")


def _run_bfd_config(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_config_bfd_global")


def _run_bfd_verify_global(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_verify_bfd_global")


def _run_bfd_verify_session(args: argparse.Namespace) -> int:
    return _run_ospfv3(args, "fw_verify_bfd_session")


def _run_ospfv3(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.ospfv3_bfd import (
        build_ospfv3_bfd_dry_run,
        build_ospfv3_bfd_payload,
        execute_ospfv3_bfd,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        payload = build_ospfv3_bfd_payload(
            op_id,
            {
                "id": _single_arg(args, "id") if hasattr(args, "id") else None,
                "enable": getattr(args, "enable", None),
                "router_id": getattr(args, "router_id", None),
                "redistribute": getattr(args, "redistribute", []),
                "interface": getattr(args, "interface", None),
                "area": getattr(args, "area", None),
                "cost": getattr(args, "cost", None),
                "priority": getattr(args, "priority", None),
                "hello_interval": getattr(args, "hello_interval", None),
                "retransmit_interval": getattr(args, "retransmit_interval", None),
                "dead_interval": getattr(args, "dead_interval", None),
                "transmit_delay": getattr(args, "transmit_delay", None),
                "type_network": getattr(args, "type_network", None),
                "detect_multiplier": getattr(args, "detect_multiplier", None),
                "min_rx_interval": getattr(args, "min_rx_interval", None),
                "min_tx_interval": getattr(args, "min_tx_interval", None),
            },
        )
        if not ctx.get("execute"):
            result = build_ospfv3_bfd_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=int(getattr(args, "page", 1)), size=int(getattr(args, "size", 40)),
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_ospfv3_bfd(
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
