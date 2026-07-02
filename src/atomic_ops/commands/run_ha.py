"""HA (high availability) runner commands."""

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
    return (
        CommandGroup(
            name="ha",
            help="HA configuration operations.",
            description="HA sync, config, monitored interface, and VRRP operations.",
            children=(
                CommandSpec(name="hasync-config", help="Synchronize HA configuration.", description="PUT /api/v1/hasync to synchronize HA configuration.", handler=_run_hasync, add_args=_add_hasync_args),
                CommandSpec(name="hasynclist-verify", help="Verify HA sync status list.", description="GET /api/v1/hasynclist.", handler=_run_hasynclist_verify, add_args=None),
                CommandSpec(name="haconfig-config", help="Configure HA settings.", description="PUT /api/v1/haconfig.", handler=_run_haconfig, add_args=_add_haconfig_args),
                CommandSpec(name="hainterface-config", help="Add HA monitored interface.", description="POST /api/v1/hainterface.", handler=_run_hainterface_config, add_args=_add_hainterface_args),
                CommandSpec(name="hainterface-delete", help="Delete HA monitored interface.", description="DELETE /api/v1/hainterface.", handler=_run_hainterface_delete, add_args=_add_delete_args),
                CommandSpec(name="hainterface-delete-batch", help="Batch-delete HA monitored interfaces.", description="Batch DELETE /api/v1/hainterface.", handler=_run_hainterface_delete_batch, add_args=_add_delete_args),
                CommandSpec(name="hainterface-verify", help="Verify HA monitored interfaces.", description="GET /api/v1/hainterface.", handler=_run_hainterface_verify, add_args=None),
                CommandSpec(name="havrrp-config", help="Add HA VRRP entry.", description="POST /api/v1/havrrp.", handler=_run_havrrp_config, add_args=_add_havrrp_args),
                CommandSpec(name="havrrp-update", help="Update HA VRRP entry.", description="PUT /api/v1/havrrp.", handler=_run_havrrp_update, add_args=_add_havrrp_update_args),
                CommandSpec(name="havrrp-delete", help="Delete HA VRRP entry.", description="DELETE /api/v1/havrrp.", handler=_run_havrrp_delete, add_args=_add_delete_args),
                CommandSpec(name="havrrp-delete-batch", help="Batch-delete HA VRRP entries.", description="Batch DELETE /api/v1/havrrp.", handler=_run_havrrp_delete_batch, add_args=_add_delete_args),
                CommandSpec(name="havrrp-verify", help="Verify HA VRRP entries.", description="GET /api/v1/havrrp.", handler=_run_havrrp_verify, add_args=None),
            ),
        ),
        CommandGroup(
            name="haiplink",
            help="HA iplink monitor operations.",
            description="HA iplink create, delete, batch-delete, and verify operations.",
            children=(
                CommandSpec(name="config", help="Create an HA iplink.", description="POST /api/v1/haiplink.", handler=_run_haiplink_config, add_args=_add_haiplink_args),
                CommandSpec(name="delete", help="Delete an HA iplink.", description="DELETE /api/v1/ha/iplink.", handler=_run_haiplink_delete, add_args=_add_delete_args),
                CommandSpec(name="delete-batch", help="Batch-delete HA iplinks.", description="Batch DELETE /api/v1/ha/iplink.", handler=_run_haiplink_delete_batch, add_args=_add_delete_args),
                CommandSpec(name="verify", help="Verify HA iplink entries.", description="GET /api/v1/haiplink with pagination.", handler=_run_haiplink_verify, add_args=_add_paged_verify_args),
            ),
        ),
        CommandGroup(
            name="halinkgroup",
            help="HA linkgroup operations.",
            description="HA linkgroup create, delete, batch-delete, and verify operations.",
            children=(
                CommandSpec(name="config", help="Create an HA linkgroup.", description="POST /api/v1/halinkgroup.", handler=_run_halinkgroup_config, add_args=_add_halinkgroup_args),
                CommandSpec(name="delete", help="Delete an HA linkgroup.", description="DELETE /api/v1/ha/iplink with isGroup=true.", handler=_run_halinkgroup_delete, add_args=_add_delete_args),
                CommandSpec(name="delete-batch", help="Batch-delete HA linkgroups.", description="Batch DELETE /api/v1/ha/iplink with isGroup=true.", handler=_run_halinkgroup_delete_batch, add_args=_add_delete_args),
                CommandSpec(name="verify", help="Verify HA linkgroup entries.", description="GET /api/v1/halinkgroup with pagination.", handler=_run_halinkgroup_verify, add_args=_add_paged_verify_args),
            ),
        ),
    )


# ── shared arg builders ────────────────────────────────────


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", help="Entry id. May be repeated for batch operations.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_paged_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=100, help="Paginated query page size.")


def _add_hasync_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--module", default="all", help="HA sync module. The only supported value is all.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_haconfig_args(parser: argparse.ArgumentParser) -> None:
    enabled_group = parser.add_mutually_exclusive_group()
    enabled_group.add_argument("--enable", dest="enable", action="store_true", default=True, help="Enable HA (default).")
    enabled_group.add_argument("--disable", dest="enable", action="store_false", help="Disable HA.")
    parser.add_argument("--role", default="BACKUP", help="HA role, e.g. MASTER or BACKUP. Open string.")
    parser.add_argument("--mode", default="MB", help="HA mode. Open string.")
    parser.add_argument("--preempt", dest="preempt", action="store_true", default=True, help="Enable preempt (default).")
    parser.add_argument("--no-preempt", dest="preempt", action="store_false", help="Disable preempt.")
    parser.add_argument("--hb-interface", help="Heartbeat interface name.")
    parser.add_argument("--local-addr", help="Heartbeat local address.")
    parser.add_argument("--remote-addr", help="Heartbeat remote address.")
    parser.add_argument("--base-sync", dest="base_sync", action="store_true", default=True, help="Enable base sync (default).")
    parser.add_argument("--no-base-sync", dest="base_sync", action="store_false", help="Disable base sync.")
    parser.add_argument("--advertise-period", type=int, default=1000, help="Heartbeat advertise period.")
    parser.add_argument("--shock-time-unit", type=int, default=120, help="Shock time unit.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_hainterface_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--track-intf", required=True, help="Monitored interface name.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_havrrp_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--interface", required=True, help="VRRP interface name.")
    parser.add_argument("--vr-id", type=int, required=True, help="VRRP virtual router id.")
    parser.add_argument("--vr-role", required=True, help="VRRP role, e.g. MASTER or BACKUP. Open string.")
    parser.add_argument("--vip", action="append", required=True, help="VRRP virtual IP CIDR. May be repeated.")
    parser.add_argument("--ip-addr", default="0.0.0.0", help="VRRP source IP address placeholder.")
    enabled_group = parser.add_mutually_exclusive_group()
    enabled_group.add_argument("--enable", dest="enable", action="store_true", default=True, help="Enable VRRP (default).")
    enabled_group.add_argument("--disable", dest="enable", action="store_false", help="Disable VRRP.")
    parser.add_argument("--use-virtual-mac", action="store_true", default=False, help="Enable virtual MAC.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_havrrp_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="VRRP entry id, e.g. GE0_9_1 or GE0_9_1ipv6.")
    parser.add_argument("--interface", required=True, help="VRRP interface name.")
    parser.add_argument("--vr-id", type=int, required=True, help="VRRP virtual router id.")
    parser.add_argument("--vr-role", required=True, help="VRRP role, e.g. MASTER or BACKUP. Open string.")
    parser.add_argument("--vip", action="append", required=True, help="VRRP virtual IP CIDR. May be repeated.")
    parser.add_argument("--ip-addr", default="0.0.0.0", help="VRRP source IP address placeholder.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_haiplink_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", required=True, help="HA iplink val.name.")
    parser.add_argument("--destination", required=True, help="HA iplink detection destination IP address.")
    parser.add_argument("--interface", required=True, help="HA iplink detection interface name.")
    parser.add_argument("--port", type=int, default=0, help="HA iplink detection destination port.")
    parser.add_argument("--detect-type", type=int, default=0, help="HA iplink detectType field.")
    parser.add_argument("--interval", type=int, default=1, help="HA iplink detection interval in seconds.")
    parser.add_argument("--retry", type=int, default=1, help="HA iplink detection retry count.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_halinkgroup_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", required=True, help="HA linkgroup val.name.")
    parser.add_argument("--description", default="", help="HA linkgroup description.")
    mode_group = parser.add_mutually_exclusive_group()
    mode_group.add_argument("--mode-strict", dest="mode_strict", action="store_true", default=False, help="Enable strict mode.")
    mode_group.add_argument("--no-mode-strict", dest="mode_strict", action="store_false", help="Disable strict mode (default).")
    parser.add_argument("--link-name", action="append", default=[], help="HA iplink name to aggregate. May be repeated.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


# ── handlers: ha group ─────────────────────────────────────


def _run_hasync(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ha import build_hasync_payload, build_ha_dry_run, execute_ha, validate_ha_payload
    return _run_ha_op(args, "fw_config_hasync", lambda: build_hasync_payload(module=getattr(args, "module", "all")), validate_via=validate_ha_payload)


def _run_hasynclist_verify(args: argparse.Namespace) -> int:
    return _run_ha_op(args, "fw_verify_hasynclist", payload_builder=None)


def _run_haconfig(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ha import build_haconfig_payload, build_ha_dry_run, execute_ha, validate_ha_payload
    def _build():
        return build_haconfig_payload(
            enable=bool(getattr(args, "enable", True)),
            role=getattr(args, "role", "BACKUP"),
            mode=getattr(args, "mode", "MB"),
            preempt=bool(getattr(args, "preempt", True)),
            hb_interface=getattr(args, "hb_interface", "") or "",
            local_addr=getattr(args, "local_addr", "") or "",
            remote_addr=getattr(args, "remote_addr", "") or "",
            base_sync=bool(getattr(args, "base_sync", True)),
            advertise_period=int(getattr(args, "advertise_period", 1000)),
            shock_time_unit=int(getattr(args, "shock_time_unit", 120)),
        )
    return _run_ha_op(args, "fw_config_haconfig", _build, validate_via=validate_ha_payload)


def _run_hainterface_config(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ha import build_hainterface_payload, build_ha_dry_run, execute_ha, validate_ha_payload
    return _run_ha_op(args, "fw_config_hainterface", lambda: build_hainterface_payload(track_intf=getattr(args, "track_intf")), validate_via=validate_ha_payload)


def _run_hainterface_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_ha_op(args, "fw_delete_hainterface", payload_builder=lambda: {"id": _single_arg(args, "id")})


def _run_hainterface_delete_batch(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ha import build_hainterface_batch_delete_payload
    return _run_ha_op(args, "fw_delete_batch_hainterface", payload_builder=lambda: build_hainterface_batch_delete_payload(entry_ids=_arg_list(args, "id")))


def _run_hainterface_verify(args: argparse.Namespace) -> int:
    return _run_ha_op(args, "fw_verify_hainterface", payload_builder=None)


def _run_havrrp_config(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ha import build_havrrp_payload, validate_ha_payload
    def _build():
        return build_havrrp_payload(
            enable=bool(getattr(args, "enable", True)),
            interface=getattr(args, "interface"),
            ip_addr=getattr(args, "ip_addr", "0.0.0.0"),
            vr_id=int(getattr(args, "vr_id")),
            vr_role=getattr(args, "vr_role"),
            vips=list(getattr(args, "vip") or []),
            use_virtual_mac=bool(getattr(args, "use_virtual_mac", False)),
        )
    return _run_ha_op(args, "fw_config_havrrp", _build, validate_via=validate_ha_payload)


def _run_havrrp_update(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ha import build_havrrp_update_payload, validate_ha_payload
    def _build():
        return build_havrrp_update_payload(
            entry_id=getattr(args, "id"),
            interface=getattr(args, "interface"),
            ip_addr=getattr(args, "ip_addr", "0.0.0.0"),
            vr_id=int(getattr(args, "vr_id")),
            vr_role=getattr(args, "vr_role"),
            vips=list(getattr(args, "vip") or []),
        )
    return _run_ha_op(args, "fw_update_havrrp", _build, validate_via=validate_ha_payload)


def _run_havrrp_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_ha_op(args, "fw_delete_havrrp", payload_builder=lambda: {"id": _single_arg(args, "id")})


def _run_havrrp_delete_batch(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ha import build_havrrp_batch_delete_payload
    return _run_ha_op(args, "fw_delete_batch_havrrp", payload_builder=lambda: build_havrrp_batch_delete_payload(entry_ids=_arg_list(args, "id")))


def _run_havrrp_verify(args: argparse.Namespace) -> int:
    return _run_ha_op(args, "fw_verify_havrrp", payload_builder=None)


# ── handlers: haiplink / halinkgroup ──────────────────────


def _run_haiplink_config(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ha_iplink import build_haiplink_payload, validate_haiplink_payload
    def _build():
        return build_haiplink_payload(
            name=getattr(args, "name"),
            destination=getattr(args, "destination"),
            interface=getattr(args, "interface"),
            port=int(getattr(args, "port", 0)),
            detect_type=int(getattr(args, "detect_type", 0)),
            interval=int(getattr(args, "interval", 1)),
            retry=int(getattr(args, "retry", 1)),
        )
    return _run_ha_iplink_op(args, "fw_config_haiplink", _build, validate_via=validate_haiplink_payload)


def _run_haiplink_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_ha_iplink_op(args, "fw_delete_haiplink", payload_builder=lambda: {"id": _single_arg(args, "id")})


def _run_haiplink_delete_batch(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ha_iplink import build_haiplink_batch_delete_payload, validate_batch_payload
    def _build():
        return build_haiplink_batch_delete_payload(entry_ids=_arg_list(args, "id"))
    return _run_ha_iplink_op(args, "fw_delete_batch_haiplink", _build, validate_via=lambda p: validate_batch_payload(p, is_group=False))


def _run_haiplink_verify(args: argparse.Namespace) -> int:
    return _run_ha_iplink_op(args, "fw_verify_haiplink", payload_builder=None)


def _run_halinkgroup_config(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ha_iplink import build_halinkgroup_payload, validate_halinkgroup_payload
    def _build():
        return build_halinkgroup_payload(
            name=getattr(args, "name"),
            description=getattr(args, "description", ""),
            mode_strict=bool(getattr(args, "mode_strict", False)),
            link_name=list(getattr(args, "link_name") or []),
        )
    return _run_ha_iplink_op(args, "fw_config_halinkgroup", _build, validate_via=validate_halinkgroup_payload)


def _run_halinkgroup_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_ha_iplink_op(args, "fw_delete_halinkgroup", payload_builder=lambda: {"id": _single_arg(args, "id")})


def _run_halinkgroup_delete_batch(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ha_iplink import build_halinkgroup_batch_delete_payload, validate_batch_payload
    def _build():
        return build_halinkgroup_batch_delete_payload(entry_ids=_arg_list(args, "id"))
    return _run_ha_iplink_op(args, "fw_delete_batch_halinkgroup", _build, validate_via=lambda p: validate_batch_payload(p, is_group=True))


def _run_halinkgroup_verify(args: argparse.Namespace) -> int:
    return _run_ha_iplink_op(args, "fw_verify_halinkgroup", payload_builder=None)


# ── dispatchers ───────────────────────────────────────────


def _run_ha_op(args: argparse.Namespace, op_id: str, payload_builder, *, validate_via=None) -> int:
    from atomic_ops.runner.ha import build_ha_dry_run, execute_ha, load_json_payload  # type: ignore

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
        payload = raw_payload if raw_payload is not None else (payload_builder() if payload_builder else None)
        if validate_via is not None and payload is not None:
            payload = validate_via(payload, op_id=op_id) if _validate_takes_op_id(validate_via) else validate_via(payload)

        if not ctx.get("execute"):
            result = build_ha_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                verify_tls=bool(ctx.get("verify_tls")), timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_ha(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                verify_tls=bool(ctx.get("verify_tls")), timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _run_ha_iplink_op(args: argparse.Namespace, op_id: str, payload_builder, *, validate_via=None) -> int:
    from atomic_ops.runner.ha_iplink import build_ha_iplink_dry_run, execute_ha_iplink, load_json_payload  # type: ignore

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
        page = int(getattr(args, "page", 1))
        size = int(getattr(args, "size", 100))
        payload = raw_payload if raw_payload is not None else (payload_builder() if payload_builder else None)
        if validate_via is not None and payload is not None:
            payload = validate_via(payload)

        if not ctx.get("execute"):
            result = build_ha_iplink_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=page, size=size, verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_ha_iplink(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=page, size=size, verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _validate_takes_op_id(validate_fn) -> bool:
    import inspect
    try:
        params = inspect.signature(validate_fn).parameters
    except (TypeError, ValueError):
        return False
    return "op_id" in params
