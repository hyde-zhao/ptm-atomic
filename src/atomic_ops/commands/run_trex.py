"""TRex traffic generator runner commands (tg trex <action>)."""

from __future__ import annotations

import argparse
import json
from typing import Any

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import (
    _to_run_envelope,
    _write_output,
    resolve_run_context,
)
from atomic_ops.errors import CliError, write_error
from atomic_ops.runner.errors import RunnerError


def build_subtree() -> tuple[CommandGroup, ...]:
    return (
        CommandGroup(
            name="tg",
            help="Traffic generator operations.",
            description="Traffic generator (tg) operations.",
            children=(
                CommandGroup(
                    name="trex",
                    help="TRex traffic generator operations.",
                    description="TRex trex-api template and stream lifecycle operations.",
                    children=(
                        CommandSpec(
                            name="acquire-ports",
                            help="Acquire TRex ports for exclusive use by a user.",
                            description="Acquire TRex ports (force=False) and bind them to a user_id until release or timeout.",
                            handler=_run_acquire_ports,
                            add_args=_add_acquire_ports_args,
                        ),
                        CommandSpec(
                            name="config-interface",
                            help="Configure TRex interfaces and learn gateway MACs.",
                            description="Configure TRex IPv4 or IPv6 interfaces and learn gateway MAC addresses.",
                            handler=_run_config_interface,
                            add_args=_add_config_interface_args,
                        ),
                        CommandSpec(
                            name="apply-template",
                            help="Apply a TRex traffic template.",
                            description="Create or update a TRex traffic template YAML on the TG host.",
                            handler=_run_apply_template,
                            add_args=_add_apply_template_args,
                        ),
                        CommandSpec(
                            name="delete-template",
                            help="Delete a TRex traffic template.",
                            description="Delete a TRex traffic template when no runtime stream uses it.",
                            handler=_run_delete_template,
                            add_args=_add_delete_template_args,
                        ),
                        CommandSpec(
                            name="start-stream",
                            help="Start a TRex traffic stream.",
                            description="Start a TRex traffic stream from a predefined traffic template.",
                            handler=_run_start_stream,
                            add_args=_add_start_stream_args,
                        ),
                        CommandSpec(
                            name="stop-stream",
                            help="Stop a TRex traffic stream.",
                            description="Stop a TRex traffic stream and clean its runtime configuration.",
                            handler=_run_stop_stream,
                            add_args=_add_stop_stream_args,
                        ),
                        CommandSpec(
                            name="verify-loss",
                            help="Verify TRex traffic loss.",
                            description="Verify TRex port statistics against a maximum allowed loss ratio.",
                            handler=_run_verify_loss,
                            add_args=_add_verify_loss_args,
                        ),
                        CommandSpec(
                            name="start-capture",
                            help="Start packet capture on a TRex port.",
                            description="Start rx (default) or tx packet capture on a TRex port; pair with stop-capture.",
                            handler=_run_start_capture,
                            add_args=_add_start_capture_args,
                        ),
                        CommandSpec(
                            name="stop-capture",
                            help="Stop packet capture and return parsed packets.",
                            description="Stop capture, return parsed packets (incl. ARP fields) and evaluate check_* assertions.",
                            handler=_run_stop_capture,
                            add_args=_add_stop_capture_args,
                        ),
                        CommandSpec(
                            name="release-ports",
                            help="Release TRex ports previously acquired by a user.",
                            description="Release TRex ports held by a user_id (all or a subset).",
                            handler=_run_release_ports,
                            add_args=_add_release_ports_args,
                        ),
                        CommandSpec(
                            name="query-port-status",
                            help="Query TRex port status (read-only diagnostics).",
                            description="Read-only TRex port status query (zero acquire): link/status/mac/src_ipv4 per port.",
                            handler=_run_query_port_status,
                            add_args=_add_query_port_status_args,
                        ),
                        CommandSpec(
                            name="verify-ownership",
                            help="Query TRex port ownership across all users.",
                            description="Query the trex-api ownership registry for current port occupation by all users.",
                            handler=_run_verify_ownership,
                            add_args=_add_verify_ownership_args,
                        ),
                        CommandSpec(
                            name="config-stateful-interface",
                            help="Configure ASTF interfaces and learn gateway MACs.",
                            description="Configure ASTF IPv4 or IPv6 interfaces (set_l3_mode) and learn gateway MAC addresses via ARP.",
                            handler=_run_config_stateful_interface,
                            add_args=_add_config_stateful_interface_args,
                        ),
                        CommandSpec(
                            name="apply-stateful-template",
                            help="Load a pre-defined ASTF template.",
                            description="Load an ASTF profile template onto the TRex ASTF instance.",
                            handler=_run_apply_stateful_template,
                            add_args=_add_apply_stateful_template_args,
                        ),
                        CommandSpec(
                            name="start-stateful-stream",
                            help="Start ASTF stateful traffic.",
                            description="Start ASTF stateful traffic from a loaded profile.",
                            handler=_run_start_stateful_stream,
                            add_args=_add_start_stateful_stream_args,
                        ),
                        CommandSpec(
                            name="start-custom-l7-stream",
                            help="Apply a custom L7 ASTF template and start traffic.",
                            description=(
                                "Composite operation: apply a custom L7 ASTF template "
                                "(http-attack or ftp-auth) with tunables, then start "
                                "stateful traffic. Apply failure aborts before start."
                            ),
                            handler=_run_start_custom_l7_stream,
                            add_args=_add_start_custom_l7_stream_args,
                        ),
                        CommandSpec(
                            name="start-pcap-stream",
                            help="Apply the p2p-replay ASTF template and start pcap replay.",
                            description=(
                                "Composite operation: apply the p2p-replay ASTF template "
                                "with a pcap basename and cps, then start stateful traffic. "
                                "Apply failure aborts before start."
                            ),
                            handler=_run_start_pcap_stream,
                            add_args=_add_start_pcap_stream_args,
                        ),
                        CommandSpec(
                            name="verify-stateful-metrics",
                            help="Verify ASTF stateful metrics.",
                            description="Query real-time ASTF statistics and optionally verify loss ratio.",
                            handler=_run_verify_stateful_metrics,
                            add_args=_add_verify_stateful_metrics_args,
                        ),
                        CommandSpec(
                            name="stop-stateful-stream",
                            help="Stop ASTF stateful traffic.",
                            description="Stop ASTF stateful traffic and clear runtime state.",
                            handler=_run_stop_stateful_stream,
                            add_args=_add_stop_stateful_stream_args,
                        ),
                        CommandSpec(
                            name="delete-stateful-template",
                            help="Unload ASTF template.",
                            description="Unload the ASTF profile from the TRex ASTF instance.",
                            handler=_run_delete_stateful_template,
                            add_args=_add_delete_stateful_template_args,
                        ),
                    ),
                ),
            ),
        ),
    )


# ── 参数注册 ──────────────────────────────────────────────


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_user_id_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--user-id",
        default="default",
        help="TRex multi-user owner id (default 'default' = legacy force mode; set "
        "dev<ip-suffix>-<seq> like dev171-1 to pair with acquire-ports for owned mode).",
    )


def _add_acquire_ports_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--user-id",
        required=True,
        help="Occupant identifier, format dev<ip-suffix>-<seq> (e.g. dev172-1).",
    )
    parser.add_argument(
        "--ports",
        required=True,
        help="Comma-separated logical port names to acquire, e.g. 2_1,2_2.",
    )
    _add_payload_args(parser)


def _add_release_ports_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--user-id",
        required=True,
        help="Occupant identifier that previously acquired the ports.",
    )
    parser.add_argument(
        "--ports",
        default=None,
        help="Comma-separated logical port names to release. If omitted, releases all ports held by the user-id.",
    )
    _add_payload_args(parser)


def _add_config_interface_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument(
        "--interfaces",
        required=True,
        help="JSON array of interface objects: port, ip, gateway, and optional mac/peer-mac/vlan fields.",
    )
    _add_payload_args(parser)


def _add_apply_template_args(parser: argparse.ArgumentParser) -> None:
    # 2026-09-23：以下 6 个"必填"参数改由 build_trex_payload 在**未直传 payload** 时
    # 校验（见 runner/trex.py 的 tg_apply_traffic_template 分支）。原为 argparse
    # required=True，即使给了 --payload-json/--payload-file 也强制要求 —— 而 `_run_trex`
    # 的 payload 分支根本不读这些值，逃生口形同虚设（真机 exit=2 usage 报错）。
    # 语义对齐 `fw_update_timeobject`："Required unless --payload-json/--payload-file
    # is given"。不能直传 payload 的参数（如 --ip-version 有默认值）不受影响。
    optional_when_payload = " Required unless --payload-json/--payload-file is given."
    parser.add_argument("--template", required=False, default=None, help="Traffic template name (^[a-z0-9_-]+$)." + optional_when_payload)
    parser.add_argument("--tx-port", required=False, default=None, help="Default TX port stored in the template." + optional_when_payload)
    parser.add_argument("--rx-port", required=False, default=None, help="Default RX port stored in the template." + optional_when_payload)
    parser.add_argument(
        "--ip-version",
        choices=("ipv4", "ipv6"),
        default="ipv4",
        help="Network layer packet type. Defaults to ipv4.",
    )
    parser.add_argument("--l4-protocol", choices=("tcp", "udp", "icmp"), required=False, default=None, help="Layer 4 protocol (icmp = echo request, no ports)." + optional_when_payload)
    parser.add_argument("--l4-sport", type=int, required=False, default=None, help="Layer 4 source port (tcp/udp only).")
    parser.add_argument("--l4-dport", type=int, required=False, default=None, help="Layer 4 destination port (tcp/udp only).")
    parser.add_argument(
        "--stream-count",
        type=int,
        default=None,
        help=(
            "Expand into N flows with consecutive L4 source ports starting at --l4-sport "
            "(tcp/udp only; default 1 = single flow). --count stays the TOTAL packet count."
        ),
    )
    parser.add_argument("--traffic-mode", choices=("count", "continuous"), required=False, default=None, help="Traffic mode." + optional_when_payload)
    parser.add_argument("--rate", required=False, default=None, help="TRex-style rate string such as 100pps or 10mbps." + optional_when_payload)
    parser.add_argument("--count", type=int, default=None, help="Packet count (required when traffic-mode=count except ICMP defaults to 5).")
    parser.add_argument("--frame-size", type=int, default=None, help="Ethernet frame size in bytes (>= 64).")
    parser.add_argument("--vlan", default=None, help="VLAN ID or VLAN stack.")
    parser.add_argument("--src-ip", default=None, help="Optional source IP.")
    parser.add_argument("--dst-ip", default=None, help="Optional destination IP.")
    parser.add_argument("--src-mac", default=None, help="Optional source MAC.")
    parser.add_argument("--dst-mac", default=None, help="Optional destination MAC.")
    _add_user_id_arg(parser)
    _add_payload_args(parser)


def _add_delete_template_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument("--template", required=True, help="Traffic template name to delete.")
    _add_payload_args(parser)


def _add_start_stream_args(parser: argparse.ArgumentParser) -> None:
    _add_stream_args(parser, include_template=True)


def _add_stop_stream_args(parser: argparse.ArgumentParser) -> None:
    _add_stream_args(parser, include_template=False)


def _add_stream_args(parser: argparse.ArgumentParser, *, include_template: bool) -> None:
    _add_user_id_arg(parser)
    parser.add_argument("--ports", required=True, help="Comma-separated TRex port IDs occupied by this operation.")
    parser.add_argument("--txport", required=True, help="TRex port ID that transmits traffic.")
    parser.add_argument(
        "--rxport",
        required=True,
        help=(
            "TRex port ID that receives traffic, or comma-separated IDs for multi-port "
            "observation (e.g. 2_4,2_5): one capture spans all listed ports and received "
            "packets are counted per port."
        ),
    )
    parser.add_argument("--name", required=True, help="Runtime stream instance name.")
    if include_template:
        parser.add_argument("--template", required=True, help="Traffic template name created by apply-template.")
    _add_payload_args(parser)


def _add_verify_loss_args(parser: argparse.ArgumentParser) -> None:
    _add_stream_args(parser, include_template=False)
    parser.add_argument("--max-loss", type=float, required=True, help="Maximum allowed loss ratio (>= 0).")
    parser.add_argument(
        "--expect-ports",
        default=None,
        help=(
            "JSON array of per-port expected ratios for multi-port observation, e.g. "
            "'[{\"port\":\"2_4\",\"ratio\":100},{\"port\":\"2_5\",\"ratio\":0}]'. "
            "Ratios must sum to 100 (ratio split) or 0 (no packet at all)."
        ),
    )
    parser.add_argument(
        "--tolerance",
        type=float,
        default=None,
        help=(
            "Allowed deviation in percentage points for intermediate ratios "
            "(0 and 100 stay strict; omitted = 0)."
        ),
    )


def _add_capture_common_args(parser: argparse.ArgumentParser) -> None:
    """start/stop capture 共用的定位参数（与已有 start/stop stream 同形）。"""
    _add_user_id_arg(parser)
    parser.add_argument("--ports", required=True, help="Comma-separated TRex port IDs occupied by this operation.")
    parser.add_argument("--rxport", required=True, help="TRex port ID that receives traffic (default capture port).")
    parser.add_argument("--txport", help="TRex port ID that transmits traffic (required when capturing tx).")
    parser.add_argument(
        "--capture-port",
        choices=("rx", "tx"),
        help="Which port to capture: rx (default) or tx. Must match between start and stop.",
    )


def _add_start_capture_args(parser: argparse.ArgumentParser) -> None:
    _add_capture_common_args(parser)
    _add_payload_args(parser)


def _add_stop_capture_args(parser: argparse.ArgumentParser) -> None:
    _add_capture_common_args(parser)
    # check_* 传哪个验哪个；不传的项不参与判定（观测模式）。
    # ⚠️ check 不通过时服务端返回失败 envelope（STATE_MISMATCH），断言才能驱动用例 PASS/FAIL。
    parser.add_argument("--check-vlan", type=int, help="Every captured packet must carry this VLAN tag.")
    no_vlan = parser.add_mutually_exclusive_group()
    no_vlan.add_argument("--check-no-vlan", dest="check_no_vlan", action="store_true", default=None,
                         help="Every captured packet must be untagged.")
    no_vlan.add_argument("--check-vlan-present", dest="check_no_vlan", action="store_false",
                         help="Captured packets must carry a VLAN tag (inverse of --check-no-vlan).")
    fragment = parser.add_mutually_exclusive_group()
    fragment.add_argument("--check-fragment", dest="check_fragment", action="store_true", default=None,
                          help="Fragmented packets must be present.")
    fragment.add_argument("--check-no-fragment", dest="check_fragment", action="store_false",
                          help="Fragmented packets must be absent.")
    parser.add_argument("--check-l4-protocol", choices=("tcp", "udp"), help="L4 protocol must be tcp or udp.")
    parser.add_argument("--check-ip-version", type=int, choices=(4, 6), help="IP version must be 4 or 6.")
    parser.add_argument("--check-min-packets", type=int, help="At least this many packets must be captured.")
    parser.add_argument("--check-arp-opcode", type=int, choices=(1, 2),
                        help="Every ARP packet must have this opcode (1=request, 2=reply) and at least one must exist.")
    parser.add_argument("--check-arp-sender-ips",
                        help="Comma-separated ARP sender IPs; each must appear at least once in the capture "
                             "(asserts 'all interface addresses are sent' / Bug-226456 missing-IP regression).")
    parser.add_argument("--check-eth-dst",
                        help="At least one captured packet must have this destination MAC (case-insensitive). "
                             "Used for static-ARP DMAC-rewrite assertions; requires the capture port to be "
                             "acquired (promiscuous) or the frame to be broadcast.")
    _add_payload_args(parser)


def _run_start_capture(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_start_capture")


def _run_stop_capture(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_stop_capture")


def _add_verify_ownership_args(parser: argparse.ArgumentParser) -> None:
    _add_payload_args(parser)


def _add_query_port_status_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument(
        "--ports",
        default=None,
        help="Comma-separated logical port names to query, e.g. 2_1,2_2. If omitted, queries all ports.",
    )
    _add_payload_args(parser)


def _add_config_stateful_interface_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument(
        "--interfaces",
        required=True,
        help="JSON array of interface objects: port, ip, gateway, and optional mac/peer-mac/vlan fields.",
    )
    _add_payload_args(parser)


def _add_apply_stateful_template_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument(
        "--template",
        required=True,
        help="Pre-defined ASTF template name (http-simple, http-multi, http-attack, ftp-auth, p2p-replay, dns-query, ftp-download, mixed-services).",
    )
    parser.add_argument(
        "--tunables",
        default=None,
        help="JSON string of template-specific tunables (e.g. '{\"fsize\": 500}').",
    )
    _add_payload_args(parser)


def _add_start_stateful_stream_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument("--mult", type=int, default=1, help="CPS multiplier (default 1).")
    parser.add_argument("--duration", type=int, default=-1, help="Duration in seconds (-1 = continuous).")
    _add_payload_args(parser)


def _add_start_custom_l7_stream_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument(
        "--template",
        choices=("http-attack", "ftp-auth"),
        default="http-attack",
        help="Custom L7 ASTF template to apply and start (default http-attack).",
    )
    parser.add_argument(
        "--tunables",
        default=None,
        help=(
            "JSON object of template-specific tunables, passed unchanged to "
            "tg_apply_stateful_template (e.g. '{\"method\":\"POST\",\"uri\":\"/login\"}')."
        ),
    )
    parser.add_argument("--mult", type=int, default=1, help="CPS multiplier (default 1).")
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Duration in seconds (-1 = continuous until stopped). Defaults to 30.",
    )
    _add_payload_args(parser)


def _add_start_pcap_stream_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument(
        "--pcap",
        required=False,
        default=None,
        help=(
            "pcap basename under the TG avl directory (no path separators or '..'). "
            "Required unless --payload-json/--payload-file is given."
        ),
    )
    parser.add_argument(
        "--cps",
        type=float,
        default=10,
        help="Connections per second for pcap replay (default 10).",
    )
    parser.add_argument("--mult", type=int, default=1, help="CPS multiplier (default 1).")
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Duration in seconds (-1 = continuous until stopped). Defaults to 30.",
    )
    _add_payload_args(parser)


def _add_verify_stateful_metrics_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    parser.add_argument(
        "--max-loss",
        type=float,
        default=None,
        help="Maximum allowed loss ratio. If omitted, only returns stats.",
    )
    _add_payload_args(parser)


def _add_stop_stateful_stream_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    _add_payload_args(parser)


def _add_delete_stateful_template_args(parser: argparse.ArgumentParser) -> None:
    _add_user_id_arg(parser)
    _add_payload_args(parser)


# ── Handler 函数 ──────────────────────────────────────────


def _run_acquire_ports(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_acquire_ports")


def _run_config_interface(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_config_interface")


def _run_apply_template(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_apply_traffic_template")


def _run_delete_template(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_delete_traffic_template")


def _run_start_stream(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_start_traffic_stream")


def _run_stop_stream(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_stop_traffic_stream")


def _run_verify_loss(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_verify_traffic_loss")


def _run_release_ports(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_release_ports")


def _run_query_port_status(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_query_port_status")


def _run_verify_ownership(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_verify_ownership")


def _run_config_stateful_interface(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_config_stateful_interface")


def _run_apply_stateful_template(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_apply_stateful_template")


def _run_start_stateful_stream(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_start_stateful_stream")


def _run_start_custom_l7_stream(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_start_custom_l7_stream")


def _run_start_pcap_stream(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_start_pcap_stream")


def _run_verify_stateful_metrics(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_verify_stateful_metrics")


def _run_stop_stateful_stream(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_stop_stateful_stream")


def _run_delete_stateful_template(args: argparse.Namespace) -> int:
    return _run_trex(args, "tg_delete_stateful_template")


def _run_trex(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.trex import (
        build_trex_dry_run,
        build_trex_payload,
        execute_trex,
        load_trex_json_payload,
        validate_trex_payload,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        raw_payload = load_trex_json_payload(
            payload_file=getattr(args, "payload_file", None),
            payload_json=getattr(args, "payload_json", None),
        )
        if raw_payload is not None:
            payload = validate_trex_payload(op_id, raw_payload)
        else:
            payload = build_trex_payload(op_id, _params_from_args(args, op_id))

        if not ctx.get("execute"):
            result = build_trex_dry_run(
                op_id=op_id,
                base_url=ctx["base_url"],
                payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_trex(
                op_id=op_id,
                base_url=ctx["base_url"],
                payload=payload,
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


def _params_from_args(args: argparse.Namespace, op_id: str) -> dict[str, Any]:
    if op_id == "tg_acquire_ports":
        return {"user_id": getattr(args, "user_id", None), "ports": _parse_ports(getattr(args, "ports", ""))}
    if op_id == "tg_release_ports":
        params: dict[str, Any] = {"user_id": getattr(args, "user_id", None)}
        ports_str = getattr(args, "ports", None)
        if ports_str:
            params["ports"] = _parse_ports(ports_str)
        return params
    if op_id == "tg_verify_ownership":
        return {}
    if op_id in {"tg_start_capture", "tg_stop_capture"}:
        params: dict[str, Any] = {
            "user_id": getattr(args, "user_id", "default"),
            "ports": _parse_ports(getattr(args, "ports", "")),
            "rxport": getattr(args, "rxport", None),
        }
        for key in ("txport", "capture_port"):
            value = getattr(args, key, None)
            if value is not None:
                params[key] = value
        if op_id == "tg_stop_capture":
            # check_* 传哪个验哪个；None（未传）不进 payload，服务端不参与判定
            for key in ("check_vlan", "check_no_vlan", "check_fragment", "check_l4_protocol",
                        "check_ip_version", "check_min_packets", "check_arp_opcode",
                        "check_eth_dst", "check_arp_sender_ips"):
                value = getattr(args, key, None)
                if value is not None:
                    # check_arp_sender_ips 是列表语义，CLI 收逗号串 -> 拆成 list
                    if key == "check_arp_sender_ips" and isinstance(value, str):
                        value = [item.strip() for item in value.split(",") if item.strip()]
                    params[key] = value
        return params
    if op_id == "tg_query_port_status":
        params: dict[str, Any] = {"user_id": getattr(args, "user_id", "default")}
        ports_str = getattr(args, "ports", None)
        if ports_str:
            params["ports"] = _parse_ports(ports_str)
        return params
    if op_id == "tg_config_interface":
        return {
            "user_id": getattr(args, "user_id", "default"),
            "interfaces": _parse_interfaces(getattr(args, "interfaces", "")),
        }
    if op_id == "tg_apply_traffic_template":
        return {
            "user_id": getattr(args, "user_id", "default"),
            "template": getattr(args, "template", None),
            "tx_port": getattr(args, "tx_port", None),
            "rx_port": getattr(args, "rx_port", None),
            "ip_version": getattr(args, "ip_version", "ipv4"),
            "l4_protocol": getattr(args, "l4_protocol", None),
            "l4_sport": getattr(args, "l4_sport", None),
            "l4_dport": getattr(args, "l4_dport", None),
            "stream_count": getattr(args, "stream_count", None),
            "traffic_mode": getattr(args, "traffic_mode", None),
            "rate": getattr(args, "rate", None),
            "count": getattr(args, "count", None),
            "frame_size": getattr(args, "frame_size", None),
            "vlan": getattr(args, "vlan", None),
            "src_ip": getattr(args, "src_ip", None),
            "dst_ip": getattr(args, "dst_ip", None),
            "src_mac": getattr(args, "src_mac", None),
            "dst_mac": getattr(args, "dst_mac", None),
        }
    if op_id in {"tg_start_traffic_stream", "tg_stop_traffic_stream", "tg_verify_traffic_loss"}:
        params = {
            "user_id": getattr(args, "user_id", "default"),
            "ports": _parse_ports(getattr(args, "ports", "")),
            "txport": getattr(args, "txport", None),
            "rxport": _parse_rxport(getattr(args, "rxport", None)),
            "name": getattr(args, "name", None),
        }
        if op_id == "tg_start_traffic_stream":
            params["template"] = getattr(args, "template", None)
        if op_id == "tg_verify_traffic_loss":
            params["max_loss"] = getattr(args, "max_loss", None)
            expect_ports = getattr(args, "expect_ports", None)
            if expect_ports:
                params["expect_ports"] = _parse_expect_ports(expect_ports)
            tolerance = getattr(args, "tolerance", None)
            if tolerance is not None:
                params["tolerance"] = tolerance
        return params
    if op_id == "tg_delete_traffic_template":
        return {"user_id": getattr(args, "user_id", "default"), "template": getattr(args, "template", None)}
    if op_id == "tg_config_stateful_interface":
        return {
            "user_id": getattr(args, "user_id", "default"),
            "interfaces": _parse_interfaces(getattr(args, "interfaces", "")),
        }
    if op_id == "tg_apply_stateful_template":
        params: dict[str, Any] = {
            "user_id": getattr(args, "user_id", "default"),
            "template": getattr(args, "template", None),
        }
        tunables_str = getattr(args, "tunables", None)
        if tunables_str:
            params["tunables"] = json.loads(tunables_str)
        return params
    if op_id == "tg_start_stateful_stream":
        return {
            "user_id": getattr(args, "user_id", "default"),
            "mult": getattr(args, "mult", 1),
            "duration": getattr(args, "duration", -1),
        }
    if op_id == "tg_start_custom_l7_stream":
        params: dict[str, Any] = {
            "user_id": getattr(args, "user_id", "default"),
            "template": getattr(args, "template", "http-attack"),
            "mult": getattr(args, "mult", 1),
            "duration": getattr(args, "duration", 30),
        }
        tunables_str = getattr(args, "tunables", None)
        if tunables_str:
            params["tunables"] = _parse_json_object("tunables", tunables_str)
        return params
    if op_id == "tg_start_pcap_stream":
        return {
            "user_id": getattr(args, "user_id", "default"),
            "pcap": getattr(args, "pcap", None),
            "cps": getattr(args, "cps", 10),
            "mult": getattr(args, "mult", 1),
            "duration": getattr(args, "duration", 30),
        }
    if op_id == "tg_verify_stateful_metrics":
        params = {"user_id": getattr(args, "user_id", "default")}
        max_loss = getattr(args, "max_loss", None)
        if max_loss is not None:
            params["max_loss"] = max_loss
        return params
    if op_id in {"tg_stop_stateful_stream", "tg_delete_stateful_template"}:
        return {"user_id": getattr(args, "user_id", "default")}
    return {}


def _parse_ports(value: str) -> list[str]:
    ports = [item.strip() for item in (value or "").split(",") if item.strip()]
    if not ports:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ports must contain at least one port id.",
            {"field": "ports"},
        )
    return ports


def _parse_rxport(value: str | None) -> str | list[str]:
    """接收口：单值保持字符串（请求体形状不变），逗号分隔多值转列表。

    多口 = 分口观测：一次抓包覆盖全部 rx 口，回包按 port_id 分口计数。
    单值仍回字符串，既有单口请求逐字不变。
    """
    ports = [item.strip() for item in (value or "").split(",") if item.strip()]
    if not ports:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "rxport must contain at least one port id.",
            {"field": "rxport"},
        )
    return ports[0] if len(ports) == 1 else ports


def _parse_expect_ports(value: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "expect-ports must be a JSON array.",
            {"field": "expect_ports", "reason": exc.msg},
        ) from exc
    if not isinstance(parsed, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "expect-ports must be a JSON array of {port, ratio} objects.",
            {"field": "expect_ports"},
        )
    return parsed


def _parse_json_object(field: str, value: str) -> dict[str, Any]:
    """解析 JSON 对象参数（tunables 等）：拒绝非对象根节点。"""
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must be a JSON object.",
            {"field": field, "reason": exc.msg},
        ) from exc
    if not isinstance(parsed, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must be a JSON object.",
            {"field": field, "type": type(parsed).__name__},
        )
    return parsed


def _parse_interfaces(value: str) -> list[dict[str, Any]]:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "interfaces must be a JSON array.",
            {"field": "interfaces", "reason": exc.msg},
        ) from exc
    if not isinstance(parsed, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "interfaces must be a JSON array of objects.",
            {"field": "interfaces"},
        )
    return parsed
