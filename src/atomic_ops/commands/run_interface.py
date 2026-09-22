"""Network interface runner commands."""

from __future__ import annotations

import argparse
from pathlib import Path
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
    # --id / --interface-kind 不在 argparse 层强制（2026-09-21）：整包重放时两者由
    # payload 自带（PUT /api/v1/intf 是覆盖式 PUT，body 的 id + val 就是完整定义）。
    # 缺参的结构化调用改由 _run_interface 内的 _require_arg 给出结构化
    # RUNNER_VALIDATION_FAILED（而非 argparse 的 usage 报错），与 --payload 的 help
    # 承诺一致 —— 与 run_policy_route.py 的 update 同款处置（先例：缺口 D）。
    # 起因：ptm-team 的 restore_snapshot 回滚把设备 verify 返回的 {"id":..,"val":{..}}
    # 整包经 --payload-json 回灌（op_mapper.handle_rollback），此前 argparse 先拦下
    # 「required: --id, --interface-kind」-> 接口快照永远重放不出去。
    parser.add_argument("--id", action="append", help="Entry id. May be repeated for batch operations. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--interface-kind", choices=("bvi", "sub", "physical", "bond", "tunnel", "pppoe"), help="NGFW interface kind. Tunnel interfaces support PUT and GET only. Required unless --payload-json/--payload-file is given.")
    parser.add_argument("--mode", choices=("Route", "Switch", "Pair", "Monitor"), default="Route", help="NGFW interface mode.")
    parser.add_argument("--name", help="Interface val.name. Defaults to --id.")
    parser.add_argument("--desc", default="", help="Interface description.")
    interface_enabled_group = parser.add_mutually_exclusive_group()
    # P2-42 告警：fw_update_interface 是覆盖式 PUT（全量替换），未传的字段会被清空。
    # 只改开关时必须回填 --ip-address，或加 --keep-ip 让 runner 先查现值回填。
    interface_enabled_group.add_argument("--interface-enabled", dest="interface_enabled", action="store_true", default=True, help="Enable the NGFW interface. WARNING: update is a full-replacement PUT; fields not passed (e.g. --ip-address) are wiped on the device. Use --keep-ip or re-pass --ip-address when only toggling the switch.")
    interface_enabled_group.add_argument("--interface-disabled", dest="interface_enabled", action="store_false", help="Disable the NGFW interface. WARNING: update is a full-replacement PUT; fields not passed (e.g. --ip-address) are wiped on the device. Use --keep-ip or re-pass --ip-address when only toggling the switch.")
    parser.add_argument("--ip-address", action="append", default=[], help="Interface CIDR address. May be repeated for IPv4 and IPv6. WARNING: 'interface update' is a full-replacement PUT; omitting this flag wipes existing IPs unless --keep-ip is given.")
    # P2-42：--keep-ip 让 runner 在 execute 前先 GET 现值 ip_addresses 回填进 payload，
    # 使「只改 enabled 不传 IP」不再清空设备 IP。默认关闭（保持既有全量覆盖语义）。
    parser.add_argument("--keep-ip", action="store_true", default=False, help="(interface update only) Before sending, look up the current device ip_addresses for the id and fill them into the PUT payload, so omitting --ip-address does not wipe existing IPs. Requires --execute (dry-run cannot query the device). Explicit --ip-address values always win.")
    parser.add_argument("--parent-name", help="Subinterface parent interface name, or optional BVI bridge member interface name (bvi kind). When given, the member port must be Switch mode with pvid equal to the BVI instance and linkType 1; prepare it with 'interface update' first.")
    parser.add_argument("--sub-id", type=int, help="Subinterface VLAN/sub id.")
    parser.add_argument("--bvi-instance", type=int, help="BVI instance id. Member port pvid must equal this value.")
    # P2-bond-schema：bond 字段说明。--bond-member 是 append 参数：多成员必须重复
    # 传参（--bond-member GE0_1 --bond-member GE0_2）；逗号串会被当成一个成员名下发。
    parser.add_argument("--bond-id", type=int, help="Bond id (bond kind). Defaults to the number in the entry id, e.g. bond1 -> 1.")
    parser.add_argument("--bond-member", action="append", default=[], help="Physical interface member for a bond (bond kind). May be repeated for multiple members, e.g. --bond-member GE0_1 --bond-member GE0_2. A comma-joined string is sent as ONE member name, not a list.")
    parser.add_argument("--bond-mode", type=int, default=5, help="Bond mode field (bond kind, val.bond.mode).")
    parser.add_argument("--bond-lb", type=int, default=0, help="Bond load-balance field (bond kind, val.bond.lb).")
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
    # 源进源出（CFG-OUTINTF-018）：/api/v1/intf 的 ipv4_reverse_path + ipv4_gateway 两字段。
    # 缺省与历史行为一致（空串 / False），只有显式传参才改变下发内容 —— 既有用例零影响。
    parser.add_argument("--ipv4-gateway", help="val.ipv4_gateway (source-route reverse path next hop, e.g. 10.0.0.1). Defaults to an empty string.")
    # bool 互斥对（同 --interface-enabled/--interface-disabled）：op_mapper 的
    # BOOL_MUTEX_FLAGS 需要 True/False 两个 flag，单 store_true 会让用例传的
    # False 被渲染成 `--ipv4-reverse-path False`（argparse 拒收该尾值）。
    ipv4_rp_group = parser.add_mutually_exclusive_group()
    ipv4_rp_group.add_argument("--ipv4-reverse-path", dest="ipv4_reverse_path", action="store_true", default=False, help="Set val.ipv4_reverse_path to true (strict source-route reverse path). Off by default.")
    ipv4_rp_group.add_argument("--no-ipv4-reverse-path", dest="ipv4_reverse_path", action="store_false", help="Set val.ipv4_reverse_path to false (the default).")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    # #batch-id-list（STORY-REM-02-04）：--id 支持三形态（重复传参 / 逗号分隔 /
    # --id-file 读文件），归并在 handler 内完成；单值形态解析结果与改动前一致。
    parser.add_argument("--id", action="append", help="Entry id. May be repeated, comma-separated (a,b,c), or supplied through --id-file (delete-batch only).")
    parser.add_argument("--id-file", help="Path to a file with one entry id per line ('#' starts a comment; blank lines are ignored). delete-batch only.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")
    # P2 delete 未就绪缺口：DUT 未就绪时 delete 直达 exit 46。--retry 提供可选内部
    # 重试（默认 0 关闭，向后兼容）；仅单条 delete 生效，delete-batch 不自动重试。
    parser.add_argument("--retry", type=int, default=0, help="Optional internal retries when the device is unreachable (exit 46: no response at all). Default 0 (no retry). Applies to single delete only.")
    parser.add_argument("--retry-backoff", type=float, default=1.0, help="Seconds to wait between delete retries. Default 1.0.")


def _read_id_file(path: str) -> list[str]:
    """按行读取 --id-file（忽略空行与 '#' 注释行；兼容 \\r\\n 与 \\n 行尾）。

    文件不可读（OSError）→ RUNNER_VALIDATION_FAILED（含路径），不静默跳过。
    """
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "--id-file is not readable.",
            {"argument": "--id-file", "path": path, "reason": exc.strerror or str(exc)},
        ) from exc
    entry_ids: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        entry_ids.append(stripped)
    return entry_ids


def _batch_delete_entry_ids(args: argparse.Namespace) -> list[str]:
    """归并 --id 三形态为 id 列表（确定性顺序：文件行序 → 传参顺序 → 逗号拆分）。

    单值形态（无逗号、无文件）的解析结果与改动前逐元素一致（兼容承诺）；
    空元素与全空输入显式报错（不静默丢弃、不静默跳过）。
    """
    merged: list[str] = []
    id_file = getattr(args, "id_file", None)
    if id_file:
        merged.extend(_read_id_file(id_file))
    for raw in _arg_list(args, "id"):
        text = str(raw)
        if "," in text:
            merged.extend(part.strip() for part in text.split(","))
        else:
            merged.append(text)
    if not merged:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Missing required runner argument.",
            {"argument": "--id"},
        )
    if any(not item.strip() for item in merged):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Entry id must be a non-empty value (blank elements are rejected, not skipped).",
            {"argument": "--id"},
        )
    return merged


def _reject_id_file(args: argparse.Namespace) -> None:
    """单条 op 不支持 --id-file：显式拒绝而非静默忽略。"""
    if getattr(args, "id_file", None):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "--id-file is only supported by delete-batch.",
            {"argument": "--id-file"},
        )


def _add_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", action="append", help="Entry id.")
    parser.add_argument("--page", type=int, help="Page number for the paginated interface query (fw_verify_interface).")
    parser.add_argument("--size", type=int, help="Page size for the paginated interface query (fw_verify_interface).")
    # P2 大批量 verify 缺口：--page-size 开启内部翻页聚合（默认不传行为不变），
    # 避免 --size 5000 之类的单次超大查询让 DUT 长时间无响应直至连接中断。
    parser.add_argument("--page-size", type=int, help="Aggregate mode: fetch ALL interfaces with internal pagination of this page size instead of one oversized query (use instead of e.g. --size 5000).")


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
        fetch_interface_ip_addresses,
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
            _reject_id_file(args)
            payload = raw_payload or {"id": _single_arg(args, "id")}
            payload = validate_delete_payload(payload)
        elif op_id == "fw_delete_batch_interface":
            # #batch-id-list（STORY-REM-02-04）：--id 三形态归并；payload 直传优先
            # 的既有语义不变（给了 --payload-* 时不读 --id / --id-file）。
            payload = raw_payload or build_interface_batch_delete_payload(
                entry_ids=_batch_delete_entry_ids(args)
            )
            payload = validate_interface_payload(payload, op_id=op_id)
        else:
            if raw_payload is not None:
                payload = validate_interface_payload(raw_payload, op_id=op_id)
            else:
                _require_arg(args, "interface_kind")
                _require_arg(args, "id")
                # P2-42：--keep-ip 仅对 fw_update_interface 生效。显式传了 --ip-address
                # 时以显式值为准；未传且 execute 时先 GET 现值回填，避免覆盖式 PUT 清空
                # 设备 IP（现场故障：STEP-014 恢复只传 enabled，50.0.0.1/24 被清空）。
                # dry-run 不发查询请求，ip_addresses 保持 CLI 值，由 dry-run envelope
                # 的 keep_ip 字段标注意图。
                keep_ip_requested = bool(getattr(args, "keep_ip", False)) and op_id == "fw_update_interface"
                explicit_ips = _arg_list(args, "ip_address")
                effective_ips = explicit_ips
                if keep_ip_requested and not explicit_ips and ctx.get("execute"):
                    effective_ips = fetch_interface_ip_addresses(
                        base_url=ctx["base_url"],
                        session_file=session_file,
                        auth_header=ctx.get("auth_header", "Authorization"),
                        entry_id=_single_arg(args, "id") or "",
                        verify_tls=bool(ctx.get("verify_tls")),
                        timeout=float(ctx.get("timeout", 10.0)),
                    )
                payload = build_interface_payload(
                    interface_kind=getattr(args, "interface_kind"),
                    entry_id=_single_arg(args, "id"),
                    mode=getattr(args, "mode", "Route"),
                    ip_addresses=effective_ips,
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
                    ipv4_gateway=getattr(args, "ipv4_gateway", None),
                    ipv4_reverse_path=bool(getattr(args, "ipv4_reverse_path", False)),
                )
            payload = validate_interface_payload(payload, op_id=op_id)

        if not ctx.get("execute"):
            result = build_interface_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
                query=_verify_query(args, op_id),
                # P2-42：dry-run 无法查询现值，仅标注 --keep-ip 意图
                keep_ip=bool(getattr(args, "keep_ip", False)) and op_id == "fw_update_interface",
            )
        else:
            result = execute_interface(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
                query=_verify_query(args, op_id),
                pppoe_password_env=getattr(args, "pppoe_password_env", None),
                # P2 大批量 verify 缺口：--page-size 聚合模式（默认 None 行为不变）
                aggregate_page_size=getattr(args, "page_size", None),
                # P2 delete 未就绪缺口：删除类 op 可选内部重试（默认 0）
                retries=int(getattr(args, "retry", 0) or 0),
                retry_backoff_seconds=float(getattr(args, "retry_backoff", 1.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
