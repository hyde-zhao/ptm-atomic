"""Policy-route runner commands."""

from __future__ import annotations

import argparse
import json
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


def build_subtree() -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(name="config", help="Create a new policy route.", description="Create a new policy route.", handler=_run_config, add_args=_add_common_args),
        CommandSpec(name="config-batch", help="Create multiple policy routes in a loop.", description="Loop-create multiple policy routes by repeated POST /api/v1/policyroute.", handler=_run_config_batch, add_args=_add_config_batch_args),
        CommandSpec(name="update", help="Update an existing policy route.", description="Update an existing policy route by id.", handler=_run_update, add_args=_add_update_args),
        CommandSpec(name="delete", help="Delete a policy route.", description="Delete a policy route by id.", handler=_run_delete, add_args=_add_delete_args),
        CommandSpec(name="delete-batch", help="Delete multiple policy routes.", description="Batch-delete NGFW policy routes by id.", handler=_run_delete_batch, add_args=_add_delete_batch_args),
        CommandSpec(name="verify", help="Verify a policy route.", description="Verify a policy route.", handler=_run_verify, add_args=_add_verify_args),
        CommandSpec(name="reset-hitcount", help="Reset a policy-route hit count.", description="Reset a policy-route hit count to zero by id.", handler=_run_reset_hitcount, add_args=_add_delete_args),
        CommandSpec(name="verify-hitcount", help="Verify a policy-route hit count.", description="Query a policy-route hit count.", handler=_run_verify_hitcount, add_args=_add_verify_args),
        CommandSpec(name="priority", help="Update policy route priority.", description="Update policy route priority ordering.", handler=_run_priority, add_args=_add_priority_args),
    )


def _add_common_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--source-network", required=False, default="any", help="Policy-route source address object or address-group name (default: any; empty normalized to any)."
    )
    parser.add_argument("--source-network-is-group", action="store_true", help="Treat --source-network as an address-group name.")
    parser.add_argument("--dst-network", default="any", help="Policy-route destination address object or address-group name (default: any; empty normalized to any).")
    parser.add_argument("--dst-network-is-group", action="store_true", help="Treat --dst-network as an address-group name.")
    parser.add_argument("--next-hop-ip", help="Policy-route forwarding next-hop IP address.")
    parser.add_argument("--in-interface", required=False, default="any", help="Policy-route incoming interface (default: any; empty normalized to any).")
    parser.add_argument("--outgoing-interface", default="", help="Policy-route outgoing interface.")
    parser.add_argument("--service", default="any", help="Policy-route service object/name.")
    parser.add_argument("--service-is-group", action="store_true", help="Treat --service as a service-group name.")
    parser.add_argument("--weight", type=int, default=100, help="Policy-route forwarding path weight.")
    parser.add_argument("--time-obj", default="", help="Policy-route time object.")
    parser.add_argument("--policy-route-type", choices=("ipv4", "ipv6"), default="ipv4", help="Policy-route address family.")
    policy_route_active_group = parser.add_mutually_exclusive_group()
    policy_route_active_group.add_argument("--policy-route-active", dest="policy_route_active", action="store_true", default=True, help="Enable the policy route.")
    policy_route_active_group.add_argument("--policy-route-inactive", dest="policy_route_active", action="store_false", help="Disable the policy route.")
    parser.add_argument("--policy-route-action", type=int, default=1, help="Policy-route action value.")
    parser.add_argument("--config-source", type=int, default=0, help="Policy-route config_source value.")
    parser.add_argument(
        "--app-list",
        help='JSON list of matched applications, e.g. \'[{"appname":"UDP应用","appid":"479"}]\'. Omit to match no application.',
    )
    parser.add_argument(
        "--app-tag-name",
        help='JSON list of matched application tag names, e.g. \'["限速应用"]\'. Omit to match no application tag.',
    )
    parser.add_argument(
        "--ip-link-name",
        help="IP-link object name to associate with the forwarding path health check (health_check={type:iplink,name}). Omit to keep health_check empty.",
    )


def _add_update_args(parser: argparse.ArgumentParser) -> None:
    _add_common_args(parser)
    # 快照整包重放通道（回滚路径）：ptm-team 的 restore_snapshot 分支把设备 verify 返回的
    # {"id":..,"val":{..}} 整包经 --payload-json 回灌（见 op_mapper.handle_rollback）。
    # 结构化字段无法表达设备的完整条目：forwarding_paths 是嵌套列表而映射表是扁平三字段、
    # applist 与映射表的 app_list 命名不一致 —— 故必须整包下发，见
    # atomic_ops.runner.policy_route.build_policy_route_replay_payload。
    # 仅 update 需要（config 的策略类型是 inverse_op，无整包语义）；两者互斥，都不给时
    # 走既有结构化路径（行为不变）。
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload (overrides structured sources).")
    parser.add_argument("--payload-json", help="Complete JSON request payload (overrides structured sources).")
    # --id 不在 argparse 层强制：整包重放时 id 由 payload 自带。缺 id 的结构化调用改由
    # _run_update 内的 _require_arg 给出结构化 RUNNER_VALIDATION_FAILED（而非 argparse 的
    # usage 报错），与 --payload 的 help 承诺一致。
    parser.add_argument(
        "--id",
        help="Policy-route entry id to update. Required unless --payload-json/--payload-file is given.",
    )


def _add_config_batch_args(parser: argparse.ArgumentParser) -> None:
    _add_common_args(parser)
    parser.add_argument(
        "--count",
        type=int,
        required=True,
        help="Number of policy routes to create in a loop.",
    )
    parser.add_argument(
        "--increment",
        action="store_true",
        help="Increment string parameters per entry (IPv4 host +carry, trailing digits, or 0001-padded name); default keeps all parameters unchanged.",
    )


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    _add_delete_args_impl(parser, require_id=True)


def _add_delete_batch_args(parser: argparse.ArgumentParser) -> None:
    # #batch-id-list（STORY-REM-02-04）：delete-batch 的 id 可由 --id-file 单独提供，
    # 故 --id 不在 argparse 层强制，改由 _batch_delete_entry_ids 在错误出口内显式校验。
    _add_delete_args_impl(parser, require_id=False)


def _add_delete_args_impl(parser: argparse.ArgumentParser, *, require_id: bool) -> None:
    # #batch-id-list（STORY-REM-02-04）：--id 支持三形态（重复传参 / 逗号分隔 /
    # --id-file 读文件），归并在 handler 内完成；单值形态解析结果与改动前一致。
    parser.add_argument("--id", required=require_id, action="append", help="Entry id. May be repeated, comma-separated (a,b,c), or supplied through --id-file (delete-batch only).")
    parser.add_argument("--id-file", help="Path to a file with one entry id per line ('#' starts a comment; blank lines are ignored). delete-batch only.")
    parser.add_argument("--policy-route-type", choices=("ipv4", "ipv6"), default="ipv4", help="Policy-route address family.")
    # P2 delete 未就绪缺口：DUT 未就绪时 delete 直达 exit 46（无响应）。--retry 提供
    # 可选内部重试（默认 0 关闭，向后兼容）；仅对「根本没拿到响应」（46）重试，
    # 设备拒绝（48）不重试。仅单条 delete 生效；delete-batch 不自动重试。
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
    parser.add_argument("--policy-route-type", choices=("ipv4", "ipv6"), default="ipv4", help="Policy-route address family.")
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=40, help="Paginated query page size.")
    # P2 大批量 verify 缺口：--page-size 开启内部翻页聚合，替代 --size 5000 之类的
    # 单次超大查询（现场会令 DUT 无响应直至连接中断）。默认不传则行为不变。
    parser.add_argument("--page-size", type=int, help="Aggregate mode: fetch ALL entries with internal pagination of this page size instead of one oversized query (use instead of e.g. --size 5000).")


def _add_priority_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--targetsite", choices=("before", "after", "first", "last"), required=True, help="Policy-route priority target site.")
    parser.add_argument("--targetid", required=True, help="Policy-route priority target id.")
    parser.add_argument("--moveid", required=True, help="Policy-route priority moving route id.")
    parser.add_argument("--policy-route-type", choices=("ipv4", "ipv6"), default="ipv4", help="Policy-route address family.")


def _parse_json_arg(raw: str | None, *, flag: str) -> Any | None:
    """将 --app-list / --app-tag-name 的 JSON 字符串参数解析为对象。

    省略时返回 None（runner 保持默认空数组）；非法 JSON 直接报 RUNNER_VALIDATION_FAILED，
    与 service-pool 的 --ranges 解析惯例保持一致。
    """
    if not raw:
        return None
    try:
        return json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{flag} must be valid JSON.",
            {"reason": exc.msg},
        ) from exc


def _run_config(args: argparse.Namespace) -> int:
    return _run_policy_route(args, "fw_config_policy_route")


def _run_config_batch(args: argparse.Namespace) -> int:
    from atomic_ops.runner.policy_route import (
        build_policy_route_batch_config_dry_run,
        build_policy_route_batch_config_payloads,
        execute_policy_route_batch_config,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        route_type = getattr(args, "policy_route_type", "ipv4")
        count = int(getattr(args, "count", 1))
        increment = bool(getattr(args, "increment", False))
        base_params: dict[str, Any] = {
            "source_network": getattr(args, "source_network"),
            "source_network_is_group": bool(getattr(args, "source_network_is_group")),
            "dst_network": getattr(args, "dst_network", "any"),
            "dst_network_is_group": bool(getattr(args, "dst_network_is_group")),
            "next_hop_ip": getattr(args, "next_hop_ip") or "",
            "in_interface": getattr(args, "in_interface"),
            "outgoing_interface": getattr(args, "outgoing_interface") or "",
            "service": getattr(args, "service", "any"),
            "service_is_group": bool(getattr(args, "service_is_group")),
            "weight": int(getattr(args, "weight", 100)),
            "time_obj": getattr(args, "time_obj", ""),
            "route_type": route_type,
            "active": bool(getattr(args, "policy_route_active", True)),
            "action": int(getattr(args, "policy_route_action", 1)),
            "config_source": int(getattr(args, "config_source", 0)),
            "applist": _parse_json_arg(getattr(args, "app_list", None), flag="--app-list"),
            "app_tag_name": _parse_json_arg(getattr(args, "app_tag_name", None), flag="--app-tag-name"),
            "ip_link_name": getattr(args, "ip_link_name", None) or None,
        }
        payloads = build_policy_route_batch_config_payloads(count=count, increment=increment, **base_params)

        if not ctx.get("execute"):
            result = build_policy_route_batch_config_dry_run(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payloads=payloads,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_policy_route_batch_config(
                op_id="fw_config_policy_route", base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payloads=payloads,
                page=int(getattr(args, "page", 1)), size=int(getattr(args, "size", 40)),
                route_type=route_type, verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _run_update(args: argparse.Namespace) -> int:
    # 缺参校验不在此处：--id 的 argparse required 已放开（整包重放时 id 由 payload 自带），
    # 而本函数在 _run_policy_route 的 try 块之外，抛 RunnerError 会成裸 traceback。
    # 校验落在 _run_policy_route 的错误出口内（同 fw_delete_batch_policy_route 模式）。
    return _run_policy_route(args, "fw_update_policy_route")


def _run_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_policy_route(args, "fw_delete_policy_route")


def _run_delete_batch(args: argparse.Namespace) -> int:
    # #batch-id-list（STORY-REM-02-04）：--id 三形态（重复 / 逗号 / --id-file）在
    # _run_policy_route 内归并；此处不再前置 _require_arg（--id-file 可单独提供，
    # 且缺参校验落在错误出口内，给结构化 RUNNER_VALIDATION_FAILED 而非 traceback）。
    return _run_policy_route(args, "fw_delete_batch_policy_route")


def _run_verify(args: argparse.Namespace) -> int:
    return _run_policy_route(args, "fw_verify_policy_route")


def _run_reset_hitcount(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_policy_route(args, "fw_reset_policy_route_hitcount")


def _run_verify_hitcount(args: argparse.Namespace) -> int:
    return _run_policy_route(args, "fw_verify_policy_route_hitcount")


def _run_priority(args: argparse.Namespace) -> int:
    return _run_policy_route(args, "fw_update_policy_route_priority")


def _run_policy_route(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.policy_route import (
        build_policy_route_batch_delete_payload,
        build_policy_route_delete_payload,
        build_policy_route_dry_run,
        build_policy_route_payload,
        build_policy_route_priority_payload,
        build_policy_route_replay_payload,
        execute_policy_route,
        validate_policy_route_payload,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        route_type = getattr(args, "policy_route_type", "ipv4")
        payload: dict[str, Any] | None

        # 快照整包重放优先（回滚路径）：仅 fw_update_policy_route 有整包语义，见 _add_update_args。
        # 命中即整包下发，绕过结构化字段（结构化表达不了嵌套 forwarding_paths 与 applist 命名差异）。
        replay_payload = (
            load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if op_id == "fw_update_policy_route"
            else None
        )
        # 缺 --id 的结构化 update：argparse 层已放开 required（整包重放时 id 在 payload 内），
        # 故缺参校验落在此错误出口内，给结构化 RUNNER_VALIDATION_FAILED 而非裸 traceback。
        if op_id == "fw_update_policy_route" and replay_payload is None:
            _require_arg(args, "id")
        if replay_payload is not None:
            payload = build_policy_route_replay_payload(replay_payload, op_id=op_id)
        elif op_id in {"fw_config_policy_route", "fw_update_policy_route"}:
            payload = build_policy_route_payload(
                source_network=getattr(args, "source_network"),
                source_network_is_group=bool(getattr(args, "source_network_is_group")),
                dst_network=getattr(args, "dst_network", "any"),
                dst_network_is_group=bool(getattr(args, "dst_network_is_group")),
                next_hop_ip=getattr(args, "next_hop_ip") or "",
                in_interface=getattr(args, "in_interface"),
                outgoing_interface=getattr(args, "outgoing_interface") or "",
                service=getattr(args, "service", "any"),
                service_is_group=bool(getattr(args, "service_is_group")),
                weight=int(getattr(args, "weight", 100)),
                time_obj=getattr(args, "time_obj", ""),
                route_type=route_type,
                entry_id=_single_arg(args, "id") if op_id == "fw_update_policy_route" else 0,
                active=bool(getattr(args, "policy_route_active", True)),
                action=int(getattr(args, "policy_route_action", 1)),
                config_source=int(getattr(args, "config_source", 0)),
                applist=_parse_json_arg(getattr(args, "app_list", None), flag="--app-list"),
                app_tag_name=_parse_json_arg(getattr(args, "app_tag_name", None), flag="--app-tag-name"),
                ip_link_name=getattr(args, "ip_link_name", None) or None,
            )
        elif op_id == "fw_delete_policy_route":
            _reject_id_file(args)
            payload = build_policy_route_delete_payload(entry_id=_single_arg(args, "id"))
        elif op_id == "fw_delete_batch_policy_route":
            payload = build_policy_route_batch_delete_payload(
                entry_ids=_batch_delete_entry_ids(args),
                route_type=route_type,
            )
            payload = validate_policy_route_payload(payload, op_id=op_id)
        elif op_id == "fw_reset_policy_route_hitcount":
            _reject_id_file(args)
            payload = build_policy_route_delete_payload(entry_id=_single_arg(args, "id"))
        elif op_id == "fw_update_policy_route_priority":
            payload = build_policy_route_priority_payload(
                targetsite=getattr(args, "targetsite"),
                targetid=getattr(args, "targetid"),
                moveid=getattr(args, "moveid"),
                route_type=route_type,
            )
        else:
            payload = None

        if not ctx.get("execute"):
            result = build_policy_route_dry_run(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=int(getattr(args, "page", 1)), size=int(getattr(args, "size", 40)),
                route_type=route_type, verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_policy_route(
                op_id=op_id, base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"), payload=payload,
                page=int(getattr(args, "page", 1)), size=int(getattr(args, "size", 40)),
                route_type=route_type, verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
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
