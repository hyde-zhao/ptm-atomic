"""IPv4 DHCP runner commands (DHCP server config/update/verify/delete, static-IP verify/batch-delete)."""

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

# 只靠 id 定位、没有任何载荷参数的子命令。它们的 --id 必填校验由 _run_dhcp 在
# try 块内完成，见该处的说明。
_ID_ONLY_OPS = frozenset(
    {"fw_delete_dhcp_server", "fw_disable_dhcp_server", "fw_delete_batch_dhcp_static_ip"}
)


def build_subtree() -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(
            name="config",
            help="Create an IPv4 DHCP server on an interface.",
            description="Create an NGFW IPv4 DHCP server through /api/v1/dhcp.",
            handler=_run_config,
            add_args=_add_config_args,
        ),
        CommandSpec(
            name="update",
            help="Update an IPv4 DHCP server by interface name.",
            description="Update an NGFW IPv4 DHCP server by interface name through /api/v1/dhcp.",
            handler=_run_update,
            add_args=_add_update_args,
        ),
        CommandSpec(
            name="disable",
            help="Disable an IPv4 DHCP server by interface name.",
            description=(
                "Disable an NGFW IPv4 DHCP server by reading its live configuration back, "
                "flipping both enable flags to false and replaying the entry verbatim through "
                "PUT /api/v1/dhcp. PUT replaces the whole configuration, so the body cannot be "
                "restated from flags: only --id is accepted."
            ),
            handler=_run_disable,
            add_args=_add_disable_args,
        ),
        CommandSpec(
            name="verify",
            help="Query IPv4 DHCP server configurations.",
            description="Query NGFW IPv4 DHCP server configurations through /api/v1/dhcp.",
            handler=_run_verify,
            add_args=_add_no_args,
        ),
        CommandSpec(
            name="delete",
            help="Delete an IPv4 DHCP server by interface name.",
            description="Delete an NGFW IPv4 DHCP server by interface name through /api/v1/dhcp?id=<ifname>.",
            handler=_run_delete,
            add_args=_add_delete_args,
        ),
        CommandSpec(
            name="static-ip-verify",
            help="List static address bindings across all DHCP servers.",
            description=(
                "List static address bindings by projecting each DHCP server's server.hosts "
                "through /api/v1/dhcp. /api/v1/dhcpstaticip itself exposes no GET (405)."
            ),
            handler=_run_static_ip_verify,
            add_args=_add_no_args,
        ),
        CommandSpec(
            name="static-ip-delete-batch",
            help="Delete static address bindings by IP address.",
            description=(
                "Batch-delete static address bindings by IP address through "
                "POST /api/v1/batchv2 with resource /api/v1/dhcpstaticip."
            ),
            handler=_run_static_ip_delete_batch,
            add_args=_add_static_ip_delete_batch_args,
        ),
    )


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_server_args(parser: argparse.ArgumentParser) -> None:
    # 标量 flag 一律 action="append"，消费侧统一走 _single_arg：重复给出报结构化
    # RUNNER_VALIDATION_FAILED，而不是 argparse 默认的「后者静默胜出」。
    parser.add_argument(
        "--ifname",
        action="append",
        help="Interface the DHCP server binds to (e.g. GE0_13). "
        "Required unless --payload-json/--payload-file is given.",
    )
    parser.add_argument(
        "--server-name",
        action="append",
        help="DHCP server name. Defaults to --ifname; the device requires this field.",
    )
    parser.add_argument(
        "--ifmode",
        action="append",
        choices=("SERVER",),
        help="Interface mode (default: SERVER). Only SERVER is documented for this family.",
    )
    enable_group = parser.add_mutually_exclusive_group()
    enable_group.add_argument(
        "--enable", dest="server_enable", action="store_true", default=True,
        help="Enable the DHCP service (default).",
    )
    enable_group.add_argument(
        "--disable", dest="server_enable", action="store_false",
        help="Disable the DHCP service.",
    )
    parser.add_argument(
        "--subnet",
        action="append",
        help="Subnet in CIDR form (e.g. 8.1.1.0/24). Must sit inside the interface's own "
        "IPv4 subnet, otherwise the device answers eDhcpdConfigIpPoolLimit. Required unless "
        "--payload-json/--payload-file is given. For multiple subnets use --payload-json.",
    )
    parser.add_argument("--range-start", action="append", help="First address of the assignment pool.")
    parser.add_argument("--range-end", action="append", help="Last address of the assignment pool.")
    parser.add_argument("--gateway", action="append", help="Gateway address handed to DHCP clients.")
    parser.add_argument(
        "--lease-limited",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Whether the lease is limited (default: true).",
    )
    parser.add_argument(
        "--lease-default-seconds",
        type=int,
        default=86400,
        help="Default lease duration in seconds (default: 86400).",
    )
    parser.add_argument("--dns1", action="append", help="Primary DNS handed to clients.")
    parser.add_argument("--dns2", action="append", help="Secondary DNS handed to clients.")
    parser.add_argument(
        "--binding",
        action="append",
        default=[],
        metavar="NAME,ADDR,MAC",
        help="Static binding as name,addr,mac. Repeat for multiple bindings. "
        "The addr is what static-ip-delete-batch removes.",
    )
    _add_payload_args(parser)


def _add_config_args(parser: argparse.ArgumentParser) -> None:
    _add_server_args(parser)


def _add_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        action="append",
        help="Interface name of the DHCP server to update. "
        "Required unless --payload-json/--payload-file is given.",
    )
    _add_server_args(parser)


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        action="append",
        required=True,
        help="Interface name of the DHCP server to delete.",
    )


def _add_disable_args(parser: argparse.ArgumentParser) -> None:
    """禁用**只接受 ``--id``**。

    body 在执行期由读回的现有条目生成（PUT 是全量替换，最小 body 会被设备拒绝），
    故不给任何配置 flag —— 给了反而会让调用方以为「没说到的字段会保留」。
    """
    parser.add_argument(
        "--id",
        action="append",
        required=True,
        help="Interface name of the DHCP server to disable.",
    )


def _add_no_args(parser: argparse.ArgumentParser) -> None:
    """本族 verify **刻意不接受任何参数**。

    实测 ``key``／``keywords``／``name``／``ifname``／``page``／``size``／``search``
    七个候选参数全部被设备**静默忽略**（返回全量而非报错）。给一个不生效的
    ``--key`` 比不给更危险 —— 用户会以为自己过滤了。
    """


def _add_static_ip_delete_batch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        action="append",
        required=True,
        help="Static binding IP address to delete (the hosts[].addr value). Repeat per address.",
    )


def _run_config(args: argparse.Namespace) -> int:
    return _run_dhcp(args, "fw_config_dhcp_server")


def _run_update(args: argparse.Namespace) -> int:
    return _run_dhcp(args, "fw_update_dhcp_server")


def _run_verify(args: argparse.Namespace) -> int:
    return _run_dhcp(args, "fw_verify_dhcp_server")


def _run_delete(args: argparse.Namespace) -> int:
    return _run_dhcp(args, "fw_delete_dhcp_server")


def _run_disable(args: argparse.Namespace) -> int:
    return _run_dhcp(args, "fw_disable_dhcp_server")


def _run_static_ip_verify(args: argparse.Namespace) -> int:
    return _run_dhcp(args, "fw_verify_dhcp_static_ip")


def _run_static_ip_delete_batch(args: argparse.Namespace) -> int:
    return _run_dhcp(args, "fw_delete_batch_dhcp_static_ip")


def _build_bindings(raw: list[str]) -> list[dict[str, Any]]:
    """把可重复的 ``--binding NAME,ADDR,MAC`` 解析成绑定字典列表。"""
    bindings: list[dict[str, Any]] = []
    for item in raw:
        parts = [part.strip() for part in str(item).split(",")]
        if len(parts) != 3 or not all(parts):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "--binding must be given as NAME,ADDR,MAC (all three non-empty).",
                {"field": "binding", "value": item},
            )
        name, addr, mac = parts
        bindings.append({"name": name, "addr": addr, "mac": mac})
    return bindings


def _run_dhcp(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.dhcp import (
        build_dhcp_dry_run,
        build_dhcp_payload,
        build_dhcp_static_ip_batch_delete_payload,
        build_dhcp_subnet,
        build_dhcp_update_payload,
        execute_dhcp,
        validate_dhcp_payload,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning(
                {"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."},
                output_format,
            )

        session_file = resolve_session_file(ctx.get("session_file"))
        payload: dict[str, Any] | None
        # 只靠 id 定位的 op：必需的 --id 在这里校验，**必须在 try 内** —— 放在
        # handler 里（调用本函数之前）抛出的 RunnerError 会越过下面的 except，
        # 变成裸 traceback 而不是结构化错误。
        if op_id in _ID_ONLY_OPS:
            _require_arg(args, "id")
        # entry_id 只在「以网卡名定位单个条目」的两个 op 上有意义；批量删的 --id
        # 是 append 列表，绝不能走 _single_arg（那会误报「只能给一次」）。
        entry_id = _single_arg(args, "id") or "" if op_id in {
            "fw_update_dhcp_server",
            "fw_delete_dhcp_server",
            "fw_disable_dhcp_server",
        } else ""

        if op_id in {"fw_config_dhcp_server", "fw_update_dhcp_server"}:
            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            if raw_payload is not None:
                payload = raw_payload
            else:
                _require_arg(args, "ifname")
                subnet = build_dhcp_subnet(
                    # _single_arg 挡住重复给出：--subnet a --subnet b 这类按下标对齐
                    # 的平行数组（--gateway g1 --gateway g2 ...）无法正确配对，多子网
                    # 必须走 --payload-json，故在这里 fail-loud 而不是静默取首个。
                    subnet=_single_arg(args, "subnet") or "",
                    range_start=_single_arg(args, "range_start") or "",
                    range_end=_single_arg(args, "range_end") or "",
                    gateway=_single_arg(args, "gateway") or "",
                )
                server_kwargs: dict[str, Any] = {
                    "ifname": _single_arg(args, "ifname") or "",
                    "ifmode": _single_arg(args, "ifmode") or "SERVER",
                    "enable": bool(getattr(args, "server_enable", True)),
                    "server_name": _single_arg(args, "server_name"),
                    "subnets": [subnet],
                    "lease_limited": bool(getattr(args, "lease_limited", True)),
                    "lease_default_seconds": int(getattr(args, "lease_default_seconds", 86400)),
                    "dns1": _single_arg(args, "dns1") or "",
                    "dns2": _single_arg(args, "dns2") or "",
                    "bindings": _build_bindings(_arg_list(args, "binding")),
                }
                if op_id == "fw_config_dhcp_server":
                    payload = build_dhcp_payload(**server_kwargs)
                else:
                    _require_arg(args, "id")
                    payload = build_dhcp_update_payload(entry_id=entry_id, **server_kwargs)
            # 崩溃护栏：无论载荷来自扁平 flag 还是 --payload-json，都必须带 lease。
            payload = validate_dhcp_payload(payload, op_id=op_id)
        elif op_id == "fw_delete_batch_dhcp_static_ip":
            payload = build_dhcp_static_ip_batch_delete_payload(entry_ids=_arg_list(args, "id"))
            payload = validate_dhcp_payload(payload, op_id=op_id)
        else:
            payload = None

        runner_kwargs = {
            "op_id": op_id,
            "base_url": ctx["base_url"],
            "session_file": session_file,
            "auth_header": ctx.get("auth_header", "Authorization"),
            "payload": payload,
            "entry_id": entry_id,
            "verify_tls": bool(ctx.get("verify_tls")),
            "timeout": float(ctx.get("timeout", 10.0)),
        }
        if not ctx.get("execute"):
            result = build_dhcp_dry_run(**runner_kwargs)
        else:
            result = execute_dhcp(**runner_kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
