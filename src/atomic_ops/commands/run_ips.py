"""IPS runner commands (rule/profile config, update, verify, delete, delete-batch).

命令树为 ``run ips rule ...`` 与 ``run ips profile ...`` 两组。规则与模板的
GET/DELETE 都把 JSON 载荷放在请求 body 中，CLI 通过 ``--payload-json``/
``--payload-file`` 可直接透传，也可用普通 flag 构造。
"""

from __future__ import annotations

import argparse
import json
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


def build_subtree() -> tuple[CommandGroup, CommandGroup, CommandGroup]:
    return (
        CommandGroup(
            name="rule",
            help="IPS rule operations.",
            description="IPS rule list/filter/selected-id queries plus create, update, delete and batch-delete operations.",
            children=(
                CommandSpec(
                    name="config",
                    help="Create a custom IPS rule.",
                    description="Create a custom IPS rule through POST /api/v1/appsec/ips/rules.",
                    handler=_run_rule_config,
                    add_args=_add_rule_config_args,
                ),
                CommandSpec(
                    name="update",
                    help="Update a custom IPS rule by id.",
                    description="Update a custom IPS rule by id through PUT /api/v1/appsec/ips/rules.",
                    handler=_run_rule_update,
                    add_args=_add_rule_update_args,
                ),
                CommandSpec(
                    name="verify",
                    help="Query IPS rules.",
                    description=(
                        "Query IPS rules through GET /api/v1/appsec/ips/rules using either the "
                        "selected-id detail body or the list/filter body."
                    ),
                    handler=_run_rule_verify,
                    add_args=_add_rule_verify_args,
                ),
                CommandSpec(
                    name="delete",
                    help="Delete one custom IPS rule by id.",
                    description="Delete one custom IPS rule through DELETE /api/v1/appsec/ips/rules.",
                    handler=_run_rule_delete,
                    add_args=_add_delete_args,
                ),
                CommandSpec(
                    name="delete-batch",
                    help="Delete multiple custom IPS rules.",
                    description="Batch-delete custom IPS rules through POST /api/v1/batch.",
                    handler=_run_rule_delete_batch,
                    add_args=_add_delete_batch_args,
                ),
            ),
        ),
        CommandGroup(
            name="profile",
            help="IPS protection-profile operations.",
            description="IPS protection-profile list queries plus create, update, delete and batch-delete operations.",
            children=(
                CommandSpec(
                    name="config",
                    help="Create an IPS protection profile.",
                    description="Create an IPS protection profile through POST /api/v1/appsec/ips/profiles.",
                    handler=_run_profile_config,
                    add_args=_add_profile_config_args,
                ),
                CommandSpec(
                    name="update",
                    help="Update an IPS protection profile by id.",
                    description="Update an IPS protection profile by id through PUT /api/v1/appsec/ips/profiles.",
                    handler=_run_profile_update,
                    add_args=_add_profile_update_args,
                ),
                CommandSpec(
                    name="verify",
                    help="Query IPS protection profiles.",
                    description="Query IPS protection profiles through GET /api/v1/appsec/ips/profiles.",
                    handler=_run_profile_verify,
                    add_args=_add_profile_verify_args,
                ),
                CommandSpec(
                    name="delete",
                    help="Delete one IPS protection profile by id.",
                    description="Delete one IPS protection profile through DELETE /api/v1/appsec/ips/profiles.",
                    handler=_run_profile_delete,
                    add_args=_add_delete_args,
                ),
                CommandSpec(
                    name="delete-batch",
                    help="Delete multiple IPS protection profiles.",
                    description="Batch-delete IPS protection profiles through POST /api/v1/batch.",
                    handler=_run_profile_delete_batch,
                    add_args=_add_delete_batch_args,
                ),
            ),
        ),
        CommandGroup(
            name="log",
            help="IPS security-log query, evidence, and pcap operations.",
            description=(
                "Query /api/v1/monitor/seclog, read packet-capture evidence metadata from "
                "/api/v1/seclog/evidence, and download the pcap from /api/v1/downloadfile."
            ),
            children=(
                CommandSpec(
                    name="capture",
                    help="Query IPS security logs.",
                    description="Query security logs through GET /api/v1/monitor/seclog.",
                    handler=_run_log_capture,
                    add_args=_add_log_capture_args,
                ),
                CommandSpec(
                    name="evidence",
                    help="Query packet-capture evidence metadata.",
                    description="Query evidence metadata through GET /api/v1/seclog/evidence?meta_file=...",
                    handler=_run_log_evidence,
                    add_args=_add_log_evidence_args,
                ),
                CommandSpec(
                    name="download-pcap",
                    help="Download a security-log pcap file.",
                    description="Download a pcap through GET /api/v1/downloadfile?id=logpcap/...",
                    handler=_run_log_download_pcap,
                    add_args=_add_log_download_pcap_args,
                ),
                CommandSpec(
                    name="cache-set",
                    help="Configure global log-cache merging.",
                    description=(
                        "Configure global log-cache merging through PUT /api/v1/logsetting/logcacheset. "
                        "The endpoint is global and is used by the IPS log flow; no GET readback exists."
                    ),
                    handler=_run_log_cache_set,
                    add_args=_add_log_cache_args,
                ),
                CommandSpec(
                    name="export",
                    help="Export IPS logs as CSV.",
                    description="Export IPS logs through GET /api/v1/export?id=logexport&logtype=ipslog&type=csv...",
                    handler=_run_log_export,
                    add_args=_add_log_export_args,
                ),
                CommandSpec(
                    name="clear",
                    help="Clear IPS security logs.",
                    description="Clear IPS logs through DELETE /api/v1/deletelog?logtype=ipslog.",
                    handler=_run_log_clear,
                    add_args=_add_log_clear_args,
                ),
                CommandSpec(
                    name="time-set",
                    help="Configure the log backup/retention time.",
                    description="Configure the log time setting through PUT /api/v1/logsetting/logtimesetting.",
                    handler=_run_log_time_set,
                    add_args=_add_log_time_set_args,
                ),
                CommandSpec(
                    name="time-verify",
                    help="Read the log backup/retention time.",
                    description="Read the log time setting through GET /api/v1/logsetting/logtimesetting.",
                    handler=_run_log_time_verify,
                    add_args=_add_no_args,
                ),
                CommandSpec(
                    name="cache-verify",
                    help="Read the global log-cache setting.",
                    description="Read the log-cache setting through GET /api/v1/logsetting/logcacheset.",
                    handler=_run_log_cache_verify,
                    add_args=_add_no_args,
                ),
                CommandSpec(
                    name="backup-list",
                    help="List log backup files.",
                    description="List backup files through GET /api/v1/logsetting/logbackcsv.",
                    handler=_run_log_backup_list,
                    add_args=_add_log_backup_list_args,
                ),
                CommandSpec(
                    name="download-task-create",
                    help="Create a log export download task.",
                    description="Create a download task through POST /api/v1/downloadfilehandle.",
                    handler=_run_log_download_task_create,
                    add_args=_add_log_download_task_create_args,
                ),
                CommandSpec(
                    name="download-task-verify",
                    help="Query a log export download task.",
                    description="Query a download task through GET /api/v1/downloadfilehandle?id=<taskid>.",
                    handler=_run_log_download_task_verify,
                    add_args=_add_log_download_task_verify_args,
                ),
                CommandSpec(
                    name="download-file",
                    help="Download an exported log file.",
                    description="Download an exported log file through GET /api/v1/downloadfile?id=<filename>.",
                    handler=_run_log_download_file,
                    add_args=_add_log_download_file_args,
                ),
            ),
        ),
    )


# ── 参数注册 ──────────────────────────────────────────────


def _add_payload_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_rule_val_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--name",
        default="",
        help="Rule name. Required unless --is-profenal is set or --payload-json/--payload-file is given.",
    )
    parser.add_argument(
        "--desc",
        help="Raw Snort-style rule body. Required unless --payload-json/--payload-file is given.",
    )
    parser.add_argument(
        "--is-profenal",
        action="store_true",
        help="Use the protection-rule form; the device derives the displayed name from the rule text.",
    )
    _add_payload_args(parser)


def _add_rule_config_args(parser: argparse.ArgumentParser) -> None:
    _add_rule_val_args(parser)


def _add_rule_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="Numeric IPS rule id to update.")
    _add_rule_val_args(parser)


def _add_rule_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=10, help="Paginated query page size.")
    parser.add_argument("--key", default="", help="Keyword search value.")
    parser.add_argument("--config-source", default=None, help="Optional config_source value (captured value: 0).")
    parser.add_argument(
        "--id",
        action="append",
        default=[],
        help="Selected rule id for the detail query. Repeat for multiple ids; switches to the selected-id body.",
    )
    parser.add_argument(
        "--level",
        action="append",
        default=[],
        help="Protection-level filter. Repeat for multiple values.",
    )
    parser.add_argument(
        "--direct",
        action="append",
        default=[],
        help="Traffic-direction filter. Repeat for multiple values.",
    )
    parser.add_argument(
        "--os",
        action="append",
        default=[],
        help="Operating-system filter. Repeat for multiple values.",
    )
    parser.add_argument(
        "--classtype",
        action="append",
        default=[],
        help="Rule-category filter. Repeat for multiple values.",
    )
    _add_payload_args(parser)


def _add_profile_val_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", help="Profile name.")
    parser.add_argument("--desc", default="", help="Profile description.")
    parser.add_argument(
        "--val-file",
        help="Path to a complete JSON val object for the profile (name, actionWrapper, filters, whiteList, customAddRuleList, desc).",
    )
    parser.add_argument(
        "--val-json",
        help="Complete JSON val object for the profile (alternative to --val-file).",
    )
    parser.add_argument("--action-wrapper-json", help="JSON list for actionWrapper.")
    parser.add_argument("--filters-json", help="JSON list for filters.")
    parser.add_argument("--white-list-json", help="JSON list for whiteList.")
    parser.add_argument("--custom-add-rule-list-json", help="JSON list for customAddRuleList.")
    _add_payload_args(parser)


def _add_profile_config_args(parser: argparse.ArgumentParser) -> None:
    _add_profile_val_args(parser)


def _add_profile_update_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", help="Numeric IPS profile id to update.")
    _add_profile_val_args(parser)


def _add_profile_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=10, help="Paginated query page size.")
    parser.add_argument("--key", default="", help="Keyword search value.")
    parser.add_argument("--config-source", default=None, help="Optional config_source value (captured value: 0).")
    _add_payload_args(parser)


def _add_delete_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", required=True, help="Numeric IPS id to delete.")


def _add_delete_batch_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--id",
        action="append",
        required=True,
        help="Numeric IPS id to delete. Repeat for multiple ids.",
    )


def _add_log_capture_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--gid",
        type=int,
        default=1,
        help="Security-log module id; only 1 (IPS) is implemented. Other log types will be added later.",
    )
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=10, help="Paginated query page size.")
    parser.add_argument(
        "--timetype",
        choices=("24h", "all", "1h", "7d", "1m", "custom"),
        default="24h",
        help="Time window preset; custom requires --starttime and --endtime.",
    )
    parser.add_argument("--starttime", type=int, help="Unix-second start timestamp (required for custom).")
    parser.add_argument("--endtime", type=int, help="Unix-second end timestamp (required for custom).")
    parser.add_argument("--rule-name", help="Rule-name filter for the IPS log query.")
    parser.add_argument(
        "--level",
        action="append",
        default=[],
        help="Rule-level filter. Repeat for multiple values.",
    )
    parser.add_argument(
        "--action",
        action="append",
        default=[],
        help="Rule-action filter. Repeat for multiple values.",
    )
    parser.add_argument("--xff", help="X-Forwarded-For filter value for the IPS log query.")


def _add_log_evidence_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--meta-file",
        required=True,
        help="Evidence metadata file name from an IPS log entry, e.g. ips_20261019_120000.meta.json.",
    )


def _add_log_download_pcap_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--pcap-filename",
        required=True,
        help="Pcap file name from the log entry or evidence meta.pcap_filename, e.g. ips_20261019_120000.pcap.",
    )
    parser.add_argument("--output-path", required=True, help="Local path where the downloaded pcap is written.")


def _add_log_cache_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", type=int, default=1, help="Log-cache id; only 1 is supported and it is not gid.")
    enable_group = parser.add_mutually_exclusive_group()
    enable_group.add_argument(
        "--enable",
        dest="log_cache_enable",
        action="store_true",
        default=True,
        help="Enable log-cache merging (default).",
    )
    enable_group.add_argument(
        "--disable",
        dest="log_cache_enable",
        action="store_false",
        help="Disable log-cache merging.",
    )
    parser.add_argument(
        "--time-set",
        type=int,
        default=60,
        help="Log merge window as an integer; the unit is device-defined (sample 60).",
    )
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_no_args(parser: argparse.ArgumentParser) -> None:
    return None


def _add_log_export_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--logtype", default="ipslog", help="Log type; only ipslog is implemented.")
    parser.add_argument("--type", dest="export_type", default="csv", help="Export format; only csv is implemented.")
    parser.add_argument(
        "--timetype",
        choices=("24h", "all", "1h", "7d", "1m", "custom"),
        default="24h",
        help="Time window preset; custom requires --starttime and --endtime.",
    )
    parser.add_argument("--starttime", type=int, help="Unix-second start timestamp (required for custom).")
    parser.add_argument("--endtime", type=int, help="Unix-second end timestamp (required for custom).")
    parser.add_argument("--output-path", required=True, help="Local path where the exported response bytes are written.")


def _add_log_clear_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--logtype", default="ipslog", help="Log type; only ipslog is implemented.")


def _add_log_time_set_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--id", default="0", help="Log time-setting id (captured value: 0).")
    parser.add_argument(
        "--time-set",
        type=int,
        default=180,
        help="Backup/retention interval as an integer; the unit is device-defined (sample 180).",
    )
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_log_backup_list_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--page", type=int, default=1, help="Paginated query page.")
    parser.add_argument("--size", type=int, default=10, help="Paginated query page size.")
    parser.add_argument("--keywords", default="", help="Optional keyword filter.")


def _add_log_download_task_create_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--data-id",
        action="append",
        required=True,
        help="Exported data id to include in the download task. Repeat for multiple ids.",
    )
    parser.add_argument("--moduletype", default="influxTask", help="Task module type (captured value: influxTask).")
    parser.add_argument("--filetype", default="csv", help="Download file type (captured value: csv).")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _add_log_download_task_verify_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--task-id", required=True, help="Download task id from download-task-create.")


def _add_log_download_file_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--file-id", required=True, help="Ready filename from download-task-verify.")
    parser.add_argument("--output-path", required=True, help="Local path where the downloaded log file is written.")


# ── 处理器 ────────────────────────────────────────────────


def _run_rule_config(args: argparse.Namespace) -> int:
    return _run_ips(args, "fw_config_ips_rule")


def _run_rule_update(args: argparse.Namespace) -> int:
    return _run_ips(args, "fw_update_ips_rule")


def _run_rule_verify(args: argparse.Namespace) -> int:
    return _run_ips(args, "fw_verify_ips_rule")


def _run_rule_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_ips(args, "fw_delete_ips_rule")


def _run_rule_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_ips(args, "fw_delete_batch_ips_rule")


def _run_profile_config(args: argparse.Namespace) -> int:
    return _run_ips(args, "fw_config_ips_profile")


def _run_profile_update(args: argparse.Namespace) -> int:
    return _run_ips(args, "fw_update_ips_profile")


def _run_profile_verify(args: argparse.Namespace) -> int:
    return _run_ips(args, "fw_verify_ips_profile")


def _run_profile_delete(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_ips(args, "fw_delete_ips_profile")


def _run_profile_delete_batch(args: argparse.Namespace) -> int:
    _require_arg(args, "id")
    return _run_ips(args, "fw_delete_batch_ips_profile")


def _run_log_capture(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_capture_ips_log")


def _run_log_evidence(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_verify_seclog_evidence")


def _run_log_download_pcap(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_download_seclog_pcap")


def _run_log_cache_set(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_config_log_cache_set")


def _run_log_export(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_export_ips_log")


def _run_log_clear(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_clear_ips_log")


def _run_log_time_set(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_config_log_time_set")


def _run_log_time_verify(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_verify_log_time_set")


def _run_log_cache_verify(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_verify_log_cache_set")


def _run_log_backup_list(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_verify_log_backup_list")


def _run_log_download_task_create(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_create_log_download_task")


def _run_log_download_task_verify(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_verify_log_download_task")


def _run_log_download_file(args: argparse.Namespace) -> int:
    return _run_ips_log(args, "fw_download_log_file")


def _run_ips_log(args: argparse.Namespace, op_id: str) -> int:
    """IPS 日志/取证/pcap 下载的公共执行路径。"""
    from atomic_ops.runner.ips import (
        build_ips_evidence_dry_run,
        build_ips_evidence_query,
        build_ips_log_dry_run,
        build_ips_log_query,
        build_ips_pcap_download_dry_run,
        build_log_cache_dry_run,
        build_log_cache_payload,
        execute_ips_evidence,
        execute_ips_log,
        execute_ips_pcap_download,
        execute_log_cache,
    )
    from atomic_ops.runner.log_ops import (
        build_clear_ips_log_dry_run,
        build_clear_ips_log_query,
        build_download_log_file_dry_run,
        build_ips_log_export_dry_run,
        build_ips_log_export_query,
        build_log_backup_list_dry_run,
        build_log_backup_list_query,
        build_log_cache_verify_dry_run,
        build_log_download_task_dry_run,
        build_log_download_task_payload,
        build_log_download_task_verify_dry_run,
        build_log_time_set_dry_run,
        build_log_time_set_payload,
        build_log_time_verify_dry_run,
        execute_clear_ips_log,
        execute_download_log_file,
        execute_ips_log_export,
        execute_log_backup_list,
        execute_log_cache_verify,
        execute_log_download_task,
        execute_log_download_task_verify,
        execute_log_time_set,
        execute_log_time_verify,
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
        base_kwargs: dict[str, Any] = {
            "base_url": ctx["base_url"],
            "session_file": session_file,
            "auth_header": ctx.get("auth_header", "Authorization"),
            "verify_tls": bool(ctx.get("verify_tls")),
            "timeout": float(ctx.get("timeout", 10.0)),
        }
        if op_id == "fw_capture_ips_log":
            query = build_ips_log_query(
                gid=getattr(args, "gid"),
                page=getattr(args, "page", 1),
                size=getattr(args, "size", 10),
                timetype=getattr(args, "timetype", "24h"),
                starttime=getattr(args, "starttime", None),
                endtime=getattr(args, "endtime", None),
                rule_name=getattr(args, "rule_name", None),
                level=_arg_list(args, "level"),
                action=_arg_list(args, "action"),
                xff=getattr(args, "xff", None),
            )
            kwargs = {**base_kwargs, "query": query}
            result = (
                execute_ips_log(**kwargs)
                if ctx.get("execute")
                else build_ips_log_dry_run(**kwargs)
            )
        elif op_id == "fw_verify_seclog_evidence":
            query = build_ips_evidence_query(meta_file=getattr(args, "meta_file", ""))
            kwargs = {**base_kwargs, "query": query}
            result = (
                execute_ips_evidence(**kwargs)
                if ctx.get("execute")
                else build_ips_evidence_dry_run(**kwargs)
            )
        elif op_id == "fw_config_log_cache_set":
            from atomic_ops.runner._payload import load_json_payload

            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            payload = raw_payload if raw_payload is not None else build_log_cache_payload(
                id=getattr(args, "id", 1),
                enable=bool(getattr(args, "log_cache_enable", True)),
                time_set=getattr(args, "time_set", 60),
            )
            kwargs = {**base_kwargs, "payload": payload}
            result = (
                execute_log_cache(**kwargs)
                if ctx.get("execute")
                else build_log_cache_dry_run(**kwargs)
            )
        elif op_id == "fw_export_ips_log":
            query = build_ips_log_export_query(
                logtype=getattr(args, "logtype", "ipslog"),
                export_type=getattr(args, "export_type", "csv"),
                timetype=getattr(args, "timetype", "24h"),
                starttime=getattr(args, "starttime", None),
                endtime=getattr(args, "endtime", None),
            )
            kwargs = {
                **base_kwargs,
                "query": query,
                "output_path": getattr(args, "output_path", ""),
            }
            result = (
                execute_ips_log_export(**kwargs)
                if ctx.get("execute")
                else build_ips_log_export_dry_run(**kwargs)
            )
        elif op_id == "fw_clear_ips_log":
            query = build_clear_ips_log_query(logtype=getattr(args, "logtype", "ipslog"))
            kwargs = {**base_kwargs, "query": query}
            result = (
                execute_clear_ips_log(**kwargs)
                if ctx.get("execute")
                else build_clear_ips_log_dry_run(**kwargs)
            )
        elif op_id == "fw_config_log_time_set":
            from atomic_ops.runner._payload import load_json_payload

            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            payload = raw_payload if raw_payload is not None else build_log_time_set_payload(
                id=getattr(args, "id", "0"),
                time_set=getattr(args, "time_set", 180),
            )
            kwargs = {**base_kwargs, "payload": payload}
            result = (
                execute_log_time_set(**kwargs)
                if ctx.get("execute")
                else build_log_time_set_dry_run(**kwargs)
            )
        elif op_id == "fw_verify_log_time_set":
            result = (
                execute_log_time_verify(**base_kwargs)
                if ctx.get("execute")
                else build_log_time_verify_dry_run(**base_kwargs)
            )
        elif op_id == "fw_verify_log_cache_set":
            result = (
                execute_log_cache_verify(**base_kwargs)
                if ctx.get("execute")
                else build_log_cache_verify_dry_run(**base_kwargs)
            )
        elif op_id == "fw_verify_log_backup_list":
            query = build_log_backup_list_query(
                page=getattr(args, "page", 1),
                size=getattr(args, "size", 10),
                keywords=getattr(args, "keywords", "") or "",
            )
            kwargs = {**base_kwargs, "query": query}
            result = (
                execute_log_backup_list(**kwargs)
                if ctx.get("execute")
                else build_log_backup_list_dry_run(**kwargs)
            )
        elif op_id == "fw_create_log_download_task":
            from atomic_ops.runner._payload import load_json_payload

            raw_payload = load_json_payload(
                payload_file=getattr(args, "payload_file", None),
                payload_json=getattr(args, "payload_json", None),
            )
            payload = raw_payload if raw_payload is not None else build_log_download_task_payload(
                data_ids=_arg_list(args, "data_id"),
                moduletype=getattr(args, "moduletype", "influxTask"),
                filetype=getattr(args, "filetype", "csv"),
            )
            kwargs = {**base_kwargs, "payload": payload}
            result = (
                execute_log_download_task(**kwargs)
                if ctx.get("execute")
                else build_log_download_task_dry_run(**kwargs)
            )
        elif op_id == "fw_verify_log_download_task":
            kwargs = {**base_kwargs, "task_id": getattr(args, "task_id", "")}
            result = (
                execute_log_download_task_verify(**kwargs)
                if ctx.get("execute")
                else build_log_download_task_verify_dry_run(**kwargs)
            )
        elif op_id == "fw_download_log_file":
            kwargs = {
                **base_kwargs,
                "file_id": getattr(args, "file_id", ""),
                "output_path": getattr(args, "output_path", ""),
            }
            result = (
                execute_download_log_file(**kwargs)
                if ctx.get("execute")
                else build_download_log_file_dry_run(**kwargs)
            )
        elif op_id == "fw_download_seclog_pcap":
            kwargs = {
                **base_kwargs,
                "pcap_filename": getattr(args, "pcap_filename", ""),
                "output_path": getattr(args, "output_path", ""),
            }
            result = (
                execute_ips_pcap_download(**kwargs)
                if ctx.get("execute")
                else build_ips_pcap_download_dry_run(**kwargs)
            )
        else:
            raise RunnerError(
                "RUNNER_UNSUPPORTED_OP",
                "Runner does not support this log operation.",
                {"op_id": op_id},
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


# ── 公共执行路径 ──────────────────────────────────────────


def _run_ips(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner._payload import load_json_payload
    from atomic_ops.runner.ips import (
        build_ips_dry_run,
        execute_ips,
        validate_ips_payload,
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
        payload = _build_payload(args, op_id, load_json_payload)
        if op_id in {"fw_delete_batch_ips_rule", "fw_delete_batch_ips_profile"}:
            payload = validate_ips_payload(payload, op_id=op_id)

        runner_kwargs: dict[str, Any] = {
            "op_id": op_id,
            "base_url": ctx["base_url"],
            "session_file": session_file,
            "auth_header": ctx.get("auth_header", "Authorization"),
            "payload": payload,
            "verify_tls": bool(ctx.get("verify_tls")),
            "timeout": float(ctx.get("timeout", 10.0)),
        }
        if not ctx.get("execute"):
            result = build_ips_dry_run(**runner_kwargs)
        else:
            result = execute_ips(**runner_kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _build_payload(args: argparse.Namespace, op_id: str, load_json_payload: Any) -> dict[str, Any]:
    from atomic_ops.runner.ips import (
        build_ips_profile_batch_delete_payload,
        build_ips_profile_delete_payload,
        build_ips_profile_payload,
        build_ips_profile_query_payload,
        build_ips_profile_update_payload,
        build_ips_rule_batch_delete_payload,
        build_ips_rule_delete_payload,
        build_ips_rule_payload,
        build_ips_rule_query_payload,
        build_ips_rule_update_payload,
    )

    raw_payload = load_json_payload(
        payload_file=getattr(args, "payload_file", None),
        payload_json=getattr(args, "payload_json", None),
    )

    if op_id in {"fw_config_ips_rule", "fw_update_ips_rule"}:
        if raw_payload is not None:
            return raw_payload
        if op_id == "fw_update_ips_rule":
            _require_arg(args, "id")
        _require_arg(args, "desc")
        name = getattr(args, "name", "") or ""
        if not getattr(args, "is_profenal", False):
            _require_arg(args, "name")
        if op_id == "fw_config_ips_rule":
            return build_ips_rule_payload(
                name=name,
                desc=getattr(args, "desc"),
                is_profenal=bool(getattr(args, "is_profenal", False)),
            )
        return build_ips_rule_update_payload(
            entry_id=_single_arg(args, "id") or "",
            name=name,
            desc=getattr(args, "desc"),
            is_profenal=bool(getattr(args, "is_profenal", False)),
        )

    if op_id == "fw_verify_ips_rule":
        if raw_payload is not None:
            return raw_payload
        return build_ips_rule_query_payload(
            ids=_arg_list(args, "id"),
            page=getattr(args, "page", 1),
            size=getattr(args, "size", 10),
            key=getattr(args, "key", "") or "",
            config_source=getattr(args, "config_source", None),
            level=_arg_list(args, "level"),
            direct=_arg_list(args, "direct"),
            os=_arg_list(args, "os"),
            classtype=_arg_list(args, "classtype"),
        )

    if op_id == "fw_delete_ips_rule":
        return build_ips_rule_delete_payload(entry_id=_single_arg(args, "id") or "")
    if op_id == "fw_delete_batch_ips_rule":
        return build_ips_rule_batch_delete_payload(entry_ids=_arg_list(args, "id"))

    if op_id in {"fw_config_ips_profile", "fw_update_ips_profile"}:
        if raw_payload is not None:
            val = raw_payload.get("val")
            if isinstance(val, dict):
                _validate_profile_val(val)
            return raw_payload
        val_payload = load_json_payload(
            payload_file=getattr(args, "val_file", None),
            payload_json=getattr(args, "val_json", None),
        )
        if op_id == "fw_update_ips_profile":
            _require_arg(args, "id")
        if val_payload is not None:
            _validate_profile_val(val_payload)
            if op_id == "fw_config_ips_profile":
                return {"val": val_payload}
            return {"id": _single_arg(args, "id"), "val": val_payload}
        action_wrapper = _load_json_list(args, "action_wrapper_json", "actionWrapper")
        filters = _load_json_list(args, "filters_json", "filters")
        white_list = _load_json_list(args, "white_list_json", "whiteList")
        custom_add_rule_list = _load_json_list(args, "custom_add_rule_list_json", "customAddRuleList")
        if op_id == "fw_config_ips_profile":
            _require_arg(args, "name")
            return build_ips_profile_payload(
                name=getattr(args, "name"),
                action_wrapper=action_wrapper,
                filters=filters,
                white_list=white_list,
                custom_add_rule_list=custom_add_rule_list,
                desc=getattr(args, "desc", "") or "",
            )
        _require_arg(args, "name")
        return build_ips_profile_update_payload(
            entry_id=_single_arg(args, "id") or "",
            name=getattr(args, "name"),
            action_wrapper=action_wrapper,
            filters=filters,
            white_list=white_list,
            custom_add_rule_list=custom_add_rule_list,
            desc=getattr(args, "desc", "") or "",
        )

    if op_id == "fw_verify_ips_profile":
        if raw_payload is not None:
            return raw_payload
        return build_ips_profile_query_payload(
            page=getattr(args, "page", 1),
            size=getattr(args, "size", 10),
            key=getattr(args, "key", "") or "",
            config_source=getattr(args, "config_source", None),
        )

    if op_id == "fw_delete_ips_profile":
        return build_ips_profile_delete_payload(entry_id=_single_arg(args, "id") or "")
    if op_id == "fw_delete_batch_ips_profile":
        return build_ips_profile_batch_delete_payload(entry_ids=_arg_list(args, "id"))

    raise RunnerError(
        "RUNNER_UNSUPPORTED_OP",
        "Runner does not support this IPS operation.",
        {"op_id": op_id},
    )


def _load_json_list(args: argparse.Namespace, attribute: str, field: str) -> list[Any] | None:
    raw = getattr(args, attribute, None)
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must be valid JSON.",
            {"field": field, "reason": exc.msg},
        ) from exc
    if not isinstance(value, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} JSON root must be a list.",
            {"field": field, "type": type(value).__name__},
        )
    return value


def _validate_profile_val(val_payload: dict[str, Any]) -> None:
    from atomic_ops.runner.ips import validate_ips_profile_val

    validate_ips_profile_val(val_payload)
