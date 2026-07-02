"""Configuration import/export runner commands."""

from __future__ import annotations

import argparse

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
            name="export-file",
            help="Configuration export operations.",
            description="Export an NGFW configuration file through the download workflow.",
            children=(
                CommandSpec(
                    name="config",
                    help="Export a configuration file.",
                    description="Export an NGFW configuration file to a local path.",
                    handler=_run_export,
                    add_args=_add_export_args,
                ),
            ),
        ),
        CommandGroup(
            name="import-file",
            help="Configuration import operations.",
            description="Import an NGFW configuration file through the upload workflow.",
            children=(
                CommandSpec(
                    name="config",
                    help="Import a configuration file.",
                    description="Import an NGFW configuration file from a local path.",
                    handler=_run_import,
                    add_args=_add_import_args,
                ),
            ),
        ),
    )


def _add_export_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--moduletype", required=True, help="NGFW export module type, e.g. systemconfig. Open string.")
    parser.add_argument("--filetype", default="tgz", help="Export archive type. Defaults to tgz.")
    parser.add_argument("--output-path", required=True, help="Local path where the exported file is written.")
    parser.add_argument("--data-id", action="append", default=[], help="Optional data id value. May be repeated.")
    parser.add_argument("--poll-timeout-ms", type=int, default=60000, help="Download task poll timeout in milliseconds.")
    parser.add_argument("--poll-interval-ms", type=int, default=2000, help="Download task poll interval in milliseconds.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload for the download handle step.")
    parser.add_argument("--payload-json", help="Complete JSON request payload for the download handle step.")


def _add_import_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--moduletype", required=True, help="NGFW import module type, e.g. systemconfig. Open string.")
    parser.add_argument("--filetype", default="tgz", help="Import archive type. Defaults to tgz.")
    parser.add_argument("--operationtype", default="override", help="Import merge strategy. Defaults to override.")
    parser.add_argument("--input-path", required=True, help="Local path of the file to upload.")
    chunk_group = parser.add_mutually_exclusive_group()
    chunk_group.add_argument("--chunkornot", dest="chunkornot", action="store_true", default=False, help="Mark the upload as chunked.")
    chunk_group.add_argument("--no-chunkornot", dest="chunkornot", action="store_false", help="Mark the upload as non-chunked (default).")
    parser.add_argument("--poll-timeout-ms", type=int, default=60000, help="Upload task poll timeout in milliseconds.")
    parser.add_argument("--poll-interval-ms", type=int, default=2000, help="Upload task poll interval in milliseconds.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload for the upload handle step.")
    parser.add_argument("--payload-json", help="Complete JSON request payload for the upload handle step.")


def _run_export(args: argparse.Namespace) -> int:
    from atomic_ops.runner.config_transfer import build_export_dry_run, execute_export_file

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        if not ctx.get("execute"):
            result = build_export_dry_run(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                moduletype=_single_arg(args, "moduletype") or "",
                filetype=getattr(args, "filetype", "tgz"),
                output_path=_single_arg(args, "output_path") or "",
                data_id=_arg_list(args, "data_id"),
                poll_timeout_ms=int(getattr(args, "poll_timeout_ms", 60000)),
                poll_interval_ms=int(getattr(args, "poll_interval_ms", 2000)),
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_export_file(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                moduletype=_single_arg(args, "moduletype") or "",
                filetype=getattr(args, "filetype", "tgz"),
                output_path=_single_arg(args, "output_path") or "",
                data_id=_arg_list(args, "data_id"),
                poll_timeout_ms=int(getattr(args, "poll_timeout_ms", 60000)),
                poll_interval_ms=int(getattr(args, "poll_interval_ms", 2000)),
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


def _run_import(args: argparse.Namespace) -> int:
    from atomic_ops.runner.config_transfer import build_import_dry_run, execute_import_file

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        if not ctx.get("execute"):
            result = build_import_dry_run(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                moduletype=_single_arg(args, "moduletype") or "",
                filetype=getattr(args, "filetype", "tgz"),
                operationtype=getattr(args, "operationtype", "override"),
                input_path=_single_arg(args, "input_path") or "",
                chunkornot=bool(getattr(args, "chunkornot", False)),
                poll_timeout_ms=int(getattr(args, "poll_timeout_ms", 60000)),
                poll_interval_ms=int(getattr(args, "poll_interval_ms", 2000)),
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_import_file(
                base_url=ctx["base_url"], session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                moduletype=_single_arg(args, "moduletype") or "",
                filetype=getattr(args, "filetype", "tgz"),
                operationtype=getattr(args, "operationtype", "override"),
                input_path=_single_arg(args, "input_path") or "",
                chunkornot=bool(getattr(args, "chunkornot", False)),
                poll_timeout_ms=int(getattr(args, "poll_timeout_ms", 60000)),
                poll_interval_ms=int(getattr(args, "poll_interval_ms", 2000)),
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
