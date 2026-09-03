"""Object data import/export runner commands."""

from __future__ import annotations

import argparse

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import (
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
            name="import-object",
            help="Object data import operations (module Excel files).",
            description="Upload a module .xlsx file and start the async data import task.",
            children=(
                CommandSpec(
                    name="file",
                    help="Import module data from an .xlsx file.",
                    description="Upload the file to /api/v1/upload and start the /api/v1/dataimport task.",
                    handler=_run_import,
                    add_args=_add_import_args,
                ),
            ),
        ),
        CommandGroup(
            name="export-object",
            help="Object data export generation operations.",
            description="Generate an object module export file through an export trigger endpoint.",
            children=(
                CommandSpec(
                    name="policy",
                    help="Generate an export through /api/v1/ip4policy/exportpolicy.",
                    description="PUT exportpolicy for ippool, ip6pool or ip4group; downloads the file when --output-path is given and the response names it.",
                    handler=_run_export_policy,
                    add_args=_add_export_trigger_args,
                ),
                CommandSpec(
                    name="data",
                    help="Generate an export through /api/v1/dataexport.",
                    description="GET dataexport?type=ip6pool; downloads the file when --output-path is given and the response names it.",
                    handler=_run_export_data,
                    add_args=_add_export_trigger_args,
                ),
            ),
        ),
        CommandGroup(
            name="download-object",
            help="Object template/export file download operations.",
            description="Download a system template or an export file from /api/v1/downloadfile.",
            children=(
                CommandSpec(
                    name="file",
                    help="Download an object module file by id.",
                    description="Download the file identified by --file-id (for example temp/macpool_tmp.xlsx).",
                    handler=_run_download,
                    add_args=_add_download_args,
                ),
            ),
        ),
    )


def _add_import_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--module", required=True, help="Module type (ippool, ip6pool, macpool, domainpool, geoip, ...).")
    parser.add_argument("--input-path", required=True, help="Local path of the .xlsx file to upload and import.")
    parser.add_argument(
        "--is-skip-dup",
        dest="is_skip_dup",
        action="store_true",
        default=True,
        help="Skip duplicate entries during import (default).",
    )
    parser.add_argument(
        "--no-skip-dup",
        dest="is_skip_dup",
        action="store_false",
        help="Overwrite or reject duplicate entries instead of skipping them.",
    )
    parser.add_argument("--payload-file", help="Path to a complete JSON import payload (val object).")
    parser.add_argument("--payload-json", help="Complete JSON import payload (val object).")


def _add_export_trigger_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--module", required=True, help="Module type for the export uploadType/type value.")
    parser.add_argument(
        "--output-path",
        help="Local path where the generated export file is written. Requires the trigger response to name the file.",
    )


def _add_download_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--file-id", required=True, help="Server file id/path, e.g. temp/macpool_tmp.xlsx.")
    parser.add_argument("--output-path", required=True, help="Local path where the downloaded file is written.")


def _run_import(args: argparse.Namespace) -> int:
    from atomic_ops.runner.object_transfer import build_object_import_dry_run, execute_object_import

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        kwargs = dict(
            base_url=ctx["base_url"],
            session_file=session_file,
            auth_header=ctx.get("auth_header", "Authorization"),
            module=_single_arg(args, "module") or "",
            input_path=_single_arg(args, "input_path") or "",
            is_skip_dup=bool(getattr(args, "is_skip_dup", True)),
            verify_tls=bool(ctx.get("verify_tls")),
            timeout=float(ctx.get("timeout", 10.0)),
        )
        result = execute_object_import(**kwargs) if ctx.get("execute") else build_object_import_dry_run(**kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _run_export_policy(args: argparse.Namespace) -> int:
    from atomic_ops.runner.object_transfer import build_object_export_policy_dry_run, execute_object_export_policy

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        kwargs = dict(
            base_url=ctx["base_url"],
            session_file=session_file,
            auth_header=ctx.get("auth_header", "Authorization"),
            module=_single_arg(args, "module") or "",
            output_path=getattr(args, "output_path", None),
            verify_tls=bool(ctx.get("verify_tls")),
            timeout=float(ctx.get("timeout", 10.0)),
        )
        result = execute_object_export_policy(**kwargs) if ctx.get("execute") else build_object_export_policy_dry_run(**kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _run_export_data(args: argparse.Namespace) -> int:
    from atomic_ops.runner.object_transfer import build_object_export_data_dry_run, execute_object_export_data

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        kwargs = dict(
            base_url=ctx["base_url"],
            session_file=session_file,
            auth_header=ctx.get("auth_header", "Authorization"),
            module=_single_arg(args, "module") or "",
            output_path=getattr(args, "output_path", None),
            verify_tls=bool(ctx.get("verify_tls")),
            timeout=float(ctx.get("timeout", 10.0)),
        )
        result = execute_object_export_data(**kwargs) if ctx.get("execute") else build_object_export_data_dry_run(**kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _run_download(args: argparse.Namespace) -> int:
    from atomic_ops.runner.object_transfer import build_object_download_dry_run, execute_object_download

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        if not ctx.get("verify_tls"):
            write_warning({"warning_code": "TLS_VERIFY_DISABLED", "message": "Device TLS verification is disabled."}, output_format)

        session_file = resolve_session_file(ctx.get("session_file"))
        kwargs = dict(
            base_url=ctx["base_url"],
            session_file=session_file,
            auth_header=ctx.get("auth_header", "Authorization"),
            file_id=_single_arg(args, "file_id") or "",
            output_path=_single_arg(args, "output_path") or "",
            verify_tls=bool(ctx.get("verify_tls")),
            timeout=float(ctx.get("timeout", 10.0)),
        )
        result = execute_object_download(**kwargs) if ctx.get("execute") else build_object_download_dry_run(**kwargs)
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
