"""Implementation for the atomic-ops packages command."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from atomic_ops.repository import ERROR_REPO_NOT_SYNCED, EXIT_CODES, ReadError, Repository


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--format",
        choices=("json", "table"),
        default="table",
        help="Output format.",
    )


def run(args: argparse.Namespace) -> int:
    output_format = getattr(args, "format", "table")
    try:
        repo = Repository.from_default_cache()
        _write_stale_warning(repo, output_format)
        payload = {
            "cache": repo.metadata_summary(),
            "packages": [item.to_dict() for item in repo.list_packages()],
        }
        _write_success(payload, output_format)
        return 0
    except ReadError as exc:
        return _write_error(exc, output_format)


def _write_success(payload: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return
    print(_package_table(payload["packages"]))


def _package_table(packages: list[dict[str, Any]]) -> str:
    headers = ("package_id", "display_name", "version", "operation_count", "description")
    rows = [
        (
            str(item.get("package_id") or ""),
            str(item.get("display_name") or ""),
            str(item.get("version") or ""),
            str(item.get("operation_count") or 0),
            str(item.get("description") or ""),
        )
        for item in packages
    ]
    widths = [
        max(len(headers[index]), *(len(row[index]) for row in rows)) if rows else len(headers[index])
        for index in range(len(headers))
    ]
    lines = [
        "  ".join(headers[index].ljust(widths[index]) for index in range(len(headers))),
        "  ".join("-" * width for width in widths),
    ]
    lines.extend(
        "  ".join(row[index].ljust(widths[index]) for index in range(len(headers)))
        for row in rows
    )
    return "\n".join(lines)


def _write_stale_warning(repo: Repository, output_format: str) -> None:
    if not repo.is_stale:
        return
    _write_warning("cache_status=STALE; read-only command is using stale local cache", output_format)


def _write_warning(message: str, output_format: str) -> None:
    if output_format == "json":
        print(json.dumps({"warning": message}, ensure_ascii=False, sort_keys=True), file=sys.stderr)
    else:
        print(f"warning: {message}", file=sys.stderr)


def _write_error(exc: ReadError, output_format: str) -> int:
    error = {
        "error_code": exc.error_code,
        "message": exc.message,
        "details": exc.details,
        "retryable": exc.retryable,
        "suggestion": _suggestion(exc.error_code),
    }
    if output_format == "json":
        print(json.dumps(error, ensure_ascii=False, sort_keys=True), file=sys.stderr)
    else:
        details = _details_text(exc.details)
        print(
            f"error: {exc.error_code}: {exc.message}\n"
            f"details: {details}\n"
            f"suggestion: {error['suggestion']}",
            file=sys.stderr,
        )
    return EXIT_CODES[exc.error_code]


def _suggestion(error_code: str) -> str:
    if error_code == ERROR_REPO_NOT_SYNCED:
        return "Run atomic-ops sync before using read commands."
    return "Rerun the command after fixing the local cache."


def _details_text(details: dict[str, Any]) -> str:
    return ", ".join(f"{key}={value}" for key, value in details.items()) if details else "{}"
