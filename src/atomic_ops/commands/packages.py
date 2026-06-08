"""Implementation for the ptm-atomic packages command."""

from __future__ import annotations

import argparse
import json
from typing import Any

from atomic_ops.errors import write_read_error, write_stale_warning
from atomic_ops.repository import ReadError, Repository


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
        write_stale_warning(repo, output_format)
        payload = {
            "cache": repo.metadata_summary(),
            "packages": [item.to_dict() for item in repo.list_packages()],
        }
        _write_success(payload, output_format)
        return 0
    except ReadError as exc:
        return write_read_error(exc, output_format, "packages")


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
