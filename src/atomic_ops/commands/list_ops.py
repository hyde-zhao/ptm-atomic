"""Implementation for the ptm-atomic list command."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from atomic_ops.errors import write_read_error, write_stale_warning, write_warning
from atomic_ops.repository import (
    ERROR_REPO_NOT_SYNCED,
    EXIT_CODES,
    SUPPORTED_DEVICES,
    ReadError,
    Repository,
)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--device",
        default=None,
        help="Filter by device type: fw, tg, mock, or sw.",
    )
    parser.add_argument(
        "--package",
        default=None,
        help="Filter operations by package manifest name.",
    )
    parser.add_argument(
        "--query",
        default=None,
        help="Filter operations by a keyword matched against op_id, aliases, tags, or description (case-insensitive).",
    )
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

        device = getattr(args, "device", None)
        device_filter = device if device in SUPPORTED_DEVICES else None
        if device and device_filter is None:
            write_warning(
                {
                    "warning_code": "UNKNOWN_DEVICE",
                    "message": f"unknown device filter ignored: {device}",
                },
                output_format,
            )
            payload = {
                "cache": repo.metadata_summary(),
                "filters": {
                    "device": None,
                    "package": getattr(args, "package", None),
                },
                "missing_count": 0,
                "operations": [],
            }
            _write_success(payload, output_format)
            return 0

        package_name = getattr(args, "package", None)
        query = getattr(args, "query", None)
        if package_name:
            operations, missing_count = repo.list_package_operations(
                package_name,
                device=device_filter,
            )
        else:
            operations = repo.list_operations(device=device_filter)
            missing_count = 0
        if query:
            operations = [operation for operation in operations if _matches_query(operation, query)]

        payload = {
            "cache": repo.metadata_summary(),
            "filters": {
                "device": device_filter,
                "package": package_name,
                "query": query,
            },
            "missing_count": missing_count,
            "operations": [operation.to_dict() for operation in operations],
        }
        _write_success(payload, output_format)
        return 0
    except ReadError as exc:
        return write_read_error(exc, output_format, "list")


def _matches_query(operation: Any, query: str) -> bool:
    """Return True when the keyword matches op_id, aliases, tags, or description."""
    needle = query.lower()
    if needle in str(operation.op_id or "").lower():
        return True
    if needle in str(operation.description or "").lower():
        return True
    for alias in operation.aliases or []:
        if needle in str(alias).lower():
            return True
    for tag in operation.tags or []:
        if needle in str(tag).lower():
            return True
    return False


def _write_success(payload: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        return

    operations = payload["operations"]
    if payload["filters"].get("package"):
        print(f"missing_count={payload['missing_count']}")
    print(_operation_table(operations))


def _operation_table(operations: list[dict[str, Any]]) -> str:
    headers = (
        "op_id",
        "device_type",
        "side_effect",
        "rollback",
        "idempotent",
        "since_version",
        "tags",
        "aliases",
        "description",
    )
    rows = [
        (
            str(item.get("op_id") or ""),
            str(item.get("device_type") or ""),
            str(item.get("side_effect") or ""),
            _rollback_label(item.get("rollback_strategy")),
            str(item.get("idempotent")).lower(),
            str(item.get("since_version") or ""),
            ", ".join(item.get("tags") or []),
            ", ".join(item.get("aliases") or []),
            str(item.get("description") or ""),
        )
        for item in operations
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


def _rollback_label(strategy: Any) -> str:
    if not isinstance(strategy, dict):
        return ""
    strategy_type = str(strategy.get("type") or "")
    op_id = str(strategy.get("op_id") or "")
    return f"{strategy_type}:{op_id}" if op_id else strategy_type
