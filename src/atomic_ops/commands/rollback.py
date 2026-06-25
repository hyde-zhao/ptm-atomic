"""Implementation for ptm-atomic rollback commands."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml

from atomic_ops.commands import CommandSpec
from atomic_ops.errors import write_json_stdout, write_read_error
from atomic_ops.repository import ReadError, Repository
from atomic_ops.rollback import readiness_report


def build_subtree() -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(
            name="check",
            help="Check rollback readiness for one op or a plan.",
            description="Check rollback readiness for one op or a plan.",
            handler=run_check,
            add_args=add_check_arguments,
        ),
    )


def add_check_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--op",
        action="append",
        default=[],
        help="Operation id to check. May be provided multiple times.",
    )
    parser.add_argument(
        "--plan",
        default=None,
        help="YAML plan or test-case file containing steps with op_id fields.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "table"),
        default="table",
        help="Output format.",
    )
    parser.set_defaults(rollback_check_parser=parser)


def run_check(args: argparse.Namespace) -> int:
    output_format = getattr(args, "format", "table")
    op_ids = _requested_op_ids(args)
    if not op_ids:
        parser = getattr(args, "rollback_check_parser")
        parser.error("rollback check requires --op or --plan")

    try:
        repo = Repository.from_default_cache()
        known_ops = {operation.op_id for operation in repo.list_operations()}
        results = []
        for op_id in op_ids:
            document = repo.read_operation(op_id)
            results.append(readiness_report(op_id, document.data, known_ops.__contains__))
        payload = _payload(results, repo.metadata_summary())
        _write_payload(payload, output_format)
        return 0 if payload["status"] == "pass" else 1
    except ReadError as exc:
        return write_read_error(exc, output_format, "rollback check")


def _requested_op_ids(args: argparse.Namespace) -> list[str]:
    op_ids = [item for item in getattr(args, "op", []) if isinstance(item, str) and item.strip()]
    plan = getattr(args, "plan", None)
    if plan:
        op_ids.extend(_read_plan_op_ids(Path(str(plan))))
    return list(dict.fromkeys(op_ids))


def _read_plan_op_ids(path: Path) -> list[str]:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    op_ids: list[str] = []
    _collect_op_ids(data, op_ids)
    return op_ids


def _collect_op_ids(value: Any, op_ids: list[str]) -> None:
    if isinstance(value, dict):
        op_id = value.get("op_id")
        if isinstance(op_id, str) and op_id:
            op_ids.append(op_id)
        for child in value.values():
            _collect_op_ids(child, op_ids)
    elif isinstance(value, list):
        for child in value:
            _collect_op_ids(child, op_ids)


def _payload(results: list[dict[str, Any]], cache: dict[str, Any]) -> dict[str, Any]:
    status = "pass" if all(result["status"] == "pass" for result in results) else "blocked"
    if len(results) == 1:
        payload = dict(results[0])
        payload["cache"] = cache
        return payload
    return {
        "status": status,
        "checked_count": len(results),
        "blocked_count": sum(1 for result in results if result["status"] != "pass"),
        "results": results,
        "cache": cache,
    }


def _write_payload(payload: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        write_json_stdout(payload)
        return
    if "results" not in payload:
        print(_result_table([payload]))
        return
    print(f"status={payload['status']}")
    print(f"checked_count={payload['checked_count']}")
    print(f"blocked_count={payload['blocked_count']}")
    print(_result_table(payload["results"]))


def _result_table(results: list[dict[str, Any]]) -> str:
    headers = ("op_id", "status", "side_effect", "rollback_strategy", "rollback_op_id", "missing", "warnings")
    rows = [
        (
            str(item.get("op_id") or ""),
            str(item.get("status") or ""),
            str(item.get("side_effect") or ""),
            str(item.get("rollback_strategy") or ""),
            str(item.get("rollback_op_id") or ""),
            ", ".join(item.get("missing") or []),
            " | ".join(item.get("warnings") or []),
        )
        for item in results
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
