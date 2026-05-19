"""Implementation for the atomic-ops adapter command."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

import yaml

from atomic_ops.repository import ERROR_REPO_NOT_SYNCED, EXIT_CODES, ReadError, Repository


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("op_id", help="Operation id whose adapter profile operation should be shown.")
    parser.add_argument(
        "--format",
        choices=("json", "yaml"),
        default="yaml",
        help="Output format.",
    )


def run(args: argparse.Namespace) -> int:
    output_format = getattr(args, "format", "yaml")
    try:
        repo = Repository.from_default_cache()
        _write_stale_warning(repo, output_format)
        document = repo.read_adapter_operation(getattr(args, "op_id"))
        payload = document.to_dict()
        if output_format == "json":
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print(yaml.safe_dump(payload, allow_unicode=True, sort_keys=False), end="")
        return 0
    except ReadError as exc:
        return _write_error(exc, output_format)


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
        return "Run atomic-ops sync after publishing a repository version that includes adapters/."
    if error_code == "OP_NOT_FOUND":
        return "Run atomic-ops sync and check that the operation declares adapter_contract_ref."
    return "Rerun the command after fixing the local cache."


def _details_text(details: dict[str, Any]) -> str:
    return ", ".join(f"{key}={value}" for key, value in details.items()) if details else "{}"
