"""Implementation for the ptm-atomic show command."""

from __future__ import annotations

import argparse
import json
from typing import Any

import yaml

from atomic_ops.errors import write_read_error, write_stale_warning
from atomic_ops.repository import ReadError, Repository


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("op_id", help="Operation id to show.")
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
        write_stale_warning(repo, output_format)
        document = repo.read_operation(getattr(args, "op_id"))
        if output_format == "json":
            print(json.dumps(document.data, ensure_ascii=False, sort_keys=True))
        else:
            print(_stable_yaml(document.raw_text, document.data), end="")
        return 0
    except ReadError as exc:
        return write_read_error(exc, output_format, "show")


def _stable_yaml(raw_text: str, data: dict[str, Any]) -> str:
    if raw_text.strip():
        return raw_text if raw_text.endswith("\n") else f"{raw_text}\n"
    return yaml.safe_dump(data, allow_unicode=True, sort_keys=False)
