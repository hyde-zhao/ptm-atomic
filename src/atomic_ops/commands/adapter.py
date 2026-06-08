"""Implementation for the ptm-atomic adapter command."""

from __future__ import annotations

import argparse
import json
from typing import Any

import yaml

from atomic_ops.errors import write_read_error, write_stale_warning
from atomic_ops.repository import ReadError, Repository


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
        write_stale_warning(repo, output_format)
        document = repo.read_adapter_operation(getattr(args, "op_id"))
        payload = document.to_dict()
        if output_format == "json":
            print(json.dumps(payload, ensure_ascii=False, sort_keys=True))
        else:
            print(yaml.safe_dump(payload, allow_unicode=True, sort_keys=False), end="")
        return 0
    except ReadError as exc:
        return write_read_error(exc, output_format, "adapter")
