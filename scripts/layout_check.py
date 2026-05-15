#!/usr/bin/env python3
"""Read-only repository layout check for atomic operation content."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


REQUIRED_TOP_LEVEL_DIRS: tuple[str, ...] = (
    "atoms",
    "schemas",
    "packages",
    "docs",
    "scripts",
)

REQUIRED_DEVICE_DIRS: tuple[str, ...] = (
    "fw",
    "tg",
    "mock",
    "sw",
)

REQUIRED_SAMPLE_FILES: tuple[str, ...] = (
    "atoms/fw/fw_verify_acl_rule.yaml",
)


def collect_violations(root: Path) -> list[str]:
    """Return missing layout entries without mutating the repository."""
    violations: list[str] = []

    for directory in REQUIRED_TOP_LEVEL_DIRS:
        if not (root / directory).is_dir():
            violations.append(f"layout violation: {directory} missing")

    atoms_root = root / "atoms"
    for device_dir in REQUIRED_DEVICE_DIRS:
        relative_path = f"atoms/{device_dir}"
        if not (atoms_root / device_dir).is_dir():
            violations.append(f"layout violation: {relative_path} missing")

    for sample_file in REQUIRED_SAMPLE_FILES:
        if not (root / sample_file).is_file():
            violations.append(f"layout violation: {sample_file} missing")

    return violations


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Check the atomic operation repository directory layout."
    )
    parser.add_argument(
        "root",
        nargs="?",
        default=".",
        help="Repository root to check. Defaults to the current directory.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    root = Path(args.root).resolve()

    violations = collect_violations(root)
    if violations:
        for violation in violations:
            print(violation, file=sys.stderr)
        return 1

    print("layout ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
