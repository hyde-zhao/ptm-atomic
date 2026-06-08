#!/usr/bin/env python3
"""Validate that every op_id referenced in packages/*.yaml resolves to an atom.

This is the automated equivalent of `ptm-atomic validate --package <name>`,
but reads the working tree directly without depending on a synced cache.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("package refs check input error: missing pyyaml", file=sys.stderr)
    raise SystemExit(2)

EXIT_SUCCESS = 0
EXIT_VIOLATIONS = 1
EXIT_INPUT_ERROR = 2


def discover_atom_ids(atoms_root: Path) -> set[str]:
    """Collect all op_ids from atoms/<device>/*.yaml files."""
    ids: set[str] = set()
    if not atoms_root.is_dir():
        return ids
    for device_dir in atoms_root.iterdir():
        if not device_dir.is_dir():
            continue
        for yaml_file in device_dir.glob("*.yaml"):
            try:
                data = yaml.safe_load(yaml_file.read_text(encoding="utf-8"))
            except (OSError, yaml.YAMLError):
                continue
            if isinstance(data, dict):
                op_id = data.get("op_id")
                if isinstance(op_id, str) and op_id:
                    ids.add(op_id)
    return ids


def load_package(path: Path) -> tuple[str, list[str]]:
    """Return (package_id, [op_id, ...]) for a package manifest."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return ("", [])
    if not isinstance(data, dict):
        return ("", [])
    pkg_id = data.get("package_id", path.stem)
    ops = data.get("operations", [])
    if isinstance(ops, list) and all(isinstance(o, str) for o in ops):
        return pkg_id, ops
    return pkg_id, []


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate package manifest op_id references against atoms."
    )
    parser.add_argument(
        "--atoms-dir",
        default="atoms",
        help="Path to atoms directory. Defaults to atoms/.",
    )
    parser.add_argument(
        "--packages-dir",
        default="packages",
        help="Path to packages directory. Defaults to packages/.",
    )
    parser.add_argument(
        "--ignore-packages",
        nargs="*",
        default=[],
        help="Package names to skip (e.g., for future device types).",
    )
    args = parser.parse_args(argv)

    atoms_path = Path(args.atoms_dir)
    packages_path = Path(args.packages_dir)

    if not atoms_path.is_dir():
        print(f"package refs check input error: {atoms_path} is not a directory", file=sys.stderr)
        return EXIT_INPUT_ERROR
    if not packages_path.is_dir():
        print(f"package refs check input error: {packages_path} is not a directory", file=sys.stderr)
        return EXIT_INPUT_ERROR

    atom_ids = discover_atom_ids(atoms_path)
    if not atom_ids:
        print("package refs check input error: no atoms found", file=sys.stderr)
        return EXIT_INPUT_ERROR

    package_files = sorted(packages_path.glob("*.yaml"))
    if not package_files:
        print("package refs check input error: no package manifests found", file=sys.stderr)
        return EXIT_INPUT_ERROR

    ignore_set = set(args.ignore_packages)
    violations: list[str] = []
    checked = 0
    total_refs = 0

    for pkg_file in package_files:
        pkg_id, ops = load_package(pkg_file)
        if not ops:
            continue
        checked += 1
        total_refs += len(ops)
        if pkg_id in ignore_set:
            continue
        missing = [op for op in ops if op not in atom_ids]
        if missing:
            for op in missing:
                violations.append(
                    f"package '{pkg_id}' references unknown op_id '{op}'"
                )

    if violations:
        for v in violations:
            print(f"package refs violation: {v}", file=sys.stderr)
        print(
            f"package refs check failed: packages={checked} "
            f"refs={total_refs} missing={len(violations)}",
            file=sys.stderr,
        )
        return EXIT_VIOLATIONS

    skipped = f" (skipped={len(ignore_set)})" if ignore_set else ""
    print(
        f"package refs ok: packages={checked} refs={total_refs} missing=0{skipped}"
    )
    return EXIT_SUCCESS


def main(argv: list[str] | None = None) -> int:
    try:
        return run(argv)
    except KeyboardInterrupt:
        print("package refs check input error: interrupted", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except Exception as exc:
        print(f"package refs check input error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
