#!/usr/bin/env python3
"""Read-only aliases consistency check for atomic operation YAML files.

Verifies:
  1. Aliases follow lowercase-hyphen format (no spaces, underscores, or capitals).
  2. Aliases do not collide with any existing op_id.
  3. An alias shared across ops from unrelated domains is flagged as a warning.

Note: duplicate aliases across a CRUD family (config/update/verify/delete)
are intentional — they ensure m-analyzer can discover all relevant ops for a
given natural-language term.  Only cross-domain duplicates are reported.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

try:
    import yaml
except ImportError:
    print("aliases check input error: missing pyyaml.  Install pyyaml to run this check.", file=sys.stderr)
    raise SystemExit(2)

EXIT_SUCCESS = 0
EXIT_VIOLATIONS = 1
EXIT_INPUT_ERROR = 2


def discover_atoms(atoms_root: Path) -> list[Path]:
    if not atoms_root.is_dir():
        return []
    return sorted(
        candidate
        for candidate in atoms_root.rglob("*.yaml")
        if candidate.is_file()
    )


def load_op(path: Path) -> tuple[str, list[str]]:
    """Return (op_id, aliases) for a single atom YAML file."""
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError):
        return ("", [])
    if not isinstance(data, dict):
        return ("", [])
    op_id = data.get("op_id", "")
    if not isinstance(op_id, str):
        op_id = ""
    raw = data.get("aliases")
    if isinstance(raw, list) and all(isinstance(item, str) for item in raw):
        return op_id, raw
    return op_id, []


def op_domain(op_id: str) -> str:
    """提取 op_id 的逻辑域，用于判断别名是否跨域共享。

    同一逻辑域内的别名共享是有意的（CRUD 族 + batch 变体），跨域才是违规。

    归一化规则：
      - 含 batch 的 op 统一归入 {device}:batch（批量是一个逻辑域）
      - policy_route_priority → 归一到 policy_route
      - 其他按动词后的全称归域
    """
    parts = op_id.split("_")
    if len(parts) < 3:
        return op_id
    device = parts[0]
    tail = parts[2:]  # 跳过 fw_<verb>

    # 批量操作统一归域
    if "batch" in tail:
        return f"{device}:batch"

    # priority 归入父域
    if tail and tail[-1] == "priority":
        tail = tail[:-1]

    domain_key = "_".join(tail)
    return f"{device}:{domain_key}"


def check_format(alias: str, op_id: str) -> str | None:
    """Return violation message if alias format is invalid, else None."""
    if not alias:
        return f"empty alias in {op_id}"
    if alias != alias.lower():
        return f"alias '{alias}' in {op_id} must be lowercase"
    if "_" in alias:
        return f"alias '{alias}' in {op_id} must use hyphens, not underscores"
    if " " in alias:
        return f"alias '{alias}' in {op_id} must not contain spaces"
    return None


def check_cross_domain_duplicates(op_aliases: dict[str, list[str]]) -> list[str]:
    """Return violations when aliases are shared across unrelated op domains."""
    violations: list[str] = []
    alias_to_domains: dict[str, set[str]] = defaultdict(set)

    for op_id, aliases in op_aliases.items():
        domain = op_domain(op_id)
        for alias in aliases:
            alias_to_domains[alias].add(domain)

    for alias, domains in alias_to_domains.items():
        if len(domains) > 1:
            violations.append(
                f"cross-domain alias '{alias}' spans {len(domains)} domains: "
                f"{', '.join(sorted(domains))}"
            )

    return violations


def check_op_id_collisions(
    op_aliases: dict[str, list[str]],
    all_op_ids: set[str],
) -> list[str]:
    """Return violations when an alias matches an existing op_id."""
    violations: list[str] = []
    for op_id, aliases in op_aliases.items():
        for alias in aliases:
            if alias in all_op_ids and alias != op_id:
                violations.append(
                    f"alias '{alias}' in {op_id} collides with existing op_id"
                )
    return violations


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check atomic operation aliases for duplicates and format."
    )
    parser.add_argument(
        "atoms_root",
        nargs="?",
        default="atoms",
        help="Path to atoms directory. Defaults to atoms/.",
    )
    args = parser.parse_args(argv)

    atoms_path = Path(args.atoms_root)
    if not atoms_path.is_dir():
        print(f"aliases check input error: {atoms_path} is not a directory", file=sys.stderr)
        return EXIT_INPUT_ERROR

    yaml_files = discover_atoms(atoms_path)
    if not yaml_files:
        print("aliases check input error: no YAML files found", file=sys.stderr)
        return EXIT_INPUT_ERROR

    op_aliases: dict[str, list[str]] = {}
    all_op_ids: set[str] = set()
    format_violations: list[str] = []

    for path in yaml_files:
        op_id, aliases = load_op(path)
        if op_id:
            all_op_ids.add(op_id)
            op_aliases[op_id] = aliases
            for alias in aliases:
                violation = check_format(alias, op_id)
                if violation:
                    format_violations.append(violation)

    domain_warnings = check_cross_domain_duplicates(op_aliases)
    collision_violations = check_op_id_collisions(op_aliases, all_op_ids)

    all_violations = format_violations + collision_violations

    # 跨域共享是软警告（batch_interface 与 interface 共享别名是合理设计）
    if domain_warnings:
        for w in domain_warnings:
            print(f"aliases warning: {w}", file=sys.stderr)

    if all_violations:
        for v in all_violations:
            print(f"aliases violation: {v}", file=sys.stderr)
        print(
            f"aliases check failed: files_checked={len(yaml_files)} "
            f"ops_with_aliases={sum(1 for a in op_aliases.values() if a)} "
            f"violations={len(all_violations)}",
            file=sys.stderr,
        )
        return EXIT_VIOLATIONS

    warning_tail = f" warnings={len(domain_warnings)}" if domain_warnings else ""
    print(
        f"aliases ok: files_checked={len(yaml_files)} "
        f"ops_with_aliases={sum(1 for a in op_aliases.values() if a)} "
        f"violations=0{warning_tail}"
    )
    return EXIT_SUCCESS


def main(argv: list[str] | None = None) -> int:
    try:
        return run(argv)
    except KeyboardInterrupt:
        print("aliases check input error: interrupted", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except Exception as exc:
        print(f"aliases check input error: {exc}", file=sys.stderr)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
