#!/usr/bin/env python3
"""Validate public adapter profiles and atom adapter_contract_ref links."""

from __future__ import annotations

import argparse
import functools
import re
import sys
from pathlib import Path
from typing import Any

import jsonschema
import yaml


EXIT_SUCCESS = 0
EXIT_VALIDATION_FAILED = 1
EXIT_INPUT_ERROR = 2
YAML_SUFFIXES = {".yaml", ".yml"}
FORBIDDEN_ADAPTER_TERM_RE = re.compile(
    r"(?i)(^|[^a-z0-9])("
    r"\.input/capacity|secret|host|token|cookie|password|ftp_pass|authorization|"
    r"private[_ -]?key|production[_ -]?(response|sample)"
    r")([^a-z0-9]|$)"
)
PUBLIC_AUTH_HEADER_NAMES = {"Authorization", "AuthorizationToken", "X-Session-Ref"}


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()
    except OSError:
        return path.as_posix()


@functools.lru_cache(maxsize=None)
def _load_yaml_by_key(path_key: str) -> Any:
    with Path(path_key).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def load_yaml(path: Path) -> Any:
    """解析 YAML，按路径缓存。

    ``collect_ref_errors`` 对每个 atom 都要读一遍它引用的适配器 profile（那份
    ``adapters/ngfw/default.yaml`` 有 6.7k 行、解析约 0.6s），且
    ``pointer_target_exists`` 还会再读一次 —— 259 个 atom 指向同一份文件时就是
    约 520 次重复解析（实测 336s），而本脚本全程只读文件、不写文件，故缓存安全。
    缓存键取 ``str(Path(...))`` 以吸收调用方传入 str 与 Path 的差异。
    """
    return _load_yaml_by_key(str(Path(path)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Validate adapter profile YAML files and atom adapter refs."
    )
    parser.add_argument(
        "--schema",
        default="schemas/adapter-profile.schema.yaml",
        help="Adapter profile schema path.",
    )
    parser.add_argument(
        "--atoms",
        default="atoms",
        help="Atom root used to verify adapter_contract_ref links.",
    )
    parser.add_argument(
        "profiles",
        nargs="*",
        default=["adapters"],
        help="Adapter profile files or directories. Defaults to adapters/.",
    )
    return parser


def discover_yaml(paths: list[str]) -> tuple[list[Path], list[str]]:
    files: dict[str, Path] = {}
    errors: list[str] = []
    for raw_path in paths:
        path = Path(raw_path)
        if not path.exists():
            errors.append(f"input_error file_path={display_path(path)} message=path does not exist")
            continue
        if path.is_file():
            if path.suffix.lower() in YAML_SUFFIXES:
                files[path.resolve().as_posix()] = path
            else:
                errors.append(f"input_error file_path={display_path(path)} message=not a YAML file")
            continue
        if path.is_dir():
            for candidate in path.rglob("*"):
                if candidate.is_file() and candidate.suffix.lower() in YAML_SUFFIXES:
                    files[candidate.resolve().as_posix()] = candidate
            continue
        errors.append(f"input_error file_path={display_path(path)} message=unsupported path")
    return sorted(files.values(), key=display_path), errors


def pointer_target_exists(profile_path: str, operation_id: str) -> bool:
    document = load_yaml(Path(profile_path))
    return (
        isinstance(document, dict)
        and isinstance(document.get("operations"), dict)
        and operation_id in document["operations"]
    )


def collect_sensitive_profile_errors(document: Any, profile_path: Path) -> list[str]:
    errors: list[str] = []

    def walk(value: Any, field_path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_path = f"{field_path}.{key}" if field_path != "$" else f"$.{key}"
                if FORBIDDEN_ADAPTER_TERM_RE.search(str(key)):
                    errors.append(
                        f"sensitive_adapter_error file_path={display_path(profile_path)} field_path={key_path} message=forbidden sensitive field name"
                    )
                walk(child, key_path)
            return

        if isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{field_path}[{index}]")
            return

        if (
            isinstance(value, str)
            and FORBIDDEN_ADAPTER_TERM_RE.search(value)
            and not is_public_auth_header_name(field_path, value)
        ):
            errors.append(
                f"sensitive_adapter_error file_path={display_path(profile_path)} field_path={field_path} message=forbidden sensitive value"
            )

    walk(document, "$")
    return errors


def is_public_auth_header_name(field_path: str, value: str) -> bool:
    return field_path.endswith(".request.auth.header_name") and value in PUBLIC_AUTH_HEADER_NAMES


def collect_ref_errors(atoms_root: Path) -> list[str]:
    errors: list[str] = []
    for atom_path in sorted(atoms_root.rglob("*.yaml"), key=display_path):
        document = load_yaml(atom_path)
        if not isinstance(document, dict):
            continue
        ref = document.get("adapter_contract_ref")
        if ref is None:
            continue
        if not isinstance(ref, str) or "#/operations/" not in ref:
            errors.append(
                f"ref_error file_path={display_path(atom_path)} field_path=$.adapter_contract_ref message=invalid adapter ref"
            )
            continue
        profile_part, operation_id = ref.split("#/operations/", 1)
        profile_path = Path(profile_part)
        if not profile_path.is_file():
            errors.append(
                f"ref_error file_path={display_path(atom_path)} field_path=$.adapter_contract_ref message=profile not found: {profile_part}"
            )
            continue
        if not pointer_target_exists(profile_part, operation_id):
            errors.append(
                f"ref_error file_path={display_path(atom_path)} field_path=$.adapter_contract_ref message=operation not found: {operation_id}"
            )
            continue
        profile = load_yaml(profile_path)
        operation = profile["operations"][operation_id]
        atom_ref = operation.get("atom_ref")
        if atom_ref != display_path(atom_path):
            errors.append(
                f"ref_error file_path={display_path(atom_path)} field_path=$.adapter_contract_ref message=adapter atom_ref mismatch: {atom_ref}"
            )
    return errors


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    schema_path = Path(args.schema)
    if not schema_path.is_file():
        print(f"input_error file_path={display_path(schema_path)} message=schema not found", file=sys.stderr)
        return EXIT_INPUT_ERROR

    profiles, input_errors = discover_yaml(list(args.profiles))
    if input_errors:
        for error in input_errors:
            print(error, file=sys.stderr)
        return EXIT_INPUT_ERROR

    schema = load_yaml(schema_path)
    validator_class = jsonschema.validators.validator_for(schema)
    validator_class.check_schema(schema)
    validator = validator_class(schema)

    validation_errors: list[str] = []
    for profile_path in profiles:
        document = load_yaml(profile_path)
        for error in sorted(validator.iter_errors(document), key=lambda item: list(item.absolute_path)):
            field_path = "$" + "".join(f".{part}" for part in error.absolute_path)
            validation_errors.append(
                f"validation_error file_path={display_path(profile_path)} field_path={field_path} message={error.message}"
            )
        validation_errors.extend(collect_sensitive_profile_errors(document, profile_path))

    validation_errors.extend(collect_ref_errors(Path(args.atoms)))
    if validation_errors:
        for error in validation_errors:
            print(error, file=sys.stderr)
        print(f"adapter profile validation failed: errors={len(validation_errors)}", file=sys.stderr)
        return EXIT_VALIDATION_FAILED

    print(f"adapter profile validation ok: profiles={len(profiles)}")
    return EXIT_SUCCESS


if __name__ == "__main__":
    raise SystemExit(main())
