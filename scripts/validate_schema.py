#!/usr/bin/env python3
"""Read-only JSON Schema validator for atomic operation YAML files."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any


EXIT_SUCCESS = 0
EXIT_VALIDATION_FAILED = 1
EXIT_INPUT_ERROR = 2
YAML_SUFFIXES = {".yaml", ".yml"}


@dataclass(frozen=True)
class Diagnostic:
    kind: str
    file_path: str
    field_path: str
    error_type: str
    message: str

    def format(self) -> str:
        message = " ".join(str(self.message).split())
        return (
            f"{self.kind} file_path={self.file_path} "
            f"field_path={self.field_path} "
            f"error_type={self.error_type} "
            f"message={message}"
        )


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()
    except OSError:
        return path.as_posix()


def input_error(file_path: str, error_type: str, message: str) -> Diagnostic:
    return Diagnostic(
        kind="input_error",
        file_path=file_path,
        field_path="$",
        error_type=error_type,
        message=message,
    )


class DiagnosticArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        print(input_error("-", "argument_error", message).format(), file=sys.stderr)
        print("schema validation input error: errors=1", file=sys.stderr)
        raise SystemExit(EXIT_INPUT_ERROR)


def build_parser() -> argparse.ArgumentParser:
    parser = DiagnosticArgumentParser(
        description="Validate atomic operation YAML files against a JSON Schema."
    )
    parser.add_argument(
        "--schema",
        default="schemas/atomic-op.schema.yaml",
        help="Schema file path. Defaults to schemas/atomic-op.schema.yaml.",
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="YAML file or directory targets. Directories are searched recursively.",
    )
    return parser


def import_dependencies() -> tuple[Any | None, Any | None, list[Diagnostic]]:
    diagnostics: list[Diagnostic] = []

    try:
        import yaml  # type: ignore[import-not-found]
    except ImportError:
        yaml = None
        diagnostics.append(
            input_error(
                "-",
                "missing_dependency",
                "Missing dependency: pyyaml. Install pyyaml to parse YAML files.",
            )
        )

    try:
        import jsonschema  # type: ignore[import-not-found]
    except ImportError:
        jsonschema = None
        diagnostics.append(
            input_error(
                "-",
                "missing_dependency",
                "Missing dependency: jsonschema. Install jsonschema to validate schemas.",
            )
        )

    return yaml, jsonschema, diagnostics


def load_yaml(path: Path, yaml_module: Any, error_type: str) -> tuple[Any | None, Diagnostic | None]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml_module.safe_load(handle), None
    except yaml_module.YAMLError as exc:
        return None, input_error(display_path(path), error_type, str(exc))
    except OSError as exc:
        return None, input_error(display_path(path), error_type, str(exc))


def load_schema(schema_path: Path, yaml_module: Any) -> tuple[dict[str, Any] | None, list[Diagnostic]]:
    diagnostics: list[Diagnostic] = []
    schema_display = display_path(schema_path)

    if not schema_path.exists():
        diagnostics.append(
            input_error(schema_display, "schema_load_error", "Schema file does not exist.")
        )
        return None, diagnostics
    if not schema_path.is_file():
        diagnostics.append(
            input_error(schema_display, "schema_load_error", "Schema path is not a file.")
        )
        return None, diagnostics

    document, diagnostic = load_yaml(schema_path, yaml_module, "schema_load_error")
    if diagnostic is not None:
        diagnostics.append(diagnostic)
        return None, diagnostics
    if not isinstance(document, dict):
        diagnostics.append(
            input_error(schema_display, "schema_load_error", "Schema document must be a mapping.")
        )
        return None, diagnostics

    return document, diagnostics


def build_validator(schema: dict[str, Any], jsonschema_module: Any) -> tuple[Any | None, list[Diagnostic]]:
    try:
        validator_class = jsonschema_module.validators.validator_for(schema)
        validator_class.check_schema(schema)
        return validator_class(schema), []
    except jsonschema_module.SchemaError as exc:
        return None, [input_error("-", "schema_invalid", exc.message)]
    except Exception as exc:
        return None, [input_error("-", "schema_invalid", str(exc))]


def discover_yaml_files(targets: Iterable[str]) -> tuple[list[Path], list[Diagnostic]]:
    files_by_key: dict[str, Path] = {}
    diagnostics: list[Diagnostic] = []

    for target in targets:
        path = Path(target)
        path_display = display_path(path)

        if not path.exists():
            diagnostics.append(input_error(path_display, "path_not_found", "Target path does not exist."))
            continue

        if path.is_file():
            if path.suffix.lower() not in YAML_SUFFIXES:
                diagnostics.append(
                    input_error(path_display, "unsupported_file_type", "Target file is not .yaml or .yml.")
                )
                continue
            files_by_key[path.resolve().as_posix()] = path
            continue

        if path.is_dir():
            discovered = [
                candidate
                for candidate in path.rglob("*")
                if candidate.is_file() and candidate.suffix.lower() in YAML_SUFFIXES
            ]
            if not discovered:
                diagnostics.append(input_error(path_display, "no_yaml_files", "Directory contains no YAML files."))
                continue
            for candidate in discovered:
                files_by_key[candidate.resolve().as_posix()] = candidate
            continue

        diagnostics.append(input_error(path_display, "unsupported_path", "Target path is not a file or directory."))

    files = sorted(files_by_key.values(), key=lambda item: display_path(item))
    if not files and not diagnostics:
        diagnostics.append(input_error("-", "no_yaml_files", "No YAML files were provided."))

    return files, diagnostics


def json_path_from_parts(parts: Iterable[Any]) -> str:
    path = "$"
    for part in parts:
        if isinstance(part, int):
            path += f"[{part}]"
        else:
            path += f".{part}"
    return path


def required_error_path(error: Any) -> str | None:
    if error.validator != "required" or not isinstance(error.instance, dict):
        return None

    required_fields = error.validator_value
    if not isinstance(required_fields, list):
        return None

    missing_fields = [field for field in required_fields if field not in error.instance]
    if not missing_fields:
        return None

    return json_path_from_parts([*error.absolute_path, missing_fields[0]])


def field_path(error: Any) -> str:
    return required_error_path(error) or json_path_from_parts(error.absolute_path)


def format_validation_error(path: Path, error: Any) -> Diagnostic:
    return Diagnostic(
        kind="validation_error",
        file_path=display_path(path),
        field_path=field_path(error),
        error_type=str(error.validator),
        message=error.message,
    )


def validate_file(path: Path, validator: Any, yaml_module: Any) -> tuple[int, list[Diagnostic], list[Diagnostic]]:
    document, diagnostic = load_yaml(path, yaml_module, "yaml_parse_error")
    if diagnostic is not None:
        return 0, [], [diagnostic]

    errors = sorted(
        validator.iter_errors(document),
        key=lambda error: (field_path(error), str(error.validator), error.message),
    )
    validation_diagnostics = [format_validation_error(path, error) for error in errors]
    return 1, validation_diagnostics, []


def run(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    yaml_module, jsonschema_module, dependency_errors = import_dependencies()
    if dependency_errors:
        for diagnostic in dependency_errors:
            print(diagnostic.format(), file=sys.stderr)
        print(
            f"schema validation input error: errors={len(dependency_errors)}",
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR

    schema_path = Path(args.schema)
    schema, schema_errors = load_schema(schema_path, yaml_module)
    if schema_errors or schema is None:
        for diagnostic in schema_errors:
            print(diagnostic.format(), file=sys.stderr)
        print(f"schema validation input error: errors={len(schema_errors)}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    validator, validator_errors = build_validator(schema, jsonschema_module)
    if validator_errors or validator is None:
        for diagnostic in validator_errors:
            print(diagnostic.format(), file=sys.stderr)
        print(f"schema validation input error: errors={len(validator_errors)}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    target_files, input_diagnostics = discover_yaml_files(args.targets)
    validation_diagnostics: list[Diagnostic] = []
    files_checked = 0

    for target_file in target_files:
        checked_count, file_validation_diagnostics, file_input_diagnostics = validate_file(
            target_file, validator, yaml_module
        )
        files_checked += checked_count
        validation_diagnostics.extend(file_validation_diagnostics)
        input_diagnostics.extend(file_input_diagnostics)

    for diagnostic in validation_diagnostics:
        print(diagnostic.format(), file=sys.stderr)
    for diagnostic in input_diagnostics:
        print(diagnostic.format(), file=sys.stderr)

    if input_diagnostics:
        print(
            f"schema validation input error: errors={len(input_diagnostics)}",
            file=sys.stderr,
        )
        return EXIT_INPUT_ERROR

    if validation_diagnostics:
        print(
            f"schema validation failed: files_checked={files_checked} "
            f"violations={len(validation_diagnostics)}",
            file=sys.stderr,
        )
        return EXIT_VALIDATION_FAILED

    print(f"schema ok: files_checked={files_checked}")
    return EXIT_SUCCESS


def main(argv: list[str] | None = None) -> int:
    try:
        return run(argv)
    except KeyboardInterrupt:
        print(
            input_error("-", "interrupted", "Interrupted by user.").format(),
            file=sys.stderr,
        )
        print("schema validation input error: errors=1", file=sys.stderr)
        return EXIT_INPUT_ERROR
    except Exception as exc:
        print(
            input_error("-", "internal_error", str(exc)).format(),
            file=sys.stderr,
        )
        print("schema validation input error: errors=1", file=sys.stderr)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
