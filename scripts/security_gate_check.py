#!/usr/bin/env python3
"""Read-only static security gate for atomic-ops repository content."""

from __future__ import annotations

import argparse
import re
import sys
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml


EXIT_SUCCESS = 0
EXIT_SENSITIVE = 31
EXIT_HIGH_RISK_GATE = 32
EXIT_INPUT_ERROR = 33

DEFAULT_SCAN_PATHS: tuple[str, ...] = (
    "atoms",
    "adapters",
    "packages",
    "docs",
    "schemas",
    "scripts",
    "src/atomic_ops",
)

OPTIONAL_DEFAULT_SCAN_PATHS: frozenset[str] = frozenset({"adapters"})

EXCLUDED_DIR_NAMES: frozenset[str] = frozenset(
    {
        ".input",
        ".git",
        ".venv",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        ".tox",
        ".nox",
        ".cache",
        "build",
        "dist",
        "htmlcov",
        "site",
        ".eggs",
    }
)

TEXT_SUFFIXES: frozenset[str] = frozenset(
    {
        ".md",
        ".rst",
        ".txt",
        ".yaml",
        ".yml",
        ".json",
        ".toml",
        ".py",
        ".sh",
        ".ps1",
        ".cfg",
        ".ini",
    }
)

YAML_SUFFIXES: frozenset[str] = frozenset({".yaml", ".yml"})
PLACEHOLDER_RE = re.compile(r"^<[^>\r\n]+>$")
HIGH_RISK_OP_ID_RE = re.compile(r"^fw_(install|init|login|config|config_batch)_")
SENSITIVE_ASSIGNMENT_RE = re.compile(
    r"(?i)\b(?P<key>token|cookie|authorization|password|ftp_pass|secret)\b"
    r"\s*[:=]\s*"
    r"(?P<value>[^<\s][^\s#,'\"]*)"
)
FORBIDDEN_ADAPTER_PROFILE_RE = re.compile(
    r"(?i)(^|[^a-z0-9])("
    r"\.input/capacity|secret|host|token|cookie|password|ftp_pass|authorization|"
    r"private[_ -]?key|production[_ -]?(response|sample)"
    r")([^a-z0-9]|$)"
)
ALLOWED_LITERAL_VALUES: frozenset[str] = frozenset({"Ngfw@123"})
PUBLIC_AUTH_HEADER_NAMES: frozenset[str] = frozenset(
    {"Authorization", "AuthorizationToken", "X-Session-Ref"}
)


@dataclass(frozen=True)
class SensitiveFinding:
    path: Path
    line: int
    rule_name: str
    key: str

    def format(self) -> str:
        return (
            "sensitive_finding "
            f"file_path={display_path(self.path)} "
            f"line={self.line} "
            f"rule={self.rule_name} "
            f"preview={self.key}=<redacted>"
        )


@dataclass(frozen=True)
class GateFinding:
    path: Path
    op_id: str
    field_path: str
    message: str

    def format(self) -> str:
        return (
            "high_risk_gate_finding "
            f"file_path={display_path(self.path)} "
            f"op_id={self.op_id} "
            f"field_path={self.field_path} "
            f"message={self.message}"
        )


@dataclass(frozen=True)
class AdapterProfileFinding:
    path: Path
    field_path: str
    message: str

    def format(self) -> str:
        return (
            "adapter_profile_sensitive_finding "
            f"file_path={display_path(self.path)} "
            f"field_path={self.field_path} "
            f"message={self.message}"
        )


@dataclass(frozen=True)
class InputFinding:
    path: Path | None
    error_type: str
    message: str

    def format(self) -> str:
        path = display_path(self.path) if self.path is not None else "-"
        return (
            "security_gate_input_error "
            f"file_path={path} "
            f"error_type={self.error_type} "
            f"message={' '.join(self.message.split())}"
        )


@dataclass(frozen=True)
class ScanTargets:
    text_files: tuple[Path, ...]
    yaml_files: tuple[Path, ...]
    input_findings: tuple[InputFinding, ...]


class SecurityGateArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        finding = InputFinding(None, "argument_error", message)
        print(finding.format(), file=sys.stderr)
        print("security gate input error: errors=1", file=sys.stderr)
        raise SystemExit(EXIT_INPUT_ERROR)


def display_path(path: Path | None) -> str:
    if path is None:
        return "-"
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()
    except OSError:
        return path.as_posix()


def build_parser() -> argparse.ArgumentParser:
    parser = SecurityGateArgumentParser(
        description=(
            "Run the read-only atomic-ops static security gate. "
            "Defaults scan atoms/, adapters/, packages/, docs/, schemas/, scripts/, and src/atomic_ops/."
        )
    )
    parser.add_argument(
        "--schema",
        default="schemas/atomic-op.schema.yaml",
        help="Schema path used as an input precondition. Defaults to schemas/atomic-op.schema.yaml.",
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Optional file or directory targets. Defaults to the six repository scan paths.",
    )
    return parser


def path_has_excluded_part(path: Path) -> bool:
    return any(part in EXCLUDED_DIR_NAMES for part in path.parts)


def is_generated_cache_path(path: Path) -> bool:
    return path_has_excluded_part(path)


def is_text_candidate(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in TEXT_SUFFIXES


def is_yaml_candidate(path: Path) -> bool:
    return path.is_file() and path.suffix.lower() in YAML_SUFFIXES


def dedupe_sorted(paths: Iterable[Path]) -> tuple[Path, ...]:
    by_key = {path.resolve().as_posix(): path for path in paths}
    return tuple(sorted(by_key.values(), key=display_path))


def resolve_scan_targets(targets: list[str]) -> ScanTargets:
    requested = targets or list(DEFAULT_SCAN_PATHS)
    default_mode = not targets
    text_files: list[Path] = []
    yaml_files: list[Path] = []
    input_findings: list[InputFinding] = []

    for requested_path in requested:
        path = Path(requested_path)
        if not path.exists():
            if default_mode and requested_path in OPTIONAL_DEFAULT_SCAN_PATHS:
                continue
            input_findings.append(
                InputFinding(path, "path_not_found", "Target path does not exist.")
            )
            continue

        if path_has_excluded_part(path):
            continue

        if path.is_file():
            if is_text_candidate(path):
                text_files.append(path)
            if is_yaml_candidate(path):
                yaml_files.append(path)
            continue

        if path.is_dir():
            for candidate in path.rglob("*"):
                if path_has_excluded_part(candidate):
                    continue
                if is_text_candidate(candidate):
                    text_files.append(candidate)
                if is_yaml_candidate(candidate):
                    yaml_files.append(candidate)
            continue

        input_findings.append(
            InputFinding(path, "unsupported_path", "Target path is not a file or directory.")
        )

    return ScanTargets(
        text_files=dedupe_sorted(text_files),
        yaml_files=dedupe_sorted(yaml_files),
        input_findings=tuple(input_findings),
    )


def validate_schema_path(schema_path: Path) -> list[InputFinding]:
    if not schema_path.exists():
        return [InputFinding(schema_path, "schema_not_found", "Schema file does not exist.")]
    if not schema_path.is_file():
        return [InputFinding(schema_path, "schema_not_file", "Schema path is not a file.")]
    if path_has_excluded_part(schema_path):
        return [InputFinding(schema_path, "schema_excluded", "Schema path is excluded.")]
    _, finding = load_yaml(schema_path, "schema_yaml_parse_error")
    return [finding] if finding is not None else []


def load_yaml(path: Path, error_type: str) -> tuple[Any | None, InputFinding | None]:
    try:
        with path.open("r", encoding="utf-8") as handle:
            return yaml.safe_load(handle), None
    except yaml.YAMLError as exc:
        return None, InputFinding(path, error_type, str(exc))
    except UnicodeDecodeError as exc:
        return None, InputFinding(path, "text_decode_error", str(exc))
    except OSError as exc:
        return None, InputFinding(path, "read_error", str(exc))


def scan_sensitive_file(path: Path) -> list[SensitiveFinding]:
    findings: list[SensitiveFinding] = []
    try:
        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                findings.extend(sensitive_findings_for_line(path, line_number, line))
    except UnicodeDecodeError:
        return findings
    except OSError as exc:
        raise RuntimeError(f"{display_path(path)}: {exc}") from exc
    return findings


def sensitive_findings_for_line(path: Path, line_number: int, line: str) -> list[SensitiveFinding]:
    if is_sensitive_rule_definition(line):
        return []

    findings: list[SensitiveFinding] = []
    for match in SENSITIVE_ASSIGNMENT_RE.finditer(line):
        key = match.group("key")
        value = match.group("value").strip().strip("'\"")
        if is_allowed_sensitive_value(value):
            continue
        findings.append(
            SensitiveFinding(
                path=path,
                line=line_number,
                rule_name=f"{key.lower()}_assignment",
                key=key.lower(),
            )
        )
    return findings


def is_sensitive_rule_definition(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return False

    lower = stripped.lower()
    if lower.startswith(("pattern:", "regex:", "forbidden_pattern:", "sensitive_pattern:")):
        return True
    return "token=|cookie:" in lower and "authorization" in lower


def is_allowed_sensitive_value(value: str) -> bool:
    if value in ALLOWED_LITERAL_VALUES:
        return True
    return bool(PLACEHOLDER_RE.fullmatch(value))


def scan_sensitive_files(paths: Iterable[Path]) -> tuple[list[SensitiveFinding], list[InputFinding]]:
    findings: list[SensitiveFinding] = []
    input_findings: list[InputFinding] = []
    for path in paths:
        try:
            findings.extend(scan_sensitive_file(path))
        except RuntimeError as exc:
            input_findings.append(InputFinding(path, "read_error", str(exc)))
    return findings, input_findings


def high_risk_gate_findings(paths: Iterable[Path]) -> tuple[list[GateFinding], list[InputFinding]]:
    gate_findings: list[GateFinding] = []
    input_findings: list[InputFinding] = []
    for path in paths:
        document, finding = load_yaml(path, "yaml_parse_error")
        if finding is not None:
            input_findings.append(finding)
            continue
        if not isinstance(document, dict):
            continue
        gate_findings.extend(check_high_risk_gate(path, document))
    return gate_findings, input_findings


def check_high_risk_gate(path: Path, document: dict[str, Any]) -> list[GateFinding]:
    op_id = document.get("op_id")
    risk = document.get("risk")
    gate = document.get("gate")

    if not isinstance(op_id, str) or not op_id:
        return []

    risk_level = ""
    if isinstance(risk, dict) and isinstance(risk.get("level"), str):
        risk_level = risk["level"].strip().lower()

    is_high_risk = risk_level == "high" or bool(HIGH_RISK_OP_ID_RE.match(op_id))
    if not is_high_risk:
        return []

    findings: list[GateFinding] = []
    if not isinstance(gate, dict):
        return [
            GateFinding(path, op_id, "$.gate", "High-risk atom must define a gate object.")
        ]

    if gate.get("required") is not True:
        findings.append(
            GateFinding(path, op_id, "$.gate.required", "High-risk atom gate.required must be true.")
        )

    reason = gate.get("reason")
    if not isinstance(reason, str) or not reason.strip():
        findings.append(
            GateFinding(path, op_id, "$.gate.reason", "High-risk atom gate.reason must be non-empty.")
        )

    approver_role = gate.get("approver_role")
    if not isinstance(approver_role, str) or not approver_role.strip():
        findings.append(
            GateFinding(path, op_id, "$.gate.approver_role", "High-risk atom gate.approver_role must be non-empty.")
        )

    evidence_required = gate.get("evidence_required")
    if not isinstance(evidence_required, list) or not any(
        isinstance(item, str) and item.strip() for item in evidence_required
    ):
        findings.append(
            GateFinding(
                path,
                op_id,
                "$.gate.evidence_required",
                "High-risk atom gate.evidence_required must contain at least one evidence item.",
            )
        )

    return findings


def is_adapter_profile_path(path: Path) -> bool:
    return "adapters" in path.parts


def adapter_profile_sensitive_findings(paths: Iterable[Path]) -> tuple[list[AdapterProfileFinding], list[InputFinding]]:
    findings: list[AdapterProfileFinding] = []
    input_findings: list[InputFinding] = []
    for path in paths:
        if not is_adapter_profile_path(path):
            continue
        document, finding = load_yaml(path, "adapter_profile_yaml_parse_error")
        if finding is not None:
            input_findings.append(finding)
            continue
        findings.extend(collect_adapter_profile_sensitive_findings(path, document))
    return findings, input_findings


def collect_adapter_profile_sensitive_findings(path: Path, document: Any) -> list[AdapterProfileFinding]:
    findings: list[AdapterProfileFinding] = []

    def walk(value: Any, field_path: str) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                key_path = f"{field_path}.{key}" if field_path != "$" else f"$.{key}"
                if FORBIDDEN_ADAPTER_PROFILE_RE.search(str(key)):
                    findings.append(
                        AdapterProfileFinding(path, key_path, "forbidden sensitive field name")
                    )
                walk(child, key_path)
            return

        if isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, f"{field_path}[{index}]")
            return

        if (
            isinstance(value, str)
            and FORBIDDEN_ADAPTER_PROFILE_RE.search(value)
            and not is_public_auth_header_name(field_path, value)
        ):
            findings.append(
                AdapterProfileFinding(path, field_path, "forbidden sensitive value")
            )

    walk(document, "$")
    return findings


def is_public_auth_header_name(field_path: str, value: str) -> bool:
    return field_path.endswith(".request.auth.header_name") and value in PUBLIC_AUTH_HEADER_NAMES


def print_help_inventory() -> None:
    print("security gate inventory:")
    print("  default_scan_paths=" + ",".join(f"{path}/" for path in DEFAULT_SCAN_PATHS))
    print("  optional_default_scan_paths=" + ",".join(sorted(OPTIONAL_DEFAULT_SCAN_PATHS)))
    print("  excluded_dirs=" + ",".join(sorted(EXCLUDED_DIR_NAMES)))
    print("  sensitive_exit_code=31")
    print("  high_risk_gate_exit_code=32")
    print("  input_error_exit_code=33")
    print("  high_risk_op_id_pattern=^fw_(install|init|login|config|config_batch)_")


def run(argv: list[str] | None = None) -> int:
    if argv is not None and "--help" in argv:
        parser = build_parser()
        print(parser.format_help(), end="")
        print_help_inventory()
        return EXIT_SUCCESS

    parser = build_parser()
    args = parser.parse_args(argv)

    schema_path = Path(args.schema)
    input_findings: list[InputFinding] = []
    input_findings.extend(validate_schema_path(schema_path))

    targets = resolve_scan_targets(list(args.targets))
    input_findings.extend(targets.input_findings)

    if input_findings:
        for finding in input_findings:
            print(finding.format(), file=sys.stderr)
        print(f"security gate input error: errors={len(input_findings)}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    sensitive_findings, sensitive_input_errors = scan_sensitive_files(targets.text_files)
    gate_findings, gate_input_errors = high_risk_gate_findings(targets.yaml_files)
    adapter_findings, adapter_input_errors = adapter_profile_sensitive_findings(targets.yaml_files)
    input_findings.extend(sensitive_input_errors)
    input_findings.extend(gate_input_errors)
    input_findings.extend(adapter_input_errors)

    if input_findings:
        for finding in input_findings:
            print(finding.format(), file=sys.stderr)
        print(f"security gate input error: errors={len(input_findings)}", file=sys.stderr)
        return EXIT_INPUT_ERROR

    for finding in sensitive_findings:
        print(finding.format(), file=sys.stderr)
    for finding in adapter_findings:
        print(finding.format(), file=sys.stderr)
    for finding in gate_findings:
        print(finding.format(), file=sys.stderr)

    sensitive_total = len(sensitive_findings) + len(adapter_findings)
    if sensitive_total:
        print(f"security gate sensitive failure: findings={sensitive_total}", file=sys.stderr)
        return EXIT_SENSITIVE

    if gate_findings:
        print(f"security gate high-risk gate failure: findings={len(gate_findings)}", file=sys.stderr)
        return EXIT_HIGH_RISK_GATE

    print(
        "security gate ok: "
        f"text_files={len(targets.text_files)} "
        f"yaml_files={len(targets.yaml_files)} "
        "sensitive_findings=0 gate_findings=0"
    )
    return EXIT_SUCCESS


def main(argv: list[str] | None = None) -> int:
    if argv is None and "--help" in sys.argv[1:]:
        parser = build_parser()
        print(parser.format_help(), end="")
        print_help_inventory()
        return EXIT_SUCCESS
    try:
        return run(argv)
    except KeyboardInterrupt:
        finding = InputFinding(None, "interrupted", "Interrupted by user.")
        print(finding.format(), file=sys.stderr)
        print("security gate input error: errors=1", file=sys.stderr)
        return EXIT_INPUT_ERROR


if __name__ == "__main__":
    raise SystemExit(main())
