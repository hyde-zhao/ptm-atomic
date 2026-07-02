"""Implementation for the ptm-atomic validate command."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Any

import yaml

from atomic_ops.aliases_lookup import extract_alias_keywords, find_ops_by_alias
from atomic_ops.errors import CliError, redact, write_error, write_json_stdout, write_warning
from atomic_ops.repository import (
    ERROR_OP_NOT_FOUND,
    ERROR_PACKAGE_NOT_FOUND,
    ERROR_REPO_NOT_SYNCED,
    SUPPORTED_DEVICES,
    ReadError,
    Repository,
)
from atomic_ops.rollback import validate_rollback_contract
from atomic_ops.suggestions import suggest_op_ids


FINDING_INVALID_TEST_CASE = "INVALID_TEST_CASE"
FINDING_YAML_PARSE_ERROR = "YAML_PARSE_ERROR"
WARNING_STALE_CACHE = "STALE_CACHE"


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "test_case",
        nargs="?",
        help="Test case YAML file to validate.",
    )
    parser.add_argument(
        "--package",
        default=None,
        help="Package manifest name to validate.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "table"),
        default="table",
        help="Output format.",
    )
    parser.add_argument(
        "--check",
        choices=("refs", "rollback"),
        default="refs",
        help="Validation check to run. refs validates operation references; rollback validates rollback metadata.",
    )
    parser.add_argument(
        "--device",
        default=None,
        help="With --check rollback, optionally filter by device type: fw, tg, mock, or sw.",
    )
    parser.set_defaults(validate_parser=parser)


def run(args: argparse.Namespace) -> int:
    _validate_mode_args(args)
    output_format = getattr(args, "format", "table")

    try:
        repo = Repository.from_default_cache()
        _write_stale_warning(repo, output_format)
        if getattr(args, "check", "refs") == "rollback":
            return _run_rollback_check(repo, args, output_format)
        if getattr(args, "package", None):
            return _run_package(repo, str(args.package), output_format)
        return _run_test_case(repo, Path(str(args.test_case)), output_format)
    except ReadError as exc:
        return _write_read_error(exc, output_format)


def _run_package(repo: Repository, package_name: str, output_format: str) -> int:
    manifest = repo.read_package(package_name)
    missing = _missing_refs(repo, manifest.operations)
    if missing:
        return _write_missing_error(missing, repo, "package", output_format)

    report = _report(
        mode="package",
        cache=repo.metadata_summary(),
        checked_count=len(manifest.operations),
        missing_count=0,
        findings=[],
        package=package_name,
    )
    _write_report(report, output_format)
    return 0


def _run_test_case(repo: Repository, test_case_path: Path, output_format: str) -> int:
    op_refs, findings = _read_test_case_refs(test_case_path)
    missing = _missing_refs(repo, op_refs)
    if missing:
        return _write_missing_error(missing, repo, "test_case", output_format)

    report = _report(
        mode="test_case",
        cache=repo.metadata_summary(),
        checked_count=len(op_refs),
        missing_count=0,
        findings=findings,
        test_case=str(test_case_path),
    )
    _write_report(report, output_format)
    return 0


def _run_rollback_check(repo: Repository, args: argparse.Namespace, output_format: str) -> int:
    package_name = getattr(args, "package", None)
    device = getattr(args, "device", None)
    device_filter = device if device in SUPPORTED_DEVICES else None
    if device and device_filter is None:
        report = _report(
            mode="rollback",
            cache=repo.metadata_summary(),
            checked_count=0,
            missing_count=0,
            findings=[
                _finding(
                    "UNKNOWN_DEVICE",
                    "validate.device",
                    f"unknown device filter: {device}",
                    severity="error",
                )
            ],
            package=package_name,
        )
        _write_report(report, output_format)
        return 1

    if package_name:
        operations, missing_count = repo.list_package_operations(package_name, device=device_filter)
    else:
        operations = repo.list_operations(device=device_filter)
        missing_count = 0

    known_ops = {operation.op_id for operation in repo.list_operations()}
    findings: list[dict[str, Any]] = []
    for operation in operations:
        document = repo.read_operation(operation.op_id)
        findings.extend(
            finding.to_dict()
            for finding in validate_rollback_contract(
                operation.op_id,
                document.data,
                known_ops.__contains__,
            )
        )

    error_count = sum(1 for finding in findings if finding.get("severity", "error") == "error")
    report = _report(
        mode="rollback",
        cache=repo.metadata_summary(),
        checked_count=len(operations),
        missing_count=missing_count,
        findings=findings,
        package=package_name,
    )
    report["status"] = "failed" if error_count or missing_count else "passed"
    report["error_count"] = error_count
    report["warning_count"] = len(findings) - error_count
    _write_report(report, output_format)
    return 1 if error_count or missing_count else 0


def _read_test_case_refs(test_case_path: Path) -> tuple[list[str], list[dict[str, Any]]]:
    try:
        data = yaml.safe_load(test_case_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        return [], [_finding(FINDING_YAML_PARSE_ERROR, str(test_case_path), str(exc))]
    except OSError as exc:
        return [], [_finding(FINDING_INVALID_TEST_CASE, str(test_case_path), str(exc))]

    if not isinstance(data, dict):
        return [], [_finding(FINDING_INVALID_TEST_CASE, str(test_case_path), "YAML root must be an object")]

    refs: list[str] = []
    findings: list[dict[str, Any]] = []
    refs.extend(_extract_step_refs(data.get("steps"), "steps", findings))

    tight_sequence = data.get("tight_sequence")
    if not isinstance(tight_sequence, dict):
        findings.append(_finding(FINDING_INVALID_TEST_CASE, "tight_sequence", "tight_sequence must be an object"))
    else:
        refs.extend(_extract_step_refs(tight_sequence.get("steps"), "tight_sequence.steps", findings))

    return refs, findings


def _extract_step_refs(
    steps: Any,
    section: str,
    findings: list[dict[str, Any]],
) -> list[str]:
    if not isinstance(steps, list):
        findings.append(_finding(FINDING_INVALID_TEST_CASE, section, f"{section} must be a list"))
        return []

    refs: list[str] = []
    for index, step in enumerate(steps):
        location = f"{section}[{index}]"
        if not isinstance(step, dict):
            findings.append(_finding(FINDING_INVALID_TEST_CASE, location, "step must be an object"))
            continue
        op_id = step.get("op_id")
        if not isinstance(op_id, str) or not op_id:
            findings.append(_finding(FINDING_INVALID_TEST_CASE, f"{location}.op_id", "op_id must be a non-empty string"))
            continue
        refs.append(op_id)
    return refs


def _missing_refs(repo: Repository, op_refs: list[str] | tuple[str, ...]) -> list[dict[str, Any]]:
    missing: list[dict[str, Any]] = []
    for index, op_id in enumerate(op_refs):
        try:
            repo.read_operation(op_id)
        except ReadError as exc:
            if exc.error_code != ERROR_OP_NOT_FOUND:
                raise
            missing.append(
                {
                    "index": index,
                    "op_id": op_id,
                }
            )
    return missing


def _write_missing_error(
    missing: list[dict[str, Any]],
    repo: Repository,
    mode: str,
    output_format: str,
) -> int:
    operations = repo.list_operations()
    candidates = [operation.op_id for operation in operations]
    missing_with_suggestions: list[dict[str, Any]] = []
    for item in missing:
        op_id = str(item["op_id"])
        alias_suggestions: list[dict[str, Any]] = []
        seen: set[str] = set()
        for keyword in extract_alias_keywords(op_id):
            for match in find_ops_by_alias(keyword, operations):
                if match["op_id"] != op_id and match["op_id"] not in seen:
                    seen.add(match["op_id"])
                    alias_suggestions.append(match)
        missing_with_suggestions.append(
            {
                "index": item["index"],
                "op_id": op_id,
                "suggestions": suggest_op_ids(op_id, candidates),
                "alias_suggestions": alias_suggestions,
            }
        )
    error = CliError(
        error_code=ERROR_OP_NOT_FOUND,
        message="One or more referenced operation ids do not exist in the local cache.",
        details={
            "command": "validate",
            "mode": mode,
            "missing_refs": missing_with_suggestions,
            "cache": repo.metadata_summary(),
        },
        retryable=False,
        suggestion="Run ptm-atomic sync, check op_id spelling, use the suggested operation ids, or run `ptm-atomic list --query <keyword>` to discover operations by business term.",
    )
    return write_error(error, output_format)


def _write_read_error(exc: ReadError, output_format: str) -> int:
    suggestion = "Rerun the command after fixing the local cache."
    if exc.error_code == ERROR_REPO_NOT_SYNCED:
        suggestion = "Run ptm-atomic sync before validating operation references."
    elif exc.error_code == ERROR_PACKAGE_NOT_FOUND:
        suggestion = "Run ptm-atomic packages and choose one of the listed package names."

    error = CliError(
        error_code=exc.error_code,
        message=exc.message,
        details={"command": "validate", **exc.details},
        retryable=exc.retryable,
        suggestion=suggestion,
    )
    return write_error(error, output_format)


def _write_stale_warning(repo: Repository, output_format: str) -> None:
    if not repo.is_stale:
        return
    write_warning(
        {
            "warning_code": WARNING_STALE_CACHE,
            "message": "cache_status=STALE; validate is using stale local cache for read-only validation",
            "details": {
                "command": "validate",
                "cache_status": "STALE",
            },
        },
        output_format,
    )


def _write_report(report: dict[str, Any], output_format: str) -> None:
    if output_format == "json":
        write_json_stdout(report)
        return

    print(_report_table(report))


def _report(
    *,
    mode: str,
    cache: dict[str, Any],
    checked_count: int,
    missing_count: int,
    findings: list[dict[str, Any]],
    package: str | None = None,
    test_case: str | None = None,
) -> dict[str, Any]:
    report: dict[str, Any] = {
        "status": "failed" if findings or missing_count else "passed",
        "mode": mode,
        "checked_count": checked_count,
        "missing_count": missing_count,
        "findings": findings,
        "cache": cache,
    }
    if package:
        report["package"] = package
    if test_case:
        report["test_case"] = test_case
    return report


def _report_table(report: dict[str, Any]) -> str:
    safe_report = redact(report)
    lines = [
        f"status={safe_report['status']}",
        f"mode={safe_report['mode']}",
        f"checked_count={safe_report['checked_count']}",
        f"missing_count={safe_report['missing_count']}",
    ]
    if safe_report.get("package"):
        lines.append(f"package={safe_report['package']}")
    if safe_report.get("test_case"):
        lines.append(f"test_case={safe_report['test_case']}")
    if "error_count" in safe_report:
        lines.append(f"error_count={safe_report['error_count']}")
    if "warning_count" in safe_report:
        lines.append(f"warning_count={safe_report['warning_count']}")

    findings = safe_report.get("findings") or []
    if findings:
        lines.append("findings:")
        for finding in findings:
            lines.append(
                "  "
                f"severity={finding.get('severity', 'error')} "
                f"finding_type={finding.get('finding_type')} "
                f"location={finding.get('location')} "
                f"message={finding.get('message')}"
            )
    else:
        lines.append("findings: none")
    return "\n".join(lines)


def _finding(finding_type: str, location: str, message: str, *, severity: str = "error") -> dict[str, Any]:
    return {
        "finding_type": finding_type,
        "location": redact(location),
        "message": redact(message),
        "severity": severity,
    }


def _validate_mode_args(args: argparse.Namespace) -> None:
    test_case = getattr(args, "test_case", None)
    package_name = getattr(args, "package", None)
    check = getattr(args, "check", "refs")
    if check == "rollback":
        if test_case:
            parser = getattr(args, "validate_parser")
            parser.error("validate --check rollback does not accept a test_case path")
        return
    if bool(test_case) == bool(package_name):
        parser = getattr(args, "validate_parser")
        parser.error("validate requires exactly one of test_case or --package")
