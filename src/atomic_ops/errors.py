"""Shared CLI error and output helpers for atomic-ops commands."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from typing import Any

from atomic_ops.metadata import redact_sensitive as _redact_sensitive
from atomic_ops.repository import EXIT_CODES


SENSITIVE_KEY_PARTS = ("authorization", "header", "password", "passwd", "pwd", "secret", "token")
SENSITIVE_LINE_PATTERN = re.compile(
    r"(?im)^.*\b(?:authorization|header|password|passwd|pwd|secret|token)\b.*$"
)


@dataclass(frozen=True)
class CliError:
    """A top-level CLI error object with a stable exit code."""

    error_code: str
    message: str
    details: dict[str, Any]
    retryable: bool = False
    suggestion: str | None = None

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.error_code]

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
            "retryable": self.retryable,
        }
        if self.suggestion:
            payload["suggestion"] = self.suggestion
        return redact(payload)


def redact(value: Any) -> Any:
    """Redact sensitive keys and secret-like substrings from output payloads."""

    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, inner in value.items():
            if _is_sensitive_key(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact(inner)
        return _redact_sensitive(redacted)
    if isinstance(value, list):
        return [_redact_sensitive(redact(item)) for item in value]
    if isinstance(value, str):
        return _redact_sensitive(SENSITIVE_LINE_PATTERN.sub("[REDACTED]", value))
    return _redact_sensitive(value)


def write_error(error: CliError, output_format: str) -> int:
    """Write a CLI error object to stderr and return its fixed exit code."""

    payload = error.to_dict()
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True), file=sys.stderr)
    else:
        details = _details_text(payload["details"])
        suggestion = payload.get("suggestion")
        lines = [
            f"error: {payload['error_code']}: {payload['message']}",
            f"details: {details}",
        ]
        if suggestion:
            lines.append(f"suggestion: {suggestion}")
        print("\n".join(lines), file=sys.stderr)
    return error.exit_code


def write_warning(warning: dict[str, Any], output_format: str) -> None:
    """Write a warning object to stderr without contaminating stdout."""

    safe_warning = redact(warning)
    if output_format == "json":
        print(json.dumps(safe_warning, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return

    warning_code = safe_warning.get("warning_code") or "WARNING"
    message = safe_warning.get("message") or ""
    print(f"warning: {warning_code}: {message}", file=sys.stderr)


def write_json_stdout(payload: dict[str, Any]) -> None:
    """Write a redacted JSON payload to stdout."""

    print(json.dumps(redact(payload), ensure_ascii=False, sort_keys=True))


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def _details_text(details: Any) -> str:
    if not isinstance(details, dict) or not details:
        return "{}"
    return ", ".join(f"{key}={value}" for key, value in details.items())
