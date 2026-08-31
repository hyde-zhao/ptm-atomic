"""Parse ptm-atomic CLI subprocess output into structured outcomes.

With `--format json`, stdout carries exactly one JSON object (the run
envelope); warnings and errors are JSON objects on stderr. Non-envelope
output (argparse errors, import errors) is surfaced in the fallback branch.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass, field
from typing import Any, Iterator


@dataclass
class RunOutcome:
    """Result of a single `ptm-atomic run` invocation."""

    exit_code: int
    success: bool
    status: str = ""  # "success" | "dry_run" | "timeout" | "failed" | ""
    op_id: str = ""
    data: dict[str, Any] = field(default_factory=dict)
    error: dict[str, Any] = field(default_factory=dict)
    raw_stdout: str = ""
    raw_stderr: str = ""

    def response(self) -> dict[str, Any]:
        """Device response payload under data.response (execute mode)."""
        payload = self.data.get("response")
        return payload if isinstance(payload, dict) else {}

    def details(self) -> dict[str, Any]:
        details = self.error.get("details")
        return details if isinstance(details, dict) else {}

    def err_code(self) -> str:
        return str(self.details().get("err_code") or self.error.get("err_code") or "")

    def err_msg(self) -> str:
        return str(self.details().get("err_msg") or self.error.get("message") or "")

    def error_code(self) -> str:
        return str(self.error.get("error_code") or "")

    def __repr__(self) -> str:  # pragma: no cover - debug aid
        return (
            f"RunOutcome(exit={self.exit_code} success={self.success} "
            f"status={self.status!r} op={self.op_id!r} err={self.error_code()}:{self.err_code()})"
        )


def _iter_json_lines(text: str) -> Iterator[Any]:
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            continue


def parse_run(proc: subprocess.CompletedProcess[str]) -> RunOutcome:
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""

    envelope: dict[str, Any] | None = None
    for obj in _iter_json_lines(stdout):
        if isinstance(obj, dict) and obj.get("op_id"):
            envelope = obj
            break

    error: dict[str, Any] = {}
    for obj in _iter_json_lines(stderr):
        if isinstance(obj, dict) and obj.get("error_code"):
            error = obj
            break

    if envelope is not None:
        status = str(envelope.get("status") or "")
        data = envelope.get("data")
        return RunOutcome(
            exit_code=proc.returncode,
            success=proc.returncode == 0 and status == "success",
            status=status,
            op_id=str(envelope.get("op_id") or ""),
            data=data if isinstance(data, dict) else {},
            error=error,
            raw_stdout=stdout,
            raw_stderr=stderr,
        )

    return RunOutcome(
        exit_code=proc.returncode,
        success=False,
        status="failed",
        error=error or {
            "error_code": "NO_ENVELOPE",
            "message": (stdout.strip() or stderr.strip() or f"exit={proc.returncode}"),
        },
        raw_stdout=stdout,
        raw_stderr=stderr,
    )
