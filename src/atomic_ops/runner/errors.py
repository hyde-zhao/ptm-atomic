"""Runner-specific error helpers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class RunnerError(Exception):
    """A runner failure with a stable top-level CLI error code."""

    error_code: str
    message: str
    details: dict[str, Any]
    retryable: bool = False
    suggestion: str | None = None

    def __str__(self) -> str:
        return self.message

