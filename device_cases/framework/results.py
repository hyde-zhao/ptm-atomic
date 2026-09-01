"""Case result aggregation: checks, per-case results, summary, JSON report."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Check:
    name: str
    ok: bool
    detail: str = ""


@dataclass
class CaseResult:
    case_id: str
    title: str
    checks: list[Check] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    skipped: bool = False
    duration_s: float = 0.0

    def record(self, check: Check) -> None:
        self.checks.append(check)

    @property
    def passed(self) -> bool:
        if self.skipped:
            return True
        return all(c.ok for c in self.checks)

    def summary(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "title": self.title,
            "passed": self.passed,
            "skipped": self.skipped,
            "duration_s": round(self.duration_s, 3),
            "checks": [{"name": c.name, "ok": c.ok, "detail": c.detail} for c in self.checks],
            "notes": self.notes,
        }


def summarize(results: list[CaseResult]) -> dict[str, Any]:
    passed = [r for r in results if r.passed and not r.skipped]
    failed = [r for r in results if not r.passed]
    skipped = [r for r in results if r.skipped]
    return {
        "total": len(results),
        "passed": len(passed),
        "failed": len(failed),
        "skipped": len(skipped),
        "failed_cases": [r.case_id for r in failed],
        "results": [r.summary() for r in results],
    }


def write_report(report_path: str, summary: dict[str, Any]) -> None:
    path = Path(report_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(summary, fh, ensure_ascii=False, indent=2, sort_keys=True)
