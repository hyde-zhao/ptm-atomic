"""Unique object naming for cases (enables atc-prefix sweep)."""

from __future__ import annotations

import uuid


def unique(case_id: int, suffix: str) -> str:
    """Build a deterministic name: atc<case_id>-<suffix>.

    NGFW object names allow letters, digits, Chinese, hyphen and dot — but no
    underscore — so hyphens are used as separators.
    """
    return f"atc{case_id}-{suffix}"


def unique_random(case_id: int, suffix: str) -> str:
    base = unique(case_id, suffix)
    return f"{base}-{uuid.uuid4().hex[:6]}"
