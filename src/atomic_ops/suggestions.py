"""Operation id suggestion helpers."""

from __future__ import annotations

from collections.abc import Iterable

from atomic_ops.repository import SUPPORTED_DEVICES


def suggest_op_ids(requested: str, candidates: Iterable[str], *, limit: int = 3) -> list[str]:
    """Return stable top-N operation id suggestions for a missing op_id."""

    unique_candidates = sorted({candidate for candidate in candidates if candidate})
    if limit <= 0 or not requested or not unique_candidates:
        return []

    filtered = _same_prefix_candidates(requested, unique_candidates)
    ranked = sorted((_levenshtein(requested, candidate), candidate) for candidate in filtered)
    return [candidate for _distance, candidate in ranked[:limit]]


def _same_prefix_candidates(requested: str, candidates: list[str]) -> list[str]:
    prefix = requested.split("_", 1)[0]
    if prefix not in SUPPORTED_DEVICES:
        return candidates
    same_prefix = [candidate for candidate in candidates if candidate.startswith(f"{prefix}_")]
    return same_prefix or candidates


def _levenshtein(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for left_index, left_char in enumerate(left, start=1):
        current = [left_index]
        for right_index, right_char in enumerate(right, start=1):
            substitution = previous[right_index - 1] + (left_char != right_char)
            insertion = current[right_index - 1] + 1
            deletion = previous[right_index] + 1
            current.append(min(substitution, insertion, deletion))
        previous = current
    return previous[-1]
