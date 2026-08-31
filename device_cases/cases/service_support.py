"""Service search support helpers shared by the service search cases."""

from __future__ import annotations

from typing import Any


def named_entries(response: Any) -> list[dict[str, Any]]:
    """All REST payload dicts that carry a non-empty string ``name``.

    Works for preset/custom service entries (name + ranges) and service group
    entries (name + servicepools). The device ignores src_port/dst_port/
    protocol on every service type (probe-confirmed on 55.63), so the only
    filter that actually narrows the result list is ``keywords`` (by name).
    """
    hits: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            name = node.get("name")
            if isinstance(name, str) and name:
                hits.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(response)
    return hits


def name_filtered(response: Any, keyword: str) -> list[dict[str, Any]]:
    """Entries whose name contains ``keyword`` (case-insensitive)."""
    low = keyword.lower()
    return [e for e in named_entries(response) if low in str(e.get("name", "")).lower()]
