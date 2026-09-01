"""Shared helpers for the geoip custom-region cases.

geoip objects have no ``name`` field — identity is the numeric ``id`` returned
on create and carried by every verify entry. The device ignores the verify
``keywords`` filter (probe-confirmed: any keyword returns the full list), so
presence/absence is asserted client-side over the full paginated response via
exact ``desc`` match. Each object also reserves a unique ip range: a second
object sharing an ip is rejected with ``eGeoipIPConflict``.
"""

from __future__ import annotations

from typing import Any

from framework.checks import Check, find_entries

# Device-validated region values for country CN (probe17g/17h isolation).
PROVINCE = "Hunan"
CITY = "Changsha"


def find_by_desc(response: dict[str, Any], desc: str) -> list[dict[str, Any]]:
    """Every verify entry whose desc equals ``desc`` (case-insensitive)."""
    return find_entries(response, lambda e: str(e.get("desc", "")).lower() == desc.lower())


def geoip_present(response: dict[str, Any], *, label: str, desc: str, want: int = 1) -> Check:
    """Assert exactly ``want`` entries with this desc appear in a verify response."""
    hits = find_by_desc(response, desc)
    ok = len(hits) == want
    detail = f"desc={desc!r} matching_entries={len(hits)} want={want}"
    if hits:
        # Sample only ASCII-safe fields: the device body is GBK-decoded and
        # Chinese region fields carry replacement chars that crash GBK consoles.
        sample = hits[0]
        detail += " e.g. {" + ", ".join(
            f"{k!r}: {sample.get(k)!r}" for k in ("id", "ip", "desc") if k in sample
        ) + "}"
    return Check(name=label, ok=ok, detail=detail)


def geoip_absent(response: dict[str, Any], *, label: str, desc: str) -> Check:
    """Assert no entry with this desc appears in a verify response."""
    return geoip_present(response, label=label, desc=desc, want=0)


def first_id(response: dict[str, Any], desc: str) -> int | None:
    """Numeric id of the entry matching ``desc``, if any."""
    for entry in find_by_desc(response, desc):
        value = entry.get("id")
        if isinstance(value, int):
            return value
    return None
