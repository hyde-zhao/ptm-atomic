"""Shared helpers for the local-certificate cases (257653/257655/257656).

Probe-confirmed device semantics for /api/v1/cert/*:
  * Identity is a numeric ``id``; the verify query is name-keyed via ``keywords``.
  * A created localcert is stored as ``<name>.csr`` (localcacert as ``<name>.crt``)
    — verify entries carry the suffixed name, while the input ``name`` is used
    for create/update.
  * ``subject`` is returned as a single concatenated string (RFC 4514-ish), e.g.
    ``/C=CN/ST=Sichuan/L=Chengdu/O=Atomic/OU=QA/CN=<name>`` for localcert and
    ``CN=<name>,OU=QA,O=Atomic,L=Chengdu,ST=Sichuan,C=CN`` for localcacert.
  * Delete is by the numeric id ONLY — deleting by the base (or suffixed) name
    fails with ``delCertFailCanNotDel``.
  * etcd key: /vnf-agent/vpp1/config/cert/v1/{localcert|localcacert}/<id>.
"""

from __future__ import annotations

from typing import Any

from framework.checks import Check, find_entries

CERT_SUBJECT_FIELDS = ("C", "ST", "L", "O", "OU", "CN")


def find_by_name(response: Any, name: str) -> list[dict[str, Any]]:
    """Every verify entry whose name is ``name`` or ``name.csr``/``name.crt``."""
    suffixes = (name, f"{name}.csr", f"{name}.crt")
    return find_entries(
        response,
        lambda e: str(e.get("name", "")).lower() in {s.lower() for s in suffixes},
    )


def cert_present(response: Any, *, label: str, name: str, want: int = 1) -> Check:
    """Assert exactly ``want`` entries for this cert name appear in a verify response."""
    hits = find_by_name(response, name)
    ok = len(hits) == want
    detail = f"name={name!r} matching_entries={len(hits)} want={want}"
    if hits:
        sample = hits[0]
        detail += " e.g. {" + ", ".join(
            f"{k!r}: {sample.get(k)!r}" for k in ("id", "name", "keyType", "keyLenth") if k in sample
        ) + "}"
    return Check(name=label, ok=ok, detail=detail)


def cert_absent(response: Any, *, label: str, name: str) -> Check:
    """Assert no entry with this cert name appears in a verify response."""
    return cert_present(response, label=label, name=name, want=0)


def first_id(response: Any, name: str) -> int | None:
    """Numeric id of the entry matching ``name`` (or its suffix), if any."""
    for entry in find_by_name(response, name):
        value = entry.get("id")
        if isinstance(value, int):
            return value
    return None


def subject_contains(response: Any, name: str, **field_values: str) -> list[str]:
    """Subject tokens present in the matching entry's concatenated subject.

    Returns the list of ``field_values`` keys whose ``<KEY>=<value>`` appears
    in the entry subject (case-insensitive). localcert encodes subject as
    ``/C=CN/ST=Sichuan/...``; localcacert as ``CN=...,ST=Sichuan,...``.
    """
    present: list[str] = []
    for entry in find_by_name(response, name):
        subject = str(entry.get("subject", ""))
        for key, value in field_values.items():
            if f"{key}={value}".lower() in subject.lower():
                present.append(key)
    return present


def subject_ok(response: Any, *, label: str, name: str, **field_values: str) -> Check:
    """Assert the verify entry's subject carries every requested field=value."""
    present = subject_contains(response, name, **field_values)
    missing = [k for k in field_values if k not in present]
    ok = not missing
    detail = f"subject fields present={sorted(present)} missing={missing or 'none'} name={name!r}"
    return Check(name=label, ok=ok, detail=detail)
