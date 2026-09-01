"""Assertion helpers shared by the object-management cases.

Each helper returns a :class:`Check` (name, ok, detail) that the case appends
to its CaseResult. Checks are deliberately tolerant of response shape: device
verify payloads are walked recursively rather than pinned to one schema.
"""

from __future__ import annotations

from typing import Any, Callable

from .envelope import RunOutcome
from .results import Check

Matcher = Callable[[dict[str, Any]], bool]


# ── response walking ──────────────────────────────────────────────────────


def find_entries(response: Any, matcher: Matcher) -> list[dict[str, Any]]:
    """Return every dict node in the response (recursively) that matches."""
    hits: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            if matcher(node):
                hits.append(node)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(response)
    return hits


def find_strings(
    response: Any,
    *,
    key_contains: str = "",
    value_contains: str = "",
) -> list[str]:
    """Return string values in the response whose key/ value contain substrings."""
    hits: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            for key, value in node.items():
                if isinstance(value, str):
                    if (not key_contains or key_contains in key) and value_contains in value:
                        hits.append(value)
                else:
                    walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(response)
    return hits


def entry_by_name(response: Any, name: str) -> list[dict[str, Any]]:
    """Entries whose 'name'-ish field equals name (case-insensitive)."""
    return find_entries(response, lambda e: str(e.get("name", "")).lower() == name.lower())


def response_error_text(response: dict[str, Any]) -> str:
    """Best-effort error text from a device error payload."""
    for key in ("errMsg", "message", "error", "msg"):
        value = response.get(key)
        if value:
            return str(value)
    return ""


# ── checks ────────────────────────────────────────────────────────────────


def expect_success(outcome: RunOutcome, *, label: str) -> Check:
    ok = outcome.success
    if ok:
        detail = f"exit={outcome.exit_code} status={outcome.status} op={outcome.op_id}"
    else:
        detail = (
            f"expected success, got status={outcome.status!r} exit={outcome.exit_code} "
            f"err={outcome.error_code()}:{outcome.err_code()}:{outcome.err_msg()}"
        )
    return Check(name=label, ok=ok, detail=detail)


def expect_rejected(
    outcome: RunOutcome,
    *,
    label: str,
    expect_err_codes: tuple[str, ...] = (),
) -> Check:
    """A device rejection (or client validation failure) is expected.

    ``expect_err_codes`` optionally pins the device-level err_code; when empty,
    any non-success outcome counts as rejection.
    """
    if not outcome.success:
        if expect_err_codes:
            code = outcome.err_code()
            ok = code in expect_err_codes
            detail = (
                f"rejected err_code={code} err_msg={outcome.err_msg()}"
                if ok
                else f"rejected with err_code={code}, expected one of {expect_err_codes}"
            )
        else:
            ok = True
            detail = f"rejected: {outcome.error_code()}:{outcome.err_code()}:{outcome.err_msg()}"
        return Check(name=label, ok=ok, detail=detail)
    return Check(
        name=label,
        ok=False,
        detail=f"expected rejection but op succeeded (status={outcome.status})",
    )


def expect_dry_run(outcome: RunOutcome, *, label: str) -> Check:
    """For --execute runs the caller asserts a real success; for dry-run a
    well-formed dry_run envelope with execute_required is expected."""
    ok = outcome.status == "dry_run" and outcome.data.get("execute_required") is True
    detail = f"status={outcome.status!r} execute_required={outcome.data.get('execute_required')}"
    return Check(name=label, ok=ok, detail=detail)


def expect_response_has(
    response: dict[str, Any],
    *,
    label: str,
    matcher: Matcher,
    want: int = 1,
    minimum: int = 0,
) -> Check:
    """Assert at least ``want`` (or ``minimum``) matching entries in response."""
    hits = find_entries(response, matcher)
    if minimum:
        ok = len(hits) >= minimum
        detail = f"matching_entries={len(hits)} minimum={minimum}"
    else:
        ok = len(hits) >= want
        detail = f"matching_entries={len(hits)} want={want}"
    if hits:
        detail += f" e.g. {hits[0]}"
    return Check(name=label, ok=ok, detail=detail)


def expect_string_occurrence(
    response: dict[str, Any],
    *,
    label: str,
    value_contains: str,
    key_contains: str = "",
    want: int = 1,
) -> Check:
    hits = find_strings(response, key_contains=key_contains, value_contains=value_contains)
    ok = len(hits) >= want
    return Check(
        name=label,
        ok=ok,
        detail=f"occurrences={len(hits)} want={want} value_contains={value_contains!r} key_contains={key_contains!r}",
    )


def expect_absent_in_rest(
    response: dict[str, Any],
    *,
    label: str,
    name: str,
) -> Check:
    """A failed create must not leave the object queryable via REST."""
    hits = entry_by_name(response, name)
    return Check(
        name=label,
        ok=len(hits) == 0,
        detail=f"matching_entries={len(hits)} (want 0)",
    )


def etcd_present(ssh_result, *, label: str, key: str, want: bool = True) -> Check:
    present = ssh_result.exit_code == 0 and bool(ssh_result.stdout.strip())
    ok = present == want
    detail = f"etcdctl get {key}: present={present} exit={ssh_result.exit_code} out={ssh_result.stdout[:120]!r}"
    return Check(name=label, ok=ok, detail=detail)


def vppctl_present(ssh_result, *, label: str, needle: str, want: bool = True) -> Check:
    present = ssh_result.contains(needle)
    ok = present == want
    detail = (
        f"vppctl output contains {needle!r}: {present} (want {want}) "
        f"out={ssh_result.text()[:200]!r}"
    )
    return Check(name=label, ok=ok, detail=detail)


# ── mode-aware helpers ────────────────────────────────────────────────────


def state_check(ctx, check: Check) -> Check:
    """Downgrade a device-state check to a pass under dry-run.

    Under ``--dry-run`` there is no device mutation and no SSH session, so
    REST-presence / etcd / vppctl assertions cannot run; the check is recorded
    as a pass with a note rather than a false failure.
    """
    if getattr(ctx, "execute", False):
        return check
    return Check(name=check.name, ok=True, detail="dry-run: device state not checked")


def op_succeeded(outcome: RunOutcome, *, ctx, label: str) -> Check:
    """Mode-aware success assertion.

    Execute: the device returned success. Dry-run: the CLI constructed a
    well-formed request (dry_run envelope with execute_required).
    """
    if getattr(ctx, "execute", False):
        return expect_success(outcome, label=label)
    ok = outcome.status == "dry_run" and outcome.data.get("execute_required") is True
    detail = f"status={outcome.status!r} execute_required={outcome.data.get('execute_required')}"
    return Check(name=label, ok=ok, detail=detail)


def op_rejected(outcome: RunOutcome, *, ctx, label: str, expect_err_codes: tuple[str, ...] = ()) -> Check:
    """Mode-aware rejection assertion.

    Execute: device (or client validation) rejected the request. Dry-run:
    client-side validation rejections are already observable (the CLI returns
    an error envelope); device-only rejections can only be observed under
    --execute, so a clean dry_run envelope passes.
    """
    if getattr(ctx, "execute", False):
        return expect_rejected(outcome, label=label, expect_err_codes=expect_err_codes)
    if outcome.status == "failed" and outcome.error_code():
        return Check(
            name=label,
            ok=True,
            detail=f"dry-run client rejection: {outcome.error_code()}:{outcome.err_msg()}",
        )
    ok = outcome.status in ("dry_run", "success")
    return Check(
        name=label,
        ok=ok,
        detail="dry-run: device rejection only observable under --execute",
    )
