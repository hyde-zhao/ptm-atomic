#!/usr/bin/env python
"""Run the object-management P0/P1 cases against a live NGFW device.

Usage examples (run from the ptm-atomic repo root):

    # Build the framework + dry-run every case (no device mutation, no creds)
    uv run --python 3.11 python device_cases/run_all.py --dry-run

    # Single case in dry-run
    uv run --python 3.11 python device_cases/run_all.py --dry-run --only 900107

    # Real execution (requires NGFW_PASSWORD / NGFW_ROOT_PASSWORD and sessions)
    OBJECT_CASE_EXECUTE=1 NGFW_PASSWORD=... NGFW_ROOT_PASSWORD=... \\
        uv run --python 3.11 python device_cases/run_all.py --execute \
        --report out/object_cases_$(date +%s).json

    # Clean up any leftover atc-prefixed objects
    uv run --python 3.11 python device_cases/run_all.py --sweep
"""

from __future__ import annotations

import argparse
import importlib
import sys
import time
from pathlib import Path

DEVICE_CASES_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(DEVICE_CASES_DIR))

from config import (  # noqa: E402
    BASE_URL,
    DEVICE_IP,
    ROOT_PASSWORD_ENV,
    SESSION_FILE,
    SSH_SESSION_FILE,
    TIMEOUT,
    VERIFY_TLS,
    WEB_PASSWORD_ENV,
)
from framework.context import CaseContext  # noqa: E402
from framework.results import CaseResult, summarize, write_report  # noqa: E402
from framework.runner import CliRunner  # noqa: E402
from framework.ssh_device import SSHDevice  # noqa: E402


def discover_cases() -> list[str]:
    cases_dir = DEVICE_CASES_DIR / "cases"
    return sorted(p.stem for p in cases_dir.glob("c_*.py"))


def load_case(module_name: str):
    return importlib.import_module(f"cases.{module_name}")


def build_context(args: argparse.Namespace) -> CaseContext:
    device = args.device or DEVICE_IP
    runner = CliRunner(
        base_url=f"https://{device}",
        session_file=SESSION_FILE,
        execute=args.execute,
        verify_tls=args.verify_tls,
        timeout=args.timeout,
    )
    ssh = SSHDevice(
        host=device,
        password_env=ROOT_PASSWORD_ENV,
        timeout=args.timeout,
    )
    return CaseContext(
        execute=args.execute,
        device=device,
        session_file=SESSION_FILE,
        ssh_session_file=SSH_SESSION_FILE,
        web_password_env=WEB_PASSWORD_ENV,
        root_password_env=ROOT_PASSWORD_ENV,
        verify_tls=args.verify_tls,
        timeout=args.timeout,
        runner=runner,
        ssh=ssh,
        report_dir=Path(args.report_dir),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--execute", action="store_true", help="Run with --execute (live device mutations).")
    mode.add_argument("--dry-run", action="store_true", help="Run without --execute (envelope/dry_run only).")
    parser.add_argument("--only", action="append", default=[], help="Case id filter (repeatable).")
    parser.add_argument("--device", default="", help="Override device IP.")
    parser.add_argument("--verify-tls", action="store_true", help="Enable TLS verification.")
    parser.add_argument("--timeout", type=float, default=TIMEOUT, help="Per-invocation timeout seconds.")
    parser.add_argument("--report", default="out/object_cases.json", help="JSON report output path.")
    parser.add_argument("--report-dir", default="out", help="Directory for any per-case artifacts.")
    parser.add_argument("--sweep", action="store_true", help="Sweep leftover atc-prefixed objects and exit.")
    args = parser.parse_args()

    ctx = build_context(args)

    if args.sweep:
        return sweep(ctx)

    case_names = discover_cases()
    if not case_names:
        print("No case modules found under device_cases/cases/", file=sys.stderr)
        return 2
    if args.only:
        wanted = {f"c_{cid}" if not cid.startswith("c_") else cid for cid in args.only}
        case_names = [name for name in case_names if name in wanted]

    results: list[CaseResult] = []
    for name in case_names:
        module = load_case(name)
        title = getattr(module, "TITLE", name)
        result = CaseResult(case_id=name, title=title)
        started = time.monotonic()
        try:
            module.run(ctx, result)
        except Exception as exc:  # noqa: BLE001 - a failing case must not abort the run
            result.record(
                _err_check("unhandled-exception", f"{type(exc).__name__}: {exc}"),
            )
            result.notes.append("case raised an unhandled exception")
        result.duration_s = time.monotonic() - started
        results.append(result)
        _print_case(result)

    summary = summarize(results)
    write_report(args.report, summary)
    print(f"\n== Summary: {summary['passed']} passed, {summary['failed']} failed, "
          f"{summary['skipped']} skipped of {summary['total']} (report: {args.report})")
    if summary["failed_cases"]:
        print(f"   Failed: {', '.join(summary['failed_cases'])}")
    return 0 if summary["failed"] == 0 else 1


def _err_check(name: str, detail: str):
    from framework.results import Check
    return Check(name=name, ok=False, detail=detail)


def _print_case(result: CaseResult) -> None:
    tag = "SKIP" if result.skipped else ("PASS" if result.passed else "FAIL")
    print(f"[{tag}] {result.case_id} {result.title} ({result.duration_s:.2f}s)")
    for check in result.checks:
        mark = "ok  " if check.ok else "FAIL"
        print(f"       {mark} {check.name}: {check.detail}")


def sweep(ctx: CaseContext) -> int:
    """Delete leftover atc-prefixed objects from a prior run, per family.

    Only the families with simple name-addressable deletion are swept here;
    remaining families are left for the operator (their cleanup is handled by
    each case's finally block during normal runs).
    """
    from framework.checks import expect_rejected

    deleted: list[str] = []
    failures: list[str] = []
    for name in _list_leftovers(ctx):
        if _try_delete(ctx, name):
            deleted.append(name)
        else:
            failures.append(name)
    print(f"Sweep: deleted {len(deleted)}, failed {len(failures)}")
    for name in failures:
        print(f"  leftover: {name}")
    return 0 if not failures else 1


def _list_leftovers(ctx: CaseContext) -> list[str]:
    # Object families are name-addressable via verify; scan IPv4 object list
    # only as the representative leftover source. Group objects reference
    # members, so sweep order matters; cases normally clean themselves.
    leftovers: list[str] = []
    for family, action in (("object", "verify"), ("service-pool", "verify")):
        outcome = ctx.runner.run(family, action, page=1, size=200)
        for entry in _walk_dicts(outcome.response()):
            name = str(entry.get("name", ""))
            if name.startswith("atc"):
                leftovers.append(name)
    return sorted(set(leftovers))


def _walk_dicts(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)


def _try_delete(ctx: CaseContext, name: str) -> bool:
    for family, action, key in (
        ("object", "delete", "object_name"),
        ("service-pool", "delete", "id"),
    ):
        outcome = ctx.runner.run(family, action, **{key: name})
        if outcome.success:
            return True
        # Already gone is fine too
        if outcome.err_code() in ("", "0") and "not exist" in outcome.err_msg().lower():
            return True
    return False


if __name__ == "__main__":
    raise SystemExit(main())
