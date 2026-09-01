"""Shared helpers for the multi-segment time-object cases (347287/347288/347291/347292).

REST 资源 /api/v1/timeobject:
  * 无 desc 字段(带 desc → "desc不允许")。
  * oneshot 段: {"starttime":{"time":"YYYY-MM-DD HH:MM:SS"},"endtime":{...}}
  * day/week 段: {"starttime":{"time":"HH:MM:SS","weekday":N},"endtime":{...}}
    (weekday 仅 week 需要; 多段 = timequantum 列表)。
  * month: {"timemonquantum":[{"time":<int小时>,"planday":"1,15"}]}。
  * 更新/删除按 name 身份, PUT 信封 {"id":name,"val":{...}}。
多段 payload 经 --payload-json 逃生口(单段 CLI 参数无法表达多段)。
"""

from __future__ import annotations

from typing import Any

from framework.checks import Check
from framework.context import CaseContext


def time_quantum_starts(ctx: CaseContext, name: str) -> tuple[list[str], Any]:
    """Stored timequantum start times of the entry named ``name``.

    Returns (starts, entry).  ``starts`` is a flat list of "HH:MM:SS" (day/week)
    or "YYYY-MM-DD HH:MM:SS" (oneshot) start strings.
    """
    from framework.object_ops import _run_verify, TIME

    vout = _run_verify(ctx, TIME, name=name)
    if not vout.success:
        return [], None
    entries = [e for e in _walk_dicts(vout.response())
               if isinstance(e, dict) and str(e.get("name", "")) == name]
    if not entries:
        return [], None
    entry = entries[0]
    quantum = entry.get("timequantum")
    starts: list[str] = []
    if isinstance(quantum, list):
        for q in quantum:
            if isinstance(q, dict):
                st = q.get("starttime")
                if isinstance(st, dict):
                    starts.append(str(st.get("time", "")))
    return starts, entry


def time_weekdays(ctx: CaseContext, name: str) -> list[int]:
    """Stored weekday values for a week-schedule time object (deduped, in order)."""
    _, entry = time_quantum_starts(ctx, name)
    if entry is None:
        return []
    quantum = entry.get("timequantum")
    days: list[int] = []
    if isinstance(quantum, list):
        for q in quantum:
            if not isinstance(q, dict):
                continue
            st = q.get("starttime")
            if isinstance(st, dict):
                wd = st.get("weekday")
                try:
                    if int(wd) not in days:
                        days.append(int(wd))
                except (TypeError, ValueError):
                    continue
    return days


def month_plandays(ctx: CaseContext, name: str) -> list[str]:
    """Stored planday tokens for a month-schedule time object."""
    from framework.object_ops import _run_verify, TIME

    vout = _run_verify(ctx, TIME, name=name)
    if not vout.success:
        return []
    entries = [e for e in _walk_dicts(vout.response())
               if isinstance(e, dict) and str(e.get("name", "")) == name]
    if not entries:
        return []
    mon = entries[0].get("timemonquantum")
    days: list[str] = []
    if isinstance(mon, list):
        for m in mon:
            if isinstance(m, dict):
                planday = m.get("planday")
                if planday:
                    days.append(str(planday))
    return days


def quantum_segments_check(*, label: str, starts: list[str],
                           expect: set[str]) -> Check:
    """Assert every expected segment start is stored."""
    ok = expect.issubset(set(starts))
    return Check(name=label, ok=ok,
                 detail=f"stored segments={starts} expect={sorted(expect)}")


def _walk_dicts(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)
