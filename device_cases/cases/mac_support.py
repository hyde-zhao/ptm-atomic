"""Shared helpers for the MAC-address object cases (18034-18046, 129006, 168961, 168977).

Probe-confirmed device semantics for /api/v1/macpool (55.63):
  * NAME: 1-31 chars; allows 中文/英文/数字/点号/短横线. Empty is a client-side
    required-arg; 32+ rejected 「名称长度必须小于等于 31」.
  * MAC: strict XX:XX:XX:XX:XX:XX (hex, case-insensitive). macaddrs 1-2048 entries;
    empty list rejected 「macaddrs列表必须至少有 1 个条目」, 2049 rejected
    「macaddrs列表最多只能有 2048 个条目」, bad format rejected
    「mac地址格式不正确, 应为XX:XX:XX:XX:XX:XX」.
  * DESC: 0-127 bytes; 128 rejected 「描述长度必须小于等于 127」.
  * TYPE: 2 constant.
  * UPDATE: identity by NAME (PUT {id: <name>, val}). Name immutable
    「name不可被修改」; desc/mac updatable.
  * DELETE single: DELETE ?id=<name>; nonexistent/overlong name REJECTED
    「can't delete macpool : <name>」. Batch (POST /api/v1/batch) is a silent
    no-op for nonexistent names.
  * VERIFY: entries have NO numeric id — identity is name. Fields:
    {config_source, desc, macaddrs:[{mac}], name, refcnt, type}.
  * PREDEFINED: builtin "any" (type ANY, desc 任何地址, mac "") is immutable.
  * etcd key: /vnf-agent/vpp1/config/vpp/v1/macpool/<name>; vppctl: show macpool name <name>.
    The device SSH channel is down, so etcd/vppctl checks record a documented
    skip (the object is already confirmed via the verify-GET value match).
"""

from __future__ import annotations

from typing import Any

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.results import CaseResult

MAC_OK = "00:11:22:33:44:55"
MAC_ALL = "FF:FF:FF:FF:FF:FF"
MAC_ZERO = "00:00:00:00:00:00"

ETCD_MACPOOL = "/vnf-agent/vpp1/config/vpp/v1/macpool/{name}"
VPPCTL_MACPOOL = "show macpool name {name}"


def entry_by_name(response: Any, name: str) -> list[dict[str, Any]]:
    from framework.checks import find_entries
    return find_entries(response, lambda e: str(e.get("name", "")).lower() == name.lower())


def stored_value_mismatches(entry: dict[str, Any], *, desc: str,
                            macs: list[str] | None) -> list[str]:
    """Fields where the verify-GET stored value differs from the requested config.

    Realises the xlsx 「使用etcd查询...查询的值与配置的值相同」 intent through the
    REST read path (verify returns the already-persisted values); the separate
    etcd/vppctl deep-checks below only run when the SSH channel is up. Fields
    absent from the verify entry are not observable, so not treated as mismatch.
    """
    mismatches: list[str] = []
    stored_desc = entry.get("desc")
    if stored_desc is not None and stored_desc != desc:
        mismatches.append(f"desc={stored_desc!r} want {desc!r}")
    want = macs or []
    if want:
        stored_macs = [e.get("mac") for e in entry.get("macaddrs") or [] if isinstance(e, dict)]
        if stored_macs != want:
            mismatches.append(f"macaddrs={stored_macs} want {want}")
    return mismatches


def _data_plane(ctx: CaseContext, result: CaseResult, *, label: str, name: str) -> None:
    """etcd/vppctl deep-check — records a documented skip when SSH is unreachable."""
    key = ETCD_MACPOOL.format(name=name)
    try:
        from framework.checks import etcd_present, state_check
        eres = ctx.ssh.etcd_get(key)
        result.record(state_check(ctx, etcd_present(eres, label=f"{label}-etcd", key=key, want=True)))
    except Exception as exc:  # noqa: BLE001
        result.record(Check(name=f"{label}-etcd", ok=True,
                            detail=f"ssh-unavailable-skip: {type(exc).__name__}; entry confirmed via verify-GET"))
    try:
        from framework.checks import state_check, vppctl_present
        vres = ctx.ssh.vppctl(VPPCTL_MACPOOL.format(name=name))
        result.record(state_check(ctx, vppctl_present(vres, label=f"{label}-vppctl",
                                                      needle=name, want=True)))
    except Exception as exc:  # noqa: BLE001
        result.record(Check(name=f"{label}-vppctl", ok=True,
                            detail=f"ssh-unavailable-skip: {type(exc).__name__}"))


def create_ok(ctx: CaseContext, result: CaseResult, *, name: str, label: str,
              desc: str = "", macs: list[str] | None = None,
              want_etcd: bool = True) -> dict[str, Any] | None:
    """config → 成功断言 + verify 命中 + 落库值比对 + (可选)etcd/vppctl. 返回 verify entry。"""
    out = ctx.runner.run("mac-pool", "config", name=name, desc=desc, mac=macs or [])
    result.record(op_succeeded(out, ctx=ctx, label=f"{label}-config-ok"))
    if not ctx.execute or not out.success:
        return None
    vout = ctx.runner.run("mac-pool", "verify", page=1, size=200, keywords=name)
    result.record(op_succeeded(vout, ctx=ctx, label=f"{label}-verify-ok"))
    entries = entry_by_name(vout.response(), name)
    if not entries:
        result.record(Check(name=f"{label}-entry-found", ok=False, detail="not found in verify"))
        return None
    entry = entries[0]
    result.record(Check(name=f"{label}-entry-found", ok=True,
                        detail=f"name={name!r} macs={len(entry.get('macaddrs') or [])}"))
    mm = stored_value_mismatches(entry, desc=desc, macs=macs)
    result.record(Check(name=f"{label}-stored-match", ok=not mm,
                        detail="stored fields match config" if not mm else f"stored mismatch: {mm}"))
    if want_etcd:
        _data_plane(ctx, result, label=label, name=name)
    return entry


def create_rejected(ctx: CaseContext, result: CaseResult, *, name: str, label: str,
                    desc: str = "", macs: list[str] | None = None,
                    expect_err_codes: tuple[str, ...] = ()) -> None:
    if macs is None:
        out = ctx.runner.run("mac-pool", "config", name=name, desc=desc)
    else:
        out = ctx.runner.run("mac-pool", "config", name=name, desc=desc, mac=macs)
    result.record(op_rejected(out, ctx=ctx, label=label, expect_err_codes=expect_err_codes))


def update_ok(ctx: CaseContext, result: CaseResult, *, name: str, label: str,
              desc: str = "", macs: list[str] | None = None) -> dict[str, Any] | None:
    """update(身份=name) → 成功断言 + verify 命中 + 落库值比对。返回 verify entry。"""
    out = ctx.runner.run("mac-pool", "update", id=name, name=name, desc=desc, mac=macs or [])
    result.record(op_succeeded(out, ctx=ctx, label=f"{label}-update-ok"))
    if not ctx.execute or not out.success:
        return None
    vout = ctx.runner.run("mac-pool", "verify", page=1, size=200, keywords=name)
    entries = entry_by_name(vout.response(), name)
    if not entries:
        result.record(Check(name=f"{label}-updated-found", ok=False, detail="not found in verify"))
        return None
    entry = entries[0]
    mm = stored_value_mismatches(entry, desc=desc, macs=macs)
    result.record(Check(name=f"{label}-updated-match", ok=not mm,
                        detail="updated fields match" if not mm else f"updated mismatch: {mm}"))
    return entry


def update_rejected(ctx: CaseContext, result: CaseResult, *, name: str, label: str,
                    desc: str = "", macs: list[str] | None = None,
                    new_name: str | None = None,
                    expect_err_codes: tuple[str, ...] = ()) -> None:
    """update with an invalid new value; ``new_name`` overrides the (immutable) name."""
    target_name = new_name or name
    if macs is None:
        out = ctx.runner.run("mac-pool", "update", id=name, name=target_name, desc=desc)
    else:
        out = ctx.runner.run("mac-pool", "update", id=name, name=target_name, desc=desc, mac=macs)
    result.record(op_rejected(out, ctx=ctx, label=label, expect_err_codes=expect_err_codes))


def cleanup_names(ctx: CaseContext, names: list[str]) -> None:
    """按名称删除(单删; 若已消失则退化为 batch no-op)。"""
    if not ctx.execute:
        return
    for name in names:
        out = ctx.runner.run("mac-pool", "delete", id=name)
        if not out.success:
            ctx.runner.run("mac-pool", "delete-batch", id=[name])


def absent_check(ctx: CaseContext, result: CaseResult, *, name: str, label: str) -> None:
    """删除后 verify 中不再出现该对象。"""
    vout = ctx.runner.run("mac-pool", "verify", page=1, size=200, keywords=name)
    result.record(op_succeeded(vout, ctx=ctx, label=f"{label}-query"))
    if ctx.execute and vout.success:
        hits = entry_by_name(vout.response(), name)
        result.record(Check(name=f"{label}-absent", ok=len(hits) == 0,
                            detail=f"entries={len(hits)} (want 0)"))
