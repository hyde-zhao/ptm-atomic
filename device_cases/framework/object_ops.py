"""Generic CRUD + verification helpers for object-like families.

All object families expose config/update/delete/verify (or group-* variants)
with name-keyed payloads and are verified the same way: REST query, etcd key,
and vppctl show command. This module maps a family descriptor to CLI calls and
standard checks so the per-case modules stay small.

Dry-run behaviour: helpers record the command-construction check (op_succeeded
/ op_rejected) and then return early; device-state checks are downgraded to
passes by `state_check`.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .checks import (
    Check,
    entry_by_name,
    etcd_present,
    op_rejected,
    op_succeeded,
    state_check,
    vppctl_present,
)
from .context import CaseContext
from .results import CaseResult


@dataclass(frozen=True)
class Family:
    name: str                # CLI family, e.g. "object", "service-pool"
    name_arg: str            # config arg carrying the object name
    id_arg: str              # update/delete arg carrying the object name
    desc_arg: str = "desc"
    create_action: str = "config"
    update_action: str = "update"
    delete_action: str = "delete"
    verify_action: str = "verify"
    verify_keywords: bool = True


# Family descriptors for the in-scope object families.
OBJ_V4 = Family(name="object", name_arg="object_name", id_arg="object_name", desc_arg="object_desc", verify_keywords=False)
OBJ_V6 = Family(name="ip6pool-object", name_arg="object_name", id_arg="object_name", desc_arg="object_desc")
GROUP_V4 = Family(name="ippool-group", name_arg="name", id_arg="id", desc_arg="desc")
GROUP_V6 = Family(name="ip6pool-group", name_arg="name", id_arg="id", desc_arg="desc")
SERVICE = Family(name="service-pool", name_arg="name", id_arg="id", desc_arg="desc")
SERVICE_GROUP = Family(
    name="service-pool",
    name_arg="name",
    id_arg="id",
    desc_arg="desc",
    create_action="group-config",
    update_action="group-update",
    delete_action="group-delete",
    verify_action="group-verify",
)
TIME = Family(name="time-object", name_arg="name", id_arg="id", desc_arg="desc")

# Data-plane lookup templates: (etcd key, vppctl command) with {name} placeholder.
# vppctl None means the family has no vppctl check (time object).
DATA_PLANE: dict[str, tuple[str, str | None]] = {
    "ipv4-obj": ("/vnf-agent/vpp1/config/vpp/v1/ippool/{name}", "show ippool name {name}"),
    "ipv6-obj": ("/vnf-agent/vpp1/config/vpp/v1/ip6pool/{name}", "show ip6pool name {name}"),
    "ipv4-group": ("/vnf-agent/vpp1/config/vpp/v1/ipgroup/{name}", "show ippool group name {name}"),
    "ipv6-group": ("/vnf-agent/vpp1/config/vpp/v1/ip6group/{name}", "show ip6pool group name {name}"),
    "service": ("/vnf-agent/vpp1/config/vpp/v1/servicepool/{name}", "show serpool name {name}"),
    "service-group": ("/vnf-agent/vpp1/config/vpp/v1/servicegroup/{name}", "show serpool group name {name}"),
    "time": ("/vnf-agent/vpp1/config/vpp/v1/timeobject/{name}", "show timeobject name {name}"),
}

# ── low-level CRUD invocations ────────────────────────────────────────────


def _run_create(ctx: CaseContext, family: Family, *, name: str, **kwargs: Any):
    return ctx.runner.run(family.name, family.create_action, **{family.name_arg: name, **kwargs})


def _run_update(ctx: CaseContext, family: Family, *, name: str, **kwargs: Any):
    return ctx.runner.run(
        family.name,
        family.update_action,
        **{family.id_arg: name, family.name_arg: name, **kwargs},
    )


def _run_delete(ctx: CaseContext, family: Family, *, name: str, **kwargs: Any):
    return ctx.runner.run(family.name, family.delete_action, **{family.id_arg: name, **kwargs})


def _run_verify(ctx: CaseContext, family: Family, *, name: str) -> Any:
    if family.verify_keywords:
        return ctx.runner.run(family.name, family.verify_action, page=1, size=100, keywords=name)
    return ctx.runner.run(family.name, family.verify_action, page=1, size=200)


# ── standard checks ───────────────────────────────────────────────────────


def check_rest_entry(
    ctx: CaseContext,
    result: CaseResult,
    *,
    family: Family,
    name: str,
    label: str,
    expect_desc: str | None = None,
) -> None:
    """REST verify query reflects the object; optionally check desc matches."""
    vout = _run_verify(ctx, family, name=name)
    result.record(op_succeeded(vout, ctx=ctx, label=f"{label}-query"))
    if not ctx.execute or not vout.success:
        return
    hits = entry_by_name(vout.response(), name)
    result.record(
        state_check(
            ctx,
            Check(name=f"{label}-entry", ok=len(hits) >= 1, detail=f"entries={len(hits)} name={name!r}"),
        )
    )
    if hits and expect_desc is not None:
        desc = str(hits[0].get("desc", ""))
        ok = desc == expect_desc
        result.record(
            state_check(
                ctx,
                Check(name=f"{label}-desc", ok=ok, detail=f"desc={desc!r} expect={expect_desc!r}"),
            )
        )


def check_absent_anywhere(
    ctx: CaseContext,
    result: CaseResult,
    *,
    family: Family,
    name: str,
    etcd_key: str,
    vppctl_cmd: str | None,
    vppctl_needle: str,
    label: str,
) -> None:
    """A rejected create must leave no trace in REST, etcd, or vppctl."""
    vout = _run_verify(ctx, family, name=name)
    result.record(op_succeeded(vout, ctx=ctx, label=f"{label}-query"))
    if ctx.execute and vout.success:
        hits = entry_by_name(vout.response(), name)
        result.record(
            state_check(
                ctx,
                Check(name=f"{label}-rest-absent", ok=len(hits) == 0, detail=f"entries={len(hits)}"),
            )
        )
    if not ctx.execute:
        return
    key = etcd_key.format(name=name)
    eres = ctx.ssh.etcd_get(key)
    result.record(state_check(ctx, etcd_present(eres, label=f"{label}-etcd-absent", key=key, want=False)))
    if vppctl_cmd:
        vres = ctx.ssh.vppctl(vppctl_cmd.format(name=name))
        result.record(
            state_check(
                ctx,
                vppctl_present(vres, label=f"{label}-vppctl-absent", needle=vppctl_needle, want=False),
            )
        )


def check_data_plane_present(
    ctx: CaseContext,
    result: CaseResult,
    *,
    family_label: str,
    name: str,
    etcd_key: str,
    vppctl_cmd: str | None,
    vppctl_needle: str,
) -> None:
    """etcd + vppctl confirm the object reached the data plane."""
    if not ctx.execute:
        return
    key = etcd_key.format(name=name)
    eres = ctx.ssh.etcd_get(key)
    result.record(state_check(ctx, etcd_present(eres, label=f"{family_label}-etcd", key=key, want=True)))
    if vppctl_cmd:
        vres = ctx.ssh.vppctl(vppctl_cmd.format(name=name))
        result.record(
            state_check(
                ctx,
                vppctl_present(vres, label=f"{family_label}-vppctl", needle=vppctl_needle, want=True),
            )
        )


# ── case-level drivers ────────────────────────────────────────────────────


def _record_cleanup(ctx: CaseContext, result: CaseResult, out, label: str) -> None:
    """Record a cleanup delete, tolerating already-gone objects.

    Cleanup deletes run after the interesting assertions; if the object was
    never created (or a prior delete already removed it) the device reports a
    not-found error. That must not turn a passing case red.
    """
    if out.success:
        result.record(op_succeeded(out, ctx=ctx, label=label))
        return
    msg = f"{out.err_msg()} {out.err_code()}".lower()
    gone = any(s in msg for s in ("not found", "不存在", "couldn't found", "does not exist", "from db"))
    if gone:
        result.record(Check(name=label, ok=True, detail=f"already gone: {out.err_code()}:{out.err_msg()}"))
    else:
        result.record(op_succeeded(out, ctx=ctx, label=label))


def run_deliver_success(
    ctx: CaseContext,
    result: CaseResult,
    *,
    family: Family,
    name: str,
    etcd_key: str,
    vppctl_cmd: str | None,
    create_kwargs: dict[str, Any],
    update_kwargs: dict[str, Any] | None = None,
    members: list[tuple[Family, str, dict[str, Any]]] = (),
) -> None:
    """Deliver a valid object: create -> update -> REST verify -> etcd -> vppctl,
    then clean up (members first, then the object) in a finally block."""
    member_cleanup: list[tuple[Family, str]] = []
    for mfam, mname, mkwargs in members:
        mout = _run_create(ctx, mfam, name=mname, **mkwargs)
        result.record(op_succeeded(mout, ctx=ctx, label=f"member-create:{mname}"))
        member_cleanup.append((mfam, mname))
        if ctx.execute and not mout.success:
            result.notes.append(f"member create failed ({mname}); skipping main-object checks")
            return

    try:
        out = _run_create(ctx, family, name=name, **create_kwargs)
        result.record(op_succeeded(out, ctx=ctx, label=f"{family.name}-create"))
        if not ctx.execute:
            return
        if not out.success:
            result.record(
                Check(name=f"{family.name}-create-abort", ok=False, detail="create failed; post-create checks skipped")
            )
            return

        check_rest_entry(
            ctx, result, family=family, name=name, label="rest-create",
            expect_desc=create_kwargs.get(family.desc_arg),
        )

        if update_kwargs:
            uout = _run_update(ctx, family, name=name, **update_kwargs)
            result.record(op_succeeded(uout, ctx=ctx, label=f"{family.name}-update"))
            if ctx.execute and uout.success:
                check_rest_entry(
                    ctx, result, family=family, name=name, label="rest-update",
                    expect_desc=update_kwargs.get(family.desc_arg),
                )

        check_data_plane_present(
            ctx, result,
            family_label=family.name, name=name,
            etcd_key=etcd_key, vppctl_cmd=vppctl_cmd, vppctl_needle=name,
        )
    finally:
        if ctx.execute:
            # Delete the main object first: group members are referenced by it
            # and the device refuses to delete a referenced member.
            dout = _run_delete(ctx, family, name=name)
            _record_cleanup(ctx, result, dout, f"{family.name}-cleanup-delete")
            for mfam, mname in reversed(member_cleanup):
                mout = _run_delete(ctx, mfam, name=mname)
                _record_cleanup(ctx, result, mout, f"member-cleanup:{mname}")


def run_deliver_failure(
    ctx: CaseContext,
    result: CaseResult,
    *,
    family: Family,
    name: str,
    etcd_key: str,
    vppctl_cmd: str | None,
    bad_kwargs: dict[str, Any],
) -> None:
    """A device-invalid create must be rejected and leave no trace anywhere."""
    out = _run_create(ctx, family, name=name, **bad_kwargs)
    result.record(op_rejected(out, ctx=ctx, label=f"{family.name}-bad-create-rejected"))
    if not ctx.execute:
        return
    check_absent_anywhere(
        ctx, result,
        family=family, name=name,
        etcd_key=etcd_key, vppctl_cmd=vppctl_cmd, vppctl_needle=name,
        label="rejected",
    )


def run_excl_reject(
    ctx: CaseContext,
    result: CaseResult,
    *,
    family: Family,
    name: str,
    valid_kwargs: dict[str, Any],
    bad_excl_networks: str,
    label: str,
    bad_kwargs: dict[str, Any] | None = None,
) -> None:
    """A valid object is created; then a create and an update carrying a
    device-invalid exclusion list (duplicate entries, or more entries than the
    per-object exclusion capacity) are both rejected and recorded in the
    operation log. The rejected list passes client-side validation — only the
    device rejects it. Mirror of case 263478. ``bad_kwargs`` overrides the
    rejected create's address fields when the case wants a distinct network.
    """
    window_start = int(time.time()) - 300
    bad_name = f"{name}-bad"
    bad_create_kwargs = {**valid_kwargs, **(bad_kwargs or {})}

    create = _run_create(ctx, family, name=name, **valid_kwargs)
    result.record(op_succeeded(create, ctx=ctx, label=f"{label}-base-create-ok"))

    bad = _run_create(ctx, family, name=bad_name, excl_networks=bad_excl_networks, **bad_create_kwargs)
    result.record(op_rejected(bad, ctx=ctx, label=f"{label}-bad-create-rejected"))

    # check2: editing the valid object into the invalid exclusion state.
    if ctx.execute and create.success:
        upd = _run_update(ctx, family, name=name, excl_networks=bad_excl_networks, **valid_kwargs)
        result.record(op_rejected(upd, ctx=ctx, label=f"{label}-bad-update-rejected"))
    elif not ctx.execute:
        # dry-run: still exercise the update construction
        upd = _run_update(ctx, family, name=name, excl_networks=bad_excl_networks, **valid_kwargs)
        result.record(op_rejected(upd, ctx=ctx, label=f"{label}-bad-update-rejected"))

    # Both rejections must appear in the operation log.
    if ctx.execute:
        cap = ctx.runner.run(
            "operation-log", "capture",
            timetype="custom", starttime=window_start, endtime=int(time.time()) + 10, page=1, size=200,
        )
        result.record(op_succeeded(cap, ctx=ctx, label=f"{label}-oplog-capture"))
        if cap.success:
            messages = oplog_messages(cap.response())
            hits = [m for m in messages if name in m]
            result.record(
                Check(name=f"{label}-oplog-base-name", ok=len(hits) >= 1, detail=f"occurrences={len(hits)} needle={name!r}")
            )
            hits = [m for m in messages if ("新增" in m or "修改" in m) and "失败" in m]
            result.record(
                Check(name=f"{label}-oplog-bad-name", ok=len(hits) >= 1, detail=f"failure entries={len(hits)}")
            )

    if ctx.execute and create.success:
        _record_cleanup(ctx, result, _run_delete(ctx, family, name=name), f"{label}-cleanup-delete")


def oplog_messages(response: Any) -> list[str]:
    """Flatten an operation-log capture response into its log messages."""
    if not isinstance(response, dict):
        return []
    messages: list[str] = []
    for entry in response.get("vals") or []:
        if isinstance(entry, dict) and isinstance(entry.get("message"), str):
            messages.append(entry["message"])
    return messages


def oplog_failure_hits(messages: list[str], action: str) -> list[str]:
    """Messages for a failed ``action`` (新增/修改/删除): the action keyword
    plus a failure marker (device logs rejections as "… 参数校验失败 …" or
    "…失败")."""
    return [m for m in messages if action in m and any(marker in m for marker in ("失败", "error", "failed"))]


def _oplog_required_present(
    messages: list[str],
    *,
    name: str,
    gone_name: str,
    bad_logged: bool,
    delete_bad_logged: bool,
) -> bool:
    """True when every operation-log entry the device must have produced is
    present in ``messages``. Used to decide whether to re-query: the log writer
    can lag under load, so a just-issued operation may not be queryable yet."""
    if not any(name in m for m in messages):
        return False
    if delete_bad_logged and not any(gone_name in m for m in messages):
        return False
    if bad_logged and (not oplog_failure_hits(messages, "新增") or not oplog_failure_hits(messages, "修改")):
        return False
    return True


def run_oplog(
    ctx: CaseContext,
    result: CaseResult,
    *,
    family: Family,
    name: str,
    config_kwargs: dict[str, Any],
    update_kwargs: dict[str, Any],
    bad_kwargs: dict[str, Any],
    members: list[tuple[Family, str, dict[str, Any]]] = (),
    bad_logged: bool = True,
    delete_bad_logged: bool = True,
) -> None:
    """Operation-log coverage: create/update/delete x success/failure, then
    assert the operation log records the object name for the operations the
    device logs with a name — successful create/update/delete.

    Rejected create/update are asserted as rejections. Whether the device also
    logs a rejected attempt depends on the family: validation failures for
    object / service / time families are logged ("… 参数校验失败 …"), while
    group-member reference rejections are not logged at all. Deleting a
    nonexistent object is logged with the attempted name for service/time
    families but not for ipv4/group families. ``bad_logged`` /
    ``delete_bad_logged`` assert the failure-log entry (default) or only report
    it (families the device does not log that rejection for).
    """
    bad_name = f"{name}-bad"
    gone_name = f"{name}-gone"
    # Wide window: the local clock runs ~137s ahead of the device clock, so a
    # narrow now-30 window can land entirely before the device-logged entries.
    window_start = int(time.time()) - 300

    member_cleanup: list[tuple[Family, str]] = []
    try:
        for mfam, mname, mkwargs in members:
            mout = _run_create(ctx, mfam, name=mname, **mkwargs)
            result.record(op_succeeded(mout, ctx=ctx, label=f"member-create:{mname}"))
            member_cleanup.append((mfam, mname))
            if ctx.execute and not mout.success:
                result.notes.append(f"member create failed ({mname}); skipping oplog sequence")
                return

        out = _run_create(ctx, family, name=name, **config_kwargs)
        result.record(op_succeeded(out, ctx=ctx, label="oplog-create-ok"))

        out = _run_create(ctx, family, name=bad_name, **bad_kwargs)
        result.record(op_rejected(out, ctx=ctx, label="oplog-create-bad"))

        out = _run_update(ctx, family, name=name, **update_kwargs)
        result.record(op_succeeded(out, ctx=ctx, label="oplog-update-ok"))

        out = _run_update(ctx, family, name=name, **bad_kwargs)
        result.record(op_rejected(out, ctx=ctx, label="oplog-update-bad"))

        out = _run_delete(ctx, family, name=name)
        result.record(op_succeeded(out, ctx=ctx, label="oplog-delete-ok"))

        out = _run_delete(ctx, family, name=gone_name)
        result.record(op_rejected(out, ctx=ctx, label="oplog-delete-bad"))

        if not ctx.execute:
            return

        def _capture() -> list[str] | None:
            cap = ctx.runner.run(
                "operation-log", "capture",
                timetype="custom", starttime=window_start, endtime=int(time.time()) + 10, page=1, size=200,
            )
            result.record(op_succeeded(cap, ctx=ctx, label="oplog-capture"))
            if not cap.success:
                return None
            return oplog_messages(cap.response())

        messages = _capture()
        if messages is None:
            return
        # The operation-log writer can lag under load (a failed delete for the
        # time family was observed missing on first query); re-query until every
        # entry the device must have logged appears, or give up after 3 tries.
        for _ in range(2):
            if _oplog_required_present(
                messages, name=name, gone_name=gone_name,
                bad_logged=bad_logged, delete_bad_logged=delete_bad_logged,
            ):
                break
            time.sleep(2)
            refreshed = _capture()
            if refreshed is None:
                return
            messages = refreshed

        # Successful create/update/delete are logged with the object name.
        for action, needle in (
            ("create-ok", name),
            ("update-ok", name),
            ("delete-ok", name),
        ):
            hits = [m for m in messages if needle in m]
            result.record(
                state_check(
                    ctx,
                    Check(
                        name=f"oplog-{action}",
                        ok=len(hits) >= 1,
                        detail=f"occurrences={len(hits)} needle={needle!r}",
                    ),
                )
            )
        # Deleting a nonexistent object logs the attempted name for service /
        # time families; ipv4-object / group families reject it without a log.
        hits = [m for m in messages if gone_name in m]
        if delete_bad_logged:
            ok = len(hits) >= 1
            detail = f"occurrences={len(hits)} needle={gone_name!r}"
        else:
            ok = True
            detail = f"occurrences={len(hits)} needle={gone_name!r} (informational: this family does not log delete-of-nonexistent)"
        result.record(state_check(ctx, Check(name="oplog-delete-bad", ok=ok, detail=detail)))
        # Rejected create/update: object/service/time families log the failure
        # (without the object name), group families do not log it at all.
        for action, label in (("新增", "oplog-create-bad"), ("修改", "oplog-update-bad")):
            hits = oplog_failure_hits(messages, action)
            if bad_logged:
                ok = len(hits) >= 1
                detail = f"failure entries={len(hits)} action={action!r}"
            else:
                ok = True
                detail = f"failure entries={len(hits)} action={action!r} (informational: group rejections not device-logged)"
            result.record(state_check(ctx, Check(name=label, ok=ok, detail=detail)))
    finally:
        if ctx.execute:
            for mfam, mname in reversed(member_cleanup):
                mout = _run_delete(ctx, mfam, name=mname)
                _record_cleanup(ctx, result, mout, f"member-cleanup:{mname}")
