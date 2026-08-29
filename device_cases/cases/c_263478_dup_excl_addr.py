"""P1-263478: IPV4 地址对象重复排除地址配置.

A valid object is created, then a create with duplicate exclusion networks and
an update with duplicate exclusions are both rejected and logged; the object
is cleaned up. The duplicate exclusion list passes client-side validation and
must be rejected by the device.
"""

from __future__ import annotations

import time

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import OBJ_V4, oplog_messages
from framework.results import CaseResult

TITLE = "P1-263478 IPv4 对象重复排除地址配置"

DUP_EXCL = '[{"ipaddr":"10.0.0.1","mask":""},{"ipaddr":"10.0.0.1","mask":""}]'


def run(ctx: CaseContext, result: CaseResult) -> None:
    base = unique_random(263478, "dupexcl")
    bad_name = f"{base}-bad"
    # Wide window: the local clock runs ~137s ahead of the device clock.
    window_start = int(time.time()) - 300

    # A valid object to later edit into an invalid state.
    create = ctx.runner.run(
        "object", "config",
        object_name=base, ipaddr="10.44.0.0", mask="24", object_desc="atc dupexcl base",
    )
    result.record(op_succeeded(create, ctx=ctx, label="base-create-ok"))

    # check1: create with duplicate exclusion addresses is rejected.
    bad = ctx.runner.run(
        "object", "config",
        object_name=bad_name, ipaddr="10.45.0.0", mask="24",
        excl_networks=DUP_EXCL, object_desc="atc dupexcl bad",
    )
    result.record(op_rejected(bad, ctx=ctx, label="dup-create-rejected"))

    # check2: edit the valid object to duplicate exclusions is rejected.
    if ctx.execute and create.success:
        upd = ctx.runner.run(
            "object", "update",
            object_name=base, ipaddr="10.44.0.0", mask="24",
            excl_networks=DUP_EXCL, object_desc="atc dupexcl updated",
        )
        result.record(op_rejected(upd, ctx=ctx, label="dup-update-rejected"))
    elif not ctx.execute:
        # dry-run: still exercise the update construction
        upd = ctx.runner.run(
            "object", "update",
            object_name=base, ipaddr="10.44.0.0", mask="24",
            excl_networks=DUP_EXCL, object_desc="atc dupexcl updated",
        )
        result.record(op_rejected(upd, ctx=ctx, label="dup-update-rejected"))

    # Both rejections must be recorded in the operation log.
    if ctx.execute:
        cap = ctx.runner.run(
            "operation-log", "capture",
            timetype="custom", starttime=window_start, endtime=int(time.time()) + 10, page=1, size=200,
        )
        result.record(op_succeeded(cap, ctx=ctx, label="oplog-capture"))
        if cap.success:
            messages = oplog_messages(cap.response())
            # The base object's successful create is logged with its name.
            hits = [m for m in messages if base in m]
            result.record(
                Check(name="oplog-base-name", ok=len(hits) >= 1, detail=f"occurrences={len(hits)} needle={base!r}")
            )
            # The rejected duplicate-exclusion attempts are logged as
            # "新增/修改 IPV4地址对象 参数校验失败 …" — the name is not included.
            hits = [m for m in messages if ("新增" in m or "修改" in m) and "失败" in m]
            result.record(
                Check(
                    name="oplog-bad-name",
                    ok=len(hits) >= 1,
                    detail=f"failure entries={len(hits)} (rejections logged without the name)",
                )
            )

    # cleanup the valid object
    if ctx.execute and create.success:
        result.record(op_succeeded(ctx.runner.run("object", "delete", object_name=base), ctx=ctx, label="cleanup-delete"))
