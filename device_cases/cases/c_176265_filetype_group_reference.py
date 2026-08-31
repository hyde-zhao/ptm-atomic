"""P2-176265: 文件类型组被引用时不允许删除.

Probe-confirmed device semantics (probe19c on 55.63): the reference
protection sits on the custom FILE TYPE, not the group. A custom file type
referenced by a file type group cannot be deleted (DELETE /api/v1/appsec/
filetype -> 400 eRequestParam "文件类型已被引用"); the group itself is
always deletable (200 even while referencing members). Releasing the
reference (deleting the group) makes the file type deletable again.

The xlsx steps assume the referenced GROUP is the protected object; the
device protects the referenced member instead. This case asserts the actual
device behavior and notes the divergence:

  check1: create a custom file type (POST appsec/filetype).
  check2: create a file type group referencing it (member {name, type:true})
          and confirm group-verify reflects the member.
  check3: delete the referenced file type -> rejected (eRequestParam).
  check4: delete the group (releases the reference), then delete the file
          type -> succeeds.
"""

from __future__ import annotations

import json
from typing import Any

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

TITLE = "P2-176265 文件类型组被引用时不允许删除"

MEMBER_TYPE_TRUE = True  # custom file types are referenced as {name, type:true}


def run(ctx: CaseContext, result: CaseResult) -> None:
    ft = unique_random(176265, "ft")
    grp = unique_random(176265, "grp")
    grp_deleted = False
    ft_deleted = False
    try:
        # check1: create a custom file type.
        out = ctx.runner.run("filetype", "config", name=ft)
        result.record(op_succeeded(out, ctx=ctx, label="ft-created"))
        if not ctx.execute:
            return

        # check2: create a file type group referencing it. The group member
        # must carry type:true for a custom file type (probe19: type:false ->
        # eRequestParam "文件类型列表格式错误"), so the payload is passed
        # verbatim via --payload-json rather than the type:false builder.
        group_payload = json.dumps({
            "id": 0,
            "val": {
                "name": grp,
                "des": "atc ref",
                "filetype": [{"name": ft, "type": MEMBER_TYPE_TRUE}],
            },
        })
        gout = ctx.runner.run("filetype", "group-config", payload_json=group_payload)
        result.record(op_succeeded(gout, ctx=ctx, label="grp-created"))
        if not gout.success:
            return

        vout = ctx.runner.run("filetype", "group-verify", page=1, size=100, keywords=grp)
        result.record(op_succeeded(vout, ctx=ctx, label="grp-verify-query"))
        if vout.success:
            result.record(_member_reflected(vout.response(), grp, ft))

        # check3: the referenced custom file type cannot be deleted.
        dout = ctx.runner.run("filetype", "delete", id=ft)
        result.record(op_rejected(dout, ctx=ctx, label="ft-delete-while-referenced",
                                  expect_err_codes=("eRequestParam",)))

        # check4: delete the group (releases the reference), then the file
        # type delete succeeds.
        gdel = ctx.runner.run("filetype", "group-delete-batch", id=grp)
        result.record(op_succeeded(gdel, ctx=ctx, label="grp-delete-releases"))
        grp_deleted = gdel.success
        fdel = ctx.runner.run("filetype", "delete", id=ft)
        result.record(op_succeeded(fdel, ctx=ctx, label="ft-delete-after-release"))
        ft_deleted = fdel.success
    finally:
        if ctx.execute:
            if not grp_deleted:
                result.record(op_succeeded(
                    ctx.runner.run("filetype", "group-delete-batch", id=grp),
                    ctx=ctx, label="cleanup-grp",
                ))
            if not ft_deleted:
                result.record(op_succeeded(
                    ctx.runner.run("filetype", "delete", id=ft),
                    ctx=ctx, label="cleanup-ft",
                ))


def _member_reflected(response: Any, grp: str, ft: str) -> Check:
    hits = [e for e in _walk_dicts(response) if isinstance(e, dict) and str(e.get("name", "")) == grp]
    if not hits:
        return Check(name="grp-reflects-member", ok=False, detail="group not found in group-verify")
    members = hits[0].get("filetype")
    names = [str(m.get("name", "")) for m in members] if isinstance(members, list) else []
    ok = ft in names
    return Check(name="grp-reflects-member", ok=ok, detail=f"members={names}")


def _walk_dicts(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk_dicts(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_dicts(item)
