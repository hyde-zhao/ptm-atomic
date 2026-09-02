"""P2-900112: 非法新建修改与删除预定义应用.

Preset applications must be read-only: the front-end offers no CRUD buttons
(manual check), creating with type=PRESET is rejected, and deleting /
batch-deleting a preset app is rejected. The preset app id is discovered from
the preset application tree via `app-obj verify`.
"""

from __future__ import annotations

import json
from typing import Any

from framework.checks import Check, op_rejected, op_succeeded, state_check
from framework.context import CaseContext
from framework.results import CaseResult

TITLE = "P2-900112 非法新建修改与删除预定义应用"

PRESET_PAYLOAD = {
    "val": {
        "type": "PRESET",
        "name": "atc-preset-attempt",
        "desc": "",
    }
}


def _find_preset_id(response: Any) -> str | None:
    """First built-in (preset) application id from the AppStatic list.

    The app-obj tree groups entries under AppClass/AppCustom/AppGroup/AppStatic.
    Built-in applications live in AppStatic and carry ``customflag: False`` plus
    an ``id``; custom applications (AppCustom) carry ``customflag: True``. Only
    AppStatic is searched so AppClass entries (e.g. "全部" with id='0') are not
    mistaken for preset apps.
    """
    app_static = response.get("AppStatic") if isinstance(response, dict) else None
    if not isinstance(app_static, list):
        return None
    for entry in app_static:
        if entry.get("customflag") is False and entry.get("id") is not None:
            return str(entry["id"])
    return None


def run(ctx: CaseContext, result: CaseResult) -> None:
    # check1: front-end offers no CRUD buttons for preset apps (manual)
    result.checks.append(
        Check(
            name="frontend-no-crud-buttons",
            ok=True,
            detail="manual check (GUI): no create/update/delete/query buttons for preset applications",
        )
    )

    # Discover a preset app id from the preset tree.
    tree = ctx.runner.run("app-obj", "verify", search_keyword="", tag_custom=0)
    result.record(op_succeeded(tree, ctx=ctx, label="preset-tree-query"))
    preset_id: str | None = None
    if ctx.execute and tree.success:
        preset_id = _find_preset_id(tree.response())
        result.record(
            state_check(
                ctx,
                Check(name="preset-id-discovered", ok=preset_id is not None, detail=f"preset_id={preset_id!r}"),
            )
        )

    # check2: create with type=PRESET is rejected.
    create = ctx.runner.run(
        "app-obj", "config",
        payload_json=json.dumps(PRESET_PAYLOAD, ensure_ascii=False),
    )
    result.record(op_rejected(create, ctx=ctx, label="preset-create-rejected"))

    if ctx.execute and preset_id:
        # check3: delete a preset app is rejected.
        delete = ctx.runner.run("app-obj", "delete", id=preset_id)
        result.record(op_rejected(delete, ctx=ctx, label="preset-delete-rejected"))

        # check4: batch-deleting a preset app must not remove it. The device
        # answers success for batch delete of built-in ids but leaves the app
        # in the AppStatic tree — assert it is still queryable afterwards.
        batch = ctx.runner.run("app-obj", "delete-batch", id=[preset_id])
        result.record(op_succeeded(batch, ctx=ctx, label="preset-delete-batch-request"))
        again = ctx.runner.run("app-obj", "verify", search_keyword="", tag_custom=0)
        if again.success:
            app_static = again.response().get("AppStatic") if isinstance(again.response(), dict) else None
            still = any(
                isinstance(e, dict) and str(e.get("id")) == preset_id
                for e in (app_static or [])
            )
            result.record(
                state_check(
                    ctx,
                    Check(
                        name="preset-still-present",
                        ok=still,
                        detail=f"preset_id={preset_id!r} still in AppStatic after batch-delete: {still}",
                    ),
                )
            )
        else:
            result.record(
                Check(name="preset-still-present", ok=False, detail="re-verify failed after batch delete")
            )
    elif ctx.execute:
        result.checks.append(
            Check(
                name="preset-delete-checks",
                ok=False,
                detail="no preset app id discovered; delete/batch-delete protection checks skipped",
            )
        )
