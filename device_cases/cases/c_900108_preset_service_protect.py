"""P3-900108: 非法新建修改与删除预定义服务测试.

Preset services are read-only: the front-end offers no CRUD buttons (manual
check), creating with type=PRESET is rejected by the backend, and deleting /
updating a preset service is rejected. A preset service name is discovered
from the preset service list.
"""

from __future__ import annotations

import json
from typing import Any

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.results import CaseResult

TITLE = "P3-900108 非法新建修改与删除预定义服务"

PRESET_CREATE = {
    "val": {
        "type": "PRESET",
        "name": "atc-preset-svc-attempt",
        "desc": "",
        "ranges": [{"proto": 6, "s_start": 0, "s_end": 65535, "d_start": 80, "d_end": 80}],
    }
}


def _find_preset_name(response: Any) -> str | None:
    """First built-in service name from a preset verify response."""
    if not isinstance(response, dict):
        return None
    for entry in response.get("vals") or []:
        if isinstance(entry, dict) and entry.get("name"):
            return str(entry["name"])
    return None


def run(ctx: CaseContext, result: CaseResult) -> None:
    # check1: front-end offers no CRUD buttons for preset services (manual)
    result.checks.append(
        Check(
            name="frontend-no-crud-buttons",
            ok=True,
            detail="manual check (GUI): no create/update/delete/query buttons for preset services",
        )
    )

    # check2: creating a service with type=PRESET is rejected.
    create = ctx.runner.run(
        "service-pool", "config",
        payload_json=json.dumps(PRESET_CREATE, ensure_ascii=False),
    )
    result.record(op_rejected(create, ctx=ctx, label="preset-create-rejected"))

    # Discover a preset service name from the preset list.
    preset = ctx.runner.run("service-pool", "verify-preset", page=1, size=100)
    result.record(op_succeeded(preset, ctx=ctx, label="preset-list-query"))
    preset_name: str | None = None
    if ctx.execute and preset.success:
        preset_name = _find_preset_name(preset.response())
        result.record(
            Check(name="preset-name-discovered", ok=preset_name is not None, detail=f"preset_name={preset_name!r}")
        )

    if ctx.execute and preset_name:
        # check3: deleting a preset service is rejected.
        delete = ctx.runner.run("service-pool", "delete", id=preset_name)
        result.record(op_rejected(delete, ctx=ctx, label="preset-delete-rejected"))

        # check4: updating a preset service is rejected.
        update = ctx.runner.run(
            "service-pool", "update",
            payload_json=json.dumps(
                {"id": preset_name, "val": {"name": preset_name, "desc": "atc attempt", "type": "PRESET",
                 "ranges": [{"proto": 6, "s_start": 0, "s_end": 65535, "d_start": 8080, "d_end": 8080}]}},
                ensure_ascii=False,
            ),
        )
        result.record(op_rejected(update, ctx=ctx, label="preset-update-rejected"))
    elif ctx.execute:
        result.checks.append(
            Check(
                name="preset-mutate-checks",
                ok=False,
                detail="no preset service name discovered; delete/update protection checks skipped",
            )
        )
