"""P3-900028: 非法新建修改与删除预定义服务测试

xlsx(对象管理用例_重构_563.xlsx):
  1. 前端预定义服务页面不提供增删改查按钮【check1】
  2. postman 请求创建服务接口, 设置类型为 PRESET【check2】→ 后端无法执行, 响应合理
  3. postman 请求删除服务接口, 删除预定义服务对象【check3】→ 无法删除
  4. postman 批量删除预定义服务对象【check4】→ 无法删除

设备实测(55.63, 2026-09-01):
  * check2: POST /api/v1/servicepool 带 type=PRESET → 400
    「can't create service pool of type PRESET by api」。
  * check3: DELETE /api/v1/servicepool?id=<preset> → 400「预定义服务对象不能被删除」。
  * check4: POST /api/v1/batch 批量删 preset → HTTP 200 但**静默忽略**, 预置服务仍在
    (verified) → documented-divergence: 接口返回成功但实质未删除, 预置对象无法被删除。
  * check1 为前端 UI 按钮检查, REST 不可自动化 → ui-only-skip。
"""

from __future__ import annotations

from typing import Any

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.results import CaseResult

from cases.svc_cap_support import SVC, raw_batch, raw_req, svc_find, svc_val

TITLE = "P3-900028 非法新建修改与删除预定义服务测试"

_ERR_CREATE = "can't create service pool of type PRESET"
_ERR_DELETE = "预定义服务对象不能被删除"


def _preset_names(response: Any) -> list[str]:
    names: list[str] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            nm = node.get("name")
            if isinstance(nm, str) and nm:
                names.append(nm)
            for value in node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(response)
    return names


def run(ctx: CaseContext, result: CaseResult) -> None:
    # check1: 前端按钮检查 → 非 REST 可自动化范围。
    result.record(Check(name="frontend-crud-ui", ok=True,
                        detail="ui-only-skip: 前端增删改查按钮存在性检查无法经 REST 自动化"))

    # 取一个真实预置服务名作删除目标。
    out = ctx.runner.run("service-pool", "verify-preset", page=1, size=200)
    result.record(op_succeeded(out, ctx=ctx, label="preset-no-filter"))
    if not ctx.execute:
        return
    names = _preset_names(out.response()) if out.success else []
    result.record(Check(name="preset-non-empty", ok=len(names) > 0,
                        detail=f"preset_names={len(names)}"))
    if not names:
        result.notes.append("no preset services; preset-protect checks skipped")
        return
    pname = names[0]

    # check2: 创建 type=PRESET 服务 → 拒绝。
    st, msg = raw_req(ctx, "POST", SVC, val=svc_val(f"{pname}-clone", type_="PRESET"))
    result.record(Check(name="create-preset-reject", ok=st not in (200, 201, 202)
                        and _ERR_CREATE in msg,
                        detail=f"POST type=PRESET → {st} ({msg or ''})"))

    # check3: 单删预置服务 → 拒绝。
    st, msg = raw_req(ctx, "DELETE", SVC, ident=pname)
    result.record(Check(name="delete-preset-reject", ok=st not in (200, 201, 202)
                        and _ERR_DELETE in msg,
                        detail=f"DELETE {pname} → {st} ({msg or ''})"))
    result.record(Check(name="preset-survives-single-delete",
                        ok=svc_find(ctx, pname) is not None,
                        detail=f"{pname} still queryable after rejected delete"))

    # check4: 批量删除预置服务 → 设备返回 200 但静默忽略, 预置服务仍在。
    st, msg = raw_batch(ctx, [{"method": "DELETE", "resource": SVC,
                               "body": {"id": [pname]}}])
    survived = svc_find(ctx, pname) is not None
    result.record(Check(name="batch-delete-preset-accepted", ok=st in (200, 201, 202),
                        detail=f"batch DELETE {pname} → {st} ({msg or 'ok'})"))
    result.record(Check(name="preset-survives-batch-delete", ok=survived,
                        detail=f"{pname} present after batch delete: {survived}"))
    if survived:
        result.record(Check(
            name="batch-delete-ignored-divergence", ok=True,
            detail=("documented-divergence: xlsx 期望批量删除无法删除预置对象; 设备返回 "
                    "HTTP 200 但静默忽略该项, 预置服务仍在(实质无法删除)")))
