"""P0-18244: 删除或者批量删除预定义应用

xlsx(对象管理用例_重构_563.xlsx):
  1. postman 请求删除应用接口, 删除预定义的应用对象【check1】→ 无法删除
  2. postman 请求批量删除接口, 删除预定义应用对象【check2】→ 无法删除

设备实测(55.63, 2026-09-01):
  * DELETE /api/v1/customappobj?id=<预置应用名> → 400
    「删除自定义应用 QQ 失败, 应用不存在」(预置应用不被当作自定义应用, 拒绝删除)。
  * POST /api/v1/batch 批量删预置应用 → HTTP 200 但**静默忽略**, 预置应用仍在
    /appall AppStatic 中可查 → documented-divergence: 接口返回成功但实质未删除。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.results import CaseResult

from cases.addr_cap_support import raw_req
from cases.app_support import APP_RES, appall, preset_app_names
from cases.svc_cap_support import raw_batch

TITLE = "P0-18244 删除或者批量删除预定义应用"


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped"))
        return
    names = preset_app_names(appall(ctx))
    result.record(Check(name="preset-non-empty", ok=len(names) > 0,
                        detail=f"preset_app_names={len(names)}"))
    if not names:
        result.notes.append("no preset apps; preset-app delete checks skipped")
        return
    pname = names[0]

    # check1: 单删预置应用 → 拒绝(不在自定义应用表)。
    st, msg = raw_req(ctx, "DELETE", APP_RES, ident=pname)
    result.record(Check(name="delete-preset-reject", ok=st not in (200, 201, 202)
                        and "不存在" in msg,
                        detail=f"DELETE {pname} → {st} ({msg or ''})"))
    result.record(Check(name="preset-survives-single-delete",
                        ok=pname in preset_app_names(appall(ctx)),
                        detail=f"{pname} still in AppStatic after rejected delete"))

    # check2: 批量删除预置应用 → 设备返回 200 但静默忽略, 预置应用仍在。
    st, msg = raw_batch(ctx, [{"method": "DELETE", "resource": APP_RES,
                               "body": {"id": [pname]}}])
    survived = pname in preset_app_names(appall(ctx))
    result.record(Check(name="batch-delete-preset-accepted", ok=st in (200, 201, 202),
                        detail=f"batch DELETE {pname} → {st} ({msg or 'ok'})"))
    result.record(Check(name="preset-survives-batch-delete", ok=survived,
                        detail=f"{pname} present after batch delete: {survived}"))
    if survived:
        result.record(Check(
            name="batch-delete-ignored-divergence", ok=True,
            detail=("documented-divergence: xlsx 期望批量删除无法删除预置对象; 设备返回 "
                    "HTTP 200 但静默忽略该项, 预置应用仍在(实质无法删除)")))
