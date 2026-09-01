"""P0-18243: 非法新建及修改预定义应用

xlsx(对象管理用例_重构_563.xlsx):
  1. 前端无法对预定义应用做任何操作【check1】
  2. postman 请求创建应用接口, 设置类型为 PRESET【check2】→ 后端无法执行, 响应合理
  3. postman 请求修改应用接口, 尝试修改任意一个预定义应用的参数【check2】→ 后端无法执行

设备实测(55.63, 2026-09-01):
  * POST /api/v1/customappobj 带 type=PRESET → 400「type不允许」(应用接口不识别
    type 字段, 直接拒绝)。
  * POST 带 customflag=false → 400「customflag: error customflag in post val」
    (预置应用标识 customflag 只允许 true, 无法伪造预置)。
  * PUT /api/v1/customappobj?id=<预置应用名> 修改预置应用 → 400
    「appname:the appname have mistake name」(预置应用不在自定义应用表中, 拒绝)。
  * check1 为前端 UI 按钮检查, REST 不可自动化 → ui-only-skip。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.addr_cap_support import raw_req
from cases.app_support import APP_RES, app_find, app_val, appall, preset_app_names

TITLE = "P0-18243 非法新建及修改预定义应用"


def run(ctx: CaseContext, result: CaseResult) -> None:
    result.record(Check(name="frontend-crud-ui", ok=True,
                        detail="ui-only-skip: 前端预定义应用按钮存在性检查无法经 REST 自动化"))
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped"))
        return

    # 取一个真实预置应用名作修改目标。
    names = preset_app_names(appall(ctx))
    result.record(Check(name="preset-non-empty", ok=len(names) > 0,
                        detail=f"preset_app_names={len(names)}"))
    if not names:
        result.notes.append("no preset apps; preset-app protect checks skipped")
        return
    pname = names[0]

    # check2a: 创建 type=PRESET 应用 → 拒绝。
    st, msg = raw_req(ctx, "POST", APP_RES,
                      val=app_val(unique_random(18243, "ap"), **{"type": "PRESET"}))
    result.record(Check(name="create-preset-reject", ok=st not in (200, 201, 202)
                        and "type不允许" in msg,
                        detail=f"POST type=PRESET → {st} ({msg or ''})"))

    # check2b: 创建 customflag=false(伪造预置) → 拒绝。
    nm = unique_random(18243, "ap")
    st, msg = raw_req(ctx, "POST", APP_RES, val=app_val(nm, customflag=False))
    result.record(Check(name="create-customflag-false-reject", ok=st not in (200, 201, 202)
                        and "customflag" in msg,
                        detail=f"POST customflag=false → {st} ({msg or ''})"))
    result.record(Check(name="no-fake-preset-created", ok=app_find(ctx, nm) is None,
                        detail=f"{nm} not created"))

    # check2c: 修改预置应用 → 拒绝(预置应用不在自定义应用表)。
    st, msg = raw_req(ctx, "PUT", APP_RES, ident=pname, val=app_val(pname))
    result.record(Check(name="update-preset-reject", ok=st not in (200, 201, 202)
                        and ("mistake" in msg or "不存在" in msg),
                        detail=f"PUT {pname} → {st} ({msg or ''})"))
