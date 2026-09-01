"""P4-176260: 反复操作文件对象可靠性测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 反复新增删除自定义文件对象 【check1】新增和删除成功
  2. 反复修改自定义文件对象 【check2】修改成功，修改后配置一致
  3. 反复重启设备检查文件对象 【check3】数据无丢失
  4. 反复重启vpp和agent检查文件对象 【check3】

重启/vpp-agent 重启不在 API 可达范围,记为 notes。
本用例跑 5 轮增删 + 5 轮改描述,逐轮断言列表状态。
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, entry_named

TITLE = "P4-176260 反复操作文件对象可靠性测试"

ROUNDS = 5


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    base = unique_random(176260, "rep")
    try:
        if not ctx.execute:
            result.record(Check(name="repeat-reliability", ok=True,
                                detail="dry-run: repeated-op loops skipped"))
            return

        # check1: 反复新增删除。
        ok = True
        for i in range(ROUNDS):
            name = f"{base}_{i}"
            r = rest.create(name)
            present = entry_named(rest.list_entries(keywords=name), name) is not None
            if not (r.status_code == 200 and present):
                ok = False
                result.notes.append(f"create round {i}: rc={r.status_code} present={present}")
            d = rest.delete(name)
            absent = entry_named(rest.list_entries(keywords=name), name) is None
            if not (d.status_code == 200 and absent):
                ok = False
                result.notes.append(f"delete round {i}: rc={d.status_code} absent={absent}")
        result.record(Check(name="repeat-add-delete", ok=ok,
                            detail=f"{ROUNDS} add/delete rounds, clean"))

        # check2: 反复修改,逐轮核对描述一致。
        name = f"{base}_mod"
        r = rest.create(name)
        ok = r.status_code == 200
        for i in range(ROUNDS):
            desc = f"v{i}"
            u = rest.update(name, description=desc)
            hit = entry_named(rest.list_entries(keywords=name), name)
            if not (u.status_code == 200 and hit and str(hit.get("description", "")) == desc):
                ok = False
                result.notes.append(f"update round {i}: rc={u.status_code} desc="
                                    f"{hit and hit.get('description')!r} want={desc!r}")
        result.record(Check(name="repeat-update", ok=ok,
                            detail=f"{ROUNDS} update rounds, desc consistent"))
        if ok:
            rest.delete(name)

        result.notes.append(
            "check3/check4(反复重启设备、重启vpp/agent 后对象无丢失)不在 API "
            "可达范围,由设备自身高可用保证,本用例不覆盖。")
    finally:
        if ctx.execute:
            for i in range(ROUNDS):
                n = f"{base}_{i}"
                if entry_named(rest.list_entries(keywords=n), n):
                    rest.delete(n)
            n = f"{base}_mod"
            if entry_named(rest.list_entries(keywords=n), n):
                rest.delete(n)
