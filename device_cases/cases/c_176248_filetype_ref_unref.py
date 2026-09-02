"""P2-176248: 自定义文件类型引用与解引用测试.

xlsx(对象管理用例_重构_563.xlsx) 7 步:
  1. 创建自定义文件类型对象 file1
  2. 文件类型组添加 file1, 检查 file1 引用计数【check1】
  3. 文件类型组删除 file1, 检查 file1 引用计数【check1】
  4. 多个文件类型组引用同个文件对象, 检查 file1 引用计数【check1】
  5. 多个文件类型组解引用同个文件对象, 检查计数【check1】
  6. 删除被引用自定义文件类型对象【check2】→ 提示该对象被引用
  7. 被引用对象删除失败后, 检查引用计数【check3】→ 引用计数不变化

设备实测(55.63, probe31/probe32): 自定义文件类型被 filetypeObj 组引用时,单对象列表
入口 refcnt 字段 0→1(一组)→2(两组) 精确反映引用数;DELETE 被引用对象 → 400「文件类型
正在被引用」且 refcnt 不变化;组不允许空成员表,「组删除 file1」落实为更新组成员(换入
helper file2)或删除组本身。组身份恒可删(c_176265 口径)。
"""
from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, group_member_names

TITLE = "P2-176248 自定义文件类型引用与解引用测试"

_OK = (200, 201)
_ERR_REFERENCED = "被引用"


def _refcnt(rest: FiletypeRest, name: str) -> int | None:
    e = next((x for x in rest.list_entries(keywords=name) if x.get("name") == name), None)
    if e is None:
        return None
    try:
        return int(e.get("refcnt", e.get("refCnt", -1)))
    except (TypeError, ValueError):
        return None


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return

    rest = FiletypeRest(ctx)
    base = unique_random(176248, "ft")
    f1 = f"{base}-f1"
    f2 = f"{base}-f2"
    g1 = f"{base}-g1"
    g2 = f"{base}-g2"

    def refcnt_check(label: str, want: int | None) -> None:
        got = _refcnt(rest, f1)
        result.record(Check(name=label, ok=got == want,
                            detail=f"{f1} refcnt={got} want={want}"))

    def members_of(gname: str) -> list[str]:
        hit = next((e for e in rest.list_groups(keywords=gname) if e.get("name") == gname), None)
        return group_member_names(hit) if hit else []

    try:
        # step1: 创建 file1 (+ helper file2)。
        r = rest.create(f1)
        result.record(Check(name="create-file1", ok=r.status_code == 200,
                            detail=f"create {f1} → {r.status_code}"))
        r = rest.create(f2)
        result.record(Check(name="create-helper-file2", ok=r.status_code == 200,
                            detail=f"create helper {f2} → {r.status_code}"))
        if r.status_code != 200 or _refcnt(rest, f1) is None:
            return
        refcnt_check("refcnt-baseline", 0)

        # step2: G1 引用 file1 → refcnt 1。
        r = rest.create_group(g1, members=[f1])
        result.record(Check(name="group1-add-file1", ok=r.status_code in _OK,
                            detail=f"group {g1}=[{f1}] → {r.status_code}"))
        result.record(Check(name="group1-member-stored", ok=f1 in members_of(g1),
                            detail=f"members={members_of(g1)}"))
        refcnt_check("refcnt-after-group1-add", 1)

        # step3: 组删除 file1(更新 G1 成员为 file2)→ refcnt 0。
        r = rest.update_group(g1, members=[f2])
        result.record(Check(name="group1-remove-file1", ok=r.status_code in _OK,
                            detail=f"update {g1}=[{f2}] → {r.status_code}"))
        refcnt_check("refcnt-after-group1-remove", 0)

        # step4: 两个组同时引用 file1 → refcnt 2。
        r = rest.create_group(g2, members=[f1])
        result.record(Check(name="group2-add-file1", ok=r.status_code in _OK,
                            detail=f"group {g2}=[{f1}] → {r.status_code}"))
        r = rest.update_group(g1, members=[f1])
        result.record(Check(name="group1-readd-file1", ok=r.status_code in _OK,
                            detail=f"update {g1}=[{f1}] → {r.status_code}"))
        refcnt_check("refcnt-two-groups", 2)

        # step5: 两个组解引用 → refcnt 0。
        r = rest.delete_groups([g1])  # 删组释放引用(c_176265: 组恒可删)
        result.record(Check(name="unref-group1-delete", ok=r.status_code in (200, 201),
                            detail=f"delete group {g1} → {r.status_code}"))
        r = rest.update_group(g2, members=[f2])  # G2 换成员移除 file1
        result.record(Check(name="unref-group2-remove", ok=r.status_code in _OK,
                            detail=f"update {g2}=[{f2}] → {r.status_code}"))
        refcnt_check("refcnt-after-all-unref", 0)

        # step6: 重新引用后删除被引用 file1 → 失败「被引用」。
        r = rest.update_group(g2, members=[f1])
        result.record(Check(name="re-reference", ok=r.status_code in _OK,
                            detail=f"update {g2}=[{f1}] → {r.status_code}"))
        refcnt_check("refcnt-before-delete-attempt", 1)
        r = rest.delete(f1)
        hit = _ERR_REFERENCED in r.text
        result.record(Check(name="delete-referenced-fail", ok=r.status_code not in _OK and hit,
                            detail=f"delete referenced {f1} → {r.status_code} {'被引用' if hit else r.text[:80]}"))

        # step7: 删除失败后引用计数不变化 → 仍 1。
        refcnt_check("refcnt-unchanged-after-fail", 1)
    finally:
        try:
            rest.delete_groups([g1, g2])
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"cleanup groups failed: {type(exc).__name__}")
        try:
            rest.delete(f1)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"cleanup {f1} failed: {type(exc).__name__}")
        try:
            rest.delete(f2)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"cleanup {f2} failed: {type(exc).__name__}")
