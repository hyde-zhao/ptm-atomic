"""P1-176262: 新建文件类型组失败测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 使用接口添加对象为空 【check1】新增失败
  2. 使用接口新增对象组名称为任意非法字符 【check1】新增失败
  3. 使用接口新增对象组名称为超过字符限制 【check1】新增失败
  4. 使用接口新增IDMC-开头文件类型组 【check1】新增失败

设备实测(55.63, probe19c): POST /api/v1/appsec/filetypeObj 空 val / 空名称被
设备拒;IDMC- 为预定义文件类型保留段;超长名被设备拒;非法字符按设备规则判定。
除空对象 step 外,均携带 1 个合法成员,使拒绝可归因于名字本身而非空成员表
(空 filetype 列表同样触发 eRequestParam 文件类型列表格式错误)。被拒断言后
复查列表,若设备意外接受某名称则记录 divergence 并清理(镜像 c_176245 口径)。
CLI 无 group-config 子命令 → 全部走 FiletypeRest 原始 POST。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest

TITLE = "P1-176262 新建文件类型组失败测试"

_GROUP_OK = (200, 201)


def _rejected(r) -> bool:
    return r.status_code not in _GROUP_OK


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return

    rest = FiletypeRest(ctx)
    member = unique_random(176262, "m")
    attempted: list[str] = []

    def _record(label: str, r, *, detail_extra: str = "") -> None:
        detail = f"POST filetypeObj {label} → {r.status_code} {detail_extra}"
        result.record(Check(name=label, ok=_rejected(r), detail=detail.strip()))

    try:
        # 合法成员,使步骤 2-4 的拒绝可归因于名字。
        r = rest.create(member)
        result.record(Check(name="precondition-member", ok=r.status_code == 200,
                            detail=f"create member {member} → {r.status_code}"))
        if r.status_code != 200:
            return

        # step1: 添加对象为空 → 拒绝。
        r = rest.post_group_raw({})
        _record("empty-object-rejected", r)

        # step2: 非法字符名 → 拒绝。
        bad = unique_random(176262, "bad") + "/;x"
        attempted.append(bad)
        r = rest.post_group(bad, members=[member])
        _record("illegal-char-rejected", r)

        # step3: 超过字符限制(300 字符)→ 拒绝。
        long = "176262_" + "n" * 300
        attempted.append(long)
        r = rest.post_group(long, members=[member])
        _record("overlength-rejected", r)

        # step4: IDMC- 前缀(保留段)→ 拒绝。
        idmc = f"IDMC-{unique_random(176262, 'resv')}"
        attempted.append(idmc)
        r = rest.post_group(idmc, members=[member])
        _record("idmc-prefix-rejected", r)

        # divergence 复查: 设备若意外接受非法组名,记录并计入清理。
        for n in attempted:
            if n and any(e.get("name") == n for e in rest.list_groups(keywords=n)):
                result.notes.append(f"divergence: illegal group name {n!r} was accepted")
    finally:
        # 清理被意外接受的名字,避免残留。
        for n in attempted:
            try:
                if any(e.get("name") == n for e in rest.list_groups(keywords=n)):
                    rest.delete_groups([n])
            except Exception as exc:  # noqa: BLE001
                result.notes.append(f"cleanup {n} failed: {type(exc).__name__}")
        try:
            rest.delete(member)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"cleanup member failed: {type(exc).__name__}")
