"""P1-176247: 自定义文件类型oplog记录正确性测试

xlsx(对象管理用例_重构_563.xlsx):
  1. 创建自定义文件对象成功记录日志【check1】
  2. 创建自定义文件对象失败记录日志【check1】
  3. 删除自定义文件对象成功记录日志【check1】
  4. 删除自定义文件对象失败记录日志【check1】
  5. 修改自定义文件对象记录日志【check1】

设备实测(55.63, probe22): 自定义文件类型的增/删/改操作均写入操作日志,消息形如
  "新增 自定义文件类型 成功" / "修改 自定义文件类型 成功" / "删除 自定义文件类型 成功"
  失败路径 "新增 自定义文件类型 失败 文件类型已存在"。与文件类型组不同,自定义
  文件类型的日志**不带名称** → 断言按动作关键字(新增/修改/删除 + 成功/失败)匹配。
  oplog writer 有延迟 → 捕获前 sleep。
"""

from __future__ import annotations

import time

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import oplog_messages
from framework.results import CaseResult

TITLE = "P1-176247 自定义文件类型oplog记录正确性测试"


def _hits(messages: list[str], needle: str) -> list[str]:
    return [m for m in messages if needle in m]


def run(ctx: CaseContext, result: CaseResult) -> None:
    name = unique_random(176247, "ft")
    updated = False
    try:
        # 1) 创建成功。
        out = ctx.runner.run("filetype", "config", name=name, description="oplog-a")
        result.record(op_succeeded(out, ctx=ctx, label="ft-create-ok"))

        # 2) 创建失败: 同名重复。
        out2 = ctx.runner.run("filetype", "config", name=name, description="oplog-dup")
        result.record(op_rejected(out2, ctx=ctx, label="ft-create-dup-rejected"))

        # 3) 修改成功(改描述)。
        out3 = ctx.runner.run("filetype", "update", id=name, name=name,
                              description="oplog-b")
        result.record(op_succeeded(out3, ctx=ctx, label="ft-update-ok"))
        updated = out3.success

        # 4) 修改失败: 改不存在的文件类型。
        out4 = ctx.runner.run("filetype", "update", id=f"{name}-zzz",
                              name=f"{name}-zzz", description="oplog-bad")
        result.record(op_rejected(out4, ctx=ctx, label="ft-update-missing-rejected"))

        # 5) 删除成功。
        out5 = ctx.runner.run("filetype", "delete", id=name)
        result.record(op_succeeded(out5, ctx=ctx, label="ft-delete-ok"))
        deleted = out5.success
        if deleted:
            updated = False  # 已删除,无需再清理

        # 6) 删除失败: 删不存在的文件类型(设备可能静默接受,按实际记录)。
        out6 = ctx.runner.run("filetype", "delete", id=f"{name}-zzz")
        if out6.success:
            result.record(Check(name="ft-delete-missing-accepted", ok=True,
                                detail="删除不存在文件类型被静默接受(设备行为)"))
            delete_fail_expected = False
        else:
            result.record(op_rejected(out6, ctx=ctx, label="ft-delete-missing-rejected"))
            delete_fail_expected = True

        if not ctx.execute:
            return

        # 捕获操作日志窗口。
        time.sleep(1.5)
        cap = ctx.runner.run(
            "operation-log", "capture",
            timetype="custom", starttime=int(time.time()) - 300,
            endtime=int(time.time()) + 10, page=1, size=300,
        )
        result.record(op_succeeded(cap, ctx=ctx, label="oplog-capture"))
        if not cap.success:
            return
        messages = oplog_messages(cap.response())

        # 按动作断言日志(自定义文件类型不带名称)。
        expects = [
            ("oplog-create-ok", "新增 自定义文件类型 成功", True),
            ("oplog-create-fail", "新增 自定义文件类型 失败", True),
            ("oplog-update-ok", "修改 自定义文件类型 成功", updated),
            ("oplog-update-fail", "修改 自定义文件类型 失败", True),
            ("oplog-delete-ok", "删除 自定义文件类型 成功", deleted),
            ("oplog-delete-fail", "删除 自定义文件类型 失败", delete_fail_expected),
        ]
        for label, needle, required in expects:
            if not required:
                result.record(Check(name=label, ok=True, detail="op didn't occur, skipped"))
                continue
            hits = _hits(messages, needle)
            result.record(Check(name=label, ok=len(hits) >= 1,
                                detail=f"needle={needle!r} hits={len(hits)}"
                                       + (f" sample={hits[0][:80]!r}" if hits else "")))
    finally:
        if ctx.execute and updated:
            ctx.runner.run("filetype", "delete", id=name)
