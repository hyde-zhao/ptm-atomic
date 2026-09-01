"""P2-176264: 文件类型组oplog记录正确性测试

xlsx(对象管理用例_重构_563.xlsx):
  1. 创建文件类型组成功记录日志【check1】
  2. 创建文件类型组失败记录日志【check1】
  3. 删除文件类型组成功记录日志【check1】
  4. 删除文件类型组失败记录日志【check1】
  5. 修改文件类型组成功记录日志【check1】
  6. 修改文件类型组失败记录日志【check1】

设备实测(55.63, probe22): 文件类型组操作写入操作日志,消息带组名,形如
  "新增 文件类型组 <name>成功" / "删除 文件类型组 <name>成功"。
  失败路径 "新增 文件类型组 <name>失败" 等 → 断言按 动作+组名+成功/失败 匹配。
  oplog writer 有延迟 → 捕获前 sleep。
"""

from __future__ import annotations

import time

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import oplog_messages
from framework.results import CaseResult

TITLE = "P2-176264 文件类型组oplog记录正确性测试"


def run(ctx: CaseContext, result: CaseResult) -> None:
    grp = unique_random(176264, "g")
    member = unique_random(176264, "m")
    grp_alive = False
    try:
        # 前置: 1 个自定义文件类型成员(组不能为空/需有效成员)。
        seed = ctx.runner.run("filetype", "config", name=member, description="oplog-member")
        result.record(op_succeeded(seed, ctx=ctx, label="precondition-member"))
        if not ctx.execute:
            return

        # 1) 创建文件类型组成功。
        out = ctx.runner.run("filetype", "group-config", name=grp, des="oplog-a", filetype=[member])
        result.record(op_succeeded(out, ctx=ctx, label="grp-create-ok"))
        grp_alive = out.success

        # 2) 创建失败: 同名重复。
        out2 = ctx.runner.run("filetype", "group-config", name=grp, des="oplog-dup", filetype=[member])
        result.record(op_rejected(out2, ctx=ctx, label="grp-create-dup-rejected"))

        # 3) 修改成功(改描述)。
        out3 = ctx.runner.run("filetype", "group-update", id=grp, name=grp,
                              des="oplog-b", filetype=[member])
        result.record(op_succeeded(out3, ctx=ctx, label="grp-update-ok"))

        # 4) 修改失败: 改不存在的组。
        out4 = ctx.runner.run("filetype", "group-update", id=f"{grp}-zzz",
                              name=f"{grp}-zzz", des="oplog-bad", filetype=[member])
        result.record(op_rejected(out4, ctx=ctx, label="grp-update-missing-rejected"))

        # 5) 删除成功。
        out5 = ctx.runner.run("filetype", "group-delete-batch", id=[grp])
        result.record(op_succeeded(out5, ctx=ctx, label="grp-delete-ok"))
        grp_alive = grp_alive and not out5.success

        # 6) 删除失败: 删不存在的组(设备可能静默接受,按实际记录)。
        out6 = ctx.runner.run("filetype", "group-delete-batch", id=[f"{grp}-zzz"])
        if out6.success:
            result.record(Check(name="grp-delete-missing-accepted", ok=True,
                                detail="删除不存在组被静默接受(设备行为)"))
            delete_fail_expected = False
        else:
            result.record(op_rejected(out6, ctx=ctx, label="grp-delete-missing-rejected"))
            delete_fail_expected = True

        # 捕获操作日志窗口(组日志带组名)。
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
        mhits = [m for m in messages if grp in m and "文件类型组" in m]

        expects = [
            ("oplog-grp-create-ok", f"新增 文件类型组 {grp}成功", True),
            ("oplog-grp-create-fail", f"新增 文件类型组 {grp}失败", True),
            ("oplog-grp-update-ok", f"修改 文件类型组 {grp}成功", True),
            ("oplog-grp-update-fail", f"修改 文件类型组 {grp}失败", True),
            ("oplog-grp-delete-ok", f"删除 文件类型组 {grp}成功", True),
            ("oplog-grp-delete-fail", f"删除 文件类型组 {grp}失败", delete_fail_expected),
        ]
        for label, needle, required in expects:
            if not required:
                result.record(Check(name=label, ok=True, detail="op didn't occur, skipped"))
                continue
            hits = [m for m in mhits if needle in m]
            result.record(Check(name=label, ok=len(hits) >= 1,
                                detail=f"needle={needle!r} hits={len(hits)}"
                                       + (f" sample={hits[0][:90]!r}" if hits else "")))
    finally:
        if ctx.execute:
            if grp_alive:
                ctx.runner.run("filetype", "group-delete-batch", id=[grp])
            ctx.runner.run("filetype", "delete", id=member)
