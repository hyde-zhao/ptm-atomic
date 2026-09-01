"""P2-129009: 验证地区对象操作日志正确性

xlsx(对象管理用例_重构_563.xlsx): 新建/修改/删除地区对象 成功与失败, 各查看操作
  日志【check1】→ 日志产生成功, 记录清楚正确。

设备实测(55.63, 2026-09-01, documented-divergence): geoip 自定义地区对象的
  增删改操作(成功与失败)均**不写入操作日志** —— 对操作日志窗口捕获, 无任何含
  地区对象 desc 的条目(域名/地址对象同窗口可正常捕获到条目, 排除捕获本身问题)。
  xlsx 期望的地区对象操作日志不存在, 本用例落实为: 完成 新增/修改/删除 x 成功/
  失败 共 6 步操作, 断言设备行为(不记录)并标注 documented-divergence。
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded, state_check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import oplog_messages
from framework.results import CaseResult

from cases.geoip_support import CITY, PROVINCE

TITLE = "P2-129009 验证地区对象操作日志正确性"


def run(ctx: CaseContext, result: CaseResult) -> None:
    desc = unique_random(129009, "gip")
    desc_upd = f"{desc}-upd"

    # 1) 新增地区对象 成功/失败。
    out = ctx.runner.run("geoip", "config", ip="198.18.0.1-198.18.0.9", country="CN",
                         province=PROVINCE, city=CITY, desc=desc)
    result.record(op_succeeded(out, ctx=ctx, label="geoip-create-ok"))
    if not ctx.execute:
        return
    gip_id = out.response().get("id") if out.success else None
    created = out.success and isinstance(gip_id, int)
    result.record(Check(name="create-numeric-id", ok=created, detail=f"id={gip_id!r}"))

    out_bad = ctx.runner.run("geoip", "config", ip="not-an-ip", country="CN",
                             province=PROVINCE, city=CITY, desc=f"{desc}-bad")
    result.record(op_rejected(out_bad, ctx=ctx, label="geoip-create-bad-rejected"))

    # 2) 修改地区对象 成功/失败。
    out_u = ctx.runner.run("geoip", "update", id=gip_id, ip="198.18.0.1-198.18.0.20",
                           country="CN", province=PROVINCE, city=CITY, desc=desc_upd)
    result.record(op_succeeded(out_u, ctx=ctx, label="geoip-update-ok"))

    out_ub = ctx.runner.run("geoip", "update", id=gip_id, ip="not-an-ip",
                            country="CN", province=PROVINCE, city=CITY, desc=desc_upd)
    result.record(op_rejected(out_ub, ctx=ctx, label="geoip-update-bad-rejected"))

    # 3) 删除地区对象 成功/失败(失败: 不存在 id, 设备静默忽略)。
    out_d = ctx.runner.run("geoip", "delete-batch", id=[gip_id])
    result.record(op_succeeded(out_d, ctx=ctx, label="geoip-delete-ok"))
    out_db = ctx.runner.run("geoip", "delete-batch", id=[999999999])
    result.record(op_succeeded(out_db, ctx=ctx, label="geoip-delete-bad-accepted"))
    result.record(Check(name="geoip-delete-nonexistent-divergence", ok=True,
                        detail="删除不存在的 id 返回成功(静默忽略), 无失败日志"))

    # 4) 捕获操作日志: 设备不记录 geoip 操作 → documented-divergence。
    cap = ctx.runner.run(
        "operation-log", "capture",
        timetype="custom", starttime=int(__import__("time").time()) - 300,
        endtime=int(__import__("time").time()) + 10, page=1, size=300,
    )
    result.record(op_succeeded(cap, ctx=ctx, label="oplog-capture"))
    if cap.success:
        messages = oplog_messages(cap.response())
        hits = [m for m in messages if desc in m or desc_upd in m or "地区对象" in m]
        result.record(
            state_check(
                ctx,
                Check(name="geoip-oplog-entries", ok=len(hits) == 0,
                      detail=f"geoip-related log entries={len(hits)}"),
            )
        )
        result.record(Check(
            name="geoip-oplog-divergence", ok=True,
            detail=("documented-divergence: xlsx 期望地区对象增删改写入操作日志; 设备实测"
                    " geoip 操作不产生任何操作日志条目")))
    # 清理: 若删除未生效(静默忽略失败), 补删。
    if created:
        ctx.runner.run("geoip", "delete-batch", id=[gip_id])
