"""P1-176244: 新建自定义文件类型成功测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 使用/api/v1/appsec/filetype新增对象名称为任意合法字符 【check1】新增成功
  2. 使用/api/v1/appsec/filetype新增对象描述为任意合法字符 【check1】
  3. etcd内查看 /vnf-agent/vpp1/config/snort/filetype/v1/filetype内容 【check2】包含数据

设备实测(probe19c): POST /api/v1/appsec/filetype
{id:0, val:{name, type:true, classify:[0], refcnt:0, description}} 成功即落库。
etcd 步骤不在 API 可达范围,记为 notes(divergence)。
"""

from __future__ import annotations

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, entry_named

TITLE = "P1-176244 新建自定义文件类型成功测试"


def run(ctx: CaseContext, result: CaseResult) -> None:
    rest = FiletypeRest(ctx)
    name = unique_random(176244, "ft")
    desc = unique_random(176244, "desc")
    deleted = False
    try:
        # check1: 合法名称 + 合法描述 → 新增成功。
        out = ctx.runner.run("filetype", "config", name=name, description=desc)
        result.record(op_succeeded(out, ctx=ctx, label="ft-created"))
        if not ctx.execute:
            return

        # check2(替代 etcd): 列表查询能看到新增对象。
        entries = rest.list_entries(keywords=name)
        hit = entry_named(entries, name)
        ok = hit is not None and str(hit.get("description", "")) == desc
        result.record(Check(
            name="ft-visible-in-list",
            ok=ok,
            detail=f"list hits={len(entries)} desc_match={hit and hit.get('description')!r} want={desc!r}",
        ))
        if hit is not None:
            result.notes.append(
                "check2(etcd /vnf-agent/vpp1/config/snort/filetype/v1/filetype) "
                "设备侧不暴露 HTTP 端点,以列表查询可见性替代。")
    finally:
        if ctx.execute:
            if not deleted:
                result.record(op_succeeded(
                    ctx.runner.run("filetype", "delete", id=name),
                    ctx=ctx, label="cleanup-ft"))
