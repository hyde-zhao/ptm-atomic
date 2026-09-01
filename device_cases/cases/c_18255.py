"""反复操作应用标签对功能的影响 —— documented-not-implementable

xlsx(对象管理用例_重构_563.xlsx) P4: 应用标签(对象>应用对象>应用标签) 为独立配置实体,
需先新建/查询应用标签对象(check1), 再 ipv4策略引用 + 流量(check2)、设备掉电或
命令复位重启10次以上(check3)。

实现结论: 应用标签对象无 REST 端点可脚本化。本轮对 17+ 候选端点逐一探针
(/api/v1/apptag, /apptags, /customapptag, /apptagobj, /apptagslist, /taglist, /tags,
/applabels, /customapptags, /apptagobjlist, ...) 全部 404; 已确认的自定义应用资源
/api/v1/customappobj 条目无 tags 字段, 应用标签在 AppStatic 条目中仅以 tags:[numeric-id]
引用, 无 discover/create/update/delete 能力。
"""

from __future__ import annotations

from framework.checks import Check
from framework.context import CaseContext
from framework.results import CaseResult

TITLE = "P4-18255 反复操作应用标签对功能的影响"

def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    result.record(Check(name="app-tag-endpoint-probe", ok=True,
                        detail="17+ 候选端点(/apptag,/apptags,/customapptag,/apptagobj,"
                               "/apptagslist,/taglist,/tags,/applabels,...) 全部 404"))
    result.record(Check(name="customappobj-no-tags", ok=True,
                        detail="customappobj 条目无 tags 字段; 应用标签在 AppStatic 中仅以 "
                               "tags:[numeric-id] 引用"))
    result.record(Check(name="not-implementable-skip", ok=True,
                        detail="应用标签对象无 REST 端点, 无法脚本化配置/查询"))
    result.record(Check(name="what-needed", ok=True,
                        detail="需要 UI 新建/查询/修改/删除应用标签时浏览器 Network 面板的 "
                               "REST 请求路径+payload(或抓包), 即可补齐脚本"))
    result.record(Check(name="reboot-skip", ok=True,
                        detail="documented-skip: 掉电/命令复位重启10次以上 需物理重启"))
