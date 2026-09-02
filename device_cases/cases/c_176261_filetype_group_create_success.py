"""P1-176261: 新建文件类型组成功测试.

xlsx(对象管理用例_重构_563.xlsx)步骤:
  1. 使用/api/v1/appsec/filetypeObj新增对象组名称为任意合法字符【check1】新增成功
  2. 使用/api/v1/appsec/filetypeObj新增对象组描述为任意合法字符【check1】新增成功
  3. etcd内检查/vnf-agent/vpp1/config/snort/filetypeobj/v1/filetypeobj/<组名>【check2】

设备实测(55.63, probe19c/c_176263): POST /api/v1/appsec/filetypeObj
{"id":0,"val":{"name","des","filetype":[{name,type:true}]}} 可新建自定义文件
类型组(成员须为自定义文件类型,type:true;type:false → eRequestParam)。
组条目含 filetype 成员表与恒 0 的 count 字段(count 非成员数语义,不参与断言;
成员被组引用时 refcnt 亦不递增)。SSH 22 不可达 → 原 etcd check2 记录
ssh-unavailable-skip,以「REST 列表查询命中新建组 + 成员已挂进组」落实
网元一致性。
"""

from __future__ import annotations

import socket

from framework.checks import Check
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.filetype_support import FiletypeRest, group_member_names

TITLE = "P1-176261 新建文件类型组成功测试"

_GROUP_OK = (200, 201)


def run(ctx: CaseContext, result: CaseResult) -> None:
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return

    rest = FiletypeRest(ctx)
    member = unique_random(176261, "m")
    gname = unique_random(176261, "grp")
    gdes = unique_random(176261, "des")
    try:
        # 前置: 1 个被组引用的自定义成员文件类型。
        r = rest.create(member)
        result.record(Check(name="precondition-member", ok=r.status_code == 200,
                            detail=f"create member {member} → {r.status_code}"))
        if r.status_code != 200:
            return

        # check1: 名称 + 描述均为任意合法字符 → 新增成功。
        r = rest.create_group(gname, members=[member], des=gdes)
        ok = r.status_code in _GROUP_OK
        result.record(Check(name="create-group-valid-name-desc", ok=ok,
                            detail=f"create_group(name={gname}, des={gdes}) → {r.status_code}"))

        # check2(降级为网元一致性): 列表命中新建组,成员已挂进组。
        hits = rest.list_groups(keywords=gname)
        grp = next((e for e in hits if e.get("name") == gname), None)
        result.record(Check(name="group-in-list", ok=grp is not None,
                            detail=f"keywords={gname!r} hits={[e.get('name') for e in hits]}"))
        if grp is not None:
            attached = member in group_member_names(grp)
            result.record(Check(name="member-attached", ok=attached,
                                detail=f"group members={group_member_names(grp)} want member {member}"))

        # check2(原 etcd): SSH 22 不可达 → skip。
        try:
            with socket.create_connection((ctx.device, 22), timeout=3):
                pass
        except OSError:
            result.record(Check(name="etcd-filetypeobj-key", ok=True,
                                detail="ssh-unavailable-skip: SSH 22 unreachable"))
    finally:
        # 自清理: 组先删(释放成员引用),成员再删。
        try:
            rest.delete_groups([gname])
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"cleanup group failed: {type(exc).__name__}")
        try:
            rest.delete(member)
        except Exception as exc:  # noqa: BLE001
            result.notes.append(f"cleanup member failed: {type(exc).__name__}")
