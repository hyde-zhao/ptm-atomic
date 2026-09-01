"""Shared helpers for the service-object cases
(129024 / 256060 / 900028 / 18187 / 18188).

Probe-confirmed device semantics (55.63, 2026-09-01):
  * 服务组单组最大成员 = 256。  256→ok, 257→reject
    「服务组容量超过限制,当前配置数量 257」。(xlsx 文案为「服务地址组对象单个容量超过
    限制,当前配置数量257」, 关键词取「容量超过限制」「当前配置数量」→ divergence: 文案不同。)
  * 被引用的自定义服务不可删除 → 400「{name}被引用无法被删除」。
    解引用方式: 把组从 [S1] 更新为 [S2](组不允许空成员列表, PUT 空列表 → 400
    「服务对象列表为空」)。解引用后 S1 可删。
  * 预定义服务保护: POST type=PRESET → 400「can't create service pool of type
    PRESET by api」; DELETE ?id=<preset> → 400「预定义服务对象不能被删除」;
    批量 DELETE(preset) → HTTP 200 但**静默忽略**(预置服务仍在) →
    900028 check4 记为 documented-divergence。

REST 资源:
  服务对象 /api/v1/servicepool         服务组 /api/v1/servicepool/group
  payload: 对象 {"val":{name,desc,type:"CUSTOM",ranges:[{proto,s_start,s_end,d_start,d_end}]}}
           组   {"val":{name,desc,servicepools:[names]}}
  update:   PUT <res>?id=<name> body {"id":name,"val":{...}}
  delete:   DELETE <res>?id=<name>
  batch:    POST /api/v1/batch {"batch":[{"method","resource","body"}]}
"""

from __future__ import annotations

from typing import Any

import requests

from framework.checks import Check
from framework.context import CaseContext
from framework.results import CaseResult

from cases.addr_cap_support import raw_headers, raw_req, record_cap  # noqa: F401  (re-export)

SVC = "/api/v1/servicepool"
SVC_GRP = "/api/v1/servicepool/group"

SVC_MAX_MEMBERS = 256


def raw_delete(ctx: CaseContext, resource: str, name: str) -> None:
    requests.delete(f"{ctx.base_url}{resource}?id={name}", headers=raw_headers(ctx),
                    verify=bool(ctx.verify_tls), timeout=20)


def raw_batch(ctx: CaseContext, items: list[dict[str, Any]]) -> tuple[int, str]:
    """POST /api/v1/batch. 返回 (status, errMsg 片段)。"""
    r = requests.post(f"{ctx.base_url}/api/v1/batch", headers=raw_headers(ctx),
                      verify=bool(ctx.verify_tls), json={"batch": items}, timeout=60)
    msg = ""
    try:
        body = r.json()
        msg = str(body.get("errMsg") or body.get("errCode") or "")[:140]
    except Exception:  # noqa: BLE001
        msg = r.text[:80]
    return r.status_code, msg


def svc_find(ctx: CaseContext, name: str) -> dict[str, Any] | None:
    """关键字精确查服务对象(含 CUSTOM/PRESET), 返回匹配条目。"""
    r = requests.get(f"{ctx.base_url}{SVC}?page=1&size=50&keywords={name}",
                     headers=raw_headers(ctx), verify=bool(ctx.verify_tls), timeout=20)
    try:
        vals = r.json().get("vals") or []
    except Exception:  # noqa: BLE001
        vals = []
    return next((e for e in vals if isinstance(e, dict) and e.get("name") == name), None)


def grp_find(ctx: CaseContext, name: str) -> dict[str, Any] | None:
    r = requests.get(f"{ctx.base_url}{SVC_GRP}?page=1&size=1&keywords={name}",
                     headers=raw_headers(ctx), verify=bool(ctx.verify_tls), timeout=20)
    try:
        vals = r.json().get("vals") or []
    except Exception:  # noqa: BLE001
        vals = []
    return next((e for e in vals if isinstance(e, dict) and e.get("name") == name), None)


def svc_val(name: str, *, type_: str = "CUSTOM", desc: str = "",
            ranges: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    if ranges is None:
        ranges = [{"proto": 6, "s_start": 0, "s_end": 65535, "d_start": 0, "d_end": 65535}]
    return {"name": name, "desc": desc, "type": type_, "ranges": ranges}


def grp_val(name: str, servicepools: list[str], desc: str = "") -> dict[str, Any]:
    return {"name": name, "desc": desc, "servicepools": servicepools}


def bulk_create_services(ctx: CaseContext, names: list[str], *, desc: str = "cap-mem",
                         type_: str = "CUSTOM") -> tuple[int, list[str]]:
    ok = 0
    fails: list[str] = []
    for nm in names:
        st, _ = raw_req(ctx, "POST", SVC, val=svc_val(nm, type_=type_, desc=desc))
        if st in (200, 201, 202):
            ok += 1
        else:
            fails.append(f"{nm}:{st}")
    return ok, fails


def verify_svc_member_count(ctx: CaseContext, result: CaseResult, *, name: str,
                            expect: int, label: str) -> None:
    entry = grp_find(ctx, name)
    if entry is None:
        result.record(Check(name=label, ok=False, detail="service group not found in verify"))
        return
    count = len(entry.get("servicepools") or [])
    result.record(Check(name=label, ok=count == expect, detail=f"members={count} want {expect}"))
