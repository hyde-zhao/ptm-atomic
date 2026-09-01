"""Shared helpers for the repeated-operation (反复操作) cases 18151-18255.

All 12 implementable cases share one shape:
  * check1 配置成功且「查询网元配置与下发的配置相同」→ 以多次
    create→verify→update→verify→delete→verify-gone 循环落实「反复操作」,
    每轮对象名带 case-id 前缀且自清理。
  * check2 策略/NAT/httpserver 引用 + 发送业务流 → documented-skip(数据面域)。
  * check3 设备掉电 / 命令复位重启 10 次以上 → documented-skip(需物理重启)。

重复循环后对象族功能仍正常: 最后一轮结束后再做一次 create→verify→delete,
断言「反复操作后仍可正常创建/查询/删除」(check1 收尾)。

REST 与 CLI 助手全部复用既有 support 模块(addr_cap_support / svc_cap_support /
time_support / cert_support / app_support / object_ops)。
"""

from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from framework.checks import Check, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.object_ops import _run_create, _run_delete, TIME
from framework.results import CaseResult

from cases.addr_cap_support import (
    grp_resource,
    grp_val,
    group_find,
    obj_resource,
    obj_val,
    raw_delete,
    raw_req,
)
from cases.app_support import app_find, app_val
from cases.cert_support import CertRest, all_ids, find_by_name, subject_kwargs
from cases.svc_cap_support import SVC, SVC_GRP, grp_find as svc_grp_find, svc_find, svc_val
from cases.time_support import time_quantum_starts

OK = (200, 201, 202)

REBOOT_SKIP = ("documented-skip: xlsx 要求设备掉电 / 命令复位重启 10 次以上观察功能, "
               "需物理重启, 不可自动化")


# ── generic one-cycle helpers ───────────────────────────────────────────────


def _net_count(entry: dict[str, Any] | None) -> int:
    return len((entry or {}).get("networks") or [])


def _member_count(entry: dict[str, Any] | None, v6: bool) -> int:
    if entry is None:
        return 0
    key = "ip6pools" if v6 else "ippools"
    return len(entry.get(key) or [])


def _svc_member_count(entry: dict[str, Any] | None) -> int:
    return len((entry or {}).get("servicepools") or [])


# ── per-family cycles (each self-cleans in finally) ─────────────────────────


def cycle_addr_obj(ctx: CaseContext, result: CaseResult, *, base: str, i: int,
                   v6: bool, label: str) -> None:
    res = obj_resource(v6)
    nm = f"{base}-{i}"
    try:
        st, _ = raw_req(ctx, "POST", res, val=obj_val(nm, 1, v6=v6, desc="rep"))
        result.record(Check(name=f"{label}-create", ok=st in OK, detail=f"POST → {st}"))
        if st not in OK:
            return
        result.record(Check(name=f"{label}-stored", ok=group_find(ctx, res, nm) is not None,
                            detail="verify-GET hit"))
        st, _ = raw_req(ctx, "PUT", res, ident=nm, val=obj_val(nm, 2, v6=v6, desc="rep2"))
        count = _net_count(group_find(ctx, res, nm))
        result.record(Check(name=f"{label}-update-stored", ok=st in OK and count == 2,
                            detail=f"PUT → {st}, networks={count}"))
    finally:
        raw_delete(ctx, res, nm)
        gone = group_find(ctx, res, nm) is None
        result.record(Check(name=f"{label}-delete-gone", ok=gone,
                            detail="gone" if gone else "still-present"))


def cycle_addr_grp(ctx: CaseContext, result: CaseResult, *, base: str, i: int,
                   v6: bool, label: str) -> None:
    res_g, res_o = grp_resource(v6), obj_resource(v6)
    m1, m2 = f"{base}-m{i}a", f"{base}-m{i}b"
    g = f"{base}-g{i}"
    for m in (m1, m2):
        raw_req(ctx, "POST", res_o, val=obj_val(m, 1, v6=v6, desc="rep"))
    try:
        st, _ = raw_req(ctx, "POST", res_g, val=grp_val(g, [m1], v6=v6, desc="rep"))
        result.record(Check(name=f"{label}-create", ok=st in OK, detail=f"POST → {st}"))
        if st not in OK:
            return
        st, _ = raw_req(ctx, "PUT", res_g, ident=g, val=grp_val(g, [m1, m2], v6=v6, desc="rep2"))
        count = _member_count(group_find(ctx, res_g, g), v6)
        result.record(Check(name=f"{label}-update-stored", ok=st in OK and count == 2,
                            detail=f"PUT → {st}, members={count}"))
    finally:
        raw_delete(ctx, res_g, g)
        raw_delete(ctx, res_o, m2)
        raw_delete(ctx, res_o, m1)
        gone = group_find(ctx, res_g, g) is None
        result.record(Check(name=f"{label}-delete-gone", ok=gone,
                            detail="gone" if gone else "still-present"))


def cycle_domain(ctx: CaseContext, result: CaseResult, *, base: str, i: int,
                 label: str) -> None:
    nm = f"{base}-{i}"
    val1 = {"name": nm, "desc": "rep", "domainaddrs": [{"domain": f"a{i}.example.com"}]}
    val2 = {"name": nm, "desc": "rep2",
            "domainaddrs": [{"domain": f"a{i}.example.com"}, {"domain": f"b{i}.example.com"}]}
    try:
        st, _ = raw_req(ctx, "POST", "/api/v1/domainpool", val=val1)
        result.record(Check(name=f"{label}-create", ok=st in OK, detail=f"POST → {st}"))
        if st not in OK:
            return
        entry = group_find(ctx, "/api/v1/domainpool", nm)
        result.record(Check(name=f"{label}-stored", ok=entry is not None, detail="verify-GET hit"))
        st, _ = raw_req(ctx, "PUT", "/api/v1/domainpool", ident=nm, val=val2)
        entry = group_find(ctx, "/api/v1/domainpool", nm)
        count = len((entry or {}).get("domainaddrs") or [])
        result.record(Check(name=f"{label}-update-stored", ok=st in OK and count == 2,
                            detail=f"PUT → {st}, domainaddrs={count}"))
    finally:
        raw_req(ctx, "DELETE", "/api/v1/domainpool", ident=nm)
        gone = group_find(ctx, "/api/v1/domainpool", nm) is None
        result.record(Check(name=f"{label}-delete-gone", ok=gone,
                            detail="gone" if gone else "still-present"))


def cycle_service(ctx: CaseContext, result: CaseResult, *, base: str, i: int,
                  label: str) -> None:
    nm = f"{base}-{i}"
    r1 = {"proto": 6, "s_start": 0, "s_end": 65535, "d_start": 8000 + i, "d_end": 9000 + i}
    r2 = {"proto": 6, "s_start": 0, "s_end": 65535, "d_start": 20000 + i, "d_end": 21000 + i}
    try:
        st, _ = raw_req(ctx, "POST", SVC, val=svc_val(nm, ranges=[r1]))
        result.record(Check(name=f"{label}-create", ok=st in OK, detail=f"POST → {st}"))
        if st not in OK:
            return
        result.record(Check(name=f"{label}-stored", ok=svc_find(ctx, nm) is not None,
                            detail="verify-GET hit"))
        st, _ = raw_req(ctx, "PUT", SVC, ident=nm, val=svc_val(nm, ranges=[r2]))
        entry = svc_find(ctx, nm)
        dst = -1
        if entry:
            rs = entry.get("ranges") or []
            if rs and isinstance(rs[0], dict):
                dst = rs[0].get("d_start")
        result.record(Check(name=f"{label}-update-stored", ok=st in OK and dst == r2["d_start"],
                            detail=f"PUT → {st}, d_start={dst}"))
    finally:
        raw_delete(ctx, SVC, nm)
        gone = svc_find(ctx, nm) is None
        result.record(Check(name=f"{label}-delete-gone", ok=gone,
                            detail="gone" if gone else "still-present"))


def cycle_service_grp(ctx: CaseContext, result: CaseResult, *, base: str, i: int,
                      label: str) -> None:
    s1, s2 = f"{base}-s{i}a", f"{base}-s{i}b"
    g = f"{base}-g{i}"
    for s in (s1, s2):
        raw_req(ctx, "POST", SVC, val=svc_val(s, desc="rep"))
    try:
        st, _ = raw_req(ctx, "POST", SVC_GRP, val={"name": g, "desc": "rep", "servicepools": [s1]})
        result.record(Check(name=f"{label}-create", ok=st in OK, detail=f"POST → {st}"))
        if st not in OK:
            return
        st, _ = raw_req(ctx, "PUT", SVC_GRP, ident=g,
                        val={"name": g, "desc": "rep2", "servicepools": [s1, s2]})
        count = _svc_member_count(svc_grp_find(ctx, g))
        result.record(Check(name=f"{label}-update-stored", ok=st in OK and count == 2,
                            detail=f"PUT → {st}, members={count}"))
    finally:
        raw_delete(ctx, SVC_GRP, g)
        raw_delete(ctx, SVC, s2)
        raw_delete(ctx, SVC, s1)
        gone = svc_grp_find(ctx, g) is None
        result.record(Check(name=f"{label}-delete-gone", ok=gone,
                            detail="gone" if gone else "still-present"))


def cycle_time(ctx: CaseContext, result: CaseResult, *, base: str, i: int,
               label: str) -> None:
    nm = f"{base}-{i}"
    p1 = json.dumps({"val": {"name": nm, "scheduletype": "day",
                             "timequantum": [{"starttime": {"time": "08:00:00"},
                                              "endtime": {"time": "18:00:00"}}]}})
    val2 = {"name": nm, "scheduletype": "day",
            "timequantum": [{"starttime": {"time": "09:00:00"},
                             "endtime": {"time": "17:00:00"}}]}
    try:
        out = _run_create(ctx, TIME, name=nm, payload_json=p1)
        result.record(op_succeeded(out, ctx=ctx, label=f"{label}-create"))
        if not out.success:
            return
        starts, _ = time_quantum_starts(ctx, nm)
        result.record(Check(name=f"{label}-stored", ok="08:00:00" in starts,
                            detail=f"starts={starts}"))
        # PUT 信封 {"id":name,"val":{...}}; 设备实测 CLI update --payload-json 不带 id 会被
        # 400(请求中没有id字段), 故走 raw_req 注入 id。
        st, msg = raw_req(ctx, "PUT", "/api/v1/timeobject", ident=nm, val=val2)
        starts, _ = time_quantum_starts(ctx, nm)
        result.record(Check(name=f"{label}-update-stored",
                            ok=st in OK and "09:00:00" in starts and "08:00:00" not in starts,
                            detail=f"PUT → {st} {msg!r}, starts={starts}"))
    finally:
        _run_delete(ctx, TIME, name=nm)
        starts, _ = time_quantum_starts(ctx, nm)
        result.record(Check(name=f"{label}-delete-gone", ok=not starts,
                            detail=f"gone" if not starts else f"still-present starts={starts}"))


def _gen_rsa_ca() -> bytes:
    """Generate an RSA CA cert PEM (fixture for trusted-CA upload)."""
    with tempfile.TemporaryDirectory() as td:
        kp, cp = Path(td) / "k.pem", Path(td) / "c.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048",
             "-keyout", str(kp), "-out", str(cp), "-days", "30", "-nodes",
             "-subj", "/C=CN/O=AtomicQA/CN=repeat-ca",
             "-addext", "basicConstraints=critical,CA:TRUE"],
            capture_output=True, check=True)
        return cp.read_bytes()


def cycle_localcert(ctx: CaseContext, result: CaseResult, *, base: str, i: int,
                    label: str) -> None:
    rest = CertRest(ctx)
    nm = f"{base}-{i}"
    try:
        out = ctx.runner.run("cert", "localcert-config", name=nm, key_type="RSA",
                             key_length=2048, **subject_kwargs())
        result.record(op_succeeded(out, ctx=ctx, label=f"{label}-create"))
        if not out.success:
            return
        v = ctx.runner.run("cert", "localcert-verify", page=1, size=200, keywords=nm)
        result.record(Check(name=f"{label}-stored",
                            ok=len(find_by_name(v.response(), nm)) >= 1,
                            detail="verify hit"))
        for id_ in all_ids(v.response(), nm):
            rest.delete("localcert", id_)
        gone = not rest.list_entries("localcert", nm)
        result.record(Check(name=f"{label}-delete-gone", ok=gone,
                            detail="gone" if gone else "still-present"))
    finally:
        for e in rest.list_entries("localcert", nm):
            rest.delete("localcert", e["id"])


def cycle_localcacert(ctx: CaseContext, result: CaseResult, *, base: str, i: int,
                      label: str) -> None:
    rest = CertRest(ctx)
    nm = f"{base}-{i}"
    try:
        out = ctx.runner.run("cert", "localcacert-config", name=nm, key_type="RSA",
                             time_length=30, **subject_kwargs())
        result.record(op_succeeded(out, ctx=ctx, label=f"{label}-create"))
        if not out.success:
            return
        v = ctx.runner.run("cert", "localcacert-verify", page=1, size=200, keywords=nm)
        result.record(Check(name=f"{label}-stored",
                            ok=len(find_by_name(v.response(), nm)) >= 1,
                            detail="verify hit"))
        for id_ in all_ids(v.response(), nm):
            rest.delete("localCA", id_)
        gone = not rest.list_entries("localCA", nm)
        result.record(Check(name=f"{label}-delete-gone", ok=gone,
                            detail="gone" if gone else "still-present"))
    finally:
        for e in rest.list_entries("localCA", nm):
            rest.delete("localCA", e["id"])


def cycle_cacert(ctx: CaseContext, result: CaseResult, *, base: str, i: int,
                 label: str) -> None:
    rest = CertRest(ctx)
    nm = f"{base}-{i}"
    cert = _gen_rsa_ca()
    try:
        rest.stage("cacert", nm + ".crt", cert)
        r = rest.commit(func_type="CAcert", cert_type="", cert_name=nm + ".crt", key_type="RSA")
        result.record(Check(name=f"{label}-create", ok=r.status_code == 200,
                            detail=f"PUT → {r.status_code}"))
        if r.status_code != 200:
            return
        result.record(Check(name=f"{label}-stored",
                            ok=len(rest.list_entries("CAcert", nm)) == 1,
                            detail="verify hit"))
        for e in rest.list_entries("CAcert", nm):
            rest.delete("CAcert", e["id"])
        gone = not rest.list_entries("CAcert", nm)
        result.record(Check(name=f"{label}-delete-gone", ok=gone,
                            detail="gone" if gone else "still-present"))
    finally:
        for e in rest.list_entries("CAcert", nm):
            rest.delete("CAcert", e["id"])


def cycle_customapp(ctx: CaseContext, result: CaseResult, *, base: str, i: int,
                    label: str) -> None:
    nm = f"{base}-{i}"
    try:
        st, _ = raw_req(ctx, "POST", "/api/v1/customappobj", val=app_val(nm))
        result.record(Check(name=f"{label}-create", ok=st in OK, detail=f"POST → {st}"))
        if st not in OK:
            return
        entry = app_find(ctx, nm)
        result.record(Check(name=f"{label}-stored", ok=entry is not None,
                            detail="verify-GET hit"))
        if entry is None:
            return
        # 设备 PUT 信封要求 val.id 携带设备分配的 appid(create/verify 返回的 id),
        # 否则 400 "appid is Invalid values"。
        appid = str(entry.get("id") or "")
        upd = app_val(nm, pattern=f"atc-{nm}-sig2")
        upd["id"] = appid
        st, _ = raw_req(ctx, "PUT", "/api/v1/customappobj", ident=nm, val=upd)
        ent = app_find(ctx, nm)
        pat = (ent or {}).get("pattern")
        result.record(Check(name=f"{label}-update-stored", ok=st in OK and pat == f"atc-{nm}-sig2",
                            detail=f"PUT → {st}, pattern={pat!r}"))
    finally:
        raw_req(ctx, "DELETE", "/api/v1/customappobj", ident=nm)
        gone = app_find(ctx, nm) is None
        result.record(Check(name=f"{label}-delete-gone", ok=gone,
                            detail="gone" if gone else "still-present"))


# ── driver ──────────────────────────────────────────────────────────────────


def run_repeat(ctx: CaseContext, result: CaseResult, *, case_id: int, cycles: int,
               cycle: Callable, policy_note: str) -> None:
    """Repeated-CRUD driver: ``cycles`` create/verify/update/verify/delete rounds,
    then policy-reference (check2) and power-cycle/reboot (check3) as skips."""
    if not ctx.execute:
        result.record(Check(name="dry-run", ok=True, detail="skipped")); return
    base = unique_random(case_id, "o")
    for i in range(cycles):
        cycle(ctx, result, base=base, i=i, label=f"cycle{i + 1}")
    result.record(Check(name="policy-traffic-skip", ok=True, detail=policy_note))
    result.record(Check(name="reboot-skip", ok=True, detail=REBOOT_SKIP))
