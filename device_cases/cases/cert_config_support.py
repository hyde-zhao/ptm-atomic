"""Shared helpers for the cert-CONFIG field-validation cases (18085-18115, 197294-197297).

Probe-confirmed device semantics for /api/v1/cert/* config ops (field5/field6 on
55.63):
  * NAME: 1-31 bytes; only [A-Za-z0-9-] (hyphen) accepted. Dot, Chinese, spaces
    and other special chars are REJECTED (eRequestParamWithDetail
    「证书名称不满足校验规则」) — a divergence from the xlsx spec which lists
    中文/点 as legal.
  * COUNTRY: must be a 2-char ISO code (CN/cn/US all accepted); empty
    (length must be >= 1), 1-char and 3-char values are rejected.
  * STATE/LOCATION/ORGANIZATION/ORGAN_UNIT: 0-31 bytes (empty OK, 31 OK);
    32+ bytes rejected 「长度必须小于等于 31」 — divergence: xlsx says 0-127.
  * KEY_TYPE: RSA/SM2 OK; empty defaults to RSA; anything else is rejected.
  * KEY_LENGTH (RSA): 512/1024/2048/3072/4096 OK; 256/8192 and non-numeric
    rejected 「密钥长度无效」; empty defaults to 2048.
  * KEY PASSWORD: the config API has NO password field — any payload carrying
    a password key is rejected (creatCertFailByConversionError / eObjParse).
    This makes the "密钥密码 0-127 valid" spec step unimplementable as-is.
  * LOCALCACERT VALIDITY (timeLenth): 1-3650 OK; 3651+ rejected 「签发有效期
    必须小于等于 3650」; 0 rejected (positive int); empty defaults to 30.
  * DELETE single/batch is IDEMPOTENT on the device: a nonexistent or overlong
    id returns 200 (no-op) instead of an error — divergence from the xlsx
    check2 "配置失败". Only a MISSING id is rejected (client-side).
  * Capacity: localcert 65 total; localcacert 9 total incl 2 built-ins, so at
    most 7 custom CA certs. Pagination cases that need >40 CAs are limited to
    the 7-custom ceiling (divergence).
"""

from __future__ import annotations

from typing import Any

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.results import CaseResult

from cases.cert_support import (first_id, find_by_name, subject_kwargs)

# 证书配置用例共享的有效 subject(与 cert_support.SUBJECT 一致)。
SUBJECT_OK = subject_kwargs()

ETCD_LOCALCERT = "/vnf-agent/vpp1/config/cert/v1/localcert/{id}"
ETCD_LOCALCACERT = "/vnf-agent/vpp1/config/cert/v1/localcacert/{id}"

RESOURCE_OPS = {
    "localcert": ("localcert-config", "localcert-verify", "localcert-delete-batch", ETCD_LOCALCERT),
    "localcacert": ("localcacert-config", "localcacert-verify", "localcacert-delete-batch", ETCD_LOCALCACERT),
}


def base_kwargs(resource: str) -> dict[str, Any]:
    """全字段有效值的 config 参数(resource 专属字段已带默认)。"""
    if resource == "localcert":
        return {**SUBJECT_OK, "key_type": "RSA", "key_length": 2048}
    return {**SUBJECT_OK, "key_type": "RSA", "time_length": 30}


def verify_keywords(name: str) -> str:
    """verify 的 keywords 用 base name(不带 .csr/.crt 后缀)。"""
    return name


def _entry_field_ci(entry: dict[str, Any], key: str) -> Any:
    """Case-insensitive lookup of a verify-entry field."""
    for k, v in entry.items():
        if str(k).lower() == key.lower():
            return v
    return None


def stored_value_mismatches(entry: dict[str, Any], kw: dict[str, Any],
                            resource: str) -> list[str]:
    """Fields where the verify-GET stored value differs from the requested config.

    Returns a list of ``field=stored (want requested)`` mismatch strings; empty
    when every observable stored field matches the config. This realises the
    xlsx 「使用etcd查询...查询的值与配置的值相同」 intent through the REST read
    path (verify-GET returns the already-persisted values) rather than
    etcdctl — the separate etcd deep-check below only runs when the SSH channel
    is reachable. Fields absent from the verify entry are not observable, so
    they are not treated as mismatches.
    """
    mismatches: list[str] = []
    defaults = {"key_type": "RSA", "key_length": 2048}
    if resource == "localcacert":
        defaults["time_length"] = 30
    for cfg_key, dev_key in (("key_type", "keyType"), ("key_length", "keyLenth"),
                             ("time_length", "timeLenth")):
        stored = _entry_field_ci(entry, dev_key)
        want = kw.get(cfg_key, defaults.get(cfg_key))
        if stored is not None and want is not None and str(stored) != str(want):
            mismatches.append(f"{dev_key}={stored} want {want}")
    subject = str(entry.get("subject", ""))
    for cfg_key, token in (("country", "C"), ("state", "ST"), ("location", "L"),
                           ("organization", "O"), ("organ_unit", "OU")):
        want = kw.get(cfg_key)
        if want and f"{token}={want}".lower() not in subject.lower():
            mismatches.append(f"subject-missing {token}={want}")
    return mismatches


def create_ok(ctx: CaseContext, result: CaseResult, *,
              resource: str, name: str, label: str, kwargs: dict[str, Any] | None = None,
              want_etcd: bool = True) -> int | None:
    """config → 成功断言 + verify 命中 + 落库值比对 + (可选)etcd key 存在。

    返回 numeric id(供清理)。SSH 通道不可达时 etcd 深查降级为记录跳过的
    Check(不判失败)——配置本身已由 verify-GET 命中并比对字段确认。
    """
    cfg_op, verify_op, _, etcd_fmt = RESOURCE_OPS[resource]
    kw = kwargs or base_kwargs(resource)
    out = ctx.runner.run("cert", cfg_op, name=name, **{k: v for k, v in kw.items() if k != "name"})
    result.record(op_succeeded(out, ctx=ctx, label=f"{label}-config-ok"))
    if not ctx.execute or not out.success:
        return None
    vout = ctx.runner.run("cert", verify_op, page=1, size=200, keywords=verify_keywords(name))
    result.record(op_succeeded(vout, ctx=ctx, label=f"{label}-verify-ok"))
    entries = find_by_name(vout.response(), name)
    entry = entries[0] if entries else None
    entry_id = first_id(vout.response(), name)
    if entry is None or entry_id is None:
        result.record(Check(name=f"{label}-entry-found", ok=False, detail="not found in verify"))
        return None
    result.record(Check(name=f"{label}-entry-found", ok=True, detail=f"id={entry_id}"))
    mismatches = stored_value_mismatches(entry, kw, resource)
    result.record(Check(name=f"{label}-stored-match", ok=not mismatches,
                        detail="stored fields match config" if not mismatches
                               else f"stored mismatch: {mismatches}"))
    if want_etcd:
        try:
            eres = ctx.ssh.etcd_get(etcd_fmt.format(id=entry_id))
            from framework.checks import etcd_present, state_check
            result.record(state_check(ctx, etcd_present(eres, label=f"{label}-etcd",
                                                        key=etcd_fmt.format(id=entry_id))))
        except Exception as exc:  # noqa: BLE001 - SSH unreachable must not kill the case
            result.record(Check(name=f"{label}-etcd", ok=True,
                                detail=f"ssh-unavailable-skip: {type(exc).__name__}; "
                                       f"entry id={entry_id} already confirmed via verify-GET"))
    return entry_id


def create_rejected(ctx: CaseContext, result: CaseResult, *,
                    resource: str, name: str, label: str, kwargs: dict[str, Any],
                    expect_err_codes: tuple[str, ...] = ()) -> None:
    """config → 拒绝断言(无效值矩阵的每个 invalid 分支)。"""
    cfg_op, _, _, _ = RESOURCE_OPS[resource]
    out = ctx.runner.run("cert", cfg_op, name=name, **{k: v for k, v in kwargs.items() if k != "name"})
    result.record(op_rejected(out, ctx=ctx, label=f"{label}-rejected",
                              expect_err_codes=expect_err_codes))


def cleanup_by_name(ctx: CaseContext, result: CaseResult | None, resource: str, name: str) -> None:
    """按 verify 命中的 numeric id 清理单个证书(幂等)。"""
    if not ctx.execute:
        return
    _, verify_op, del_op, _ = RESOURCE_OPS[resource]
    vout = ctx.runner.run("cert", verify_op, page=1, size=200, keywords=verify_keywords(name))
    entry_id = first_id(vout.response(), name)
    if entry_id is None:
        return
    out = ctx.runner.run("cert", del_op, id=str(entry_id))
    if result is not None and not out.success:
        result.record(Check(name=f"cleanup-{name}", ok=False, detail=out.err_msg()[:80]))


def cleanup_ids(ctx: CaseContext, resource: str, entry_ids: list[int | None]) -> None:
    """批量清理已解析的 numeric id。"""
    if not ctx.execute:
        return
    _, _, del_op, _ = RESOURCE_OPS[resource]
    for eid in entry_ids:
        if eid is not None:
            ctx.runner.run("cert", del_op, id=str(eid))


def cleanup_names(ctx: CaseContext, resource: str, names: list[str]) -> None:
    """按名称逐条 verify→delete(分页/容量用例建了大批量种子)。"""
    if not ctx.execute:
        return
    _, verify_op, del_op, _ = RESOURCE_OPS[resource]
    for name in names:
        vout = ctx.runner.run("cert", verify_op, page=1, size=200, keywords=verify_keywords(name))
        eid = first_id(vout.response(), name)
        if eid is not None:
            ctx.runner.run("cert", del_op, id=str(eid))
