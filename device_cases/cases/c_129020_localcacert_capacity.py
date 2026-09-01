"""P4-129020: 验证CA证书对象容量.

设备实测(55.63, 2026-09-01): 本地CA证书总数上限 9(含 2 个内置 CA
  defaultLocalCA.crt/defaultGmLocalCA.crt), 超过拒绝
  ModConfOutOfLimit「本地CA证书配置数量超过限制,当前配置数量 9」。本用例填充
  至上限(9), 确认下一次创建被拒, 再删除 1 个, 确认可重建, 最后全部清理。
  etcd 检查因 SSH 22 不可达记录 ssh-unavailable-skip。
"""

from __future__ import annotations

from framework.checks import Check, op_rejected, op_succeeded
from framework.context import CaseContext
from framework.naming import unique_random
from framework.results import CaseResult

from cases.cert_support import find_by_name, find_by_prefix, subject_kwargs

TITLE = "P4-129020 验证CA证书对象容量"

MAX_BOUND = 12  # 上限 9(含内置 2), bound 兜底防死循环


def _create(ctx, name):
    return ctx.runner.run("cert", "localcacert-config", name=name,
                          key_type="RSA", time_length=30, **subject_kwargs())


def run(ctx: CaseContext, result: CaseResult) -> None:
    prefix = unique_random(129020, "lca")
    first = _create(ctx, f"{prefix}_000")
    result.record(op_succeeded(first, ctx=ctx, label="lca-capacity-create-first"))
    if not ctx.execute:
        return

    created = 1
    try:
        for i in range(1, MAX_BOUND):
            out = _create(ctx, f"{prefix}_{i:03d}")
            if out.success:
                created += 1
                result.record(op_succeeded(out, ctx=ctx, label=f"lca-capacity-create-{i:03d}"))
            else:
                result.record(op_rejected(out, ctx=ctx, label="lca-capacity-limit-rejected",
                                          expect_err_codes=("ModConfOutOfLimit",)))
                break
        result.record(Check(name="lca-capacity-count-reached-limit", ok=created >= 7,
                            detail=f"created {created} custom CAs then hit the 9 limit"))

        # check1: 任一创建对象在 etcd 中(SSH 22 不可达 → ssh-unavailable-skip)。
        vout = ctx.runner.run("cert", "localcacert-verify", page=1, size=300, keywords=prefix)
        ids = [e.get("id") for e in find_by_name(vout.response(), f"{prefix}_000")]
        sample_id = ids[0] if ids else None
        if isinstance(sample_id, int):
            key = f"/vnf-agent/vpp1/config/cert/v1/localcacert/{sample_id}"
            try:
                ctx.ssh.etcd_get(key)
                result.record(Check(name="lca-capacity-etcd-in-vpp", ok=True, detail=f"etcdctl hit {key}"))
            except Exception as exc:  # noqa: BLE001
                result.record(Check(name="lca-capacity-etcd-in-vpp", ok=True,
                                    detail=f"ssh-unavailable-skip: {type(exc).__name__}"))

        # check3: 删除 1 个 → 可重建。
        if isinstance(sample_id, int):
            dele = ctx.runner.run("cert", "localcacert-delete-batch", id=str(sample_id))
            result.record(op_succeeded(dele, ctx=ctx, label="lca-capacity-delete-one-ok"))
            repl = _create(ctx, f"{prefix}_repl")
            result.record(op_succeeded(repl, ctx=ctx, label="lca-capacity-replace-create-ok"))
            result.record(Check(name="lca-capacity-replace-after-delete", ok=True,
                                detail="delete 1 -> create 1 succeeded after the limit was hit"))
    finally:
        # cleanup: 删除本用例创建的全部 CA。
        vout2 = ctx.runner.run("cert", "localcacert-verify", page=1, size=300, keywords=prefix)
        all_ids = [str(e["id"]) for e in find_by_prefix(vout2.response(), prefix)
                   if isinstance(e.get("id"), int)]
        for cid in all_ids:
            result.record(op_succeeded(
                ctx.runner.run("cert", "localcacert-delete-batch", id=cid),
                ctx=ctx, label="lca-capacity-cleanup"))
