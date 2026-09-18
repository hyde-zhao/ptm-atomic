"""批量删除载荷的 id 列表承载 helper（STORY-REM-02-04 / ADR-REM-04 ①）。

背景（下游现场 P2-18）：2048 条策略路由的批量删除被展开成大量 ``--id`` 参数，
且框架侧按 ``_REPEAT_FLAG_CHUNK_SIZE = 200`` 逐元素分块为多次进程调用，
参数列表长度与进程启动开销把 DUT 打到无响应（``exit=46``）。本模块把承载形态
从「N 个 item × 每 item 1 个 id」收敛为「**1 个 item × N 个 id**」：单请求承载
N 个 id 后，「id 数」不再等于「参数个数」。

契约（``CT-REM-ATOM-CLI`` v1.1 载荷面，见 STORY-REM-02-04 LLD §6.1）：
- 主形态 ``single_item``：``batch`` 长度 1，``item.body.id`` 为非空字符串列表（N>=1）；
- 兼容形态 ``per_id_item``：``batch`` 长度 N、每 item 1 个 id（v1.0 逐字节等价，
  供「设备不接受列表形态」时一键回退，回退为常量切换、零逻辑改动）；
- ``item.body.is_ip6`` 存在时，长度由对齐策略决定（``per_item`` = N / ``first_value`` = 1），
  取值字符串由各族自行推导（本模块只负责**对齐形态**，不负责取值语义）。

区域划分（ADR-REM-06）：构造函数族属 ``#batch-id-list``（STORY-REM-02-04）；
``delete-batch`` 返回结构对齐（``count`` / ``success_count`` / ``failed_count`` /
``failed[]`` / ``per_item_result``）属 ``#batch-result``（STORY-REM-02-03，已落地于
本模块下半部）。本模块是**唯一**构造 ``body.id`` 列表的落点（UT-BULK-15 静态扫描锚点）。
"""

from __future__ import annotations

import sys
from typing import Any, Callable

from atomic_ops.runner.errors import RunnerError


# ── #batch-id-list（STORY-REM-02-04）─────────────────────────────────────

# 承载形态：single_item（主路径，ADR-REM-04 ①）/ per_id_item（兼容回退）。
# 回退触发条件（ADR-REM-04）：实测证明设备不接受列表形态 → 切回 per_id_item
# 并由框架侧配套强制回查（02-02）；本常量为回退开关，回退后与 v1.0 逐字节等价。
BATCH_ID_CARRIER: str = "single_item"

# is_ip6 对齐语义（AUTH-REM-01 实测回填后仅切此常量，零逻辑改动）：
#   per_item    -> is_ip6 与 id 逐位对应（长度 = N）
#   first_value -> is_ip6 仅取首值（长度 = 1）
# 离线不可判定该语义（契约原文 "for that item" 在 1 id/item 时两种读法同义），
# 故参数化隔离，不声称已定性。
BATCH_IS_IP6_ALIGNMENT: str = "per_item"

# 合法取值集合（用于非法取值的显式报错，UT-BULK-14）。
BATCH_ID_CARRIERS: tuple[str, ...] = ("single_item", "per_id_item")
BATCH_IS_IP6_ALIGNMENTS: tuple[str, ...] = ("per_item", "first_value")


def build_batch_delete_payload(
    *,
    entry_ids: list[str],
    resource: str,
    is_ip6_values: list[str] | None = None,
    validate_entry: Callable[[str], None] | None = None,
    carrier: str | None = None,
    alignment: str | None = None,
) -> dict[str, Any]:
    """构造批量删除载荷（单 item 承载 N 个 id 为主形态）。

    Args:
        entry_ids: 待删除 id 列表（非空；元素为非空字符串，或由 ``validate_entry`` 先校验）
        resource: 族内资源路径（如 ``/api/v1/policyroute``）
        is_ip6_values: is_ip6 取值列表；``None`` 表示该族不生成 ``is_ip6`` 键
            （不补空列表，避免契约面扩散）
        validate_entry: 逐条校验回调（保留各族既有校验语义，如接口 id 透传校验）
        carrier: 覆盖默认承载形态（测试与回退用；``None`` = 读模块常量）
        alignment: 覆盖默认对齐策略（测试与回退用；``None`` = 读模块常量）

    Returns:
        ``{"batch": [...]}``：主形态为单 item（``body.id`` = N 元列表）；
        ``carrier="per_id_item"`` 时为 N item（v1.0 等价形态）。

    Raises:
        RunnerError("RUNNER_VALIDATION_FAILED"): 空 id 列表 / id 元素非法 /
            承载或对齐策略取值非法 / ``is_ip6_values`` 与 id 列表长度不可对齐
            （既非等长也非单值）。长度 1 的 ``is_ip6_values`` 在 ``per_item``
            对齐下自动降级为 ``first_value`` 并向 stderr 告警（不静默）。
    """
    effective_carrier = _resolve_choice("carrier", carrier, BATCH_ID_CARRIER, BATCH_ID_CARRIERS)
    effective_alignment = _resolve_choice(
        "alignment", alignment, BATCH_IS_IP6_ALIGNMENT, BATCH_IS_IP6_ALIGNMENTS
    )
    if not isinstance(entry_ids, list) or not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    for entry_id in entry_ids:
        # 族内校验优先（保留各族既有报错语义），helper 自检兜底直接调用场景。
        if validate_entry is not None:
            validate_entry(entry_id)
        if not isinstance(entry_id, str) or not entry_id.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch delete entry id must be a non-empty string.",
                {"field": "id"},
            )

    resolved_is_ip6 = _resolve_is_ip6_values(entry_ids, is_ip6_values, effective_alignment)

    if effective_carrier == "per_id_item":
        per_id_batch: list[dict[str, Any]] = []
        for index, entry_id in enumerate(entry_ids):
            body: dict[str, Any] = {"id": [str(entry_id)]}
            if resolved_is_ip6 is not None:
                value = (
                    resolved_is_ip6[index]
                    if len(resolved_is_ip6) == len(entry_ids)
                    else resolved_is_ip6[0]
                )
                body["is_ip6"] = [value]
            per_id_batch.append({"method": "DELETE", "resource": resource, "body": body})
        return {"batch": per_id_batch}

    single_body: dict[str, Any] = {"id": [str(entry_id) for entry_id in entry_ids]}
    if resolved_is_ip6 is not None:
        single_body["is_ip6"] = list(resolved_is_ip6)
    return {"batch": [{"method": "DELETE", "resource": resource, "body": single_body}]}


def _resolve_choice(field: str, value: str | None, default: str, allowed: tuple[str, ...]) -> str:
    """解析承载 / 对齐策略取值（``None`` = 默认常量；非法值显式报错并列出合法集合）。"""
    if value is None:
        return default
    if value not in allowed:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"Unsupported batch delete {field}.",
            {"field": field, "value": value, "allowed": list(allowed)},
        )
    return value


def _resolve_is_ip6_values(
    entry_ids: list[str],
    is_ip6_values: list[str] | None,
    alignment: str,
) -> list[str] | None:
    """按对齐策略解析 is_ip6 取值列表的长度（``None`` = 该族不生成 is_ip6 键）。

    - ``first_value``：取首值（长度 1）；
    - ``per_item``：与 id 列表等长则原样；长度为 1 时降级为 ``first_value`` 并
      向 stderr 告警；其余长度显式报错（**不静默补位或截断**，NFR-04）。
    """
    if is_ip6_values is None:
        return None
    if not isinstance(is_ip6_values, list) or not is_ip6_values:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "is_ip6 values must be a non-empty list when provided.",
            {"field": "is_ip6"},
        )
    for value in is_ip6_values:
        if not isinstance(value, str) or not value.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "is_ip6 value must be a non-empty string.",
                {"field": "is_ip6"},
            )
    if alignment == "first_value":
        return [is_ip6_values[0]]
    if len(is_ip6_values) == len(entry_ids):
        return list(is_ip6_values)
    if len(is_ip6_values) == 1:
        # 显式降级（不静默）：单值与 N 个 id 无法逐位对应，按「首值开关」构造并告警。
        print(
            "warning: is_ip6 value list of length 1 cannot align per-item with "
            f"{len(entry_ids)} ids; falling back to first_value alignment.",
            file=sys.stderr,
        )
        return [is_ip6_values[0]]
    raise RunnerError(
        "RUNNER_VALIDATION_FAILED",
        "is_ip6 values must align with the id list (same length, or a single value).",
        {"field": "is_ip6", "ids": len(entry_ids), "is_ip6": len(is_ip6_values)},
    )


# ── #batch-result（STORY-REM-02-03）─────────────────────────────────────
#
# 背景（下游现场 P2-76）：delete-batch 的返回体此前既无计数也无失败清单，消费方把
# 「没有字段」读成「没有失败」。本区域把设备响应摘要成 ``CT-REM-ATOM-RESULT`` v1.0
# 的返回结构（**追加式**：既有键不改名、不移动、不删除），并用 ``per_item_result``
# 显式声明**能力边界**：``False`` = 设备未提供可逐条采信的结果，消费方**不得**解读为
# 「无失败」（须触发回查，框架侧采纳归 STORY-REM-02-02 的 ``#bulk-verdict``）。

# 设备返回体中「逐条结果」的识别键。本仓唯一有现场声明证据的键为 ``BatchResult``
# （``adapters/ngfw/default.yaml`` 对 ``/api/v1/batch`` 的声明：
# ``{"BatchResult":[{"msg":"success"},...]}``，按请求顺序）。识别键以常量登记：
# 实测发现新形状时在此处扩展（不散落魔法字符串）。
BATCH_RESULT_KEYS: tuple[str, ...] = ("BatchResult",)

# 逐条结果的判定标记（**保守枚举**：只认证据面出现过的取值，不做「非失败即成功」式放宽）。
# 命中成功标记 -> success；命中失败标记或带非成功消息 -> failed；两者皆不命中 ->
# **不可判定**（整批降级为能力边界，不猜测）。
BATCH_ITEM_SUCCESS_MARKERS: tuple[str, ...] = ("success", "ok")
BATCH_ITEM_FAILURE_MARKERS: tuple[str, ...] = ("failed", "failure", "error")


def summarize_batch_result(response: Any, *, requested_count: int) -> dict[str, Any]:
    """把设备批量删除响应摘要成 ``CT-REM-ATOM-RESULT`` v1.0 返回结构（追加式）。

    返回键（与 ``config-batch`` 同层级；调用方以 ``**`` 追加进既有结果 dict）::

        {"count": 2048,             # 请求条目总数（与 config-batch 同键、同语义）
         "success_count": 2048,     # 成功条目数；不可得时 None（**None != 0**）
         "failed_count": 0,         # 失败条目数；不可得时 None
         "failed": [],              # 失败条目（index / status / error_code / message，
                                    # 形状对齐 config-batch.failed[]）；不可得时为 []
         "per_item_result": True}   # **能力声明**：True=设备逐条结果可采信；
                                    # False=设备未提供可逐条采信的结果 -> 消费方
                                    # **不得**解读为「无失败」，须触发回查

    保守口径（三条硬规则）：

    1. ``per_item_result`` **只有**在「逐条结果数与请求条目数一一对应」且「每条都能
       明确判定成功/失败」时才为 ``True``；其余一律 ``False``（**不默认 True**）。
       注意：id 列表承载形态（``#batch-id-list`` 的 ``single_item``）下设备按
       **batch item**（=1 个）而非按 id 返回结果，条目数对不上 -> ``False`` ——
       这正是「设备不返回逐条结果」的显式表达。
    2. 计数字段不可得时落 ``None``（**不省略键**）：``None``（不可得）与 ``0``
       （确知为零）必须可区分；``failed`` 恒为列表（不可得时为 ``[]``，且由
       ``per_item_result`` 标明不可采信）。
    3. ``count`` 恒可得（来自请求，不依赖设备）；响应非 dict / 无识别键 / 条目形状
       异常一律按能力边界降级（**不抛解析异常、不臆造逐条结果**）。

    Args:
        response: 设备响应体（``dict``；非 dict 按能力边界降级）。
        requested_count: 请求条目总数（>=1 的整数；来自请求侧，不由设备推断）。

    Returns:
        含上述五键的返回结构；既有键（``op_id`` / ``status`` / ``response`` 等）不受影响。

    Raises:
        RunnerError("RUNNER_VALIDATION_FAILED"): ``requested_count`` 非 >=1 的整数
            （调用侧契约错误，fail-loud；``bool`` 亦不接受）。
    """
    if (
        not isinstance(requested_count, int)
        or isinstance(requested_count, bool)
        or requested_count < 1
    ):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "requested_count must be a positive integer (batch delete carries at "
            "least one entry).",
            {"field": "count", "received_type": type(requested_count).__name__},
        )
    summary: dict[str, Any] = {
        "count": requested_count,
        "success_count": None,
        "failed_count": None,
        "failed": [],
        "per_item_result": False,
    }
    items = _extract_batch_items(response)
    if items is None or len(items) != requested_count:
        # 能力边界：无逐条结果键，或条目数与请求条目数无法一一对应（不猜测、不放大）。
        return summary
    classified = [_classify_batch_item(index, item) for index, item in enumerate(items, start=1)]
    if any(entry is None for entry in classified):
        # 有任一条目不可判定 -> 整批降级（保守侧优先，不产出半可信计数）。
        return summary
    failed = [entry for entry in classified if entry is not None and entry["status"] == "failed"]
    summary["success_count"] = len(classified) - len(failed)
    summary["failed_count"] = len(failed)
    summary["failed"] = failed
    summary["per_item_result"] = True
    return summary


def _extract_batch_items(response: Any) -> list[Any] | None:
    """从设备响应取出逐条结果列表；无识别键 / 形状不符 -> ``None``（不猜测）。"""
    if not isinstance(response, dict):
        return None
    for key in BATCH_RESULT_KEYS:
        value = response.get(key)
        if isinstance(value, list):
            return value
    return None


def _classify_batch_item(index: int, item: Any) -> dict[str, Any] | None:
    """判定单条设备结果；无法明确判定 -> ``None``（调用侧据此整批降级）。

    - 成功：``status`` 或 ``msg`` / ``message`` / ``errMsg`` 命中成功标记；
    - 失败：``status`` 命中失败标记，或带**非成功消息**（有报错消息即失败依据，
      不把报错消息读成成功）；
    - 其余形状（非 dict / 无可用标记）-> 不可判定。

    失败条目形状对齐 ``config-batch.failed[]``：``{index, status, error_code, message}``；
    ``error_code`` / ``message`` 取自设备字段，无则 ``None``（不臆造）。
    """
    if not isinstance(item, dict):
        return None
    status = _item_text(item, ("status",))
    message = _item_text(item, ("msg", "message", "errMsg"))
    if _is_marker(status, BATCH_ITEM_SUCCESS_MARKERS) or _is_marker(
        message, BATCH_ITEM_SUCCESS_MARKERS
    ):
        return {"index": index, "status": "success"}
    if _is_marker(status, BATCH_ITEM_FAILURE_MARKERS) or message is not None:
        return {
            "index": index,
            "status": "failed",
            "error_code": _item_text(item, ("errCode", "errorCode", "error_code")),
            "message": message,
        }
    return None


def _item_text(item: dict[str, Any], keys: tuple[str, ...]) -> str | None:
    """取首个非空字符串字段（``strip`` 后**原样**保留，不改写设备原文）；无则 ``None``。"""
    for key in keys:
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _is_marker(value: str | None, markers: tuple[str, ...]) -> bool:
    """标记比对（大小写不敏感；``None`` 与未知取值均不命中）。"""
    return value is not None and value.casefold() in markers
