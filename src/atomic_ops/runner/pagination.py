"""P2 大批量 verify 缺口：分页聚合共享工具。

背景（下游现场 2026-09-08~09-11）：用例以 ``--size 5000`` 一次性查询 2048 条
对象时，DUT 长时间无响应直至连接中断（"Device request failed before a response
was received."），后续清理步被静默跳过。共享 helper 供各 verify runner 以
**内部翻页聚合**代替单次超大查询：调用方传 ``fetch_page(page, size)``（返回设备
响应 dict 或抛 RunnerError），本模块按页循环拉取并聚合 ``vals``。

默认行为向后兼容：仅在 CLI 显式传 ``--page-size`` 时进入聚合模式，不传时
runner 仍走原单次查询路径。
"""

from __future__ import annotations

from typing import Any, Callable

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected


# 聚合翻页的页数上限：按最小页 1 条计，1000 页足以覆盖设备容量，同时防止
# count 缺失/异常时死循环。
DEFAULT_MAX_PAGES = 1000


def response_payload_or_raise(
    op_id: str,
    method: str,
    fetched: tuple[int, dict[str, Any], str],
) -> dict[str, Any]:
    """校验 ``request_json`` 三元组的状态码并返回响应 dict（GET→200，其余→2xx）。"""
    status_code, response_payload, _text = fetched
    success_status = {200} if method == "GET" else {200, 201, 202}
    if status_code not in success_status:
        raise_if_device_session_rejected(status_code, response_payload)
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "Device request did not return a success status while paging.",
            {"op_id": op_id, "status_code": status_code},
        )
    return response_payload


def fetch_all_pages(
    fetch_page: Callable[[int, int], dict[str, Any]],
    *,
    page_size: int,
    max_pages: int = DEFAULT_MAX_PAGES,
) -> dict[str, Any]:
    """按 ``page_size`` 翻页聚合设备返回的 ``vals`` 列表。

    终止条件（任一满足即停）：
    - 当前页 ``vals`` 非列表或为空；
    - 当前页返回条数 < page_size（最后一页）；
    - 响应带 ``count`` 且已聚合条数 >= count；
    - 达到 ``max_pages`` 保险上限（结果标记 ``truncated: true``）。

    返回形状与单页响应兼容（``vals``/``count``），并附加 ``pages``/``page_size``/
    ``truncated`` 供调用方与消费方感知聚合发生。
    """
    if page_size < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Page size for aggregated verify must be a positive integer.",
            {"field": "page_size", "value": page_size},
        )
    aggregated: list[Any] = []
    count: Any = None
    pages = 0
    truncated = False
    for page in range(1, max_pages + 1):
        response = fetch_page(page, page_size)
        pages = page
        if not isinstance(response, dict):
            break
        if count is None and isinstance(response.get("count"), int):
            count = response["count"]
        vals = response.get("vals")
        if not isinstance(vals, list) or not vals:
            break
        aggregated.extend(vals)
        if isinstance(count, int) and len(aggregated) >= count:
            break
        if len(vals) < page_size:
            break
        if page == max_pages:
            truncated = True
    return {
        "vals": aggregated,
        "count": count if isinstance(count, int) else len(aggregated),
        "pages": pages,
        "page_size": page_size,
        "truncated": truncated,
    }
