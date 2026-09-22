"""NGFW NAT runner for /api/v1/natsnat, /api/v1/iterate/natdnat, /api/v1/natstatic.

NAT 规则按两个正交维度组织：

- **转换族**（snat / dnat / static）各自拥有独立端点，因此每族独自拥有 create、
  update、delete、verify 四个原子操作。
- **网络协议**（当前仅 nat44；nat66 / nat46 / nat64 为预留位）不改变端点与方法，
  只改变 payload 的 ``natType`` 字段与 GET 的查询值，因此协议是同一操作的参数。

设备契约存在若干**不可归一化**的不对称，全部按抓包原样保留：

- 创建与删除的 ``id`` 是 JSON **字符串**，修改的 ``id`` 是 JSON **整数**；
- 创建/修改 payload 写作 ``relate.isIpv6``，而回读记录写作 ``relate.is_ipv6``；
- DELETE 把 id 放在 ``?id=`` 查询参数且不发 body，与 ``fw_delete_iptun`` /
  ``fw_delete_interface`` 同形（2026-09-21 真机实测订正，原记的 body 形态有误）；
- ``fw_update_nat_hitcount`` 是清除命中计数的写操作，不是查询。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import (
    RunnerError,
    raise_if_device_session_rejected,
    raise_if_resource_not_found,
)
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

NAT_ENDPOINTS: dict[str, tuple[str, str]] = {
    "fw_config_nat_snat": ("POST", "/api/v1/natsnat"),
    "fw_update_nat_snat": ("PUT", "/api/v1/natsnat"),
    "fw_delete_nat_snat": ("DELETE", "/api/v1/natsnat"),
    "fw_verify_nat_snat": ("GET", "/api/v1/natsnat"),
    "fw_config_nat_dnat": ("POST", "/api/v1/iterate/natdnat"),
    "fw_update_nat_dnat": ("PUT", "/api/v1/iterate/natdnat"),
    "fw_delete_nat_dnat": ("DELETE", "/api/v1/iterate/natdnat"),
    "fw_verify_nat_dnat": ("GET", "/api/v1/iterate/natdnat"),
    "fw_config_nat_static": ("POST", "/api/v1/natstatic"),
    "fw_update_nat_static": ("PUT", "/api/v1/natstatic"),
    "fw_delete_nat_static": ("DELETE", "/api/v1/natstatic"),
    "fw_verify_nat_static": ("GET", "/api/v1/natstatic"),
    "fw_update_nat_hitcount": ("PUT", "/api/v1/nathitcount"),
    "fw_delete_batch_nat": ("POST", "/api/v1/batch"),
}

GET_OPS = frozenset({"fw_verify_nat_snat", "fw_verify_nat_dnat", "fw_verify_nat_static"})
DELETE_OPS = frozenset({"fw_delete_nat_snat", "fw_delete_nat_dnat", "fw_delete_nat_static"})
UPDATE_OPS = frozenset({"fw_update_nat_snat", "fw_update_nat_dnat", "fw_update_nat_static"})
CONFIG_OPS = frozenset({"fw_config_nat_snat", "fw_config_nat_dnat", "fw_config_nat_static"})
BATCH_OPS = frozenset({"fw_delete_batch_nat"})
HITCOUNT_OP = "fw_update_nat_hitcount"

# GET 与三个删除操作都不带 body：删除把规则 id 放在 ``?id=<string>`` 查询参数里，
# 与 iptun / interface 同形（2026-09-21 真机实测修正 —— 原 body 形态被设备判为
# 全量删除，返回 400 eRequestParam「Delete all ... not supported in generic delete
# operation」；``?id=<n>`` 形态返回 200 success）。
NO_BODY_OPS = GET_OPS | DELETE_OPS

# 转换族到端点。族不同即端点不同 → 独立原子操作。
NAT_FAMILIES: dict[str, str] = {
    "snat": "/api/v1/natsnat",
    "dnat": "/api/v1/iterate/natdnat",
    "static": "/api/v1/natstatic",
}

# 网络协议预留位：设备当前只暴露 nat44。新增 nat66 / nat46 / nat64 时只改这一处
# （外加 NAT_TYPE_IS_IPV6），op_id、端点、adapter 模板都无需改动。
SUPPORTED_NAT_TYPES: tuple[str, ...] = ("nat44",)
DEFAULT_NAT_TYPE = "nat44"

# 协议到 nathitcount 的 ``val.is_ipv6`` 的映射；nat44 是双栈唯一可执行值。
NAT_TYPE_IS_IPV6: dict[str, bool] = {"nat44": False}

# nathitcount 的 ``val.type`` 取值，与转换族同名但取值集合固定为这三个。
HITCOUNT_FAMILIES: tuple[str, ...] = ("snat", "dnat", "static")
HITCOUNT_ID = 0

BATCH_METHOD = "DELETE"


def build_nat_rule_payload(
    *,
    op_id: str,
    val: dict[str, Any] | None = None,
    nat_type: str = DEFAULT_NAT_TYPE,
    entry_id: str | None = None,
) -> dict[str, Any]:
    """组装创建/修改请求 body。

    创建为 ``{"val": {...}}``；修改为 ``{"id": <int>, "val": {...}}``，其中 id 按
    抓包保持整数类型。``val`` 整体直传，跨协议新增字段无需改动本函数。
    """
    if op_id not in CONFIG_OPS and op_id not in UPDATE_OPS:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this NAT rule operation.",
            {"op_id": op_id},
        )
    if not isinstance(val, dict) or not val:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT rule val object is required.",
            {"field": "val", "op_id": op_id},
        )

    payload: dict[str, Any] = {}
    if op_id in UPDATE_OPS:
        payload["id"] = _coerce_int_id("id", entry_id)
    payload["val"] = _apply_nat_type(val, nat_type)
    validate_nat_payload(payload, op_id=op_id)
    return payload


def build_nat_delete_payload(*, op_id: str, entry_id: str | None) -> dict[str, Any]:
    """组装删除选择器 ``{"id": "<string>"}``。

    2026-09-21 真机实测修正：id **不经 body 下发**，改走 ``?id=<string>`` 查询
    参数（body 形态被设备判为全量删除并 400）；此结构保留用于 dry-run 呈现与
    ``_extract_nat_summary`` 的 id 回显，实际请求由 ``_query_params`` 承载。
    """
    if op_id not in DELETE_OPS:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this NAT delete operation.",
            {"op_id": op_id},
        )
    payload = {"id": _coerce_string_id("id", entry_id)}
    validate_nat_payload(payload, op_id=op_id)
    return payload


def build_nat_hitcount_payload(
    *,
    family: str,
    nat_type: str = DEFAULT_NAT_TYPE,
    rule_ids: list[str] | None = None,
) -> dict[str, Any]:
    """组装命中计数清除请求 body。

    抓包中 id 恒为 0；``val.rule_ids`` 可选，用于把清除范围收窄到指定规则。
    """
    if family not in HITCOUNT_FAMILIES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT hit counter family is unsupported.",
            {"field": "family", "actual": family, "allowed": list(HITCOUNT_FAMILIES)},
        )
    resolved_type = _validate_nat_type(nat_type)
    val: dict[str, Any] = {
        "type": family,
        "is_ipv6": NAT_TYPE_IS_IPV6[resolved_type],
    }
    if rule_ids:
        val["rule_ids"] = [_coerce_string_id("rule_ids", item) for item in rule_ids]
    payload = {"id": HITCOUNT_ID, "val": val}
    validate_nat_payload(payload, op_id=HITCOUNT_OP)
    return payload


def build_nat_batch_delete_payload(*, family: str, entry_ids: list[str] | None) -> dict[str, Any]:
    """组装单设备内批量删除 body。

    每一项的 ``resource`` 由转换族决定；``body.id`` 是非空字符串列表。
    """
    resource = NAT_FAMILIES.get(family)
    if resource is None:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT batch delete family is unsupported.",
            {"field": "family", "actual": family, "allowed": sorted(NAT_FAMILIES)},
        )
    ids = [_coerce_string_id("id", item) for item in (entry_ids or [])]
    if not ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    batch = [{"method": BATCH_METHOD, "resource": resource, "body": {"id": [entry_id]}} for entry_id in ids]
    payload = {"batch": batch}
    validate_nat_payload(payload, op_id="fw_delete_batch_nat")
    return payload


def validate_nat_payload(payload: dict[str, Any] | None, *, op_id: str) -> dict[str, Any] | None:
    """按 op 校验请求 body 形状，并返回要下发的那份 body。

    创建/修改会按抓包契约归一化 ``id``：修改写成整数（抓包 ``{"id":3,...}``），创建则
    移除（抓包创建 body 只有 ``{"val": {...}}``，id 由设备分配）。返回的 body 可能与
    入参不是同一对象，调用方必须使用返回值。
    """
    if op_id in GET_OPS:
        return payload
    if op_id in BATCH_OPS:
        return _validate_batch_payload(payload)
    if op_id == HITCOUNT_OP:
        return _validate_hitcount_payload(payload)
    if op_id in DELETE_OPS:
        _coerce_string_id("id", (payload or {}).get("id"))
        return payload
    if op_id in CONFIG_OPS or op_id in UPDATE_OPS:
        body = payload if isinstance(payload, dict) else {}
        val = body.get("val")
        if not isinstance(val, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "NAT rule payload val object is required.",
                {"field": "val", "op_id": op_id},
            )
        _validate_nat_type(str(val.get("natType") or ""))
        if op_id in UPDATE_OPS:
            # 修改 PUT 的 body id 在抓包中是整数（{"id":3,...}）。写回整数形态：调用方
            # 可能给字符串（argparse 的 --id 恒为字符串；回滚重放的快照记录同样带字符串
            # id），设备契约只认整数形态。
            body["id"] = _coerce_int_id("id", body.get("id"))
        else:
            # 创建 POST 的抓包 body 只有 {"val": {...}}，无 id —— id 由设备在响应中分配
            # （{"id":"1","msg":"success"}）。回滚重放会带上设备记录里的 id，它不属于创建
            # 契约，因此不随请求下发。
            body.pop("id", None)
        return body
    raise RunnerError(
        "RUNNER_UNSUPPORTED_OP",
        "Runner does not support this NAT operation.",
        {"op_id": op_id},
    )


def build_nat_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
    page: int | None = None,
    size: int | None = None,
    nat_type: str = DEFAULT_NAT_TYPE,
) -> dict[str, Any]:
    method, _path = _method_path(op_id)
    query = _query_params(
        op_id,
        page=page,
        size=size,
        nat_type=nat_type,
        entry_id=(payload or {}).get("id") if isinstance(payload, dict) else None,
    )
    return {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(base_url, op_id, query=query),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "query": dict(query) if query else None,
            "payload": None if op_id in NO_BODY_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_nat(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
    page: int | None = None,
    size: int | None = None,
    nat_type: str = DEFAULT_NAT_TYPE,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    query = _query_params(
        op_id,
        page=page,
        size=size,
        nat_type=nat_type,
        entry_id=(payload or {}).get("id") if isinstance(payload, dict) else None,
    )
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    status_code, response_payload, _text = request_json(
        method,
        _request_url(base_url, op_id, query=query),
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise_if_device_session_rejected(status_code, response_payload)
        # 幂等「目标状态已达成」归一（2026-09-21 补齐，与 policy_route / timeobject 同款）：
        # 删除的创建步回滚与用例清理步会重复删除同一 NAT 规则，第二次设备答
        # 400 eRequestParam「Couldn't found 1 from DB」——语义上「目标不存在 == 目标状态
        # 已达成」，不构成残留。此前本函数未接入归一，致 fw_delete_nat_{snat,dnat} 的
        # 回滚恒报 CLEANUP_FAILED 假阳性（策略配置 run-20260921-174814 实测 4 条）。
        # 登记表 IDEMPOTENT_ERROR_TYPES 是唯一门：未登记的 op（create/update/verify）
        # 天然免疫，非删除类失败行为零变化。extra_details 保留本函数旧分支的诊断键
        # （response_keys），幂等命中时既有键集合仍为「追加而非替换」。
        raise_if_resource_not_found(
            status_code,
            response_payload,
            op_id=op_id,
            extra_details={"response_keys": sorted(response_payload.keys())},
        )
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "NAT device request did not return a success status.",
            {
                "op_id": op_id,
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    result: dict[str, Any] = {
        "op_id": op_id,
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": method,
            "path": path,
            "query": dict(query) if query else None,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }
    # 兑现 atom returns.data 里声明的 nat_rule_id / count（对照
    # runner/policy_route.py::_extract_policy_route_summary 的同一做法）。
    result.update(_extract_nat_summary(op_id, payload, response_payload))
    return result


def _extract_nat_summary(
    op_id: str,
    payload: dict[str, Any] | None,
    response_payload: dict[str, Any],
) -> dict[str, Any]:
    """从设备响应（必要时结合请求）提取 atom ``returns.data`` 声明的结构化字段。

    抓包证据：
    - 创建响应 ``{"id":"1","msg":"success"}`` —— id 是**字符串**，且是设备分配的
    - 修改响应 ``{"msg":"success"}`` / 删除响应 ``{"msg":"success"}`` —— 不回显 id，
      故按请求回显（修改是整数 id，删除是字符串 id，各保持抓包时的类型）
    - 查询响应 ``{count, page, size, vals:[...]}`` —— vals 每条带**整数** id

    Returns:
        待并入 result 的字段；无适用字段时返回空 dict。**绝不臆造 id**：拿不到就不放。
    """
    summary: dict[str, Any] = {}
    response = response_payload if isinstance(response_payload, dict) else {}
    if op_id in CONFIG_OPS:
        entry_id = response.get("id")
        if entry_id not in (None, ""):
            summary["nat_rule_id"] = entry_id
        # 到达此处说明 POST 成功（失败响应已在上方按状态码拦截）。兑现 atom
        # returns.data.created 契约，供调用方判断是否需要 rollback。
        summary["created"] = True
    elif op_id in UPDATE_OPS or op_id in DELETE_OPS:
        entry_id = (payload or {}).get("id")
        if entry_id not in (None, ""):
            summary["nat_rule_id"] = entry_id
    elif op_id in GET_OPS:
        if "count" in response:
            summary["count"] = response.get("count")
        vals = response.get("vals")
        if isinstance(vals, list):
            # atom postcondition：每条 vals 记录的 id 是 update/delete 的选择器，
            # 故直接摊平成列表（对照 policy_route verify 的 policy_route_ids）。
            summary["nat_rule_ids"] = [
                item.get("id") for item in vals if isinstance(item, dict)
            ]
    return summary


def _request_url(base_url: str, op_id: str, *, query: dict[str, str] | None = None) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    # GET 的筛选条件与 DELETE 的选择器 id 都走查询参数（两者均无 body）。
    if query:
        url = f"{url}?{urlencode(query)}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return NAT_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this NAT operation.",
            {"op_id": op_id},
        ) from exc


def _query_params(
    op_id: str,
    *,
    page: int | None,
    size: int | None,
    nat_type: str,
    entry_id: str | None = None,
) -> dict[str, str] | None:
    """查询参数。GET：page、size、natType（顺序与抓包一致）；DELETE：id。

    删除的选择器 id 必须经此通道下发 —— 设备对无 id 的 DELETE 一律按全量删除
    处理并拒绝（2026-09-21 真机实测）。
    """
    if op_id in DELETE_OPS:
        return {"id": _coerce_string_id("id", entry_id)}
    if op_id not in GET_OPS:
        return None
    query: dict[str, str] = {}
    if page is not None:
        query["page"] = str(_coerce_non_negative_int("page", page, minimum=1))
    if size is not None:
        query["size"] = str(_coerce_non_negative_int("size", size, minimum=1))
    query["natType"] = _validate_nat_type(nat_type)
    return query


def _validate_nat_type(nat_type: str) -> str:
    if nat_type not in SUPPORTED_NAT_TYPES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT protocol type is unsupported.",
            {"nat_type": nat_type, "allowed": list(SUPPORTED_NAT_TYPES)},
        )
    return nat_type


def _apply_nat_type(val: dict[str, Any], nat_type: str) -> dict[str, Any]:
    """把协议参数写入 ``val.natType``；与入参内已有值冲突时拒绝，不静默覆盖。"""
    resolved = _validate_nat_type(nat_type)
    existing = val.get("natType")
    if existing is not None and existing != resolved:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT val.natType conflicts with the requested nat_type.",
            {"val_natType": existing, "nat_type": resolved},
        )
    merged = dict(val)
    merged["natType"] = resolved
    return merged


def _validate_hitcount_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    body = payload or {}
    val = body.get("val")
    if not isinstance(val, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT hit counter payload val object is required.",
            {"field": "val"},
        )
    family = val.get("type")
    if family not in HITCOUNT_FAMILIES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT hit counter val.type is unsupported.",
            {"field": "val.type", "actual": family, "allowed": list(HITCOUNT_FAMILIES)},
        )
    if not isinstance(val.get("is_ipv6"), bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT hit counter val.is_ipv6 must be a boolean.",
            {"field": "val.is_ipv6", "actual": val.get("is_ipv6")},
        )
    rule_ids = val.get("rule_ids")
    if rule_ids is not None:
        if not isinstance(rule_ids, list) or not rule_ids:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "NAT hit counter val.rule_ids must be a non-empty list when present.",
                {"field": "val.rule_ids"},
            )
        for item in rule_ids:
            _coerce_string_id("val.rule_ids", item)
    return body


def _validate_batch_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    batch = (payload or {}).get("batch")
    if not isinstance(batch, list) or not batch:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Batch delete payload must contain a non-empty batch list.",
            {"field": "batch"},
        )
    allowed = set(NAT_FAMILIES.values())
    for item in batch:
        if not isinstance(item, dict):
            raise RunnerError("RUNNER_VALIDATION_FAILED", "Batch item must be an object.", {"field": "batch"})
        if item.get("method") != BATCH_METHOD or item.get("resource") not in allowed:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch NAT delete only supports DELETE items targeting a NAT rule endpoint.",
                {"method": item.get("method"), "resource": item.get("resource"), "allowed": sorted(allowed)},
            )
        body = item.get("body")
        ids = body.get("id") if isinstance(body, dict) else None
        if not isinstance(ids, list) or not ids:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch NAT delete item body.id must be a non-empty list.",
                {"field": "body.id"},
            )
        for item_id in ids:
            _coerce_string_id("body.id", item_id)
    return payload


def _coerce_string_id(field: str, value: Any) -> str:
    """创建响应、删除 body、批量 body 的 id 都是字符串；保持字符串不动。"""
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT id must be a non-empty string.",
            {"field": field, "actual": value},
        )
    return value


def _coerce_int_id(field: str, value: Any) -> int:
    """修改（PUT）body 的 id 在抓包中是整数，不做字符串化。"""
    if isinstance(value, bool) or value is None:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT update id must be a non-negative integer.",
            {"field": field, "actual": value},
        )
    text = str(value).strip()
    if not text.isdigit():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT update id must be a non-negative integer.",
            {"field": field, "actual": value},
        )
    return int(text)


def _coerce_non_negative_int(field: str, value: Any, *, minimum: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < minimum:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "NAT integer field is below its minimum.",
            {"field": field, "value": parsed, "minimum": minimum},
        )
    return parsed
