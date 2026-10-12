"""NGFW IPsec runner for /api/v1/ipsec, /api/v1/ipsec/port, /api/v1/ipsec/ikesa, /api/v1/ipsec/ipsecsa.

IPsec 的策略、端口/NAT-T 与运行态 SA 各自拥有独立端点，按 HTTP 方法/端点拆分为
8 个原子操作。设备契约里有若干**不可归一化**的不对称，全部按抓包原样保留：

- ``PUT /api/v1/ipsec`` 是 **upsert**：id 即策略名并决定对象，响应只有
  ``{"msg":"success"}``，**不回显对象体**，故新增/修改无法从响应区分，必须靠后续
  GET 复验；
- ``DELETE /api/v1/ipsec`` 把 id 放在 **查询串**（``?id=<name>``）且不发 body —— 与
  NAT 三族的「id 放 JSON body」形态相反，因此 URL 拼接必须按 op 分流而不是按族分流；
- 策略列表与端口列表的记录**都没有 id 字段**：策略靠 ``name`` 标识，端口靠
  ``ip_protocol`` 标识；端口的 PUT 信封 id 是**固定字面量 ``"0"``**。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

IPSEC_ENDPOINTS: dict[str, tuple[str, str]] = {
    "fw_config_ipsec_policy": ("PUT", "/api/v1/ipsec"),
    "fw_delete_ipsec_policy": ("DELETE", "/api/v1/ipsec"),
    "fw_verify_ipsec_policy": ("GET", "/api/v1/ipsec"),
    "fw_update_ipsec_port": ("PUT", "/api/v1/ipsec/port"),
    "fw_verify_ipsec_port": ("GET", "/api/v1/ipsec/port"),
    "fw_verify_ipsec_ikesa": ("GET", "/api/v1/ipsec/ikesa"),
    "fw_verify_ipsec_sa": ("GET", "/api/v1/ipsec/ipsecsa"),
    "fw_delete_batch_ipsec": ("POST", "/api/v1/batch"),
}

GET_OPS = frozenset(
    {
        "fw_verify_ipsec_policy",
        "fw_verify_ipsec_port",
        "fw_verify_ipsec_ikesa",
        "fw_verify_ipsec_sa",
    }
)
# 只有这两个查询在抓包里带 page/size；策略与端口查询既无 body 也无查询参数。
PAGED_GET_OPS = frozenset({"fw_verify_ipsec_ikesa", "fw_verify_ipsec_sa"})
DELETE_OPS = frozenset({"fw_delete_ipsec_policy"})
UPSERT_OPS = frozenset({"fw_config_ipsec_policy"})
PORT_UPDATE_OPS = frozenset({"fw_update_ipsec_port"})
BATCH_OPS = frozenset({"fw_delete_batch_ipsec"})
ENVELOPE_PUT_OPS = UPSERT_OPS | PORT_UPDATE_OPS

# delete-policy 的 id 走查询串（与 NAT 三族的 JSON body 相反），故除 GET 外它也不带 body。
NO_BODY_OPS = GET_OPS | DELETE_OPS

# 端口 PUT 信封的 id 是抓包里的固定字面量，不是选择器。
IPSEC_PORT_ID = "0"

BATCH_METHOD = "DELETE"
BATCH_RESOURCE = "/api/v1/ipsec"

# 运行态查询里用于回执的标识字段：策略列表无 id，靠 name；端口列表靠 ip_protocol。
IDENTITY_FIELD: dict[str, str] = {
    "fw_verify_ipsec_policy": "name",
    "fw_verify_ipsec_port": "ip_protocol",
}


def build_ipsec_policy_payload(*, op_id: str, envelope: dict[str, Any] | None) -> dict[str, Any]:
    """组装策略 upsert 信封 ``{"id": "<policy-name>", "val": {...}}``。

    ``val`` 整体直传：PTMP / PTP 两种形状、以及后续新增的字段都不需要改动本函数。
    """
    if op_id not in UPSERT_OPS:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this IPsec policy operation.",
            {"op_id": op_id},
        )
    body = dict(envelope) if isinstance(envelope, dict) else {}
    body["id"] = _coerce_non_empty_string("id", body.get("id"))
    val = body.get("val")
    if not isinstance(val, dict) or not val:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPsec policy val object is required.",
            {"field": "val", "op_id": op_id},
        )
    validate_ipsec_payload(body, op_id=op_id)
    return body


def build_ipsec_port_payload(*, val: dict[str, Any] | None) -> dict[str, Any]:
    """组装端口/NAT-T 更新信封 ``{"id": "0", "val": {...}}``。

    id 是设备契约里的固定字面量，不接受调用方指定。
    """
    if not isinstance(val, dict) or not val:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPsec port val object is required.",
            {"field": "val", "op_id": "fw_update_ipsec_port"},
        )
    body: dict[str, Any] = {"id": IPSEC_PORT_ID, "val": dict(val)}
    validate_ipsec_payload(body, op_id="fw_update_ipsec_port")
    return body


def build_ipsec_batch_delete_payload(*, policy_names: list[str]) -> dict[str, Any]:
    """组装批量删除 body ``{"batch":[{"method":"DELETE","resource":"/api/v1/ipsec","body":{"id":[...]}}]}``。"""
    names = [_coerce_non_empty_string("id", name) for name in policy_names]
    if not names:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Batch IPsec policy delete requires at least one policy name.",
            {"field": "id"},
        )
    payload = {
        "batch": [
            {"method": BATCH_METHOD, "resource": BATCH_RESOURCE, "body": {"id": names}}
        ]
    }
    validate_ipsec_payload(payload, op_id="fw_delete_batch_ipsec")
    return payload


def validate_ipsec_payload(payload: dict[str, Any] | None, *, op_id: str) -> dict[str, Any] | None:
    """按 op 校验请求 body / 选择器形状，并返回要下发的那份 body。

    GET 与 delete-policy 不下发 body（delete-policy 的 id 走查询串），返回 None。
    """
    if op_id in GET_OPS:
        return None
    if op_id in DELETE_OPS:
        # 无条件透传：不构造 body，id 由 _query_params 放进查询串。
        return None
    if op_id in BATCH_OPS:
        return _validate_batch_payload(payload)
    if op_id in UPSERT_OPS:
        body = payload if isinstance(payload, dict) else {}
        _coerce_non_empty_string("id", body.get("id"))
        if not isinstance(body.get("val"), dict) or not body.get("val"):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "IPsec policy val object is required.",
                {"field": "val", "op_id": op_id},
            )
        return body
    if op_id in PORT_UPDATE_OPS:
        body = payload if isinstance(payload, dict) else {}
        _coerce_non_empty_string("id", body.get("id"))
        if str(body.get("id")) != IPSEC_PORT_ID:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "IPsec port update id is fixed by the device contract.",
                {"field": "id", "actual": body.get("id"), "expected": IPSEC_PORT_ID},
            )
        if not isinstance(body.get("val"), dict) or not body.get("val"):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "IPsec port val object is required.",
                {"field": "val", "op_id": op_id},
            )
        return body
    raise RunnerError(
        "RUNNER_UNSUPPORTED_OP",
        "Runner does not support this IPsec operation.",
        {"op_id": op_id},
    )


def build_ipsec_dry_run(
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
    entry_id: str | None = None,
) -> dict[str, Any]:
    method, _path = _method_path(op_id)
    query = _query_params(op_id, page=page, size=size, entry_id=entry_id)
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


def _fetch_ipsec_policy_names(
    *, base_url: str, headers: dict[str, str], timeout: float, verify_tls: bool
) -> set[str]:
    """GET /api/v1/ipsec（与 verify-policy 同形）取现存策略名集合。

    2026-10-12：用于 fw_config_ipsec_policy 的创建/更新分派——部分设备型号
    （DAS-TGFW-G3300-HU 实测）的 PUT 是**严格更新**：对象不存在即拒
    「Put请求试图修改不存在的内容」；创建必须走 POST {"val": ...}。
    """
    url = _request_url(base_url, "fw_verify_ipsec_policy")
    status_code, response_payload, _text = request_json(
        "GET", url, headers=headers, json_payload=None,
        timeout=timeout, verify_tls=verify_tls,
    )
    if status_code not in GET_SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response_payload)
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "IPsec policy existence pre-check did not return a success status.",
            {
                "op_id": "fw_config_ipsec_policy",
                "status_code": status_code,
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
            },
        )
    items: Any = response_payload.get("vals") if isinstance(response_payload, dict) else response_payload
    if not isinstance(items, list):
        items = []
    return {str(it.get("name")) for it in items if isinstance(it, dict) and it.get("name")}


def execute_ipsec(
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
    entry_id: str | None = None,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    query = _query_params(op_id, page=page, size=size, entry_id=entry_id)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}

    # 2026-10-12：config-policy 的「存在则 PUT / 不存在则 POST」分派。
    # 设备契约（实测）：PUT 为严格更新（不存在即拒），创建必须 POST {"val": ...}（无 id 信封）。
    # 先在 GET 上查重，按结果选择方法；查重失败响亮报错（不蒙猜）。
    upsert_method = method
    if op_id == "fw_config_ipsec_policy":
        policy_name = str((payload or {}).get("id") or "")
        existing = _fetch_ipsec_policy_names(
            base_url=base_url, headers=headers, timeout=timeout, verify_tls=verify_tls
        )
        if policy_name and policy_name not in existing:
            upsert_method = "POST"
            payload = {"val": (payload or {}).get("val")}
            query = None

    status_code, response_payload, _text = request_json(
        upsert_method,
        _request_url(base_url, op_id, query=query),
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if upsert_method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise_if_device_session_rejected(status_code, response_payload)
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if upsert_method == "GET" else "RUNNER_CONFIG_REJECTED",
            "IPsec device request did not return a success status.",
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
            "method": upsert_method,
            "path": path,
            "query": dict(query) if query else None,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }
    # 兑现 atom returns.data 里声明的 ipsec_policy_id / count（对照
    # runner/nat.py::_extract_nat_summary 的同一做法）。
    result.update(_extract_ipsec_summary(op_id, payload, response_payload, entry_id))
    return result


def _extract_ipsec_summary(
    op_id: str,
    payload: dict[str, Any] | None,
    response_payload: dict[str, Any],
    entry_id: str | None,
) -> dict[str, Any]:
    """从设备响应（必要时结合请求）提取 atom ``returns.data`` 声明的结构化字段。

    抓包证据：
    - 策略 upsert / 端口更新 / 删除的响应都是 ``{"msg":"success"}``，**不回显任何对象体**，
      故 id 只能按请求回显；也因此无法从响应判断 upsert 是新建还是覆盖，**不得臆造 created**。
    - 查询响应形状不一：分页查询是 ``{count, page, size, vals:[...]}``，策略/端口查询
      只有 ``{"vals":[...]}``。取值一律「有才放」。

    Returns:
        待并入 result 的字段；无适用字段时返回空 dict。
    """
    summary: dict[str, Any] = {}
    response = response_payload if isinstance(response_payload, dict) else {}
    if op_id in UPSERT_OPS or op_id in DELETE_OPS or op_id in PORT_UPDATE_OPS:
        identity = (payload or {}).get("id") or entry_id
        if identity not in (None, ""):
            key = "ipsec_port_id" if op_id in PORT_UPDATE_OPS else "ipsec_policy_id"
            summary[key] = identity
    elif op_id in GET_OPS:
        if "count" in response:
            summary["count"] = response.get("count")
        vals = response.get("vals")
        if isinstance(vals, list):
            identity = IDENTITY_FIELD.get(op_id)
            if identity:
                # 策略与端口列表没有 id 字段：策略靠 name、端口靠 ip_protocol 标识。
                summary["ipsec_identities"] = [
                    item.get(identity) for item in vals if isinstance(item, dict)
                ]
            summary["ipsec_sa_names"] = [
                item.get("name") for item in vals if isinstance(item, dict)
            ]
    elif op_id in BATCH_OPS:
        batch_result = response.get("BatchResult")
        if isinstance(batch_result, list):
            summary["batch_result_count"] = len(batch_result)
    return summary


def _request_url(base_url: str, op_id: str, *, query: dict[str, str] | None = None) -> str:
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    # 只有分页 GET 与 delete-policy 带查询串；策略/端口 GET 无查询参数，其余 op 的
    # 选择器都在 body 里。按 op 分流而非按族分流 —— 同一族内 delete 与 GET 形态不同。
    if (op_id in PAGED_GET_OPS or op_id in DELETE_OPS) and query:
        url = f"{url}?{urlencode(query)}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return IPSEC_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this IPsec operation.",
            {"op_id": op_id},
        ) from exc


def _query_params(
    op_id: str,
    *,
    page: int | None,
    size: int | None,
    entry_id: str | None,
) -> dict[str, str] | None:
    """查询串。顺序与抓包一致：分页是 page、size，删除是 id。"""
    if op_id in PAGED_GET_OPS:
        query: dict[str, str] = {}
        if page is not None:
            query["page"] = str(_coerce_non_negative_int("page", page, minimum=1))
        if size is not None:
            query["size"] = str(_coerce_non_negative_int("size", size, minimum=1))
        return query
    if op_id in DELETE_OPS:
        return {"id": _coerce_non_empty_string("id", entry_id)}
    return None


def _validate_batch_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    batch = (payload or {}).get("batch")
    if not isinstance(batch, list) or not batch:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Batch IPsec delete payload must contain a non-empty batch list.",
            {"field": "batch"},
        )
    for item in batch:
        if not isinstance(item, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED", "Batch item must be an object.", {"field": "batch"}
            )
        if item.get("method") != BATCH_METHOD or item.get("resource") != BATCH_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch IPsec delete only supports DELETE items targeting /api/v1/ipsec.",
                {"method": item.get("method"), "resource": item.get("resource")},
            )
        body = item.get("body")
        names = body.get("id") if isinstance(body, dict) else None
        if not isinstance(names, list) or not names:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch IPsec delete item body.id must be a non-empty list.",
                {"field": "body.id"},
            )
        for name in names:
            _coerce_non_empty_string("body.id", name)
    return payload


def _coerce_non_empty_string(field: str, value: Any) -> str:
    """策略名 / 端口的 id 都是非空字符串，保持字符串不动。"""
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPsec identifier must be a non-empty string.",
            {"field": field, "actual": value},
        )
    return value


def _coerce_non_negative_int(field: str, value: Any, *, minimum: int = 0) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPsec integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < minimum:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPsec integer field is below its minimum.",
            {"field": field, "value": parsed, "minimum": minimum},
        )
    return parsed
