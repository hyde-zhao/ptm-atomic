"""NGFW control-policy (acl_policy) runner.

控制策略覆盖 IPv4 与 IPv6 两个地址族，二者仅请求路径不同
（/api/v1/ip4policy/fwaclconf 与 /api/v1/ip6policy/fwaclconf），val body 完全一致。
policy_type 在运行时选择路径前缀，不在 body 中携带地址族标记，这与 policy-route
在 body 中携带 is_ip6/type 的做法不同。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

# policy_type -> fwaclconf 请求路径
ACL_POLICY_BASE_PATHS = {
    "ipv4": "/api/v1/ip4policy/fwaclconf",
    "ipv6": "/api/v1/ip6policy/fwaclconf",
}
ACL_POLICY_BATCH_PATH = "/api/v1/batch"
# 默认 policy_group 过滤值（中文"全部"），由 urlencode 自动转义
DEFAULT_POLICY_GROUP = "全部"

ACL_POLICY_METHODS = {
    "fw_config_acl_policy": "POST",
    "fw_update_acl_policy": "PUT",
    "fw_delete_acl_policy": "DELETE",
    "fw_verify_acl_policy": "GET",
}
GET_OPS = {"fw_verify_acl_policy"}
DELETE_OPS = {"fw_delete_acl_policy"}
BATCH_OPS = {"fw_delete_batch_acl_policy"}
NO_BODY_OPS = GET_OPS | DELETE_OPS
POLICY_TYPES = {"ipv4", "ipv6"}


def build_acl_policy_payload(
    *,
    policy_type: str = "ipv4",
    name: str,
    enable: bool = True,
    action: int = 1,
    log: bool = False,
    szone: str = "any",
    dzone: str = "any",
    policy_group: str = DEFAULT_POLICY_GROUP,
    desc: str = "",
    src_addr: str = "any",
    src_addr_is_group: bool = False,
    dst_addr: str = "any",
    dst_addr_is_group: bool = False,
    service: str = "any",
    service_is_group: bool = False,
    entry_id: int | str = 0,
) -> dict[str, Any]:
    """构造控制策略 config/update 的请求 body。

    entry_id 为 0 时返回 config 的 {val: {...}}（POST 不带顶层 id）；
    entry_id>0 时返回 update 的 {id, val}（PUT 顶层带 id，val 不含 id）。
    """
    _validate_non_empty("name", name)
    _validate_policy_type(policy_type)
    val: dict[str, Any] = {
        "enable": enable,
        "do_reset": False,
        "session_switch": False,
        "action": action,
        "session_time": 0,
        "policy_group": policy_group,
        "desc": desc,
        "szone": szone,
        "dzone": dzone,
        "src_mac": [{"addr_name": "any"}],
        "src_dns": [{"dns_name": "any"}],
        "dst_mac": [{"addr_name": "any"}],
        "dst_dns": [{"dns_name": "any"}],
        "src_geo": [],
        "dst_geo": [],
        "name": name,
        "log": log,
        "src_addr": [{"addr_name": src_addr, "is_group": src_addr_is_group}],
        "dst_addr": [{"addr_name": dst_addr, "is_group": dst_addr_is_group}],
        "service": [{"service_name": service, "is_group": service_is_group}],
        "applist": [],
        "userlist": [],
        "app_tag_name": [],
        "sec_obj_data": [],
    }
    if entry_id:
        entry_id = _validate_positive_int("id", entry_id)
        return {"id": entry_id, "val": val}
    return {"val": val}


def build_acl_policy_delete_payload(*, entry_id: int | str) -> dict[str, int]:
    return {"id": _validate_positive_int("id", entry_id)}


def build_acl_policy_batch_delete_payload(
    *,
    entry_ids: list[str],
    policy_type: str = "ipv4",
) -> dict[str, Any]:
    """构造批量删除 payload。resource 由 policy_type 决定，body.id 为字符串列表，无 is_ip6。"""
    resource = _policy_resource(policy_type)
    if not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": "id"},
        )
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        _validate_non_empty("id", entry_id)
        batch.append(
            {
                "method": "DELETE",
                "resource": resource,
                "body": {"id": [str(entry_id)]},
            }
        )
    return {"batch": batch}


def validate_acl_policy_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    if op_id in BATCH_OPS:
        return _validate_acl_policy_batch_payload(payload, policy_type_hint=None)
    return payload


def _validate_acl_policy_batch_payload(
    payload: dict[str, Any], *, policy_type_hint: str | None
) -> dict[str, Any]:
    batch = payload.get("batch")
    if not isinstance(batch, list) or not batch:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Batch delete payload must contain a non-empty batch list.",
            {"field": "batch"},
        )
    resources: set[str] = set()
    for item in batch:
        if not isinstance(item, dict):
            raise RunnerError("RUNNER_VALIDATION_FAILED", "Batch item must be an object.", {"field": "batch"})
        if item.get("method") != "DELETE":
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch acl-policy delete only supports DELETE items.",
                {"method": item.get("method")},
            )
        resource = item.get("resource")
        if resource not in ACL_POLICY_BASE_PATHS.values():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch acl-policy delete resource must be /api/v1/ip4policy/fwaclconf or /api/v1/ip6policy/fwaclconf.",
                {"resource": resource},
            )
        resources.add(str(resource))
        body = item.get("body")
        ids = body.get("id") if isinstance(body, dict) else None
        if not isinstance(ids, list) or not ids:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch delete item body.id must be a non-empty list.",
                {"field": "batch"},
            )
    # 整批必须同一地址族（同 resource path），不允许 ip4/ip6 混用
    if len(resources) > 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Batch acl-policy delete must target a single address family; ip4 and ip6 resources cannot mix.",
            {"resources": sorted(resources)},
        )
    return payload


def build_acl_policy_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    policy_type: str,
    page: int,
    size: int,
    policy_id: int | None = None,
    content: str = "",
    policy_name: str = "",
    source: str = "",
    destination: str = "",
    service: str = "",
    policy_group: str = DEFAULT_POLICY_GROUP,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method = _method(op_id)
    request_payload = None if op_id in NO_BODY_OPS else payload
    return {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(
                base_url,
                op_id,
                policy_type=policy_type,
                page=page,
                size=size,
                policy_id=policy_id,
                payload=payload,
                content=content,
                policy_name=policy_name,
                source=source,
                destination=destination,
                service=service,
                policy_group=policy_group,
            ),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": request_payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_acl_policy(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    policy_type: str,
    page: int,
    size: int,
    policy_id: int | None = None,
    content: str = "",
    policy_name: str = "",
    source: str = "",
    destination: str = "",
    service: str = "",
    policy_group: str = DEFAULT_POLICY_GROUP,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method = _method(op_id)
    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    url = _request_url(
        base_url,
        op_id,
        policy_type=policy_type,
        page=page,
        size=size,
        policy_id=policy_id,
        payload=payload,
        content=content,
        policy_name=policy_name,
        source=source,
        destination=destination,
        service=service,
        policy_group=policy_group,
    )
    status_code, response_payload, _text = request_json(
        method,
        url,
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "Control-policy device request did not return a success status.",
            {
                "op_id": op_id,
                "status_code": status_code,
                "err_code": response_payload.get("errCode") if isinstance(response_payload, dict) else None,
                "err_msg": (response_payload.get("errMsg") or response_payload.get("message")) if isinstance(response_payload, dict) else None,
                "response_keys": sorted(response_payload.keys()) if isinstance(response_payload, dict) else [],
            },
        )
    result: dict[str, Any] = {
        "op_id": op_id,
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": method,
            "path": _path(op_id, policy_type),
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }
    result.update(_extract_acl_policy_summary(op_id, response_payload))
    return result


def _extract_acl_policy_summary(op_id: str, response_payload: Any) -> dict[str, Any]:
    """兑现 atom returns.data 契约。

    verify 返回 acl_policy_ids 列表与 count；config/update 响应仅 {"msg":"success"}，
    不含策略 id，故不提取（acl_policy_id 保持占位，需后续 verify 按 name 解析）。
    """
    summary: dict[str, Any] = {}
    if op_id == "fw_verify_acl_policy" and isinstance(response_payload, dict):
        vals = response_payload.get("vals")
        if isinstance(vals, list):
            summary["acl_policy_ids"] = [
                item.get("id") for item in vals if isinstance(item, dict)
            ]
        summary["count"] = response_payload.get("count")
    return summary


def _request_url(
    base_url: str,
    op_id: str,
    *,
    policy_type: str,
    page: int,
    size: int,
    policy_id: int | None = None,
    payload: dict[str, Any] | None = None,
    content: str = "",
    policy_name: str = "",
    source: str = "",
    destination: str = "",
    service: str = "",
    policy_group: str = DEFAULT_POLICY_GROUP,
) -> str:
    _validate_positive_int("page", page)
    _validate_positive_int("size", size)
    url = f"{normalize_base_url(base_url)}{_path(op_id, policy_type)}"
    if op_id in GET_OPS:
        if policy_id is not None:
            # 单查模式：?id=N（id=0 查默认策略）
            url = f"{url}?{urlencode({'id': policy_id})}"
        else:
            # 分页过滤模式：所有过滤字段都带上，policy_group 默认"全部"并 URL 编码
            query = {
                "page": page,
                "size": size,
                "content": content,
                "policy_id": "",
                "policy_name": policy_name,
                "source": source,
                "destination": destination,
                "service": service,
                "policy_group": policy_group,
            }
            url = f"{url}?{urlencode(query)}"
    elif op_id in DELETE_OPS:
        entry_id = str((payload or {}).get("id") or "")
        _validate_non_empty("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method(op_id: str) -> str:
    if op_id == "fw_delete_batch_acl_policy":
        return "POST"
    try:
        return ACL_POLICY_METHODS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this acl-policy operation.",
            {"op_id": op_id},
        ) from exc


def _path(op_id: str, policy_type: str) -> str:
    if op_id == "fw_delete_batch_acl_policy":
        return ACL_POLICY_BATCH_PATH
    return _policy_resource(policy_type)


def _policy_resource(policy_type: str) -> str:
    policy_type = _validate_policy_type(policy_type)
    return ACL_POLICY_BASE_PATHS[policy_type]


def _validate_policy_type(policy_type: str) -> str:
    if policy_type not in POLICY_TYPES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Policy type must be ipv4 or ipv6.",
            {"field": "policy_type", "policy_type": policy_type, "allowed": sorted(POLICY_TYPES)},
        )
    return policy_type


def _validate_positive_int(field: str, value: int | str) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Control-policy integer field is invalid.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Control-policy integer field must be positive.",
            {"field": field, "value": parsed},
        )
    return parsed


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required control-policy field is empty.",
            {"field": field},
        )
