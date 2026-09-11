"""NGFW control-policy group (acl_policy_group) runner.

策略组覆盖 IPv4 与 IPv6，二者仅请求路径不同（/api/v1/ip4policy/group 与
/api/v1/ip6policy/group），body 一致。update 是重命名语义：顶层 id 固定为 "1"，
靠 val.old_name / val.new_name 驱动。删除按 name 查询，无 body。
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

ACL_POLICY_GROUP_BASE_PATHS = {
    "ipv4": "/api/v1/ip4policy/group",
    "ipv6": "/api/v1/ip6policy/group",
}

ACL_POLICY_GROUP_METHODS = {
    "fw_config_acl_policy_group": "POST",
    "fw_update_acl_policy_group": "PUT",
    "fw_delete_acl_policy_group": "DELETE",
    "fw_verify_acl_policy_group": "GET",
}
GET_OPS = {"fw_verify_acl_policy_group"}
DELETE_OPS = {"fw_delete_acl_policy_group"}
NO_BODY_OPS = GET_OPS | DELETE_OPS
POLICY_TYPES = {"ipv4", "ipv6"}


def build_acl_policy_group_payload(*, name: str) -> dict[str, Any]:
    _validate_non_empty("name", name)
    return {"val": {"name": name}}


def build_acl_policy_group_update_payload(*, old_name: str, new_name: str) -> dict[str, Any]:
    _validate_non_empty("old_name", old_name)
    _validate_non_empty("new_name", new_name)
    # PUT 的顶层 id 固定为 "1"，重命名由 old_name/new_name 驱动
    return {"id": "1", "val": {"old_name": old_name, "new_name": new_name}}


def build_acl_policy_group_delete_payload(*, name: str) -> dict[str, str]:
    _validate_non_empty("name", name)
    return {"name": name}


def build_acl_policy_group_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    policy_type: str,
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
            "url": _request_url(base_url, op_id, policy_type=policy_type, payload=payload),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": request_payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_acl_policy_group(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    policy_type: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method = _method(op_id)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    url = _request_url(base_url, op_id, policy_type=policy_type, payload=payload)
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
        raise_if_device_session_rejected(status_code, response_payload)
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "Control-policy group device request did not return a success status.",
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
            "path": _group_resource(policy_type),
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }
    result.update(_extract_acl_policy_group_summary(op_id, response_payload))
    return result


def _extract_acl_policy_group_summary(op_id: str, response_payload: Any) -> dict[str, Any]:
    """兑现 atom returns.data 契约。verify 返回 group_names 列表与 count。"""
    summary: dict[str, Any] = {}
    if op_id == "fw_verify_acl_policy_group" and isinstance(response_payload, dict):
        vals = response_payload.get("vals")
        if isinstance(vals, list):
            summary["group_names"] = [
                item.get("name") for item in vals if isinstance(item, dict)
            ]
        summary["count"] = response_payload.get("count")
    return summary


def _request_url(
    base_url: str,
    op_id: str,
    *,
    policy_type: str,
    payload: dict[str, Any] | None,
) -> str:
    url = f"{normalize_base_url(base_url)}{_group_resource(policy_type)}"
    if op_id in DELETE_OPS:
        name = str((payload or {}).get("name") or "")
        _validate_non_empty("name", name)
        url = f"{url}?{urlencode({'name': name})}"
    # verify 无 query；config/update 无 query
    return url


def _method(op_id: str) -> str:
    try:
        return ACL_POLICY_GROUP_METHODS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this acl-policy-group operation.",
            {"op_id": op_id},
        ) from exc


def _group_resource(policy_type: str) -> str:
    policy_type = _validate_policy_type(policy_type)
    return ACL_POLICY_GROUP_BASE_PATHS[policy_type]


def _validate_policy_type(policy_type: str) -> str:
    if policy_type not in POLICY_TYPES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Policy type must be ipv4 or ipv6.",
            {"field": "policy_type", "policy_type": policy_type, "allowed": sorted(POLICY_TYPES)},
        )
    return policy_type


def _validate_non_empty(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required control-policy-group field is empty.",
            {"field": field},
        )
