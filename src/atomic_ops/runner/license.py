"""NGFW license query runner for /api/v1/licensedev and /api/v1/license.

两个端点都是只读 GET，不需要 body，也不改变设备状态。license 响应中的
``module[]`` 覆盖各业务模块；IPS 模块的 ``name`` 为“入侵防御”，runner
单独把它暴露为 ``ips_module``，便于 IPS 用例判断授权是否可用。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200}
IPS_MODULE_NAME = "入侵防御"

LICENSE_ENDPOINTS: dict[str, tuple[str, str]] = {
    "fw_verify_license_dev": ("GET", "/api/v1/licensedev"),
    "fw_verify_license": ("GET", "/api/v1/license"),
}


def build_license_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    return {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": f"{normalize_base_url(base_url)}{path}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_license(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    status_code, response_payload, _text = request_json(
        method,
        f"{normalize_base_url(base_url)}{path}",
        headers=headers,
        json_payload=None,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response_payload, op_id=op_id)
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "License device request did not return a success status.",
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
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }
    if op_id == "fw_verify_license_dev":
        result.update(_extract_license_dev(response_payload))
    else:
        result.update(_extract_license(response_payload))
    return result


def _extract_license_dev(response_payload: dict[str, Any]) -> dict[str, Any]:
    vals = response_payload.get("vals")
    device: dict[str, Any] = {}
    if isinstance(vals, list):
        for item in vals:
            if isinstance(item, dict):
                device = item
                break
    elif isinstance(vals, dict):
        device = vals
    elif isinstance(response_payload.get("devType"), str) or isinstance(
        response_payload.get("devSn"), str
    ):
        device = response_payload
    return {
        "dev_type": device.get("devType"),
        "dev_sn": device.get("devSn"),
        "dev_auth_type": device.get("devAuthType"),
        "user_auth_type": device.get("userAuthType"),
        "cpu_num": device.get("cpuNum"),
        "mem_size": device.get("memSize"),
        "device_type_name": device.get("DeviceTypeName"),
    }


def _extract_license(response_payload: dict[str, Any]) -> dict[str, Any]:
    info = response_payload.get("info")
    modules = response_payload.get("module")
    if not isinstance(info, dict):
        info = {}
    if not isinstance(modules, list):
        modules = []
    ips_module = next(
        (
            item
            for item in modules
            if isinstance(item, dict) and item.get("name") == IPS_MODULE_NAME
        ),
        None,
    )
    return {
        "license_info": info,
        "modules": modules,
        "ips_module": ips_module,
        "module_count": len(modules),
    }


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return LICENSE_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this license operation.",
            {"op_id": op_id},
        ) from exc
