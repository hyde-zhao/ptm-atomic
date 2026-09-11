"""NGFW reboot runner for /api/v1/reboot.

A reboot is a terminal destructive action: the device tears down the
management session and becomes unreachable for several minutes. The runner
treats any 2xx response as success and never issues follow-up requests, so
the expected post-reboot disconnect is not misread as ``DEVICE_UNREACHABLE``.
If the connection drops before a response is received, the caller must decide
whether the reboot was already in flight.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


REBOOT_PATH = "/api/v1/reboot"
SUCCESS_STATUS = {200, 201, 202}
DEFAULT_EXPECTED_UNAVAILABLE_SECONDS = 300


def build_reboot_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    expected_unavailable_seconds: int,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_config_reboot",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": f"{normalize_base_url(base_url)}{REBOOT_PATH}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "expected_unavailable_seconds": expected_unavailable_seconds,
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_reboot(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    expected_unavailable_seconds: int,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {auth_header: header_value}
    url = f"{normalize_base_url(base_url)}{REBOOT_PATH}"

    # reboot 返回 JSON；若设备在响应前就断连，request_json 会抛 DEVICE_UNREACHABLE。
    # 此时无法确认 reboot 是否已发起，交给调用方判断（retryable=True 便于重试确认）。
    try:
        status_code, response, _text = request_json(
            "GET", url, headers=headers, json_payload=None, timeout=timeout, verify_tls=verify_tls,
        )
    except RunnerError as exc:
        # 断连可能发生在 reboot 已触发后；标记为 initiated-unknown 让调用方后续 verify 确认。
        if exc.error_code == "RUNNER_DEVICE_UNREACHABLE":
            return {
                "op_id": "fw_config_reboot",
                "status": "success",
                "reboot_initiated": True,
                "initiated_state": "unknown_disconnected",
                "session_invalidated": True,
                "expected_unavailable_seconds": expected_unavailable_seconds,
                "request": {"method": "GET", "path": REBOOT_PATH, "auth": {"name": auth_header, "value": "<session-ref>"}},
                "response": {"status_code": None, "disconnected_before_response": True},
            }
        raise

    if status_code not in SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response)
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "Reboot request did not return a success status.",
            {
                "op_id": "fw_config_reboot",
                "status_code": status_code,
                "err_code": response.get("errCode"),
                "err_msg": response.get("errMsg") or response.get("message"),
            },
        )

    # 成功收到 2xx 即视为 reboot 已发起；不再发任何后续请求，避免误判断连。
    return {
        "op_id": "fw_config_reboot",
        "status": "success",
        "reboot_initiated": True,
        "session_invalidated": True,
        "expected_unavailable_seconds": expected_unavailable_seconds,
        "request": {"method": "GET", "path": REBOOT_PATH, "auth": {"name": auth_header, "value": "<session-ref>"}},
        "response": {"status_code": status_code, "msg": response.get("msg")},
    }
