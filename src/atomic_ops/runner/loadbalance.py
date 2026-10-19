"""Runner for link load-balance policy atoms (链路负载分担, /api/v1/loadbalancepolicy).

设备 REST API(2026-08-27 实测):
- POST  /api/v1/loadbalancepolicy  创建: {"val": {"name","enable","mode","interfaces":[{"name"}]}}
- GET   /api/v1/loadbalancepolicy  查询
- DELETE /api/v1/loadbalancepolicy?id=<数字id>  删除
mode 枚举: 1=链路带宽, 2=链路权重, 4=链路主备备份
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.session import read_session_file

LB_URL = "/api/v1/loadbalancepolicy"
SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}
_MODE_LABELS = {1: "链路带宽", 2: "链路权重", 4: "链路主备备份"}


def _build_payload(
    *,
    name: str,
    enable: bool,
    mode: int,
    interfaces: list,
    session_hold: bool,
    overload_protection: bool,
    payload_file: str | None,
    payload_json: str | None,
) -> dict[str, Any]:
    """构造 loadbalancepolicy 创建 payload(手动构造,不依赖 load_json_payload 以简化)。"""
    if payload_json:
        import json
        return json.loads(payload_json)
    if payload_file:
        import json
        with open(payload_file, encoding="utf-8") as f:
            return json.load(f)
    if mode not in _MODE_LABELS:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"mode must be 1/2/4 ({_MODE_LABELS}), got {mode}.",
            {"mode": mode, "allowed": _MODE_LABELS},
        )
    if not isinstance(interfaces, list) or len(interfaces) < 2:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "interfaces must be a list with at least 2 entries.",
            {"interfaces": interfaces},
        )
    val: dict[str, Any] = {
        "name": name,
        "enable": bool(enable),
        "mode": int(mode),
        "interfaces": [
            {"name": it if isinstance(it, str) else it.get("name", "")}
            for it in interfaces
        ],
    }
    if session_hold:
        val["sessionHold"] = True
    if overload_protection:
        val["overloadProtection"] = True
    return {"val": val}


def _auth_headers(session_file: Path, auth_header: str) -> dict[str, str]:
    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    return {"Content-Type": "application/json", auth_header: header_value}


def build_link_loadbalance_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_config_link_loadbalance",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "POST",
            "url": base_url + LB_URL,
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_link_loadbalance(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    headers = _auth_headers(session_file, auth_header)
    status_code, response_payload, _text = request_json(
        "POST",
        base_url + LB_URL,
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "Link load-balance policy create request did not return a success status.",
            {
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    return {
        "op_id": "fw_config_link_loadbalance",
        "status": "success",
        "status_code": status_code,
        "request": {"method": "POST", "path": LB_URL, "auth": {"name": auth_header, "value": "<session-ref>"}},
        "response": response_payload,
    }
