"""TRex traffic generator runner for the trex-api HTTP service.

The trex-api service exposes a single dispatch endpoint
``POST /api/v1/ops/{op_id}`` for all six ``tg`` operations. Requests carry a
flat JSON payload (no ``{id, val}`` wrapping) and the response is an
``OperationEnvelope`` whose ``status`` / ``error_type`` fields decide success --
the HTTP status code stays 200 even when an operation fails. The service is
unauthenticated, so the runner sends no credential header and does not touch
the NGFW session file.
"""

from __future__ import annotations

import json
import re
from ipaddress import AddressValueError, ip_address
from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import (
    IDEMPOTENT_ERROR_TYPES,  # noqa: F401 - 再导出（既有导入面兼容）
    RunnerError,
    idempotent_error_details,
    validate_idempotent_registry,  # noqa: F401 - 再导出（既有导入面兼容）
)
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url


SUCCESS_STATUS = {200}
TEMPLATE_RE = re.compile(r"^[a-z0-9_-]+$")
RATE_RE = re.compile(r"^[1-9][0-9]*(pps|kbps|mbps|gbps)$", re.IGNORECASE)

TREX_STATEFUL_OPS = {
    "tg_config_stateful_interface",
    "tg_apply_stateful_template",
    "tg_start_stateful_stream",
    "tg_verify_stateful_metrics",
    "tg_stop_stateful_stream",
    "tg_delete_stateful_template",
}

TREX_OPS: dict[str, tuple[str, str]] = {
    op_id: ("POST", f"/api/v1/ops/{op_id}")
    for op_id in (
        "tg_acquire_ports",
        "tg_config_interface",
        "tg_apply_traffic_template",
        "tg_start_traffic_stream",
        "tg_verify_traffic_loss",
        "tg_stop_traffic_stream",
        "tg_delete_traffic_template",
        "tg_release_ports",
        "tg_query_port_status",
    )
}
# ownership 走独立 GET 端点，非 /api/v1/ops/{op_id} 调度
TREX_OPS["tg_verify_ownership"] = ("GET", "/api/v1/ownership")
# Stateful (ASTF) operations
TREX_OPS.update({
    op_id: ("POST", f"/api/v1/ops/{op_id}")
    for op_id in TREX_STATEFUL_OPS
})

# user_id 命名规范：default（兼容旧流程）或 dev<ip末段>-<序号>（如 dev172-1）
USER_ID_RE = re.compile(r"^(default|dev\d{1,3}-\d+)$")

# 这 6 个 op 在多用户占用模式下接受可选 user_id 并转发到 trex-api；
# acquire/release 的 user_id 是必填参数，由各自的 build/validate 分支单独处理
_USER_ID_FORWARD_OPS = {
    "tg_config_interface",
    "tg_apply_traffic_template",
    "tg_start_traffic_stream",
    "tg_verify_traffic_loss",
    "tg_stop_traffic_stream",
    "tg_delete_traffic_template",
    "tg_query_port_status",
}
# Stateful (ASTF) ops also forward user_id
_USER_ID_FORWARD_OPS.update(TREX_STATEFUL_OPS)

# trex-api OperationEnvelope.error_type -> (CLI runner error_code, retryable)
ERROR_TYPE_MAP: dict[str, tuple[str, bool]] = {
    "INVALID_PARAM": ("RUNNER_VALIDATION_FAILED", False),
    "RESOURCE_NOT_FOUND": ("RUNNER_VALIDATION_FAILED", False),
    "STATE_MISMATCH": ("RUNNER_VALIDATION_FAILED", False),
    "RESOURCE_CONFLICT": ("RUNNER_CONFIG_REJECTED", False),
    "INTERNAL_ERROR": ("RUNNER_RESPONSE_INVALID", False),
    "DEVICE_UNREACHABLE": ("RUNNER_DEVICE_UNREACHABLE", True),
    "TIMEOUT": ("RUNNER_DEVICE_UNREACHABLE", True),
}


# ── 幂等停流契约（CT-REM-ATOM-STOP v1.1；区域 #stop-stream-contract）──────────
# 2026-09-20：机制主体已迁至 ``runner/errors.py``（FW 删除族共用同一契约，登记表
# 见其 ``IDEMPOTENT_ERROR_TYPES`` 段）。本模块仅**再导出**，维持既有导入面
# （``tests/test_runner.py`` 从本模块导入 ``IDEMPOTENT_ERROR_TYPES`` /
# ``idempotent_error_details`` / ``validate_idempotent_registry``）零改动。
# 技术边界不变：不改 ``ERROR_TYPE_MAP``、不改 ``EXIT_CODES``、不新增 atom 顶层字段。
# 本模块 :615 的 ``details.update(idempotent_error_details(...))`` 调用点不变。

def load_trex_json_payload(*, payload_file: str | None, payload_json: str | None) -> dict[str, Any] | None:
    """Load an optional complete JSON payload supplied by the caller."""
    if payload_file and payload_json:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "--payload-file and --payload-json cannot be used together.",
            {"fields": ["payload_file", "payload_json"]},
        )
    if not payload_file and not payload_json:
        return None
    try:
        raw = Path(payload_file).read_text(encoding="utf-8") if payload_file else str(payload_json)
        payload = json.loads(raw)
    except OSError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "TRex payload file cannot be read.",
            {"path": payload_file, "reason": exc.__class__.__name__},
        ) from exc
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "TRex payload must be valid JSON.",
            {"reason": exc.msg},
        ) from exc
    if not isinstance(payload, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "TRex payload JSON root must be an object.",
            {"type": type(payload).__name__},
        )
    return payload


def build_trex_payload(op_id: str, params: dict[str, Any]) -> dict[str, Any]:
    """Build the flat trex-api request payload for ``op_id`` from CLI params."""
    if op_id == "tg_acquire_ports":
        ports = params.get("ports")
        if not isinstance(ports, list) or not ports:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "ports must be a non-empty list.",
                {"field": "ports"},
            )
        payload: dict[str, Any] = {"user_id": params.get("user_id"), "ports": ports}
    elif op_id == "tg_release_ports":
        payload = {"user_id": params.get("user_id")}
        ports = params.get("ports")
        if ports:
            payload["ports"] = ports
    elif op_id == "tg_config_interface":
        interfaces = params.get("interfaces")
        if not isinstance(interfaces, list) or not interfaces:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "interfaces must be a non-empty list.",
                {"field": "interfaces"},
            )
        payload: dict[str, Any] = {"interfaces": interfaces}
    elif op_id == "tg_apply_traffic_template":
        # 2026-09-23：这 6 个字段原先靠 argparse required=True 保证；但用例直传
        # --payload-json/--payload-file 时 `_run_trex` 走 payload 分支、根本不到这里，
        # 而 argparse 仍强制要求它们 -> 逃生口不可用（真机 exit=2 usage）。现改为
        # CLI 侧 required=False，**无 payload 路径**由本函数校验，与
        # `fw_update_timeobject` 的 "Required unless --payload-json/--payload-file
        # is given" 语义一致。
        for required_field in ("template", "tx_port", "rx_port", "l4_protocol", "traffic_mode", "rate"):
            if params.get(required_field) in (None, ""):
                raise RunnerError(
                    "RUNNER_VALIDATION_FAILED",
                    f"{required_field} is required unless --payload-json/--payload-file is given.",
                    {"field": required_field},
                )
        payload = {
            "template": params.get("template"),
            "tx_port": params.get("tx_port"),
            "rx_port": params.get("rx_port"),
            "ip_version": params.get("ip_version") or "ipv4",
            "l4_protocol": params.get("l4_protocol"),
            "l4_sport": params.get("l4_sport"),
            "l4_dport": params.get("l4_dport"),
            "traffic_mode": params.get("traffic_mode"),
            "rate": params.get("rate"),
        }
        for optional in ("count", "stream_count", "frame_size", "vlan", "src_ip", "dst_ip", "src_mac", "dst_mac"):
            value = params.get(optional)
            if value is not None:
                payload[optional] = value
    elif op_id in {"tg_start_traffic_stream", "tg_stop_traffic_stream", "tg_verify_traffic_loss"}:
        payload = {
            "ports": params.get("ports"),
            "txport": params.get("txport"),
            "rxport": params.get("rxport"),
            "name": params.get("name"),
        }
        if op_id == "tg_start_traffic_stream":
            payload["template"] = params.get("template")
        if op_id == "tg_verify_traffic_loss":
            payload["max_loss"] = params.get("max_loss")
            for optional in ("expect_ports", "tolerance"):
                value = params.get(optional)
                if value is not None:
                    payload[optional] = value
    elif op_id == "tg_delete_traffic_template":
        payload = {"template": params.get("template")}
    elif op_id == "tg_apply_stateful_template":
        payload = {
            "template": params.get("template"),
        }
        tunables = params.get("tunables")
        if tunables is not None:
            payload["tunables"] = tunables
    elif op_id == "tg_config_stateful_interface":
        interfaces = params.get("interfaces")
        if not isinstance(interfaces, list) or not interfaces:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "interfaces must be a non-empty list.",
                {"field": "interfaces"},
            )
        payload: dict[str, Any] = {"interfaces": interfaces}
    elif op_id == "tg_start_stateful_stream":
        payload = {
            "mult": params.get("mult", 1),
            "duration": params.get("duration", -1),
        }
    elif op_id == "tg_verify_stateful_metrics":
        payload = {}
        max_loss = params.get("max_loss")
        if max_loss is not None:
            payload["max_loss"] = max_loss
    elif op_id == "tg_stop_stateful_stream":
        payload = {}
    elif op_id == "tg_delete_stateful_template":
        payload = {}
    elif op_id == "tg_verify_ownership":
        # GET 查询无请求体
        payload: dict[str, Any] = {}
    elif op_id == "tg_query_port_status":
        # 只读诊断查询：ports 可选（缺省=全部），user_id 仅选池内 client
        payload = {}
        ports = params.get("ports")
        if ports:
            payload["ports"] = ports
    else:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this TRex operation.",
            {"op_id": op_id, "supported_ops": list(TREX_OPS)},
        )
    # 多用户占用模式：非 default 的 user_id 转发到 trex-api（default/省略走旧 force 模式）
    if op_id in _USER_ID_FORWARD_OPS:
        user_id = params.get("user_id")
        if user_id is not None and user_id != "default":
            payload["user_id"] = user_id
    return validate_trex_payload(op_id, payload)


def validate_trex_payload(op_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Validate the trex-api payload against the operation contract locally."""
    if op_id == "tg_acquire_ports":
        _validate_user_id(payload.get("user_id"))
        ports = payload.get("ports")
        if not isinstance(ports, list) or not ports:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "ports must be a non-empty list of logical port names.",
                {"field": "ports"},
            )
    elif op_id == "tg_release_ports":
        _validate_user_id(payload.get("user_id"))
        ports = payload.get("ports")
        if ports is not None and (not isinstance(ports, list) or not ports):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "ports must be a non-empty list or omitted to release all.",
                {"field": "ports"},
            )
    elif op_id == "tg_config_interface":
        _validate_interfaces(payload.get("interfaces"))
    elif op_id == "tg_apply_traffic_template":
        _validate_template_name(payload.get("template"), field="template")
        _require_payload_str(payload, "tx_port")
        _require_payload_str(payload, "rx_port")
        ip_version = payload.get("ip_version", "ipv4")
        if ip_version not in ("ipv4", "ipv6"):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "ip_version must be ipv4 or ipv6.",
                {"field": "ip_version", "actual": ip_version},
            )
        l4_proto = payload.get("l4_protocol")
        if l4_proto not in ("tcp", "udp", "icmp"):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "l4_protocol must be tcp, udp or icmp.",
                {"field": "l4_protocol", "actual": l4_proto},
            )
        if l4_proto in ("tcp", "udp"):
            payload["l4_sport"] = _validate_port_int("l4_sport", payload.get("l4_sport"))
            payload["l4_dport"] = _validate_port_int("l4_dport", payload.get("l4_dport"))
        else:
            # ICMP 无端口
            payload["l4_sport"] = None
            payload["l4_dport"] = None
        traffic_mode = payload.get("traffic_mode")
        if traffic_mode not in ("count", "continuous"):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "traffic_mode must be count or continuous.",
                {"field": "traffic_mode", "actual": traffic_mode},
            )
        rate = payload.get("rate")
        if not isinstance(rate, str) or not RATE_RE.fullmatch(rate):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "rate must use TRex-style units such as 100pps or 10mbps.",
                {"field": "rate", "actual": rate},
            )
        if traffic_mode == "count":
            count = payload.get("count")
            if count is None:
                if payload.get("l4_protocol") == "icmp":
                    # ICMP 默认 5 个报文（与 ping 一致），可用 --count 覆盖
                    count = 5
                else:
                    raise RunnerError(
                        "RUNNER_VALIDATION_FAILED",
                        "count is required when traffic_mode=count.",
                        {"field": "count"},
                    )
            payload["count"] = _validate_positive_int("count", count)
        elif payload.get("count") is not None:
            payload["count"] = _validate_positive_int("count", payload["count"])
        if payload.get("frame_size") is not None:
            payload["frame_size"] = _validate_min_int("frame_size", payload["frame_size"], minimum=64)
        _validate_ip_pair(ip_version, payload.get("src_ip"), payload.get("dst_ip"))
        # 多流（stream_count，2026-09-22 分口观测）：l4_sport 是**起始**端口，
        # 展开成 N 条源端口连续的五元组；count 仍是**总包数**。
        # 口径与 trex-api schema 一致：ICMP 无 L4 端口可变化 -> 任何非空
        # stream_count 都拒绝（服务端同口径）；tcp/udp 的起始端口已由上方分支
        # 强制必填（l4_sport 缺失在本地即被拒），故服务端那条「stream_count 有值
        # 而 l4_sport 为 None -> 多流静默退化为单流」的形态在本地不可达。
        stream_count = payload.get("stream_count")
        if stream_count is not None:
            if l4_proto == "icmp":
                raise RunnerError(
                    "RUNNER_VALIDATION_FAILED",
                    "stream_count is not valid for icmp (no L4 ports to vary).",
                    {"field": "stream_count", "l4_protocol": l4_proto},
                )
            stream_count = _validate_positive_int("stream_count", stream_count)
            # 资源守卫（非协议约束）：单模板展开的流数上限。2026-09-23 由 1000 提到
            # 10000 —— 用户需按 10000 个端口构造大规模多流（端口空间本身由下方
            # l4_sport/l4_dport 越界检查兜底，与本上限是两回事）。服务端 trex-api
            # schemas.py 的 le 必须同步放开，否则请求在服务端 422。
            if stream_count > 10000:
                raise RunnerError(
                    "RUNNER_VALIDATION_FAILED",
                    "stream_count must not exceed 10000.",
                    {"field": "stream_count", "actual": stream_count},
                )
            if payload["l4_sport"] + stream_count - 1 > 65535:
                raise RunnerError(
                    "RUNNER_VALIDATION_FAILED",
                    "l4_sport + stream_count - 1 must not exceed 65535.",
                    {
                        "field": "stream_count",
                        "l4_sport": payload["l4_sport"],
                        "stream_count": stream_count,
                    },
                )
            payload["stream_count"] = stream_count
    elif op_id in {"tg_start_traffic_stream", "tg_stop_traffic_stream", "tg_verify_traffic_loss"}:
        ports = _validate_ports_list(payload.get("ports"))
        payload["ports"] = ports
        _require_payload_str(payload, "txport")
        rxports = _validate_rxport(payload.get("rxport"), ports)
        # 允许 txport==rxport（ICMP 应答回同一口；非 ICMP 由 trex-api 按模板协议拒绝）
        if payload["txport"] not in ports:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "txport must be included in ports.",
                {"ports": ports, "txport": payload["txport"]},
            )
        _require_payload_str(payload, "name")
        if op_id == "tg_start_traffic_stream":
            _validate_template_name(payload.get("template"), field="template")
        if op_id == "tg_verify_traffic_loss":
            max_loss = payload.get("max_loss")
            if not isinstance(max_loss, (int, float)) or isinstance(max_loss, bool) or max_loss < 0:
                raise RunnerError(
                    "RUNNER_VALIDATION_FAILED",
                    "max_loss must be a non-negative number.",
                    {"field": "max_loss", "actual": max_loss},
                )
            payload["max_loss"] = float(max_loss)
            if payload.get("expect_ports") is not None:
                _validate_expect_ports(payload["expect_ports"], rxports)
            tolerance = payload.get("tolerance")
            if tolerance is not None:
                if (
                    not isinstance(tolerance, (int, float))
                    or isinstance(tolerance, bool)
                    or not 0 <= tolerance <= 100
                ):
                    raise RunnerError(
                        "RUNNER_VALIDATION_FAILED",
                        "tolerance must be a number between 0 and 100.",
                        {"field": "tolerance", "actual": tolerance},
                    )
                payload["tolerance"] = float(tolerance)
    elif op_id == "tg_delete_traffic_template":
        _validate_template_name(payload.get("template"), field="template")
    elif op_id == "tg_apply_stateful_template":
        _validate_template_name(payload.get("template"), field="template")
    elif op_id == "tg_config_stateful_interface":
        interfaces = payload.get("interfaces")
        if not isinstance(interfaces, list) or not interfaces:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "interfaces must be a non-empty list.",
                {"field": "interfaces"},
            )
    elif op_id == "tg_start_stateful_stream":
        mult = payload.get("mult", 1)
        if not isinstance(mult, int) or mult < 1:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "mult must be a positive integer.",
                {"field": "mult"},
            )
        duration = payload.get("duration", -1)
        if not isinstance(duration, int) or (duration != -1 and duration <= 0):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "duration must be -1 (continuous) or a positive integer.",
                {"field": "duration"},
            )
    elif op_id in {"tg_verify_stateful_metrics", "tg_stop_stateful_stream", "tg_delete_stateful_template"}:
        pass  # no required fields beyond optional user_id
    elif op_id == "tg_verify_ownership":
        # GET 查询无请求体，无需校验
        pass
    elif op_id == "tg_query_port_status":
        ports = payload.get("ports")
        if ports is not None and (not isinstance(ports, list) or not ports):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "ports must be a non-empty list or omitted to query all.",
                {"field": "ports"},
            )
    else:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this TRex operation.",
            {"op_id": op_id, "supported_ops": list(TREX_OPS)},
        )
    # 转发的 user_id 校验命名规范（覆盖 CLI 传参与 --payload-json 两种入口）
    if op_id in _USER_ID_FORWARD_OPS and "user_id" in payload:
        _validate_user_id(payload["user_id"])
    return payload


def build_trex_dry_run(
    *,
    op_id: str,
    base_url: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, _path = _method_path(op_id)
    return {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(base_url, op_id),
            "auth": {"name": "(none)", "value": "<trex-no-auth>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_trex(
    *,
    op_id: str,
    base_url: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    if method == "GET":
        # ownership 查询：GET 端点，无请求体，响应是裸 {count, ownerships} 对象非 OperationEnvelope
        status_code, response_payload, _text = request_json(
            "GET",
            _request_url(base_url, op_id),
            headers=None,
            json_payload=None,
            timeout=timeout,
            verify_tls=verify_tls,
        )
        if status_code not in SUCCESS_STATUS:
            raise RunnerError(
                "RUNNER_RESPONSE_INVALID",
                "TRex trex-api ownership query did not return a success HTTP status.",
                {
                    "op_id": op_id,
                    "status_code": status_code,
                    "response_keys": sorted(response_payload.keys()),
                },
            )
        return {
            "op_id": op_id,
            "status": "success",
            "status_code": status_code,
            "request": {"method": "GET", "path": path, "auth": {"name": "(none)"}},
            "response": response_payload,
        }
    headers = {"Content-Type": "application/json"}
    status_code, response_payload, _text = request_json(
        method,
        _request_url(base_url, op_id),
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "TRex trex-api request did not return a success HTTP status.",
            {
                "op_id": op_id,
                "status_code": status_code,
                "response_keys": sorted(response_payload.keys()),
            },
        )
    envelope_status = str(response_payload.get("status") or "")
    if envelope_status == "success":
        return {
            "op_id": op_id,
            "status": "success",
            "status_code": status_code,
            "request": {"method": method, "path": path, "auth": {"name": "(none)"}},
            "response": response_payload.get("data") or {},
        }
    error_type = str(response_payload.get("error_type") or "INTERNAL_ERROR")
    error_code, retryable = ERROR_TYPE_MAP.get(error_type, ("RUNNER_RESPONSE_INVALID", False))
    details: dict[str, Any] = {
        "op_id": op_id,
        "envelope_status": envelope_status or "unknown",
        "error_type": error_type,
        "data": response_payload.get("data") or {},
        "diag_snapshot_ref": response_payload.get("diag_snapshot_ref") or "",
    }
    # 幂等停流统一键（CT-REM-ATOM-STOP v1.1）：命中登记表才追加；未命中 details 逐键不变
    details.update(idempotent_error_details(op_id, error_type))
    raise RunnerError(
        error_code,
        f"TRex trex-api operation {op_id} failed with error_type {error_type}.",
        details,
        retryable=retryable,
    )


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return TREX_OPS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this TRex operation.",
            {"op_id": op_id, "supported_ops": list(TREX_OPS)},
        ) from exc


def _request_url(base_url: str, op_id: str) -> str:
    """Build the full trex-api URL.

    When the TREX_API_URL environment variable is set it takes precedence over
    ``base_url`` so that TG operations can target a different host than the
    NGFW management address supplied via ``--base-url``.
    """
    import os as _os
    tg_url = _os.environ.get("TREX_API_URL", "")
    if tg_url:
        _, path = _method_path(op_id)
        return f"{tg_url.rstrip('/')}{path}"
    _method, path = _method_path(op_id)
    return f"{normalize_base_url(base_url)}{path}"


def _validate_user_id(value: Any) -> str:
    """校验 user_id 命名规范：default 或 dev<ip末段>-<序号>。"""
    if not isinstance(value, str) or not value:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "user_id is required.",
            {"field": "user_id"},
        )
    if not USER_ID_RE.fullmatch(value):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "user_id must be 'default' or match 'dev<ip-suffix>-<seq>' (e.g. dev172-1).",
            {"field": "user_id", "actual": value},
        )
    return value


def _validate_interfaces(interfaces: Any) -> None:
    if not isinstance(interfaces, list) or not interfaces:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "interfaces must be a non-empty list.",
            {"field": "interfaces"},
        )
    for index, item in enumerate(interfaces):
        if not isinstance(item, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each interface entry must be an object.",
                {"field": "interfaces", "index": index},
            )
        for required in ("port", "ip", "gateway"):
            value = item.get(required)
            if not isinstance(value, str) or not value.strip():
                raise RunnerError(
                    "RUNNER_VALIDATION_FAILED",
                    f"Interface entry is missing required field {required}.",
                    {"field": f"interfaces[{index}].{required}"},
                )
        try:
            ip_version = ip_address(item["ip"]).version
            gateway_version = ip_address(item["gateway"]).version
        except (AddressValueError, ValueError) as exc:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Interface ip or gateway is not a valid IP address.",
                {"field": f"interfaces[{index}]", "ip": item.get("ip"), "gateway": item.get("gateway")},
            ) from exc
        if ip_version != gateway_version:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Interface ip and gateway must use the same IP version.",
                {"field": f"interfaces[{index}]", "ip": item["ip"], "gateway": item["gateway"]},
            )


def _validate_template_name(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not TEMPLATE_RE.fullmatch(value):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must match ^[a-z0-9_-]+$.",
            {"field": field, "actual": value},
        )
    return value


def _validate_ports_list(value: Any) -> list[str]:
    if not isinstance(value, list) or not value:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "ports must be a non-empty list.",
            {"field": "ports"},
        )
    ports: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each port entry must be a non-empty string.",
                {"field": "ports", "actual": item},
            )
        ports.append(item)
    return ports


def _validate_rxport(value: Any, ports: list[str]) -> list[str]:
    """归一并校验 rxport：单值字符串或字符串列表，每一项都须在 ports 内。

    多口 = 分口观测（一次抓包覆盖全部 rx 口，回包按 port_id 分口计数）。
    单值是原形态，请求体形状不变；返回**归一的列表**仅供本地成员检查使用，
    payload 里的原形态不动（由 trex-api schema 归一）。
    """
    if isinstance(value, str):
        rxports = [value] if value.strip() else []
    elif isinstance(value, list) and all(isinstance(item, str) and item.strip() for item in value):
        rxports = list(value)
    else:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "rxport must be a port id or a non-empty list of port ids.",
            {"field": "rxport", "actual": value},
        )
    if not rxports:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "rxport must contain at least one port id.",
            {"field": "rxport", "actual": value},
        )
    missing = [port for port in rxports if port not in ports]
    if missing:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "rxport must be included in ports.",
            {"field": "rxport", "ports": ports, "rxport": value, "missing": missing},
        )
    return rxports


def _validate_expect_ports(value: Any, rxports: list[str]) -> None:
    """本地预校验分口期望分布：形状、端口归属、占比之和。

    与 trex-api schema 同口径 —— 这里先拦是为了让用法错误在 dry-run 静态门
    就暴露（错误信息落在用例侧，而不是等 TG 回一个 INVALID_PARAM）。
    占比之和只允许 100（按比例分布）或 0（要求各口都收不到包）。
    """
    if not isinstance(value, list) or not value:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "expect_ports must be a non-empty list of {port, ratio} objects.",
            {"field": "expect_ports", "actual": value},
        )
    seen: set[str] = set()
    total = 0.0
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "expect_ports entries must be objects with port and ratio.",
                {"field": "expect_ports", "index": index, "actual": item},
            )
        port = item.get("port")
        if not isinstance(port, str) or not port.strip():
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "expect_ports entry requires a port id.",
                {"field": "expect_ports", "index": index, "actual": item},
            )
        if port not in rxports:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "expect_ports port must be one of rxport.",
                {"field": "expect_ports", "index": index, "port": port, "rxport": rxports},
            )
        if port in seen:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "expect_ports must not repeat a port.",
                {"field": "expect_ports", "index": index, "port": port},
            )
        seen.add(port)
        ratio = item.get("ratio")
        if (
            not isinstance(ratio, (int, float))
            or isinstance(ratio, bool)
            or not 0 <= ratio <= 100
        ):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "expect_ports ratio must be a number between 0 and 100.",
                {"field": "expect_ports", "index": index, "ratio": ratio},
            )
        total += float(ratio)
    if abs(total - 100.0) > 1e-6 and abs(total) > 1e-6:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "expect_ports ratio sum must be 100 (ratio split) or 0 (no traffic).",
            {"field": "expect_ports", "total_ratio": total},
        )


def _validate_port_int(field: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                f"{field} must be an integer port number.",
                {"field": field, "actual": value},
            ) from exc
    if value < 0 or value > 65535:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must be between 0 and 65535.",
            {"field": field, "actual": value},
        )
    return value


def _validate_positive_int(field: str, value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                f"{field} must be a positive integer.",
                {"field": field, "actual": value},
            ) from exc
    if value <= 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must be a positive integer.",
            {"field": field, "actual": value},
        )
    return value


def _validate_min_int(field: str, value: Any, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                f"{field} must be an integer.",
                {"field": field, "actual": value},
            ) from exc
    if value < minimum:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must be >= {minimum}.",
            {"field": field, "actual": value, "minimum": minimum},
        )
    return value


def _validate_ip_pair(ip_version: str, src_ip: Any, dst_ip: Any) -> None:
    expected = 6 if ip_version == "ipv6" else 4
    src_present = src_ip is not None
    dst_present = dst_ip is not None
    if src_present and dst_present:
        try:
            src_version = ip_address(src_ip).version
            dst_version = ip_address(dst_ip).version
        except (AddressValueError, ValueError) as exc:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "src_ip or dst_ip is not a valid IP address.",
                {"src_ip": src_ip, "dst_ip": dst_ip},
            ) from exc
        if src_version != dst_version:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "src_ip and dst_ip must use the same IP version.",
                {"src_ip": src_ip, "dst_ip": dst_ip},
            )
        if src_version != expected:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "src_ip and dst_ip do not match ip_version.",
                {"ip_version": ip_version, "src_ip": src_ip, "dst_ip": dst_ip},
            )
    elif ip_version == "ipv6":
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPv6 traffic requires both src_ip and dst_ip.",
            {"ip_version": ip_version},
        )
    elif src_present or dst_present:
        address = src_ip if src_present else dst_ip
        try:
            actual = ip_address(address).version
        except (AddressValueError, ValueError) as exc:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "src_ip or dst_ip is not a valid IP address.",
                {"address": address},
            ) from exc
        if actual != expected:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "src_ip or dst_ip does not match ip_version.",
                {"ip_version": ip_version, "address": address},
            )


def _require_payload_str(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"Required field {key} is missing or empty.",
            {"field": key},
        )
    return value
