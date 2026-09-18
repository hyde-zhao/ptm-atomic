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
from typing import Any, Mapping

from atomic_ops.repository import Repository
from atomic_ops.runner.errors import RunnerError
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
# 背景：停流被逆序回滚二次 stop 时设备返回 RESOURCE_NOT_FOUND，被 ERROR_TYPE_MAP
# 映射为 RUNNER_VALIDATION_FAILED；消费方只认 {"stream_not_found","not_found"} →
# 永不命中 → 非成功回滚一律归一为 CLEANUP_FAILED → cleanup_failed=True → exit 9
# 假阳性（现场 615 条记录中 cleanup_errors 非空 290 条，涉停流 242 条）。
# 本区域把「幂等停流」做成运行期机器可读的统一键：
#   消费方判定式 = details.error_type == "RESOURCE_NOT_FOUND"
#                  且 details.idempotent == true（双条件，缺一即按「非幂等」保守处理）
# 技术边界：不改 ERROR_TYPE_MAP（三类语义的区分归 R-F-REM-018）、
# 不改 EXIT_CODES、不新增 atom 顶层字段（schema `additionalProperties: false`）。
IDEMPOTENT_ERROR_TYPES: dict[str, frozenset[str]] = {
    "tg_stop_traffic_stream": frozenset({"RESOURCE_NOT_FOUND"}),
}

_IDEMPOTENT_DECL_FIELD = "idempotent"
_IDEMPOTENT_DECL_ERROR_FIELD = "error_types"
# 幂等成功语义的错误类型：atom `error_types` 含该值且 `idempotent: true` 时，
# 表达「目标流不存在 = 目标状态已达成」，不构成残留
_IDEMPOTENT_SUCCESS_ERROR_TYPE = "RESOURCE_NOT_FOUND"


def _idempotent_source_ref(op_id: str) -> str:
    """幂等标记的键来源（仓相对逻辑路径 + 声明字段），供消费方回溯契约声明位置。"""
    device = op_id.split("_", 1)[0]
    return f"atoms/{device}/{op_id}.yaml#{_IDEMPOTENT_DECL_FIELD}"


def idempotent_error_details(op_id: str, error_type: str) -> dict[str, Any]:
    """返回追加到 ``RunnerError.details`` 的幂等标记；未命中返回空 dict。

    命中条件（两者同时成立）：
      1. ``op_id`` 在 ``IDEMPOTENT_ERROR_TYPES`` 登记表中，且 ``error_type`` 属于其集合；
      2. 该 op 的 atom 声明 ``idempotent: true`` 成立 —— 由
         :func:`validate_idempotent_registry` 在契约层证明（测试 / 运维显式调用），
         **不在本热路径上重读本地 cache**（避免每次回滚都读一次 cache）。

    未命中返回 ``{}``：调用方的 ``details`` 与改动前**逐键一致**，非幂等 op 零影响。
    """
    declared = IDEMPOTENT_ERROR_TYPES.get(op_id)
    if not declared or error_type not in declared:
        return {}
    return {"idempotent": True, "idempotent_source": _idempotent_source_ref(op_id)}


def _declared_error_types(declaration: Mapping[str, Any]) -> set[str]:
    """从 atom 声明中取出 ``error_types`` 枚举（非列表形态视为空集，不猜）。"""
    raw = declaration.get(_IDEMPOTENT_DECL_ERROR_FIELD)
    if not isinstance(raw, (list, tuple, set, frozenset)):
        return set()
    return {item for item in raw if isinstance(item, str)}


def _registry_declaration_findings(op_id: str, declaration: Mapping[str, Any]) -> list[str]:
    """单个登记项 ↔ 其 atom 声明的一致性检查（正向）。"""
    findings: list[str] = []
    if declaration.get(_IDEMPOTENT_DECL_FIELD) is not True:
        findings.append(f"idempotent-not-declared:{op_id}")
    declared_types = _declared_error_types(declaration)
    for error_type in sorted(IDEMPOTENT_ERROR_TYPES[op_id] - declared_types):
        findings.append(f"undeclared-error-type:{op_id}:{error_type}")
    return findings


def _read_idempotent_declaration(op_id: str) -> tuple[Mapping[str, Any] | None, str]:
    """只读读取 op 的 atom 声明（本地 cache）。返回 ``(声明, 不可读原因)``。

    与 ``commands/run.py::_load_rollback_context`` 同款只读用法；任何不可读都归一为
    显式原因（不静默通过）。不触设备、不读凭据、不写任何状态。
    """
    try:
        document = Repository.from_default_cache().read_operation(op_id)
    except Exception as exc:  # noqa: BLE001 - 不可读必须转为显式不一致项（NFR-04 无静默）
        return None, exc.__class__.__name__
    data = document.data
    if not isinstance(data, Mapping):
        return None, "declaration-not-mapping"
    return data, ""


def validate_idempotent_registry(
    declarations: Mapping[str, Mapping[str, Any]] | None = None,
) -> list[str]:
    """幂等登记表 ↔ atom 声明一致性校验；返回不一致项列表（空列表 = 一致）。

    对每个登记 op 读 atom 声明：

    - 声明不可读 → ``decl-unavailable:<op_id>``（显式，不静默通过）
    - atom ``idempotent`` 必须为 ``true`` → 否则 ``idempotent-not-declared:<op_id>``
    - 登记集合必须 ⊆ atom ``error_types`` → 否则 ``undeclared-error-type:<op_id>:<type>``
    - 声明面内 ``idempotent: true`` 且 ``error_types`` 含
      ``RESOURCE_NOT_FOUND`` 却不在登记表 → ``missing-registration:<op_id>``（漏登记）

    ``declarations`` 为可选的**声明面注入**（契约矩阵 / 单测用，形如
    ``{op_id: atom_yaml_dict}``）；为 ``None`` 时对登记表中的每个 op 走本地 cache 只读。
    **反向检查（漏登记）只在声明面被显式注入时可用** —— 无注入时只覆盖登记表内 op
    （避免在守卫里全量枚举 cache）。本函数是**显式调用**（测试 / 运维），
    不在 runner 热路径上执行。
    """
    findings: list[str] = []

    for op_id in sorted(IDEMPOTENT_ERROR_TYPES):
        if declarations is not None:
            injected = declarations.get(op_id)
            if not isinstance(injected, Mapping):
                findings.append(f"decl-unavailable:{op_id}")
                continue
            declaration: Mapping[str, Any] = injected
        else:
            declaration, _reason = _read_idempotent_declaration(op_id)
            if declaration is None:
                findings.append(f"decl-unavailable:{op_id}")
                continue
        findings.extend(_registry_declaration_findings(op_id, declaration))

    # 反向检查（漏登记）：登记表缺项会让消费方读不到统一键 —— 属 03-06 的根因同类
    if declarations is not None:
        for op_id in sorted(declarations):
            if op_id in IDEMPOTENT_ERROR_TYPES:
                continue
            candidate = declarations[op_id]
            if not isinstance(candidate, Mapping):
                continue
            if candidate.get(_IDEMPOTENT_DECL_FIELD) is not True:
                continue
            if _IDEMPOTENT_SUCCESS_ERROR_TYPE in _declared_error_types(candidate):
                findings.append(f"missing-registration:{op_id}")

    return findings


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
        for optional in ("count", "frame_size", "vlan", "src_ip", "dst_ip", "src_mac", "dst_mac"):
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
    elif op_id in {"tg_start_traffic_stream", "tg_stop_traffic_stream", "tg_verify_traffic_loss"}:
        ports = _validate_ports_list(payload.get("ports"))
        payload["ports"] = ports
        _require_payload_str(payload, "txport")
        _require_payload_str(payload, "rxport")
        # 允许 txport==rxport（ICMP 应答回同一口；非 ICMP 由 trex-api 按模板协议拒绝）
        if payload["txport"] not in ports or payload["rxport"] not in ports:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "txport and rxport must both be included in ports.",
                {"ports": ports, "txport": payload["txport"], "rxport": payload["rxport"]},
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
