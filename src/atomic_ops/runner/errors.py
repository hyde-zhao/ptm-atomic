"""Runner-specific error helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

from atomic_ops.repository import ERROR_RUNNER_CONFIG_REJECTED, Repository


@dataclass(frozen=True)
class RunnerError(Exception):
    """A runner failure with a stable top-level CLI error code."""

    error_code: str
    message: str
    details: dict[str, Any]
    retryable: bool = False
    suggestion: str | None = None

    def __str__(self) -> str:
        return self.message


# ── 凭据缺失与认证失败分层（STORY-S6-02）─────────────────────
# 事故背景：`source .env` 未 export 时凭据环境变量不会进入子进程，此前报错只写
# "credential environment variable is not set"，与口令错/会话失效（AUTH_FAILED 语义）
# 混在一起，执行方无法定位。分层口径：
# - 凭据缺失（环境变量未注入/为空）-> RUNNER_CREDENTIAL_MISSING（exit 43），
#   消息点名环境变量并附注入指引，凭据从未到达认证环节；
# - 认证失败（口令错/凭据被拒）-> RUNNER_LOGIN_FAILED（exit 44）；
# - 会话失效（token/会话状态）-> RUNNER_SESSION_INVALID（exit 45，本模块不改其语义）。
# 文案安全口径（重要）：错误输出层（atomic_ops/errors.py SENSITIVE_LINE_PATTERN）
# 会把包含独立词 password/passwd/pwd/secret/token/authorization/header 的整行替换为
# [REDACTED]。因此本层文案禁止出现上述独立词；环境变量名用下划线形式（如
# FW_WEB_PASSWORD）不会被词边界命中，可安全输出；绝不回显凭据值。
CREDENTIAL_INJECTION_HINT = (
    "Inject the credential into the environment before running, e.g. "
    "`set -a; source .env; set +a` (exports every KEY=VALUE line of .env in the "
    "working directory), then rerun. Never print or log the credential value."
)


def credential_missing_error(env_name: str, *, field_name: str | None = None) -> RunnerError:
    """构造"凭据环境变量未注入/为空"错误（RUNNER_CREDENTIAL_MISSING）。

    消息点名缺失的环境变量并附注入指引；details 只携带变量名/参数字段名，
    不携带任何凭据值（NO_CREDENTIAL_READ）。
    """
    details: dict[str, Any] = {"env": env_name}
    if field_name:
        details["missing"] = field_name
    return RunnerError(
        "RUNNER_CREDENTIAL_MISSING",
        f"Credential environment variable {env_name} is not set or is empty "
        "in the runner process (credential not injected).",
        details,
        suggestion=CREDENTIAL_INJECTION_HINT,
    )


# ── 设备侧会话失效归类（CR-059 多 DUT 配置下发）──────────────
# 背景：设备侧 web 会话过期/失效时，HTTP 401/403 或响应体携带会话失效特征码，
# 此前在各 runner 的非成功状态分支里散落映射为 RUNNER_CONFIG_REJECTED /
# RUNNER_RESPONSE_INVALID，调用方（ptm-te 等）的自动重连逻辑无法命中。
# 统一口径：
# - HTTP 401/403 -> RUNNER_SESSION_INVALID；
# - 响应体（errCode/errMsg 等任意字段）包含会话失效特征串 -> RUNNER_SESSION_INVALID；
# - 其余状态码与业务错误（如 400 + 业务 errCode）保持既有 error_type 不变。
# 边界：登录路径（ngfw_login）的 401/403 语义保持 RUNNER_LOGIN_FAILED
# （STORY-S6-02 分层），不接入本判定；SSH/TGFW-CLI 的 STATE_MISMATCH 是
# shell 输出断言失败，与会话失效无关，同样不接入。
# 文案安全口径：message/details/suggestion 不得出现独立词 password/passwd/
# pwd/secret/token/authorization/header（输出层会整行 REDACT）。
DEVICE_SESSION_EXPIRY_MARKERS = ("eTokenCheck", "eTokenParse", "Expire check failed")

SESSION_REJECTION_STATUS_CODES = frozenset({401, 403})


def is_device_session_rejection(status_code: int, response_payload: Any = None) -> bool:
    """判定设备响应是否为会话失效（HTTP 401/403 或响应体携带失效特征串）。

    ``response_payload`` 为设备返回的 JSON 对象；序列化后做子串匹配，
    避免只盯单一字段而漏掉 errMsg 携带特征的情况。业务错误（400 + 业务
    errCode）不含特征串，不会被误判。
    """
    if status_code in SESSION_REJECTION_STATUS_CODES:
        return True
    if isinstance(response_payload, dict) and response_payload:
        try:
            blob = json.dumps(response_payload, ensure_ascii=False, default=str)
        except (TypeError, ValueError):
            return False
        return any(marker in blob for marker in DEVICE_SESSION_EXPIRY_MARKERS)
    return False


def device_session_rejection_error(
    status_code: int,
    response_payload: Any = None,
    *,
    op_id: str | None = None,
) -> RunnerError:
    """构造设备侧会话失效错误（RUNNER_SESSION_INVALID）。

    details 携带 status_code 与设备 errCode/errMsg（与既有 RUNNER_CONFIG_REJECTED
    的输出字段保持一致，不回显凭据）。
    """
    err_code = response_payload.get("errCode") if isinstance(response_payload, dict) else None
    err_msg = (
        (response_payload.get("errMsg") or response_payload.get("message"))
        if isinstance(response_payload, dict)
        else None
    )
    details: dict[str, Any] = {
        "status_code": status_code,
        "err_code": err_code,
        "err_msg": err_msg,
    }
    if op_id:
        details["op_id"] = op_id
    return RunnerError(
        "RUNNER_SESSION_INVALID",
        "Device request was rejected because the web session is invalid or expired.",
        details,
        suggestion=(
            "Re-run ptm-atomic run auth login --execute for this base_url to obtain "
            "a fresh session, then retry the operation."
        ),
    )


def raise_if_device_session_rejected(
    status_code: int,
    response_payload: Any = None,
    *,
    op_id: str | None = None,
) -> None:
    """会话失效时抛出 RUNNER_SESSION_INVALID，否则原样返回（供各 runner 复用）。

    用法：各 runner 非成功状态分支在既有 raise RunnerError(...) 之前调用；
    未命中时流程照旧走原有 error_type，既有映射不变。
    """
    if is_device_session_rejection(status_code, response_payload):
        raise device_session_rejection_error(status_code, response_payload, op_id=op_id)


# ── 幂等「目标状态已达成」契约（CT-REM-ATOM-STOP v1.1 / CT-REM-ATOM-DELETE）──
# 背景：停流被逆序回滚二次 stop 时设备返回 RESOURCE_NOT_FOUND，被 ERROR_TYPE_MAP
# 映射为 RUNNER_VALIDATION_FAILED；消费方只认 {"stream_not_found","not_found"} →
# 永不命中 → 非成功回滚一律归一为 CLEANUP_FAILED → cleanup_failed=True → exit 9
# 假阳性（现场 615 条记录中 cleanup_errors 非空 290 条，涉停流 242 条）。
# 2026-09-20 起本表同时承载 FW 删除族的「对象不存在」（见下方
# RESOURCE_NOT_FOUND_ERR_CODES 段），两张契约同构。
# 本表把「幂等成功」做成运行期机器可读的统一键：
#   消费方判定式 = details.error_type == "RESOURCE_NOT_FOUND"
#                  且 details.idempotent == true（双条件，缺一即按「非幂等」保守处理）
# 技术边界：不改 ERROR_TYPE_MAP（三类语义的区分归 R-F-REM-018）、
# 不改 EXIT_CODES、不新增 atom 顶层字段（schema `additionalProperties: false`）。
# 2026-09-20 自 trex.py 迁出到本模块（FW 族也要用；trex.py 再导出保持兼容）。
IDEMPOTENT_ERROR_TYPES: dict[str, frozenset[str]] = {
    "tg_stop_traffic_stream": frozenset({"RESOURCE_NOT_FOUND"}),
    # FW 删除族：创建步回滚与用例清理步重复删除同一对象时设备报「不存在」
    # （2026-09-20 实测三类 err_code，见 RESOURCE_NOT_FOUND_ERR_CODES 段）
    "fw_delete_policy_route": frozenset({"RESOURCE_NOT_FOUND"}),
    "fw_delete_object": frozenset({"RESOURCE_NOT_FOUND"}),
    "fw_delete_timeobject": frozenset({"RESOURCE_NOT_FOUND"}),
    # NAT 删除族（2026-09-21 实测）：设备原文 400 eRequestParam
    # 「Couldn't found 1 from DB」——与策略路由/对象删除同构（见下方
    # RESOURCE_NOT_FOUND_ERR_CODES 段）；此前 nat.py 未接入归一，回滚恒报
    # CLEANUP_FAILED 假阳性（策略配置 run-20260921-174814 实测 4 条）。
    "fw_delete_nat_snat": frozenset({"RESOURCE_NOT_FOUND"}),
    "fw_delete_nat_dnat": frozenset({"RESOURCE_NOT_FOUND"}),
    # 修改类（2026-09-21 实测）：回滚 restore_snapshot 恢复配置时对象已不存在
    # （400 ePolicyRouteIdNotExist「修改ipv4策略路由N失败，策略路由不存在」）——
    # 对象既已不在，无物可恢复即无需恢复，不构成残留。执行期负例不受影响：
    # 运行时代码仍为 RUNNER_CONFIG_REJECTED（exit 48），仅 details 增幂等键。
    "fw_update_policy_route": frozenset({"RESOURCE_NOT_FOUND"}),
    # 接口删除族（2026-09-21 实测补）：用例清理步删自己创建的子接口时，该接口
    # 已被创建步回滚删除，设备答 400 eIntfGetTypeByName「unknow interface GE0_3.100」
    # —— 接口不存在即目标状态已达成，不构成残留。此前 interface.py 未接入归一，
    # 致 fw_delete_interface 的回滚恒报 CLEANUP_FAILED 假阳性（策略配置
    # run-20260921-190022 实测 3 条：028/029/030）。反例 eIntfisRefed（被引用）
    # 是**另一个 errCode**，不在 RESOURCE_NOT_FOUND_ERR_CODES 内，仍判真失败。
    "fw_delete_interface": frozenset({"RESOURCE_NOT_FOUND"}),
}

_IDEMPOTENT_DECL_FIELD = "idempotent"
_IDEMPOTENT_DECL_ERROR_FIELD = "error_types"
# 幂等成功语义的错误类型：atom `error_types` 含该值且 `idempotent: true` 时，
# 表达「目标流/对象不存在 = 目标状态已达成」，不构成残留
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
    """校验 ``IDEMPOTENT_ERROR_TYPES`` 与 atom 声明面一致，返回不一致项列表（空 = 一致）。

    正向（登记表每个 op）：
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


# ── 目标资源不存在归类（CT-REM-ATOM-DELETE 幂等契约）──────────────────────
# 背景：创建步的回滚与用例显式清理步会**重复删除同一对象**（case_runner 的
# cleanup 在用例所有 step 跑完后统一执行，此时清理步已删过）。第二次删除设备
# 返回 400 + 「不存在」—— 语义上「目标不存在 == 目标状态已达成」，与
# tg_stop_traffic_stream 的幂等停流同构（见上方 IDEMPOTENT_ERROR_TYPES）。
# 此前统一映射为 RUNNER_CONFIG_REJECTED，消费方当失败 ⇒ cleanup_failed 假阳性
# （2026-09-20 策略配置 run 实测 28 项；tg 停流同类现场 242 条）。
# 实测设备原文（ptm-atomic 侧 exec-log，2026-09-20）：
#   fw_delete_policy_route 400 ePolicyRouteIdNotExist 「删除ipv4策略路由2失败，策略路由不存在」
#   fw_delete_object       400 eObjGetNoExist        「Couldn't found OBJ-SRC-192 from DB」
#   fw_delete_timeobject   400 eRequestParam         「Couldn't found TOBJ-5MIN from DB」
# 实测设备原文（2026-09-21 补，接口族）：
#   fw_delete_interface    400 eIntfGetTypeByName    「unknow interface GE0_3.100」
# 反例（**不得**归一）：fw_delete_interface 的 eIntfisRefed「该接口已被引用」
# —— 删除确实未完成，是真失败（与 eIntfGetTypeByName 是不同的 errCode，不冲突）。
RESOURCE_NOT_FOUND_ERR_CODES = frozenset({
    "ePolicyRouteIdNotExist",
    "eObjGetNoExist",
    # 字面为「按名取接口类型失败」，实际语义即「不认识该接口」= 接口不存在。
    # 与上面两码同为**专用**错误码（非通用参数码），故入明确集合而非 generic 集合。
    # 佐证：历史 run 全量扫描 14 次出现，errMsg 无一例外为 unknow interface
    # {bond1(6), GE0_3.100(4), bvi1(4)}，无其它文案形态。该码另见于
    # fw_config_interface 的「配置不存在接口」负例 —— 那类 op 未登记幂等表，天然免疫。
    "eIntfGetTypeByName",
})
# eRequestParam 是通用参数错误码，单凭它不足以判定「不存在」，须配 errMsg 文案佐证。
_RESOURCE_NOT_FOUND_GENERIC_ERR_CODES = frozenset({"eRequestParam"})
RESOURCE_NOT_FOUND_MESSAGE_MARKERS = ("Couldn't found", "不存在")


def is_resource_not_found(status_code: int, response_payload: Any = None) -> bool:
    """判定设备响应是否为「目标资源不存在」。

    判据（任一成立）：
    - errCode 命中明确集合（``RESOURCE_NOT_FOUND_ERR_CODES``）；
    - errCode 为通用参数码（``_RESOURCE_NOT_FOUND_GENERIC_ERR_CODES``）且
      errMsg/errMessage/message 命中「不存在」文案特征。
    """
    if not isinstance(response_payload, dict):
        return False
    err_code = response_payload.get("errCode")
    if not isinstance(err_code, str):
        return False
    if err_code in RESOURCE_NOT_FOUND_ERR_CODES:
        return True
    if err_code in _RESOURCE_NOT_FOUND_GENERIC_ERR_CODES:
        blob = " ".join(
            str(response_payload.get(key) or "")
            for key in ("errMsg", "errMessage", "message")
        )
        return any(marker in blob for marker in RESOURCE_NOT_FOUND_MESSAGE_MARKERS)
    return False


def resource_not_found_error(
    status_code: int,
    response_payload: Any = None,
    *,
    op_id: str | None = None,
    error_code: str = ERROR_RUNNER_CONFIG_REJECTED,
    extra_details: Mapping[str, Any] | None = None,
) -> RunnerError:
    """构造「目标资源不存在」错误（幂等语义）。

    ``details`` 携带幂等契约的键（error_type / idempotent / idempotent_source），供
    ptm-team ``case_runner._rollback_idempotent_hit`` 的双条件判定（``is True`` 严格
    比较）命中；字段布局与既有 RUNNER_CONFIG_REJECTED 分支保持一致
    （status_code / err_code / err_msg），不回显凭据。

    ``error_code``（**运行时代码**，决定 CLI 退出码）默认沿用设备拒绝类的
    ``RUNNER_CONFIG_REJECTED``（exit 48）—— 与调用点既有分支**逐字一致**，故退出码
    零变化；不改 ``EXIT_CODES``（``CliError.exit_code`` 是 ``EXIT_CODES[error_code]``
    的无兜底查表，未登记的新码会 KeyError）。与 ``details["error_type"]``
    （**设备原始类型** ``RESOURCE_NOT_FOUND``）分层：原始类型与幂等键才是消费方判据。

    ``extra_details``（2026-09-21 新增，可选）：调用点原有失败分支的**诊断键**
    （如 nat.py 的 ``response_keys``）经此透传，保持「既有键追加而非替换」——
    契约键（error_type / status_code / err_code / err_msg / op_id / 幂等键）在
    其后统一写入，**不可被 extra 覆盖**。
    """
    err_code = response_payload.get("errCode") if isinstance(response_payload, dict) else None
    err_msg = (
        (response_payload.get("errMsg") or response_payload.get("message"))
        if isinstance(response_payload, dict)
        else None
    )
    details: dict[str, Any] = {}
    if extra_details:
        details.update(extra_details)
    details.update(
        {
            "error_type": "RESOURCE_NOT_FOUND",
            "status_code": status_code,
            "err_code": err_code,
            "err_msg": err_msg,
        }
    )
    if op_id:
        details["op_id"] = op_id
        details.update(idempotent_error_details(op_id, "RESOURCE_NOT_FOUND"))
    return RunnerError(
        error_code,
        "Device reports the target resource does not exist; the goal state is already reached.",
        details,
    )


def raise_if_resource_not_found(
    status_code: int,
    response_payload: Any = None,
    *,
    op_id: str = "",
    extra_details: Mapping[str, Any] | None = None,
) -> None:
    """删除/回滚类 op 的目标资源不存在时抛 RESOURCE_NOT_FOUND，否则原样返回。

    用法：在设备请求失败的**统一分支**调用（各 runner 的通用执行函数内，
    ``raise_if_device_session_rejected(...)`` 之后、既有 ``raise RunnerError(...)``
    之前），**无需按 op_id 分支** —— ``IDEMPOTENT_ERROR_TYPES`` 登记表是唯一权威门，
    未登记的 op（创建 / 查询 / 未登记更新、以及「被引用」类拒绝）天然免疫。
    误判方向（把真失败当幂等成功）会漏报真残留，最不可接受（同
    ``_rollback_idempotent_hit`` 的保守侧），故登记表只收「目标不存在 == 目标状态
    已达成」语义的 op。未命中时流程照旧走原有 error_type，既有映射与退出码均不变。

    ``extra_details`` 透传给 :func:`resource_not_found_error`（调用点原有诊断键）。
    """
    declared = IDEMPOTENT_ERROR_TYPES.get(op_id)
    if not declared or _IDEMPOTENT_SUCCESS_ERROR_TYPE not in declared:
        return
    if is_resource_not_found(status_code, response_payload):
        raise resource_not_found_error(
            status_code,
            response_payload,
            op_id=op_id,
            extra_details=extra_details,
        )

