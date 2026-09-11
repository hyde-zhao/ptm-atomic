"""Runner-specific error helpers."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any


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

