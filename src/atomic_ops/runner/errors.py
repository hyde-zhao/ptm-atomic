"""Runner-specific error helpers."""

from __future__ import annotations

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

