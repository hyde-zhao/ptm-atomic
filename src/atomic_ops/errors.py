"""Shared CLI error and output helpers for ptm-atomic commands."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from typing import Any, TYPE_CHECKING

from atomic_ops.metadata import redact_sensitive as _redact_sensitive
from atomic_ops.repository import (
    ERROR_OP_NOT_FOUND,
    ERROR_PACKAGE_NOT_FOUND,
    ERROR_REPO_NOT_SYNCED,
    EXIT_CODES,
)

if TYPE_CHECKING:
    from atomic_ops.repository import ReadError, Repository


SENSITIVE_KEY_PARTS = ("authorization", "header", "password", "passwd", "pwd", "secret", "token")
SENSITIVE_LINE_PATTERN = re.compile(
    r"(?im)^.*\b(?:authorization|header|password|passwd|pwd|secret|token)\b.*$"
)


@dataclass(frozen=True)
class CliError:
    """A top-level CLI error object with a stable exit code."""

    error_code: str
    message: str
    details: dict[str, Any]
    retryable: bool = False
    suggestion: str | None = None

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.error_code]

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error_code": self.error_code,
            "message": self.message,
            "details": self.details,
            "retryable": self.retryable,
        }
        if self.suggestion:
            payload["suggestion"] = self.suggestion
        return redact(payload)


def redact(value: Any) -> Any:
    """Redact sensitive keys and secret-like substrings from output payloads."""

    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, inner in value.items():
            if _is_sensitive_key(str(key)):
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = redact(inner)
        return _redact_sensitive(redacted)
    if isinstance(value, list):
        return [_redact_sensitive(redact(item)) for item in value]
    if isinstance(value, str):
        return _redact_sensitive(SENSITIVE_LINE_PATTERN.sub("[REDACTED]", value))
    return _redact_sensitive(value)


def write_error(error: CliError, output_format: str) -> int:
    """Write a CLI error object to stderr and return its fixed exit code.

    P2 探针空响应缺口（下游现场 2026-09-08~09-11）：失败原先只写 stderr，stdout
    保持为空——消费方（op_mapper._parse_atomic_output / _load_op_decl）把「空
    stdout」一律按 None 处理，导致「探测失败（如设备不可达 exit 46）」与「本地无
    该 op 声明」不可区分。现约定：``--format json`` 模式下失败也在 stdout 打印一
    行机器可读 JSON（status=error + error_code/error_type/retryable/exit_code），
    使调用方能区分两者；stderr 输出、退出码与非 json 模式输出格式全部保持不变
    （向后兼容）。
    """

    payload = error.to_dict()
    # run execute 错误：写 exec-log 审计日志（含透传的 err_code/err_msg），
    # 并在 payload 标注 run_id 供调用方定位日志文件。非 run 命令的 contextvar 未设，不记。
    from atomic_ops.runner.exec_log import current_run, run_log_path, write_exec_log

    ctx = current_run()
    if ctx is not None and ctx.mode == "execute":
        details = error.details if isinstance(error.details, dict) else {}
        write_exec_log(
            run_id=ctx.run_id,
            op_id=details.get("op_id"),
            mode=ctx.mode,
            status="error",
            status_code=details.get("status_code"),
            err_code=details.get("err_code"),
            err_msg=details.get("err_msg"),
            error_type=error.error_code,
        )
        payload["run_id"] = ctx.run_id
        payload["exec_log_path"] = str(run_log_path(ctx.run_id))
    if output_format == "json":
        print(json.dumps(payload, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        # 失败也在 stdout 留机器可读结构：error_type 与 error_code 同值冗余给出，
        # 便于不同消费方按任一键名读取；retryable 对应错误码表的 retryable 语义
        # （如 RUNNER_DEVICE_UNREACHABLE=true）。
        stdout_payload = {
            "status": "error",
            "error_code": error.error_code,
            "error_type": error.error_code,
            "message": payload.get("message"),
            "details": payload.get("details"),
            "retryable": payload.get("retryable", False),
            "exit_code": error.exit_code,
        }
        if payload.get("suggestion"):
            stdout_payload["suggestion"] = payload["suggestion"]
        if payload.get("run_id"):
            stdout_payload["run_id"] = payload["run_id"]
            stdout_payload["exec_log_path"] = payload["exec_log_path"]
        print(json.dumps(redact(stdout_payload), ensure_ascii=False, sort_keys=True))
    else:
        details = _details_text(payload["details"])
        suggestion = payload.get("suggestion")
        lines = [
            f"error: {payload['error_code']}: {payload['message']}",
            f"details: {details}",
        ]
        if suggestion:
            lines.append(f"suggestion: {suggestion}")
        print("\n".join(lines), file=sys.stderr)
    return error.exit_code


def write_warning(warning: dict[str, Any], output_format: str) -> None:
    """Write a warning object to stderr without contaminating stdout."""

    safe_warning = redact(warning)
    if output_format == "json":
        print(json.dumps(safe_warning, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return

    warning_code = safe_warning.get("warning_code") or "WARNING"
    message = safe_warning.get("message") or ""
    print(f"warning: {warning_code}: {message}", file=sys.stderr)


def write_json_stdout(payload: dict[str, Any]) -> None:
    """Write a redacted JSON payload to stdout."""

    print(json.dumps(redact(payload), ensure_ascii=False, sort_keys=True))


def _is_sensitive_key(key: str) -> bool:
    normalized = key.lower()
    return any(part in normalized for part in SENSITIVE_KEY_PARTS)


def details_text(details: Any) -> str:
    """Convert a details dict to a human-readable string."""
    if not isinstance(details, dict) or not details:
        return "{}"
    return ", ".join(f"{key}={value}" for key, value in details.items())


# 保留内部版本用于 write_error 内部
_details_text = details_text


def write_stale_warning(repo: Repository, output_format: str) -> None:
    """输出统一的 stale cache 警告。"""
    if not repo.is_stale:
        return
    write_warning(
        {
            "warning_code": "STALE_CACHE",
            "message": "cache_status=STALE; using stale local cache for read-only operation",
            "details": {"command": "unknown", "cache_status": "STALE"},
        },
        output_format,
    )


def write_read_error(exc: ReadError, output_format: str, command: str) -> int:
    """统一的 ReadError → CliError 转换和输出。

    根据 error_code 自动选择对应的 suggestion。
    """
    suggestion_map = {
        ERROR_REPO_NOT_SYNCED: "Run ptm-atomic sync before using read commands.",
        ERROR_OP_NOT_FOUND: "Run ptm-atomic sync and check the op_id spelling.",
        ERROR_PACKAGE_NOT_FOUND: "Run ptm-atomic packages and choose one of the listed package names.",
    }
    suggestion = suggestion_map.get(exc.error_code, "Rerun the command after fixing the local cache.")
    return write_error(
        CliError(
            error_code=exc.error_code,
            message=exc.message,
            details={"command": command, **exc.details},
            retryable=exc.retryable,
            suggestion=suggestion,
        ),
        output_format,
    )
