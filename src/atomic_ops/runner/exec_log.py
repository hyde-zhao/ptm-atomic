"""本地执行审计日志：按 run_id 写 JSONL 到 state 目录。

仅记录 execute 调用（含错误），不记 dry-run。调用方靠成功 envelope 输出的
``metadata.exec_log``（run_id + path）或错误 stderr 里的 run_id 定位日志文件。

路径（与 atom 缓存 ~/.cache/ptm-atomic 分开，日志是运行历史不应被缓存清理）：

  Linux/macOS: ~/.local/state/ptm-atomic/runs/{run_id}/exec-log.jsonl
  Windows:     %LOCALAPPDATA%\\ptm-atomic\\runs\\{run_id}\\exec-log.jsonl
"""

from __future__ import annotations

import contextvars
import json
import os
import secrets
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

RUNS_SUBDIR = "runs"
LOG_FILENAME = "exec-log.jsonl"


@dataclass
class RunContext:
    """当前 run 执行上下文，由 contextvar 持有，贯穿 handler 执行。"""

    run_id: str
    mode: str  # "execute" | "dry_run"
    start_ts: float  # time.monotonic()，用于计算 duration


_current_run: contextvars.ContextVar[RunContext | None] = contextvars.ContextVar(
    "ptm_atomic_current_run", default=None
)


def generate_run_id() -> str:
    """生成 run_id：<本地时间戳>-<8hex>。"""
    stamp = datetime.now().strftime("%Y%m%d%H%M%S")
    return f"{stamp}-{secrets.token_hex(4)}"


def resolve_state_root() -> Path:
    """平台相关 state 根目录。"""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or str(Path.home())
        return Path(base) / "ptm-atomic"
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local" / "state")
    return Path(base) / "ptm-atomic"


def run_log_path(run_id: str) -> Path:
    """返回某次 run 的 exec-log 文件路径。"""
    return resolve_state_root() / RUNS_SUBDIR / run_id / LOG_FILENAME


def bind_run_context(run_id: str, mode: str) -> contextvars.Token:
    """设置当前 run 上下文，返回 token 供 reset_run_context 恢复。"""
    return _current_run.set(RunContext(run_id=run_id, mode=mode, start_ts=time.monotonic()))


def reset_run_context(token: contextvars.Token) -> None:
    _current_run.reset(token)


def current_run() -> RunContext | None:
    return _current_run.get()


def write_exec_log(
    *,
    run_id: str,
    op_id: str | None,
    mode: str,
    status: str,
    status_code: int | None = None,
    err_code: Any = None,
    err_msg: str | None = None,
    error_type: str | None = None,
    duration_ms: int | None = None,
) -> Path:
    """写一条 exec-log JSONL，返回日志文件路径。"""
    record: dict[str, Any] = {
        "run_id": run_id,
        "timestamp": datetime.now().isoformat(timespec="milliseconds"),
        "op_id": op_id,
        "mode": mode,
        "status": status,
    }
    if status_code is not None:
        record["http_status"] = status_code
    if err_code is not None:
        record["err_code"] = err_code
    if err_msg is not None:
        record["err_msg"] = err_msg
    if error_type is not None:
        record["error_type"] = error_type
    if duration_ms is None:
        ctx = _current_run.get()
        if ctx is not None and ctx.run_id == run_id:
            duration_ms = int((time.monotonic() - ctx.start_ts) * 1000)
    if duration_ms is not None:
        record["duration_ms"] = duration_ms
    path = run_log_path(run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")
    return path
