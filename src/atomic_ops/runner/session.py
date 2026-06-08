"""Session file handling for NGFW runner commands."""

from __future__ import annotations

import json
import os
from hashlib import sha256
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import RunnerError


DEFAULT_SESSION_FILE = Path.home() / ".local" / "state" / "ptm-atomic" / "ngfw" / "session.json"
SESSION_FILE_MODE = 0o600


def resolve_session_file(raw_path: str | None) -> Path:
    if raw_path:
        return Path(raw_path).expanduser()
    return DEFAULT_SESSION_FILE


def ensure_session_path_allowed(path: Path, *, cwd: Path | None = None) -> None:
    resolved = path.expanduser().resolve(strict=False)
    repo_root = (cwd or Path.cwd()).resolve(strict=False)
    try:
        resolved.relative_to(repo_root)
    except ValueError:
        return
    raise RunnerError(
        "RUNNER_SESSION_INVALID",
        "Session file must not be written inside the current repository.",
        {"session_file": str(path)},
        suggestion="Use the default session path or a path under ~/.local/state/ptm-atomic/.",
    )


def write_session_file(
    path: Path,
    *,
    base_url: str,
    username: str,
    session_value: str,
    source_op_id: str,
) -> dict[str, Any]:
    ensure_session_path_allowed(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "schema_version": "1.0",
        "base_url": base_url.rstrip("/"),
        "username": username,
        "session_value": session_value,
        "source_op_id": source_op_id,
        "created_at": datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "expires_at": None,
    }
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    descriptor = os.open(path, flags, SESSION_FILE_MODE)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    os.chmod(path, SESSION_FILE_MODE)
    return payload


def read_session_file(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise RunnerError(
            "RUNNER_SESSION_INVALID",
            "Session file does not exist.",
            {"session_file": str(path)},
            suggestion="Run ptm-atomic run fw_login_web_management --execute first.",
        )
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        raise RunnerError(
            "RUNNER_SESSION_INVALID",
            "Session file permissions are too broad.",
            {"session_file": str(path), "mode": oct(mode)},
            suggestion="Set session file permissions to 0600.",
        )
    try:
        with path.open("r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        raise RunnerError(
            "RUNNER_SESSION_INVALID",
            "Session file is unreadable or invalid JSON.",
            {"session_file": str(path)},
        ) from exc
    if not isinstance(payload, dict):
        raise RunnerError(
            "RUNNER_SESSION_INVALID",
            "Session file root must be an object.",
            {"session_file": str(path)},
        )
    session_value = payload.get("session_value")
    if not isinstance(session_value, str) or not session_value.strip():
        raise RunnerError(
            "RUNNER_SESSION_INVALID",
            "Session file does not contain a usable session reference.",
            {"session_file": str(path), "missing_field": "session_value"},
        )
    return payload


def session_summary(path: Path, payload: dict[str, Any]) -> dict[str, Any]:
    session_value = str(payload.get("session_value", ""))
    return {
        "session_file": str(path),
        "base_url": payload.get("base_url"),
        "username": payload.get("username"),
        "state_status": "valid",
        "session_ref": _session_ref(session_value),
        "session_prefix": session_value[:8] if session_value else "",
        "expires_at": payload.get("expires_at"),
    }


def _session_ref(session_value: str) -> str:
    if not session_value:
        return "<session-ref>"
    digest = sha256(session_value.encode("utf-8")).hexdigest()[:12]
    return f"<session:{digest}>"
