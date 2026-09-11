"""Session file handling for NGFW runner commands."""

from __future__ import annotations

import json
import os
import re
from hashlib import sha256
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import RunnerError


DEFAULT_SESSION_FILE = Path.home() / ".local" / "state" / "ptm-atomic" / "ngfw" / "session.json"
SESSION_FILE_MODE = 0o600

# scheme://netloc[/path...] 形态；仅用于绑定比较前的规范化拆分。
_URL_WITH_SCHEME_RE = re.compile(r"^([A-Za-z][A-Za-z0-9+.\-]*)://([^/?#]*)(.*)$")


def normalize_base_url(url: str) -> str:
    """返回用于绑定比较的规范化 base_url（CR-059 多 DUT 会话绑定）。

    规则：
    - 去首尾空白、去尾部斜杠；
    - scheme 与 host 小写（host 大小写不敏感）；
    - 默认端口归一：``https://host:443`` 等价 ``https://host``、
      ``http://host:80`` 等价 ``http://host``（避免既有正常流程被误判）；
      非默认端口保留；
    - 无 scheme 的输入按原样处理（不强加 scheme，也不做端口归一）；
    - 非字符串输入返回空串。

    注意：与 ``ngfw_login.normalize_base_url``（CLI 入口校验，要求必须携带
    scheme，否则抛错）职责不同；本函数只做宽松规范化，供绑定比较使用。
    """
    if not isinstance(url, str):
        return ""
    cleaned = url.strip().rstrip("/")
    if not cleaned:
        return ""
    match = _URL_WITH_SCHEME_RE.match(cleaned)
    if match is None:
        # 无 scheme：按原样处理（保留大小写与端口），不强加 scheme。
        return cleaned
    scheme = match.group(1).lower()
    netloc = match.group(2)
    rest = match.group(3)
    if scheme in ("https", "http"):
        default_port = "443" if scheme == "https" else "80"
        netloc = _strip_default_port(netloc, default_port)
    return f"{scheme}://{netloc.lower()}{rest}"


def _strip_default_port(netloc: str, default_port: str) -> str:
    """去掉 netloc 中与 scheme 匹配的默认端口；兼容 IPv6 字面量 ``[::1]:443``。"""
    if netloc.startswith("["):
        bracket_end = netloc.find("]")
        if bracket_end != -1 and netloc[bracket_end + 1 : bracket_end + 2] == ":":
            port = netloc[bracket_end + 2 :]
            if port == default_port:
                return netloc[: bracket_end + 1]
        return netloc
    host, sep, port = netloc.rpartition(":")
    if sep and host and port == default_port:
        return host
    return netloc


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


def read_session_file(path: Path, *, expect_base_url: str | None = None) -> dict[str, Any]:
    """读取 session 文件；``expect_base_url`` 非空时校验设备绑定（CR-059）。

    - ``expect_base_url=None``（缺省）时完全不校验，行为与历史版本逐字节一致；
    - 非 None 时与文件内 ``base_url`` 双向经 :func:`normalize_base_url` 归一后
      比较，不等则抛 ``RUNNER_SESSION_INVALID``（多 DUT 场景防止跨设备误用
      session 文件静默发生）。
    """
    if not path.is_file():
        raise RunnerError(
            "RUNNER_SESSION_INVALID",
            "Session file does not exist.",
            {"session_file": str(path)},
            suggestion="Run ptm-atomic run fw_login_web_management --execute first.",
        )
    mode = path.stat().st_mode & 0o777
    if mode & 0o077:
        import sys
        if sys.platform != 'win32':
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
    if expect_base_url is not None:
        _ensure_session_bound_to_device(path, payload, expect_base_url)
    return payload


def _ensure_session_bound_to_device(path: Path, payload: dict[str, Any], expect_base_url: str) -> None:
    """校验 session 文件的 base_url 与调用方期望的设备一致（CR-059）。"""
    session_base_url = payload.get("base_url")
    expected = normalize_base_url(expect_base_url)
    actual = normalize_base_url(session_base_url) if isinstance(session_base_url, str) else ""
    if actual == expected:
        return
    raise RunnerError(
        "RUNNER_SESSION_INVALID",
        "Session file belongs to a different device (base_url mismatch).",
        {
            "session_file": str(path),
            "session_base_url": session_base_url if isinstance(session_base_url, str) else None,
            "expected_base_url": expect_base_url,
        },
        suggestion="该 session 文件属于其它设备，请对该 base_url 重新执行 fw_login_web_management",
    )


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
