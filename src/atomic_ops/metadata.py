"""Metadata and cache helpers for atomic-ops sync."""

from __future__ import annotations

import json
import os
import re
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


DEFAULT_REPO_URL = "git@<GITLAB_HOST>:<ORG/PROJECT>/ptm-atomic.git"
DEFAULT_BRANCH = "main"
SPARSE_PATHS = ("atoms", "schemas", "packages", "docs", "adapters")

STATUS_SYNCED = "SYNCED"
STATUS_STALE = "STALE"

ERROR_GIT_AUTH_FAILED = "GIT_AUTH_FAILED"
ERROR_GIT_NETWORK_ERROR = "GIT_NETWORK_ERROR"
ERROR_REPO_NOT_SYNCED = "REPO_NOT_SYNCED"

WARNING_SPARSE_FALLBACK = "GIT_SPARSE_FALLBACK"

EXIT_CODES = {
    ERROR_GIT_AUTH_FAILED: 21,
    ERROR_GIT_NETWORK_ERROR: 22,
    ERROR_REPO_NOT_SYNCED: 24,
}

REQUIRED_METADATA_FIELDS = {
    "source_repo",
    "default_branch",
    "ref_mode",
    "current_ref",
    "commit_sha",
    "synced_at",
    "last_sync_status",
    "cache_root",
    "sparse_paths",
}


class MetadataError(Exception):
    """Raised when cache metadata cannot be safely read or written."""

    def __init__(self, message: str, *, error_code: str = ERROR_REPO_NOT_SYNCED) -> None:
        super().__init__(redact_sensitive(message))
        self.error_code = error_code


def utc_now_iso() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def redact_sensitive(value: Any) -> Any:
    """Return a copy of value with URL credentials and secret-like fields redacted."""

    if isinstance(value, dict):
        return {key: redact_sensitive(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [redact_sensitive(inner) for inner in value]
    if not isinstance(value, str):
        return value

    text = value
    text = re.sub(
        r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?[^\s,;]+",
        r"\1\2[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)\b(token|password|passwd|pwd|secret)=([^&\s;]+)",
        r"\1=[REDACTED]",
        text,
    )
    text = re.sub(
        r"(?i)(https?://)([^/\s:@]+)(?::[^/\s@]*)?@",
        r"\1[REDACTED]@",
        text,
    )
    text = re.sub(
        r"(?i)(://[^/\s?]+/[^?\s]*\?[^ \n\r]*\b(?:token|password|passwd|pwd|secret)=)[^&\s;]+",
        r"\1[REDACTED]",
        text,
    )
    return text


def repo_url_without_credentials(repo_url: str) -> str:
    """Return a repository URL safe to persist in metadata or git config."""

    text = re.sub(r"(?i)^(https?://)(?:[^/@\s]+@)(.+)$", r"\1\2", repo_url)
    text = re.sub(
        r"(?i)\b(token|password|passwd|pwd|secret)=([^&\s;]+)",
        r"\1=[REDACTED]",
        text,
    )
    return text


def resolve_cache_root() -> Path:
    if sys.platform.startswith("win"):
        local_app_data = os.environ.get("LOCALAPPDATA")
        if not local_app_data:
            raise MetadataError("LOCALAPPDATA is not set; cannot resolve atomic-ops cache root")
        return Path(local_app_data).expanduser() / "atomic-ops" / "repo"
    return Path.home() / ".cache" / "atomic-ops" / "repo"


def metadata_path(cache_root: Path) -> Path:
    return cache_root / "_metadata.json"


def ensure_cache_parent_writable(cache_root: Path) -> None:
    """Create the cache parent and fail fast when any parent segment is a file."""

    cache_root = cache_root.expanduser()
    parent = cache_root.parent
    current = parent.anchor and Path(parent.anchor) or Path(".")

    for segment in parent.parts:
        if segment == parent.anchor:
            continue
        current = current / segment
        if current.exists() and not current.is_dir():
            raise MetadataError(f"安装路径被非目录占用: {current}")

    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise MetadataError(f"cannot create cache parent {parent}: {exc}") from exc

    if not os.access(parent, os.W_OK):
        raise MetadataError(f"cache parent is not writable: {parent}")


def is_git_cache(cache_root: Path) -> bool:
    return cache_root.is_dir() and (cache_root / ".git").exists()


def read_metadata(cache_root: Path) -> dict[str, Any]:
    path = metadata_path(cache_root)
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
    except FileNotFoundError as exc:
        raise MetadataError(f"metadata file is missing: {path}") from exc
    except json.JSONDecodeError as exc:
        raise MetadataError(f"metadata file is damaged: {path}") from exc
    except OSError as exc:
        raise MetadataError(f"metadata file is unreadable: {path}: {exc}") from exc

    validate_metadata(data, cache_root)
    return data


def validate_metadata(data: Any, cache_root: Path) -> None:
    if not isinstance(data, dict):
        raise MetadataError("metadata root must be an object")
    missing = sorted(REQUIRED_METADATA_FIELDS.difference(data))
    if missing:
        raise MetadataError(f"metadata missing required fields: {', '.join(missing)}")
    if data.get("ref_mode") not in {"latest", "pinned"}:
        raise MetadataError("metadata ref_mode must be latest or pinned")
    if data.get("last_sync_status") not in {STATUS_SYNCED, STATUS_STALE}:
        raise MetadataError("metadata last_sync_status must be SYNCED or STALE")
    if not isinstance(data.get("sparse_paths"), list) or not all(
        isinstance(item, str) for item in data["sparse_paths"]
    ):
        raise MetadataError("metadata sparse_paths must be a list of strings")
    if not cache_root.is_dir() or not (cache_root / ".git").exists():
        raise MetadataError(f"cache git repository is missing or incomplete: {cache_root}")


def write_metadata(cache_root: Path, data: dict[str, Any]) -> dict[str, Any]:
    safe_data = redact_sensitive(dict(data))
    validate_metadata(safe_data, cache_root)
    path = metadata_path(cache_root)
    tmp_path = path.with_name(f"{path.name}.tmp")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            json.dump(safe_data, handle, ensure_ascii=False, indent=2, sort_keys=True)
            handle.write("\n")
        tmp_path.replace(path)
    except OSError as exc:
        raise MetadataError(f"cannot write metadata file {path}: {exc}") from exc
    return safe_data


def build_metadata(
    *,
    cache_root: Path,
    source_repo: str,
    default_branch: str,
    ref_mode: str,
    current_ref: str | None,
    commit_sha: str,
    last_sync_status: str = STATUS_SYNCED,
    last_error_code: str | None = None,
    last_warning_code: str | None = None,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "source_repo": repo_url_without_credentials(source_repo),
        "default_branch": default_branch,
        "ref_mode": ref_mode,
        "current_ref": current_ref,
        "commit_sha": commit_sha,
        "synced_at": utc_now_iso(),
        "last_sync_status": last_sync_status,
        "cache_root": str(cache_root.resolve()),
        "sparse_paths": list(SPARSE_PATHS),
        "last_error_code": last_error_code,
        "last_warning_code": last_warning_code,
    }
    return data


def mark_stale(cache_root: Path, data: dict[str, Any], error_code: str) -> dict[str, Any]:
    stale = dict(data)
    stale["last_sync_status"] = STATUS_STALE
    stale["last_error_code"] = error_code
    stale["synced_at"] = utc_now_iso()
    return write_metadata(cache_root, stale)


def success_summary(data: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": data["last_sync_status"],
        "source_repo": data["source_repo"],
        "ref_mode": data["ref_mode"],
        "current_ref": data["current_ref"],
        "commit_sha": data["commit_sha"],
        "cache_root": data["cache_root"],
        "sparse_paths": data["sparse_paths"],
    }
