"""Implementation for the atomic-ops sync command."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from atomic_ops.git_ops import GitClient, GitError, sparse_fallback_warning
from atomic_ops.metadata import (
    DEFAULT_BRANCH,
    DEFAULT_REPO_URL,
    ERROR_GIT_AUTH_FAILED,
    ERROR_GIT_NETWORK_ERROR,
    ERROR_REPO_NOT_SYNCED,
    EXIT_CODES,
    SPARSE_PATHS,
    STATUS_SYNCED,
    MetadataError,
    build_metadata,
    ensure_cache_parent_writable,
    is_git_cache,
    mark_stale,
    read_metadata,
    redact_sensitive,
    repo_url_without_credentials,
    resolve_cache_root,
    success_summary,
    write_metadata,
)


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--repo",
        default=None,
        help="Git repository URL to sync. Defaults to the TGFW atomic operation repository.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--latest",
        action="store_true",
        help="Track and refresh the repository default branch.",
    )
    mode.add_argument(
        "--ref",
        default=None,
        help="Checkout a pinned branch, tag, or commit SHA.",
    )
    parser.add_argument(
        "--format",
        choices=("json", "text"),
        default="text",
        help="Output format for successful results and errors.",
    )


def run(args: argparse.Namespace) -> int:
    output_format = getattr(args, "format", "text")
    cache_root: Path | None = None
    existing_metadata: dict[str, Any] | None = None
    repo_url = getattr(args, "repo", None) or DEFAULT_REPO_URL

    try:
        cache_root = resolve_cache_root()
        ensure_cache_parent_writable(cache_root)
        if is_git_cache(cache_root):
            existing_metadata = read_metadata(cache_root)
            if not getattr(args, "repo", None):
                repo_url = str(existing_metadata.get("source_repo") or DEFAULT_REPO_URL)

        client = GitClient(
            repo_url=repo_url,
            cache_root=cache_root,
            sparse_paths=SPARSE_PATHS,
        )
        version = client.check_version()
        warning = None
        if not version.supports_sparse_checkout:
            warning = sparse_fallback_warning(version)
            _write_warning(warning, output_format)

        cache_existed = is_git_cache(cache_root)
        client.ensure_clone(supports_sparse=version.supports_sparse_checkout)
        if cache_existed and getattr(args, "repo", None):
            client.set_origin_url(repo_url_without_credentials(repo_url))
        if existing_metadata is None and is_git_cache(cache_root):
            try:
                existing_metadata = read_metadata(cache_root)
            except MetadataError:
                existing_metadata = None

        default_branch = _select_default_branch(client, existing_metadata)
        ref_mode, current_ref = _select_ref_mode(args, existing_metadata, default_branch)

        if ref_mode == "latest":
            client.refresh_latest(default_branch)
            current_ref = default_branch
        else:
            if not current_ref:
                raise MetadataError("pinned sync requires a non-empty ref")
            client.refresh_pinned(current_ref)

        commit_sha = client.commit_sha()
        data = build_metadata(
            cache_root=cache_root,
            source_repo=repo_url,
            default_branch=default_branch,
            ref_mode=ref_mode,
            current_ref=current_ref,
            commit_sha=commit_sha,
            last_sync_status=STATUS_SYNCED,
            last_warning_code=warning["warning_code"] if warning else None,
        )
        data = write_metadata(cache_root, data)
        _write_success(data, output_format)
        return 0
    except GitError as exc:
        if exc.error_code == ERROR_GIT_NETWORK_ERROR and cache_root is not None:
            stale_metadata = _try_mark_stale(cache_root, existing_metadata)
            if stale_metadata is not None:
                _write_error(
                    ERROR_GIT_NETWORK_ERROR,
                    "Git network access failed; using stale local cache for read-only work.",
                    output_format,
                    cache_root=cache_root,
                    cache_status="STALE",
                    ref_mode=stale_metadata.get("ref_mode"),
                    detail_message=str(exc),
                )
                return EXIT_CODES[ERROR_GIT_NETWORK_ERROR]
        return _fail_from_code(
            exc.error_code,
            str(exc),
            output_format,
            cache_root=cache_root,
            cache_status=_cache_status(existing_metadata),
        )
    except MetadataError as exc:
        return _fail_from_code(
            exc.error_code,
            str(exc),
            output_format,
            cache_root=cache_root,
            cache_status=_cache_status(existing_metadata),
        )


def _select_default_branch(
    client: GitClient,
    existing_metadata: dict[str, Any] | None,
) -> str:
    fallback = DEFAULT_BRANCH
    if existing_metadata and isinstance(existing_metadata.get("default_branch"), str):
        fallback = existing_metadata["default_branch"]
    return client.detect_default_branch(fallback)


def _select_ref_mode(
    args: argparse.Namespace,
    existing_metadata: dict[str, Any] | None,
    default_branch: str,
) -> tuple[str, str | None]:
    if getattr(args, "latest", False):
        return "latest", default_branch
    requested_ref = getattr(args, "ref", None)
    if requested_ref:
        return "pinned", requested_ref
    if existing_metadata:
        ref_mode = existing_metadata.get("ref_mode")
        if ref_mode == "pinned":
            current_ref = existing_metadata.get("current_ref")
            if not isinstance(current_ref, str) or not current_ref:
                raise MetadataError("metadata pinned mode is missing current_ref")
            return "pinned", current_ref
    return "latest", default_branch


def _try_mark_stale(
    cache_root: Path,
    existing_metadata: dict[str, Any] | None,
) -> dict[str, Any] | None:
    try:
        data = existing_metadata or read_metadata(cache_root)
        return mark_stale(cache_root, data, ERROR_GIT_NETWORK_ERROR)
    except MetadataError:
        return None


def _cache_status(existing_metadata: dict[str, Any] | None) -> str:
    if existing_metadata and existing_metadata.get("last_sync_status"):
        return str(existing_metadata["last_sync_status"])
    return "NOT_SYNCED"


def _fail_from_code(
    error_code: str,
    message: str,
    output_format: str,
    *,
    cache_root: Path | None,
    cache_status: str,
) -> int:
    stable_message = _stable_message(error_code, message)
    _write_error(
        error_code,
        stable_message,
        output_format,
        cache_root=cache_root,
        cache_status=cache_status,
    )
    return EXIT_CODES.get(error_code, EXIT_CODES[ERROR_REPO_NOT_SYNCED])


def _stable_message(error_code: str, detail: str) -> str:
    if error_code == ERROR_GIT_AUTH_FAILED:
        return "Git repository authentication failed while syncing the operation repository."
    if error_code == ERROR_GIT_NETWORK_ERROR:
        return "Git network access failed while syncing the operation repository."
    if error_code == ERROR_REPO_NOT_SYNCED:
        return f"Local operation repository cache is missing, unreadable, or damaged: {detail}"
    return redact_sensitive(detail)


def _suggestion(error_code: str) -> str:
    if error_code == ERROR_GIT_AUTH_FAILED:
        return "Configure SSH keys or the system Git credential helper, then rerun atomic-ops sync."
    if error_code == ERROR_GIT_NETWORK_ERROR:
        return "Check network access to the Git repository and rerun atomic-ops sync."
    return "Run atomic-ops sync again after fixing the cache path or removing the damaged cache."


def _retryable(error_code: str) -> bool:
    return error_code in {ERROR_GIT_NETWORK_ERROR, ERROR_REPO_NOT_SYNCED}


def _write_success(data: dict[str, Any], output_format: str) -> None:
    summary = success_summary(data)
    if output_format == "json":
        print(json.dumps(redact_sensitive(summary), ensure_ascii=False, sort_keys=True))
        return
    print(
        "同步完成: "
        f"status={summary['status']} "
        f"ref_mode={summary['ref_mode']} "
        f"current_ref={summary['current_ref']} "
        f"commit_sha={summary['commit_sha']} "
        f"cache_root={summary['cache_root']}"
    )


def _write_warning(warning: dict[str, str], output_format: str) -> None:
    safe_warning = redact_sensitive(warning)
    if output_format == "json":
        print(json.dumps(safe_warning, ensure_ascii=False, sort_keys=True), file=sys.stderr)
    else:
        print(
            f"warning: {safe_warning['warning_code']}: {safe_warning['message']}",
            file=sys.stderr,
        )


def _write_error(
    error_code: str,
    message: str,
    output_format: str,
    *,
    cache_root: Path | None,
    cache_status: str,
    ref_mode: object | None = None,
    detail_message: str | None = None,
) -> None:
    details: dict[str, Any] = {
        "command": "sync",
        "cache_status": cache_status,
    }
    if cache_root is not None:
        details["cache_root"] = str(cache_root)
    if ref_mode is not None:
        details["ref_mode"] = ref_mode
    if detail_message:
        details["message"] = redact_sensitive(detail_message)

    error = redact_sensitive(
        {
            "error_code": error_code,
            "message": message,
            "details": details,
            "retryable": _retryable(error_code),
            "suggestion": _suggestion(error_code),
        }
    )
    if output_format == "json":
        print(json.dumps(error, ensure_ascii=False, sort_keys=True), file=sys.stderr)
        return
    print(
        f"error: {error['error_code']}: {error['message']}\n"
        f"suggestion: {error['suggestion']}",
        file=sys.stderr,
    )
