"""System git adapter for atomic-ops sync."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from atomic_ops.metadata import (
    ERROR_GIT_AUTH_FAILED,
    ERROR_GIT_NETWORK_ERROR,
    ERROR_REPO_NOT_SYNCED,
    WARNING_SPARSE_FALLBACK,
    redact_sensitive,
    repo_url_without_credentials,
)


@dataclass(frozen=True)
class GitVersion:
    raw: str
    major: int
    minor: int
    patch: int

    @property
    def supports_sparse_checkout(self) -> bool:
        return (self.major, self.minor, self.patch) >= (2, 25, 0)


@dataclass(frozen=True)
class GitCommandResult:
    args: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class GitError(Exception):
    def __init__(
        self,
        message: str,
        *,
        error_code: str,
        result: GitCommandResult | None = None,
    ) -> None:
        super().__init__(redact_sensitive(message))
        self.error_code = error_code
        self.result = result


class GitClient:
    def __init__(
        self,
        *,
        repo_url: str,
        cache_root: Path,
        sparse_paths: Sequence[str],
        timeout_seconds: int = 120,
    ) -> None:
        self.repo_url = repo_url
        self.cache_root = cache_root
        self.sparse_paths = tuple(sparse_paths)
        self.timeout_seconds = timeout_seconds
        self.git_executable = shutil.which("git")

    def check_version(self) -> GitVersion:
        if not self.git_executable:
            raise GitError(
                "git executable is not available in PATH",
                error_code=ERROR_REPO_NOT_SYNCED,
            )
        result = self._run(["--version"], cwd=None)
        match = re.search(r"git version\s+(\d+)\.(\d+)\.(\d+)", result.stdout)
        if not match:
            raise GitError(
                f"cannot parse git version: {result.stdout.strip()}",
                error_code=ERROR_REPO_NOT_SYNCED,
                result=result,
            )
        return GitVersion(
            raw=result.stdout.strip(),
            major=int(match.group(1)),
            minor=int(match.group(2)),
            patch=int(match.group(3)),
        )

    def ensure_clone(self, *, supports_sparse: bool) -> None:
        if (self.cache_root / ".git").exists():
            return
        if self.cache_root.exists():
            raise GitError(
                f"cache root exists but is not a git repository: {self.cache_root}",
                error_code=ERROR_REPO_NOT_SYNCED,
            )

        clone_args = ["clone", self.repo_url, str(self.cache_root)]
        if supports_sparse:
            clone_args = [
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                self.repo_url,
                str(self.cache_root),
            ]
        self._run(clone_args, cwd=None)
        self.set_origin_url(repo_url_without_credentials(self.repo_url))
        if supports_sparse:
            self._run(["sparse-checkout", "init", "--cone"], cwd=self.cache_root)
            self._run(["sparse-checkout", "set", *self.sparse_paths], cwd=self.cache_root)

    def set_origin_url(self, repo_url: str) -> None:
        self._run(["remote", "set-url", "origin", repo_url], cwd=self.cache_root)

    def refresh_latest(self, default_branch: str) -> None:
        self._run(["fetch", "origin"], cwd=self.cache_root)
        self._run(["checkout", default_branch], cwd=self.cache_root)
        self._run(["pull", "--ff-only", "origin", default_branch], cwd=self.cache_root)

    def refresh_pinned(self, ref: str) -> None:
        self._run(["fetch", "origin", "--tags"], cwd=self.cache_root)
        self._run(["checkout", ref], cwd=self.cache_root)

    def detect_default_branch(self, fallback: str) -> str:
        result = self._run(
            ["symbolic-ref", "--quiet", "--short", "refs/remotes/origin/HEAD"],
            cwd=self.cache_root,
            check=False,
        )
        if result.returncode != 0:
            return fallback
        branch = result.stdout.strip()
        if branch.startswith("origin/"):
            branch = branch.removeprefix("origin/")
        return branch or fallback

    def commit_sha(self) -> str:
        result = self._run(["rev-parse", "HEAD"], cwd=self.cache_root)
        return result.stdout.strip()

    def _run(
        self,
        args: Sequence[str],
        *,
        cwd: Path | None,
        check: bool = True,
    ) -> GitCommandResult:
        if not self.git_executable:
            raise GitError(
                "git executable is not available in PATH",
                error_code=ERROR_REPO_NOT_SYNCED,
            )
        command = [self.git_executable, *args]
        try:
            completed = subprocess.run(
                command,
                cwd=str(cwd) if cwd else None,
                text=True,
                capture_output=True,
                timeout=self.timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            result = GitCommandResult(
                args=tuple(args),
                returncode=124,
                stdout=exc.stdout or "",
                stderr=exc.stderr or "git command timed out",
            )
            raise GitError(
                "git command timed out",
                error_code=ERROR_GIT_NETWORK_ERROR,
                result=result,
            ) from exc
        except OSError as exc:
            raise GitError(
                f"cannot execute git: {exc}",
                error_code=ERROR_REPO_NOT_SYNCED,
            ) from exc

        result = GitCommandResult(
            args=tuple(args),
            returncode=completed.returncode,
            stdout=redact_sensitive(completed.stdout),
            stderr=redact_sensitive(completed.stderr),
        )
        if check and result.returncode != 0:
            raise GitError(
                _summarize_failure(result),
                error_code=_classify_git_error(result),
                result=result,
            )
        return result


def _summarize_failure(result: GitCommandResult) -> str:
    text = (result.stderr or result.stdout or "git command failed").strip()
    first_line = text.splitlines()[0] if text else "git command failed"
    return redact_sensitive(first_line)


def _classify_git_error(result: GitCommandResult) -> str:
    text = f"{result.stdout}\n{result.stderr}".lower()
    auth_keywords = (
        "permission denied",
        "authentication failed",
        "auth failed",
        "publickey",
        "could not read from remote repository",
        "repository not found",
    )
    if any(keyword in text for keyword in auth_keywords):
        return ERROR_GIT_AUTH_FAILED

    network_keywords = (
        "could not resolve hostname",
        "failed to connect",
        "connection timed out",
        "network is unreachable",
        "no route to host",
        "temporary failure",
        "connection refused",
        "connection reset",
        "tls",
        "ssl",
        "unable to access",
        "timeout",
    )
    if any(keyword in text for keyword in network_keywords):
        return ERROR_GIT_NETWORK_ERROR
    return ERROR_REPO_NOT_SYNCED


def sparse_fallback_warning(version: GitVersion) -> dict[str, str]:
    return {
        "warning_code": WARNING_SPARSE_FALLBACK,
        "message": (
            f"git {version.raw} is older than 2.25; atomic-ops will use a full checkout "
            "instead of sparse-checkout"
        ),
    }
