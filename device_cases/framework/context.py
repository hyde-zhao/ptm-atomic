"""Per-run context handed to every case: CLI runner + SSH device + config."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .runner import CliRunner
from .ssh_device import SSHDevice


@dataclass
class CaseContext:
    execute: bool
    device: str
    session_file: Path
    ssh_session_file: Path
    web_password_env: str
    root_password_env: str
    verify_tls: bool
    timeout: float
    runner: CliRunner
    ssh: SSHDevice
    report_dir: Path

    @property
    def base_url(self) -> str:
        return f"https://{self.device}"
