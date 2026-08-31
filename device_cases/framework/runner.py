"""Subprocess driver for `python -m atomic_ops.cli run ...`."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from .envelope import RunOutcome, parse_run

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent  # .../device_cases/framework -> ptm-atomic
SRC_DIR = PROJECT_ROOT / "src"


def _cli_env() -> dict[str, str]:
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = str(SRC_DIR) + (os.pathsep + existing if existing else "")
    return env


class CliRunner:
    """Runs the ptm-atomic CLI as a subprocess against a device.

    ``--execute`` lives at the run group level and MUST be placed before the
    family subcommand; this class always does so.
    """

    def __init__(
        self,
        *,
        base_url: str,
        session_file: Path,
        execute: bool,
        verify_tls: bool = False,
        timeout: float = 30.0,
    ) -> None:
        self.base_url = base_url
        self.session_file = session_file
        self.execute = execute
        self.verify_tls = verify_tls
        self.timeout = timeout

    def _base_cmd(self) -> list[str]:
        cmd = [
            sys.executable,
            "-m",
            "atomic_ops.cli",
            "run",
            "--base-url",
            self.base_url,
            "--session-file",
            str(self.session_file),
            "--format",
            "json",
        ]
        if self.execute:
            cmd.append("--execute")
        if not self.verify_tls:
            cmd.append("--no-verify-tls")
        return cmd

    def run(
        self,
        family: str,
        action: str,
        *,
        env: dict[str, str] | None = None,
        **options: Any,
    ) -> RunOutcome:
        """Invoke `run <family> <action>` with the given options.

        Option keys are converted to CLI flags by swapping `_` for `-`
        (``object_name`` -> ``--object-name``). List values are repeated
        flag+value pairs for append-style args; a bare ``True`` emits the flag
        with no value; ``None``/``False`` emit nothing.
        """
        cmd = self._base_cmd() + [family, action]
        for key, value in options.items():
            flag = f"--{key.replace('_', '-')}"
            if value is None or value is False:
                continue
            if value is True:
                cmd.append(flag)
            elif isinstance(value, (list, tuple)):
                for item in value:
                    cmd.append(flag)
                    cmd.append(str(item))
            else:
                cmd.append(flag)
                cmd.append(str(value))

        run_env = dict(_cli_env())
        if env:
            run_env.update(env)

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=run_env,
                timeout=self.timeout,
            )
        except subprocess.TimeoutExpired:
            return RunOutcome(
                exit_code=-1,
                success=False,
                status="timeout",
                error={"error_code": "SUBPROCESS_TIMEOUT", "message": f"cli did not finish within {self.timeout}s"},
            )
        return parse_run(proc)
