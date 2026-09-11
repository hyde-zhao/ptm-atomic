"""process 族 --username 契约测试（P2-30，2026-09-11 下游反馈吸收）。

背景（ptm-te-manaul 反馈 P2-30，现场实证）：
  `fw_verify_process_state` / `fw_kill_process` 的 SSH 用户名此前恒取 Web 会话
  用户名（admin），落到 DUT 的 CLI 交互界面（`DAS-TGFW>`，命令集仅
  auth/clear/ping/reboot/reset/set/show/tcping/trace），`pgrep` / `kill -9`
  根本无法执行 -> 5 条用例的 process 步骤恒 STATE_MISMATCH(exit 52)。
  只有 root + FW_SSH_PASSWORD 才是 Linux shell（uid=0）。

本改动固化契约（对齐 mac-age 族 `--username` 先例，default="root"）：
  - CLI 层：process 族命令注册 `--username`，默认 root
    （进程运维必须 Linux shell，Web 会话用户名是错误来源）；
  - runner 层：显式 username 优先；None 才回退 session 用户名（向后兼容，
    与 `_execute_shell_op` 既有语义一致）；
  - dry-run 预览与 execute 使用同一解析结果，不出现"预览 root / 执行 admin"错配。

全部本地 mock，不连设备。
"""

from __future__ import annotations

import argparse
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from atomic_ops.commands import run_cli
from atomic_ops.runner import ssh
from atomic_ops.runner.session import write_session_file


class ProcessArgsRegistrationTests(unittest.TestCase):
    """CLI 层：--username 注册且默认 root（P2-30 根因的入口面）。"""

    def test_verify_process_state_username_defaults_root(self) -> None:
        parser = argparse.ArgumentParser()
        run_cli._add_process_args(parser)
        ns = parser.parse_args(["--process", "vpp"])
        self.assertEqual(ns.username, "root")

    def test_kill_process_username_defaults_root(self) -> None:
        parser = argparse.ArgumentParser()
        run_cli._add_kill_args(parser)
        ns = parser.parse_args(["--process", "vpp", "--pid", "4321"])
        self.assertEqual(ns.username, "root")

    def test_username_can_be_overridden(self) -> None:
        parser = argparse.ArgumentParser()
        run_cli._add_process_args(parser)
        ns = parser.parse_args(["--process", "vpp", "--username", "operator"])
        self.assertEqual(ns.username, "operator")


class _SessionFixture(unittest.TestCase):
    """写一份 username=admin 的 session 文件（模拟 Web 会话产物）。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.session_file = Path(self._tmp.name) / "session.json"
        write_session_file(
            self.session_file,
            base_url="https://192.0.2.1",
            username="admin",
            session_value="abc123",
            source_op_id="fw_login_web_management",
        )


class VerifyProcessStateUsernameTests(_SessionFixture):
    """fw_verify_process_state：dry-run 预览与 execute 的 username 解析。"""

    def _dry_run(self, username: str | None) -> dict:
        return ssh.build_verify_process_state_dry_run(
            base_url="https://192.0.2.1",
            session_file=self.session_file,
            transport="ssh",
            host=None,
            port=None,
            username=username,
            process="vpp",
            timeout=10.0,
        )

    def test_explicit_root_wins_over_session_admin(self) -> None:
        """P2-30 修复语义：显式 root 优先，不再落到 Web 会话的 admin。"""
        result = self._dry_run("root")
        self.assertEqual(result["request"]["username"], "root")

    def test_none_falls_back_to_session_username(self) -> None:
        """向后兼容：未显式传 username 时仍回退 session（既有调用方不破）。"""
        result = self._dry_run(None)
        self.assertEqual(result["request"]["username"], "admin")

    def test_execute_passes_username_to_shell_op(self) -> None:
        """execute 路径把显式 username 透传给底层 shell 执行器。"""
        with patch.object(
            ssh, "_execute_shell_op", return_value={"data": {"pid": "4321"}}
        ) as shell_op:
            result = ssh.execute_verify_process_state(
                base_url="https://192.0.2.1",
                session_file=Path("/nonexistent/session.json"),
                transport="ssh",
                host=None,
                port=None,
                username="root",
                credential_env="FW_SSH_PASSWORD",
                process="vpp",
                timeout=10.0,
            )
        self.assertEqual(shell_op.call_args.kwargs["username"], "root")
        self.assertTrue(result["data"]["running"])
        self.assertEqual(result["data"]["process"], "vpp")


class KillProcessUsernameTests(_SessionFixture):
    """fw_kill_process：dry-run 预览与 execute 的 username 解析。"""

    def test_dry_run_explicit_username_wins(self) -> None:
        result = ssh.build_kill_process_dry_run(
            base_url="https://192.0.2.1",
            session_file=self.session_file,
            transport="ssh",
            host=None,
            port=None,
            username="root",
            process="vpp",
            pid="4321",
            timeout=10.0,
        )
        self.assertEqual(result["request"]["username"], "root")

    def test_dry_run_none_falls_back_to_session(self) -> None:
        result = ssh.build_kill_process_dry_run(
            base_url="https://192.0.2.1",
            session_file=self.session_file,
            transport="ssh",
            host=None,
            port=None,
            username=None,
            process="vpp",
            pid="4321",
            timeout=10.0,
        )
        self.assertEqual(result["request"]["username"], "admin")

    def _execute(self, username: str | None):
        fake = SimpleNamespace(exit_code=0, stdout="", stderr="")
        with patch.object(
            ssh, "read_session_file", return_value={"username": "admin"}
        ), patch.object(ssh, "_read_credential_env", return_value="secret"), patch.object(
            ssh, "_run_shell_command", return_value=fake
        ) as run_shell:
            result = ssh.execute_kill_process(
                base_url="https://192.0.2.1",
                session_file=Path("/nonexistent/session.json"),
                transport="ssh",
                host=None,
                port=None,
                username=username,
                credential_env="FW_SSH_PASSWORD",
                process="vpp",
                pid="4321",
                timeout=10.0,
            )
        return run_shell.call_args.kwargs["username"], result

    def test_execute_explicit_username_wins(self) -> None:
        effective, result = self._execute("root")
        self.assertEqual(effective, "root")
        self.assertTrue(result["data"]["killed"])

    def test_execute_none_falls_back_to_session(self) -> None:
        effective, _ = self._execute(None)
        self.assertEqual(effective, "admin")


if __name__ == "__main__":
    unittest.main()
