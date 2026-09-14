"""`--credential-env` 默认值推导回归测试（上游台账 §3.3 建议 1）。

契约（`run_cli --credential-env` 的 help 原文）：

    "defaults to the operation's credential key (FW_WEB_PASSWORD for admin ops,
     FW_SSH_PASSWORD for root vppctl ops)"

此前实现是「--execute 时必需」（前置 `RUNNER_CREDENTIAL_MISSING`），与文案不符：
默认登录身份每变一次，调用方就要全量刷用例（现场 P2-30 把进程类 op 的默认身份
由 admin 改为 root 后，用例侧 `credential_env` 全部要跟着改）。

本测试固化两条：
  1. 不显式给 `--credential-env` 时按**生效登录身份**推导 ——
     root -> FW_SSH_PASSWORD；admin / 未声明（None）-> FW_WEB_PASSWORD；
  2. 显式传入的值始终优先（推导只是兜底，不改既有显式用法）。

不触真实设备/凭据/网络：runner 函数与 run context 全部 mock。
"""

from __future__ import annotations

import argparse
import contextlib
import io
import unittest
from pathlib import Path
from unittest import mock

from atomic_ops.commands import run_cli
from atomic_ops.commands.run_cli import _default_credential_env


class DefaultCredentialEnvDerivationTests(unittest.TestCase):
    """纯推导函数：身份 -> 凭据键。"""

    def test_root_derives_ssh_password(self) -> None:
        self.assertEqual(_default_credential_env("root"), "FW_SSH_PASSWORD")

    def test_root_with_surrounding_space_derives_ssh_password(self) -> None:
        self.assertEqual(_default_credential_env(" root "), "FW_SSH_PASSWORD")

    def test_admin_derives_web_password(self) -> None:
        self.assertEqual(_default_credential_env("admin"), "FW_WEB_PASSWORD")

    def test_unspecified_identity_derives_web_password(self) -> None:
        """未声明 --username 的 op 走会话身份（admin）-> Web 口令。"""
        self.assertEqual(_default_credential_env(None), "FW_WEB_PASSWORD")
        self.assertEqual(_default_credential_env(""), "FW_WEB_PASSWORD")


class CredentialEnvCliExecuteTests(unittest.TestCase):
    """CLI 层：execute 路径不再要求显式 --credential-env，改用推导默认值。"""

    _CTX = {
        "execute": True,
        "base_url": "https://192.0.2.1",
        "output_format": "json",
        "session_file": "/tmp/does-not-matter.json",
    }

    def _invoke(self, handler, namespace, runner_fn_name: str):
        """跑 handler（execute 路径），返回 (rc, mock 的 runner 函数)。"""
        with mock.patch.object(run_cli, "resolve_run_context", return_value=dict(self._CTX)), \
                mock.patch.object(run_cli, "resolve_session_file",
                                  return_value=Path("/tmp/does-not-matter.json")), \
                mock.patch.object(run_cli, "_to_run_envelope", return_value={}), \
                mock.patch.object(run_cli, "_write_output"), \
                mock.patch(f"atomic_ops.runner.ssh.{runner_fn_name}",
                           return_value={"status": "success", "data": {}}) as runner_fn, \
                contextlib.redirect_stdout(io.StringIO()):
            rc = handler(namespace)
        return rc, runner_fn

    def test_verify_process_state_defaults_to_ssh_password(self) -> None:
        """进程类 op：--username 默认 root -> 默认取 FW_SSH_PASSWORD。"""
        ns = argparse.Namespace(
            transport="ssh", host=None, port=None, process="vpp",
            username="root", credential_env=None,
        )
        rc, runner_fn = self._invoke(
            run_cli._run_verify_process_state, ns, "execute_verify_process_state")
        self.assertEqual(rc, 0)
        self.assertEqual(runner_fn.call_args.kwargs["credential_env"], "FW_SSH_PASSWORD")

    def test_verify_neighbor_probe_defaults_to_web_password(self) -> None:
        """未声明身份的 op（username=None，走会话 admin）-> 默认取 FW_WEB_PASSWORD。"""
        ns = argparse.Namespace(
            transport="ssh", host=None, port=None, username=None, credential_env=None,
        )
        rc, runner_fn = self._invoke(
            run_cli._run_verify_neighbor_probe, ns, "execute_verify_neighbor_probe")
        self.assertEqual(rc, 0)
        self.assertEqual(runner_fn.call_args.kwargs["credential_env"], "FW_WEB_PASSWORD")

    def test_explicit_credential_env_still_wins(self) -> None:
        """显式值优先于推导（既有用法零变化）。"""
        ns = argparse.Namespace(
            transport="ssh", host=None, port=None, process="vpp",
            username="root", credential_env="MY_CUSTOM_SECRET",
        )
        rc, runner_fn = self._invoke(
            run_cli._run_verify_process_state, ns, "execute_verify_process_state")
        self.assertEqual(rc, 0)
        self.assertEqual(runner_fn.call_args.kwargs["credential_env"], "MY_CUSTOM_SECRET")


if __name__ == "__main__":
    unittest.main()
