"""`fw_check_bridge_domain` 的可选 BD 作用域（--bridge-domain-id）契约锁。

背景（现场 exec-20260923-bvi-full）：BVI 用例的后置普遍写
``fw_check_bridge_domain args={bridge_domain_id: 10}``，但该 op 只支持全表查询，
参数无 CLI 出口 → op_mapper 判 PARAM_INVALID，7 条用例恒失败。

本文件锁两件事：
  1. 给了 ``bridge_domain_id`` 时命令收敛到 ``vppctl show bridge-domain <id>``，
     成功判据换成表头锚点 ``BD-ID``（目标 BD 不存在 → 无表头 → STATE_MISMATCH）；
  2. 不给 id 时命令/判据与改造前**完全一致**（全表 + ``\\S+``），不破坏既有调用。
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from atomic_ops.runner import ssh  # noqa: E402
from atomic_ops.runner.errors import RunnerError  # noqa: E402

SESSION = Path("/nonexistent/session.json")

BD_TABLE = "\n".join(
    [
        "BD-ID  Index  BSN  Age(min)  Learning  BVI-Intf  HA-F",
        "10     1      0    5         1         1         0",
    ]
)

# 表头缺失的形态：目标 BD 不存在时 vppctl 不回表头行
BD_MISSING = "no bridge-domain with id 10"


class _Harness(unittest.TestCase):
    BASE = dict(
        base_url="https://192.0.2.1",
        session_file=SESSION,
        transport="ssh",
        host=None,
        port=None,
    )

    def _dry_run(self, **extra):
        with patch.object(ssh, "read_session_file", return_value={"username": "admin"}):
            return ssh.build_check_bridge_domain_dry_run(
                **self.BASE, timeout=10.0, **extra
            )

    def _execute(self, stdout: str, **extra):
        fake = SimpleNamespace(exit_code=0, stdout=stdout, stderr="")
        with (
            patch.object(ssh, "read_session_file", return_value={"username": "admin"}),
            patch.object(ssh, "_read_credential_env", return_value="secret"),
            patch.object(ssh, "_run_shell_command", return_value=fake),
        ):
            return ssh.execute_check_bridge_domain(
                **self.BASE,
                credential_env="FW_SSH_PASSWORD",
                timeout=10.0,
                **extra,
            )


class ScopedDryRunTests(_Harness):
    def test_default_keeps_whole_table_command_and_pattern(self) -> None:
        request = self._dry_run()["request"]
        self.assertEqual(request["command"], ssh.BRIDGE_DOMAIN_COMMAND)
        self.assertEqual(
            request["success_pattern"], ssh.BRIDGE_DOMAIN_SUCCESS_PATTERN
        )

    def test_bridge_domain_id_scopes_command_and_tightens_pattern(self) -> None:
        request = self._dry_run(bridge_domain_id=10)["request"]
        self.assertIn("show bridge-domain", request["command"])
        self.assertIn("10", request["command"])
        self.assertEqual(
            request["success_pattern"], ssh.BRIDGE_DOMAIN_SHOW_SUCCESS_PATTERN
        )
        # 全表用的 \S+ 会放过任何非空输出，scoped 形态不许再用
        self.assertNotEqual(
            request["success_pattern"], ssh.BRIDGE_DOMAIN_SUCCESS_PATTERN
        )

    def test_out_of_range_id_is_rejected_before_connecting(self) -> None:
        for bad in (0, 4095, -1):
            with self.subTest(bridge_domain_id=bad):
                with self.assertRaises(RunnerError) as caught:
                    self._dry_run(bridge_domain_id=bad)
                self.assertEqual(caught.exception.error_code, "RUNNER_VALIDATION_FAILED")


class ScopedExecuteTests(_Harness):
    def test_default_still_accepts_arbitrary_non_empty_output(self) -> None:
        r"""不给 id：既有行为不变（\S+，含 shell 横幅类输出）。"""
        result = self._execute("Last login: Mon Sep 22 on ttyAMA0")
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["bridge_domain_raw"])

    def test_identified_bridge_domain_returns_table(self) -> None:
        result = self._execute(BD_TABLE, bridge_domain_id=10)
        self.assertEqual(result["status"], "success")
        self.assertIn("BD-ID", result["bridge_domain_raw"])

    def test_missing_bridge_domain_is_state_mismatch(self) -> None:
        with self.assertRaises(RunnerError) as caught:
            self._execute(BD_MISSING, bridge_domain_id=10)
        self.assertEqual(caught.exception.error_code, "STATE_MISMATCH")

    def test_out_of_range_id_fails_validation(self) -> None:
        with self.assertRaises(RunnerError) as caught:
            self._execute(BD_TABLE, bridge_domain_id=0)
        self.assertEqual(caught.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_atom_declares_the_optional_parameter(self) -> None:
        import yaml

        atom = yaml.safe_load(
            (REPO_ROOT / "atoms" / "fw" / "fw_check_bridge_domain.yaml").read_text(
                encoding="utf-8"
            )
        )
        declared = atom["parameters"]["bridge_domain_id"]
        self.assertEqual(declared["type"], "int")
        self.assertFalse(declared["required"])


if __name__ == "__main__":
    unittest.main()
