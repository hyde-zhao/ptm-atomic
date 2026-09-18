"""STORY-REM-02-03 R1「接线补全」专项单测：五键进入两族批量删除的真实输出体。

返工背景（U-1 / ``RISK-REM-02-03-01``）：STORY-REM-02-03 首轮交付了
``runner/batch.py#batch-result`` 的 ``summarize_batch_result()``（``CT-REM-ATOM-RESULT``
v1.0 五键契约：``count`` / ``success_count`` / ``failed_count`` / ``failed[]`` /
``per_item_result``），但两族批量删除的返回构造处**未接线** —— CLI 层输出体没有五键。
本 R1 在 ``policy_route.py`` / ``interface.py`` 的 ``execute_*`` 返回构造处补**调用点**
（区域 ``#batch-result``）；本文件锁定该接线行为（契约本体语义仍由
``tests/test_batch_result.py`` 的 UT-BULK-06①~④ 覆盖）。

覆盖：
- UT-BULK-06e1/e2/e3：**CLI 端到端**（``cli_main`` + 打桩 HTTP）—— 逐条可得 -> 五键
  可采信（``per_item_result: true``）；设备不返回逐条结果 -> ``per_item_result: false``
  + 计数 ``null``（**null != 0**）+ ``failed: []``（两族各一组）；
- UT-BULK-06f：追加式 —— 既有键逐键不变、只新增五键；非批量 op 零五键；
- UT-BULK-06g：``per_id_item`` 承载形态（兼容回退）与 ``single_item`` 计数一致；
- UT-BULK-06h：载荷非批量形态 -> fail-loud（``RUNNER_VALIDATION_FAILED``，
  不产出 ``count: 0`` 的非法契约体）。

全程离线：HTTP 层打桩（``patch("<module>.request_json")``）、session 文件沙箱
（临时目录，写盘即 0600）、exec-log 沙箱（``XDG_STATE_HOME`` 临时目录）；
无设备 / 无网络 / 无凭据 / 无真实运行。
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from atomic_ops.cli import main as cli_main
from atomic_ops.runner.batch import build_batch_delete_payload
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.interface import build_interface_batch_delete_payload, execute_interface
from atomic_ops.runner.policy_route import (
    build_policy_route_batch_delete_payload,
    execute_policy_route,
)
from atomic_ops.runner.session import write_session_file

BASE_URL = "https://192.0.2.1"
POLICY_ROUTE_BATCH_OP = "fw_delete_batch_policy_route"
INTERFACE_BATCH_OP = "fw_delete_batch_interface"

# ``CT-REM-ATOM-RESULT`` v1.0 五键（本 R1 接线后必须出现在两族批量删除的输出体）。
CONTRACT_KEYS = ("count", "success_count", "failed_count", "failed", "per_item_result")
# 接线前两族执行结果的既有键（追加式：本 R1 不得改动其中任何一键）。
EXISTING_RESULT_KEYS = ("op_id", "status", "status_code", "request", "response")
# 逐条可得形态（2 条请求：1 成功 / 1 失败，形状对齐 adapters/ngfw/default.yaml 声明）。
PER_ITEM_RESPONSE = {
    "BatchResult": [
        {"msg": "success"},
        {"msg": "delete failed", "errCode": "eNotFound"},
    ]
}
# 设备不返回逐条结果形态（仓内声明的成功响应）。
NO_PER_ITEM_RESPONSE = {"msg": "success"}


def _make_session(temp_dir: str) -> Path:
    session_file = Path(temp_dir) / "session.json"
    write_session_file(
        session_file,
        base_url=BASE_URL,
        username="admin",
        session_value="abc123",
        source_op_id="fw_login_web_management",
    )
    return session_file


class _WiringHarness(unittest.TestCase):
    """共用夹具：临时 session 文件 + exec-log 状态目录沙箱（零真实运行）。"""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self._prev_state_home = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = self._tmp.name
        self.addCleanup(self._restore_state_home)
        self.session_file = _make_session(self._tmp.name)

    def _restore_state_home(self) -> None:
        if self._prev_state_home is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = self._prev_state_home
        self._tmp.cleanup()

    def _cli(
        self, module_path: str, argv: list[str], response: dict
    ) -> tuple[int, dict | None, str]:
        """CLI 端到端：真实参数解析 -> payload 构造 -> execute（HTTP 打桩）。"""
        stdout = io.StringIO()
        stderr = io.StringIO()
        with patch(f"{module_path}.request_json", return_value=(200, response, "")):
            with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                exit_code = cli_main(
                    [
                        "run", "--format", "json", "--base-url", BASE_URL,
                        "--session-file", str(self.session_file), "--execute", *argv,
                    ]
                )
        raw = stdout.getvalue().strip() or stderr.getvalue().strip()
        payload = json.loads(raw.splitlines()[-1]) if raw else None
        return exit_code, payload, stderr.getvalue()

    def _execute_policy_route(
        self, payload: dict | None, response: dict, op_id: str = POLICY_ROUTE_BATCH_OP
    ) -> dict:
        with patch(
            "atomic_ops.runner.policy_route.request_json",
            return_value=(200, response, ""),
        ):
            return execute_policy_route(
                op_id=op_id,
                base_url=BASE_URL,
                session_file=self.session_file,
                auth_header="Authorization",
                payload=payload,
                page=1,
                size=40,
                route_type="ipv4",
                verify_tls=False,
                timeout=10,
            )

    def _execute_interface(
        self, payload: dict | None, response: dict, op_id: str = INTERFACE_BATCH_OP
    ) -> dict:
        with patch(
            "atomic_ops.runner.interface.request_json",
            return_value=(200, response, ""),
        ):
            return execute_interface(
                op_id=op_id,
                base_url=BASE_URL,
                session_file=self.session_file,
                auth_header="Authorization",
                payload=payload,
                verify_tls=False,
                timeout=10,
            )


class BatchResultWiringCliTests(_WiringHarness):
    """UT-BULK-06e：CLI 端到端 —— 五键真的出现在输出信封 data 内。"""

    def test_ut_bulk_06e1_policy_route_per_item_true(self) -> None:
        """逐条结果与请求条目一一对应 -> 五键可采信（true + 计数 + failed[]）。"""
        exit_code, payload, stderr = self._cli(
            "atomic_ops.runner.policy_route",
            ["policy-route", "delete-batch", "--id", "1", "--id", "2"],
            PER_ITEM_RESPONSE,
        )
        self.assertEqual(exit_code, 0, stderr)
        self.assertEqual(payload["status"], "success")
        data = payload["data"]
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["success_count"], 1)
        self.assertEqual(data["failed_count"], 1)
        self.assertIs(data["per_item_result"], True)
        self.assertEqual(
            data["failed"],
            [
                {
                    "index": 2,
                    "status": "failed",
                    "error_code": "eNotFound",
                    "message": "delete failed",
                }
            ],
        )

    def test_ut_bulk_06e2_policy_route_no_per_item_false_null_not_zero(self) -> None:
        """设备不返回逐条结果 -> false + 计数 null（**null != 0**）+ failed == []。"""
        exit_code, payload, stderr = self._cli(
            "atomic_ops.runner.policy_route",
            ["policy-route", "delete-batch", "--id", "1", "--id", "2"],
            NO_PER_ITEM_RESPONSE,
        )
        self.assertEqual(exit_code, 0, stderr)
        data = payload["data"]
        self.assertEqual(data["count"], 2)
        self.assertIsNone(data["success_count"])
        self.assertIsNone(data["failed_count"])
        self.assertNotEqual(data["success_count"], 0)
        self.assertNotEqual(data["failed_count"], 0)
        self.assertEqual(data["failed"], [])
        self.assertIs(data["per_item_result"], False)

    def test_ut_bulk_06e3_interface_per_item_true(self) -> None:
        exit_code, payload, stderr = self._cli(
            "atomic_ops.runner.interface",
            ["interface", "delete-batch", "--id", "bvi1", "--id", "bvi2"],
            PER_ITEM_RESPONSE,
        )
        self.assertEqual(exit_code, 0, stderr)
        data = payload["data"]
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["success_count"], 1)
        self.assertEqual(data["failed_count"], 1)
        self.assertIs(data["per_item_result"], True)
        self.assertEqual(data["failed"][0]["index"], 2)

    def test_ut_bulk_06e4_interface_no_per_item_false(self) -> None:
        exit_code, payload, stderr = self._cli(
            "atomic_ops.runner.interface",
            ["interface", "delete-batch", "--id", "bvi1", "--id", "bvi2"],
            NO_PER_ITEM_RESPONSE,
        )
        self.assertEqual(exit_code, 0, stderr)
        data = payload["data"]
        self.assertEqual(data["count"], 2)
        self.assertIsNone(data["success_count"])
        self.assertIsNone(data["failed_count"])
        self.assertEqual(data["failed"], [])
        self.assertIs(data["per_item_result"], False)


class BatchResultWiringAdditiveTests(_WiringHarness):
    """UT-BULK-06f：追加式扩展 —— 既有键逐键不变，只新增五键。"""

    def test_ut_bulk_06f1_policy_route_existing_keys_unchanged(self) -> None:
        response = dict(NO_PER_ITEM_RESPONSE)
        result = self._execute_policy_route(
            build_policy_route_batch_delete_payload(entry_ids=["1", "2"]), response
        )
        self.assertEqual(result["op_id"], POLICY_ROUTE_BATCH_OP)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(
            result["request"],
            {
                "method": "POST",
                "path": "/api/v1/batch",
                "auth": {"name": "Authorization", "value": "<session-ref>"},
            },
        )
        self.assertIs(result["response"], response)
        # 只新增五键：既有键零增删（追加式硬规则）。
        self.assertEqual(set(result) - set(EXISTING_RESULT_KEYS), set(CONTRACT_KEYS))
        self.assertEqual(set(result), set(EXISTING_RESULT_KEYS) | set(CONTRACT_KEYS))

    def test_ut_bulk_06f2_interface_existing_keys_unchanged(self) -> None:
        response = dict(NO_PER_ITEM_RESPONSE)
        result = self._execute_interface(
            build_interface_batch_delete_payload(entry_ids=["bvi1", "bvi2"]), response
        )
        self.assertEqual(result["op_id"], INTERFACE_BATCH_OP)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["request"]["method"], "POST")
        self.assertEqual(result["request"]["path"], "/api/v1/batch")
        self.assertIs(result["response"], response)
        # 非 PPPoE 批量删除不出现 password_encrypted 键（既有语义不变）。
        self.assertNotIn("password_encrypted", result)
        self.assertEqual(set(result), set(EXISTING_RESULT_KEYS) | set(CONTRACT_KEYS))

    def test_ut_bulk_06f3_non_batch_ops_keep_old_shape(self) -> None:
        """接线面收窄到批量删除：单条 delete / verify 的输出体零五键。"""
        single_delete = self._execute_policy_route(
            {"id": 5}, NO_PER_ITEM_RESPONSE, op_id="fw_delete_policy_route"
        )
        self.assertFalse(set(CONTRACT_KEYS) & set(single_delete))

        verify = self._execute_interface(
            None, {"vals": []}, op_id="fw_verify_interface"
        )
        self.assertFalse(set(CONTRACT_KEYS) & set(verify))


class BatchResultWiringCountTests(_WiringHarness):
    """UT-BULK-06g/h：请求侧计数推导（两种承载形态）与 fail-loud 边界。"""

    def test_ut_bulk_06g1_per_id_item_carrier_count_matches(self) -> None:
        per_id_payload = build_batch_delete_payload(
            entry_ids=["1", "2", "3"],
            resource="/api/v1/policyroute",
            is_ip6_values=["false", "false", "false"],
            carrier="per_id_item",
        )
        self.assertEqual(len(per_id_payload["batch"]), 3)
        result = self._execute_policy_route(per_id_payload, NO_PER_ITEM_RESPONSE)
        self.assertEqual(result["count"], 3)
        self.assertIsNone(result["success_count"])
        self.assertIs(result["per_item_result"], False)

    def test_ut_bulk_06g2_interface_per_id_item_carrier_count_matches(self) -> None:
        per_id_payload = build_batch_delete_payload(
            entry_ids=["bvi1", "bvi2"],
            resource="/api/v1/intf",
            carrier="per_id_item",
        )
        result = self._execute_interface(per_id_payload, NO_PER_ITEM_RESPONSE)
        self.assertEqual(result["count"], 2)
        self.assertIs(result["per_item_result"], False)

    def test_ut_bulk_06h_degenerate_payload_fails_loud(self) -> None:
        """非批量载荷 -> 计数不可得 -> helper fail-loud（不产出 count: 0）。"""
        for op_id, module_path, kwargs in (
            (
                POLICY_ROUTE_BATCH_OP,
                "atomic_ops.runner.policy_route",
                dict(page=1, size=40, route_type="ipv4"),
            ),
            (INTERFACE_BATCH_OP, "atomic_ops.runner.interface", {}),
        ):
            with self.subTest(op_id=op_id):
                execute = (
                    execute_policy_route
                    if op_id == POLICY_ROUTE_BATCH_OP
                    else execute_interface
                )
                with patch(f"{module_path}.request_json", return_value=(200, {}, "")):
                    with self.assertRaises(RunnerError) as ctx:
                        execute(
                            op_id=op_id,
                            base_url=BASE_URL,
                            session_file=self.session_file,
                            auth_header="Authorization",
                            payload=None,
                            verify_tls=False,
                            timeout=10,
                            **kwargs,
                        )
                self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")
                self.assertEqual(ctx.exception.details.get("field"), "count")


if __name__ == "__main__":
    unittest.main()
