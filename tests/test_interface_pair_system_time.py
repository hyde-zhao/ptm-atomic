"""接口对与系统时间原子操作回归测试（离线：构造 + dry-run + mock 设备响应）。

覆盖：
- 接口对 create/update/delete 载荷构造与校验（id/name 一致性、必填字段、类型）；
- GET /api/v1/intf/pair 的客户端过滤、分页切片与字段保留；
- 系统时间 vals[0] 解析与 expected_date/expected_time 断言；
- CLI ``run interface pair-*`` / ``run system time-verify`` dry-run 路径；
- L2 顺序：先 Switch/BVI 配置，再创建接口对（mock/adapter 级最小序列）。
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from atomic_ops.cli import main as cli_main
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.interface import build_interface_payload
from atomic_ops.runner.interface_pair import (
    build_interface_pair_dry_run,
    build_interface_pair_filters,
    build_interface_pair_payload,
    build_interface_pair_update_payload,
    execute_interface_pair,
    validate_interface_pair_payload,
)
from atomic_ops.runner.session import write_session_file
from atomic_ops.runner.system_time import (
    build_system_time_dry_run,
    execute_system_time,
)

BASE_URL = "https://192.0.2.1"
PAIR_ATOM = Path(__file__).resolve().parents[1] / "atoms/fw/fw_config_interface_pair.yaml"


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


class _CliHarness(unittest.TestCase):
    def _cli(self, argv: list[str]) -> tuple[int, dict | None, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(["run", "--format", "json", "--base-url", BASE_URL, *argv])
        raw = stdout.getvalue().strip() or stderr.getvalue().strip()
        payload = json.loads(raw.splitlines()[-1]) if raw else None
        return exit_code, payload, stderr.getvalue()


class InterfacePairPayloadTests(unittest.TestCase):
    def test_create_payload_uses_val_envelope(self) -> None:
        payload = build_interface_pair_payload(
            name="pair1",
            receive_interface="GE0_1",
            transmit_interface="GE0_2",
        )
        self.assertEqual(
            payload,
            {
                "val": {
                    "name": "pair1",
                    "remark": "",
                    "receive_interface": "GE0_1",
                    "transmit_interface": "GE0_2",
                    "status_sync": False,
                    "allowed_vlan": "0",
                }
            },
        )

    def test_update_payload_carries_id_and_full_val(self) -> None:
        payload = build_interface_pair_update_payload(
            entry_id="pair1",
            receive_interface="GE0_1",
            transmit_interface="GE0_2",
            remark="updated",
            status_sync=True,
            allowed_vlan="1-4094",
        )
        self.assertEqual(payload["id"], "pair1")
        self.assertEqual(payload["val"]["name"], "pair1")
        self.assertEqual(payload["val"]["allowed_vlan"], "1-4094")
        self.assertTrue(payload["val"]["status_sync"])

    def test_update_name_defaults_to_id(self) -> None:
        payload = build_interface_pair_update_payload(
            entry_id="pair1",
            receive_interface="GE0_1",
            transmit_interface="GE0_2",
        )
        self.assertEqual(payload["val"]["name"], "pair1")

    def test_update_rejects_id_name_mismatch(self) -> None:
        with self.assertRaises(RunnerError):
            build_interface_pair_update_payload(
                entry_id="pair1",
                name="pair2",
                receive_interface="GE0_1",
                transmit_interface="GE0_2",
            )

    def test_integer_allowed_vlan_is_normalized(self) -> None:
        payload = build_interface_pair_payload(
            name="pair1",
            receive_interface="GE0_1",
            transmit_interface="GE0_2",
            allowed_vlan=0,
        )
        self.assertEqual(payload["val"]["allowed_vlan"], "0")

    def test_missing_interface_is_rejected(self) -> None:
        with self.assertRaises(RunnerError):
            build_interface_pair_payload(
                name="pair1",
                receive_interface="",
                transmit_interface="GE0_2",
            )

    def test_non_boolean_status_sync_is_rejected(self) -> None:
        with self.assertRaises(RunnerError):
            build_interface_pair_payload(
                name="pair1",
                receive_interface="GE0_1",
                transmit_interface="GE0_2",
                status_sync="true",  # type: ignore[arg-type]
            )

    def test_create_raw_payload_rejects_top_level_id(self) -> None:
        with self.assertRaises(RunnerError):
            validate_interface_pair_payload(
                {
                    "id": "pair1",
                    "val": {
                        "name": "pair1",
                        "receive_interface": "GE0_1",
                        "transmit_interface": "GE0_2",
                    },
                },
                op_id="fw_config_interface_pair",
            )

    def test_update_raw_payload_defaults_name_to_id(self) -> None:
        payload = validate_interface_pair_payload(
            {
                "id": "pair1",
                "val": {
                    "receive_interface": "GE0_1",
                    "transmit_interface": "GE0_2",
                },
            },
            op_id="fw_update_interface_pair",
        )
        self.assertEqual(payload["val"]["name"], "pair1")
        self.assertEqual(payload["val"]["allowed_vlan"], "0")

    def test_delete_requires_non_empty_id(self) -> None:
        with self.assertRaises(RunnerError):
            validate_interface_pair_payload(
                {"id": "   "}, op_id="fw_delete_interface_pair"
            )

    def test_filters_are_exact_match_values(self) -> None:
        filters = build_interface_pair_filters(
            name="pair1",
            receive_interface="GE0_1",
            transmit_interface=None,
        )
        self.assertEqual(filters, {"name": "pair1", "receive_interface": "GE0_1"})

    def test_empty_filter_is_rejected(self) -> None:
        with self.assertRaises(RunnerError):
            build_interface_pair_filters(name=" ")


class InterfacePairNameRuleTests(unittest.TestCase):
    """接口对名称规则（2026-10-21 设备实测）：中文/字母/数字/-/.，1-31，无下划线。"""

    def test_create_accepts_valid_names(self) -> None:
        for name in ("pair1", "pair-1.2", "接口对1", "A" * 31):
            with self.subTest(name=name):
                payload = build_interface_pair_payload(
                    name=name,
                    receive_interface="GE0_1",
                    transmit_interface="GE0_2",
                )
                self.assertEqual(payload["val"]["name"], name)

    def test_create_rejects_underscore_name(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_interface_pair_payload(
                name="pair_1",
                receive_interface="GE0_1",
                transmit_interface="GE0_2",
            )
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")
        self.assertIn("underscores are not allowed", ctx.exception.message)
        self.assertEqual(ctx.exception.details["value"], "pair_1")

    def test_create_rejects_name_longer_than_31(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_interface_pair_payload(
                name="a" * 32,
                receive_interface="GE0_1",
                transmit_interface="GE0_2",
            )
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_update_rejects_underscore_name(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_interface_pair_update_payload(
                entry_id="pair_1",
                receive_interface="GE0_1",
                transmit_interface="GE0_2",
            )
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_raw_payload_rejects_underscore_name(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            validate_interface_pair_payload(
                {
                    "val": {
                        "name": "pair_1",
                        "receive_interface": "GE0_1",
                        "transmit_interface": "GE0_2",
                    }
                },
                op_id="fw_config_interface_pair",
            )
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_delete_keeps_non_empty_id_rule(self) -> None:
        # 删除只要求 id 非空；名称规则由创建/更新入口负责（任务范围）。
        payload = validate_interface_pair_payload(
            {"id": "pair_1"}, op_id="fw_delete_interface_pair"
        )
        self.assertEqual(payload, {"id": "pair_1"})


class InterfacePairExecuteTests(unittest.TestCase):
    def test_verify_without_filters_projects_known_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            response = {
                "count": 1,
                "vals": [
                    {
                        "id": "pair1",
                        "name": "pair1",
                        "remark": "r",
                        "receive_interface": "GE0_1",
                        "transmit_interface": "GE0_2",
                        "allowed_vlan": "0",
                        "status_sync": False,
                        "config_source": 1,
                        "create_time": "2026-10-21 12:00:00",
                    }
                ],
            }
            with patch(
                "atomic_ops.runner.interface_pair.request_json",
                return_value=(200, response, ""),
            ) as request_mock:
                result = execute_interface_pair(
                    op_id="fw_verify_interface_pair",
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=None,
                    verify_tls=False,
                    timeout=5.0,
                    query={"page": 1, "size": 20},
                )
        self.assertEqual(result["count"], 1)
        self.assertEqual(
            result["vals"][0],
            {
                "name": "pair1",
                "remark": "r",
                "receive_interface": "GE0_1",
                "transmit_interface": "GE0_2",
                "allowed_vlan": "0",
                "status_sync": False,
                "config_source": 1,
                "create_time": "2026-10-21 12:00:00",
            },
        )
        self.assertNotIn("id", result["vals"][0])
        url = request_mock.call_args.args[1]
        self.assertIn("/api/v1/intf/pair?page=1&size=20", url)

    def test_verify_filters_client_side_and_slices_filtered_result(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            response = {
                "count": 2,
                "vals": [
                    {
                        "name": "pair1",
                        "receive_interface": "GE0_1",
                        "transmit_interface": "GE0_2",
                    },
                    {
                        "name": "pair2",
                        "receive_interface": "GE0_3",
                        "transmit_interface": "GE0_4",
                    },
                ],
            }
            filters = build_interface_pair_filters(receive_interface="GE0_1")
            with patch(
                "atomic_ops.runner.interface_pair.request_json",
                return_value=(200, response, ""),
            ):
                result = execute_interface_pair(
                    op_id="fw_verify_interface_pair",
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=None,
                    verify_tls=False,
                    timeout=5.0,
                    query={"page": 1, "size": 1},
                    filters=filters,
                )
        self.assertTrue(result["filtered"])
        self.assertEqual(result["count"], 1)
        self.assertEqual(len(result["vals"]), 1)
        self.assertEqual(result["vals"][0]["name"], "pair1")

    def test_verify_filter_requires_page_and_size_together(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            filters = build_interface_pair_filters(name="pair1")
            with self.assertRaises(RunnerError) as ctx:
                execute_interface_pair(
                    op_id="fw_verify_interface_pair",
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=None,
                    verify_tls=False,
                    timeout=5.0,
                    query={"page": 1},
                    filters=filters,
                )
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_verify_rejects_non_list_vals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.interface_pair.request_json",
                return_value=(200, {"count": 1, "vals": {"name": "pair1"}}, ""),
            ):
                with self.assertRaises(RunnerError) as ctx:
                    execute_interface_pair(
                        op_id="fw_verify_interface_pair",
                        base_url=BASE_URL,
                        session_file=session_file,
                        auth_header="Authorization",
                        payload=None,
                        verify_tls=False,
                        timeout=5.0,
                    )
        self.assertEqual(ctx.exception.error_code, "RUNNER_RESPONSE_INVALID")

    def test_delete_sends_query_id_and_no_body(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.interface_pair.request_json",
                return_value=(200, {"msg": "success"}, ""),
            ) as request_mock:
                result = execute_interface_pair(
                    op_id="fw_delete_interface_pair",
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload={"id": "pair 1"},
                    verify_tls=False,
                    timeout=5.0,
                )
        self.assertEqual(result["status"], "success")
        self.assertTrue(request_mock.call_args.args[1].endswith("?id=pair+1"))
        self.assertIsNone(request_mock.call_args.kwargs["json_payload"])

    def test_create_success_returns_success_envelope(self) -> None:
        payload = build_interface_pair_payload(
            name="pair1",
            receive_interface="GE0_1",
            transmit_interface="GE0_2",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.interface_pair.request_json",
                return_value=(200, {"msg": "success"}, ""),
            ) as request_mock:
                result = execute_interface_pair(
                    op_id="fw_config_interface_pair",
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=payload,
                    verify_tls=False,
                    timeout=5.0,
                )
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["status_code"], 200)
        self.assertEqual(result["response"], {"msg": "success"})
        self.assertEqual(request_mock.call_args.args[0], "POST")
        self.assertEqual(
            request_mock.call_args.kwargs["json_payload"]["val"]["name"], "pair1"
        )

    def test_duplicate_create_maps_eobjcreateexist(self) -> None:
        payload = build_interface_pair_payload(
            name="pair1",
            receive_interface="GE0_1",
            transmit_interface="GE0_2",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.interface_pair.request_json",
                return_value=(
                    400,
                    {"errCode": "eObjCreateExist", "errMsg": "接口对名称已存在"},
                    "",
                ),
            ):
                with self.assertRaises(RunnerError) as ctx:
                    execute_interface_pair(
                        op_id="fw_config_interface_pair",
                        base_url=BASE_URL,
                        session_file=session_file,
                        auth_header="Authorization",
                        payload=payload,
                        verify_tls=False,
                        timeout=5.0,
                    )
        error = ctx.exception
        self.assertEqual(error.error_code, "RUNNER_CONFIG_REJECTED")
        self.assertEqual(error.details["error_type"], "CONFIG_REJECTED")
        self.assertEqual(error.details["status_code"], 400)
        self.assertEqual(error.details["err_code"], "eObjCreateExist")
        self.assertEqual(error.details["err_msg"], "接口对名称已存在")
        self.assertNotIn("idempotent", error.details)

    def test_update_success_returns_success_envelope(self) -> None:
        payload = build_interface_pair_update_payload(
            entry_id="pair1",
            receive_interface="GE0_1",
            transmit_interface="GE0_2",
            remark="updated",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.interface_pair.request_json",
                return_value=(200, {"msg": "success"}, ""),
            ) as request_mock:
                result = execute_interface_pair(
                    op_id="fw_update_interface_pair",
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=payload,
                    verify_tls=False,
                    timeout=5.0,
                )
        self.assertEqual(result["status"], "success")
        self.assertEqual(request_mock.call_args.args[0], "PUT")
        self.assertEqual(request_mock.call_args.kwargs["json_payload"]["id"], "pair1")

    def test_duplicate_update_name_maps_eobjcreateexist(self) -> None:
        payload = build_interface_pair_update_payload(
            entry_id="pair1",
            receive_interface="GE0_1",
            transmit_interface="GE0_2",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.interface_pair.request_json",
                return_value=(
                    400,
                    {"errCode": "eObjCreateExist", "errMsg": "接口对名称已存在"},
                    "",
                ),
            ):
                with self.assertRaises(RunnerError) as ctx:
                    execute_interface_pair(
                        op_id="fw_update_interface_pair",
                        base_url=BASE_URL,
                        session_file=session_file,
                        auth_header="Authorization",
                        payload=payload,
                        verify_tls=False,
                        timeout=5.0,
                    )
        self.assertEqual(ctx.exception.error_code, "RUNNER_CONFIG_REJECTED")
        self.assertEqual(ctx.exception.details["error_type"], "CONFIG_REJECTED")
        self.assertEqual(ctx.exception.details["err_code"], "eObjCreateExist")

    def test_update_nonexistent_preserves_device_error(self) -> None:
        # 更新不存在的 API 行为未实测：保守处理为失败，保留设备 errCode/errMsg，
        # 不归类为 RESOURCE_NOT_FOUND（避免把未确认语义当成目标状态已达成）。
        payload = build_interface_pair_update_payload(
            entry_id="pair1",
            receive_interface="GE0_1",
            transmit_interface="GE0_2",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.interface_pair.request_json",
                return_value=(
                    400,
                    {"errCode": "eObjGetNoExist", "errMsg": "未找到对应的接口对"},
                    "",
                ),
            ):
                with self.assertRaises(RunnerError) as ctx:
                    execute_interface_pair(
                        op_id="fw_update_interface_pair",
                        base_url=BASE_URL,
                        session_file=session_file,
                        auth_header="Authorization",
                        payload=payload,
                        verify_tls=False,
                        timeout=5.0,
                    )
        error = ctx.exception
        self.assertEqual(error.error_code, "RUNNER_CONFIG_REJECTED")
        self.assertEqual(error.details["err_code"], "eObjGetNoExist")
        self.assertEqual(error.details["err_msg"], "未找到对应的接口对")
        self.assertNotEqual(error.details.get("error_type"), "RESOURCE_NOT_FOUND")

    def test_repeat_delete_maps_eobjgetnoexist_without_idempotent_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.interface_pair.request_json",
                return_value=(
                    400,
                    {"errCode": "eObjGetNoExist", "errMsg": "未找到对应的接口对"},
                    "",
                ),
            ):
                with self.assertRaises(RunnerError) as ctx:
                    execute_interface_pair(
                        op_id="fw_delete_interface_pair",
                        base_url=BASE_URL,
                        session_file=session_file,
                        auth_header="Authorization",
                        payload={"id": "pair1"},
                        verify_tls=False,
                        timeout=5.0,
                    )
        error = ctx.exception
        self.assertEqual(error.error_code, "RUNNER_CONFIG_REJECTED")
        self.assertEqual(error.details["error_type"], "RESOURCE_NOT_FOUND")
        self.assertEqual(error.details["err_code"], "eObjGetNoExist")
        self.assertEqual(error.details["err_msg"], "未找到对应的接口对")
        # 真实重复删除不是成功：不得出现幂等成功键。
        self.assertNotIn("idempotent", error.details)
        self.assertNotIn("idempotent_source", error.details)


class SystemTimeTests(unittest.TestCase):
    def test_dry_run_url_and_expectations(self) -> None:
        result = build_system_time_dry_run(
            base_url=BASE_URL,
            session_file=Path("/tmp/session.json"),
            auth_header="Authorization",
            verify_tls=False,
            timeout=5.0,
            expected_date="2026-10-21",
            expected_time="12:00:00",
        )
        self.assertEqual(result["request"]["url"], f"{BASE_URL}/api/v1/systime?id=systime")
        self.assertEqual(result["expected_date"], "2026-10-21")
        self.assertEqual(result["expected_time"], "12:00:00")

    def test_execute_returns_fields_and_match_flags(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            response = {
                "count": 1,
                "vals": [
                    {
                        "name": "systime",
                        "enable": True,
                        "date": "2026-10-21",
                        "time": "12:00:00",
                        "ntp": {"interval": 0, "mainserver": ""},
                    }
                ],
            }
            with patch(
                "atomic_ops.runner.system_time.request_json",
                return_value=(200, response, ""),
            ):
                result = execute_system_time(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    verify_tls=False,
                    timeout=5.0,
                    expected_date="2026-10-21",
                    expected_time="12:00:00",
                )
        self.assertEqual(result["name"], "systime")
        self.assertTrue(result["enable"])
        self.assertEqual(result["date"], "2026-10-21")
        self.assertEqual(result["time"], "12:00:00")
        self.assertEqual(result["ntp"], {"interval": 0, "mainserver": ""})
        self.assertTrue(result["matches_expected_date"])
        self.assertTrue(result["matches_expected_time"])
        self.assertTrue(result["matches_expected"])

    def test_execute_reports_mismatch_without_raising(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            response = {
                "vals": [
                    {"name": "systime", "enable": False, "date": "2026-10-20", "time": "23:59:59"}
                ]
            }
            with patch(
                "atomic_ops.runner.system_time.request_json",
                return_value=(200, response, ""),
            ):
                result = execute_system_time(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    verify_tls=False,
                    timeout=5.0,
                    expected_date="2026-10-21",
                    expected_time="00:00:00",
                )
        self.assertFalse(result["matches_expected_date"])
        self.assertFalse(result["matches_expected_time"])
        self.assertFalse(result["matches_expected"])

    def test_execute_rejects_empty_vals(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.system_time.request_json",
                return_value=(200, {"count": 0, "vals": []}, ""),
            ):
                with self.assertRaises(RunnerError) as ctx:
                    execute_system_time(
                        base_url=BASE_URL,
                        session_file=session_file,
                        auth_header="Authorization",
                        verify_tls=False,
                        timeout=5.0,
                    )
        self.assertEqual(ctx.exception.error_code, "RUNNER_RESPONSE_INVALID")

    def test_empty_expectation_is_rejected(self) -> None:
        with self.assertRaises(RunnerError):
            build_system_time_dry_run(
                base_url=BASE_URL,
                session_file=Path("/tmp/session.json"),
                auth_header="Authorization",
                verify_tls=False,
                timeout=5.0,
                expected_date=" ",
            )


class InterfacePairCliDryRunTests(_CliHarness):
    def test_pair_config_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            [
                "interface",
                "pair-config",
                "--name",
                "pair1",
                "--receive-interface",
                "GE0_1",
                "--transmit-interface",
                "GE0_2",
            ]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["url"], f"{BASE_URL}/api/v1/intf/pair")
        self.assertEqual(request["payload"]["val"]["name"], "pair1")

    def test_pair_update_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            [
                "interface",
                "pair-update",
                "--id",
                "pair1",
                "--receive-interface",
                "GE0_1",
                "--transmit-interface",
                "GE0_2",
                "--status-sync",
                "--allowed-vlan",
                "1-4094",
            ]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "PUT")
        self.assertEqual(request["payload"]["id"], "pair1")
        self.assertTrue(request["payload"]["val"]["status_sync"])

    def test_pair_verify_dry_run_shows_filters(self) -> None:
        exit_code, payload, _stderr = self._cli(
            [
                "interface",
                "pair-verify",
                "--name",
                "pair1",
                "--receive-interface",
                "GE0_1",
                "--page",
                "1",
                "--size",
                "20",
            ]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "GET")
        self.assertEqual(request["filters"], {"name": "pair1", "receive_interface": "GE0_1"})
        self.assertIn("page=1", request["url"])
        self.assertIn("size=20", request["url"])

    def test_pair_delete_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["interface", "pair-delete", "--id", "pair1"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "DELETE")
        self.assertTrue(request["url"].endswith("?id=pair1"))

    def test_system_time_verify_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["system", "time-verify", "--expected-date", "2026-10-21"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "GET")
        self.assertEqual(request["url"], f"{BASE_URL}/api/v1/systime?id=systime")
        self.assertEqual(payload["data"]["expected_date"], "2026-10-21")

    def test_pair_config_missing_interface_reports_validation_error(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["interface", "pair-config", "--name", "pair1", "--receive-interface", "GE0_1"]
        )
        self.assertNotEqual(exit_code, 0)
        assert payload is not None
        self.assertEqual(payload["error_code"], "RUNNER_VALIDATION_FAILED")

    def test_pair_config_underscore_name_reports_validation_error(self) -> None:
        exit_code, payload, _stderr = self._cli(
            [
                "interface",
                "pair-config",
                "--name",
                "pair_1",
                "--receive-interface",
                "GE0_1",
                "--transmit-interface",
                "GE0_2",
            ]
        )
        self.assertNotEqual(exit_code, 0)
        assert payload is not None
        self.assertEqual(payload["error_code"], "RUNNER_VALIDATION_FAILED")
        self.assertIn("underscores are not allowed", payload["message"])

    def test_pair_verify_repeated_filter_reports_validation_error(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["interface", "pair-verify", "--name", "pair1", "--name", "pair2"]
        )
        self.assertNotEqual(exit_code, 0)
        assert payload is not None
        self.assertEqual(payload["error_code"], "RUNNER_VALIDATION_FAILED")


class AtomAdapterContractTests(unittest.TestCase):
    ROOT = Path(__file__).resolve().parents[1]
    OP_IDS = (
        "fw_config_interface_pair",
        "fw_verify_interface_pair",
        "fw_update_interface_pair",
        "fw_delete_interface_pair",
        "fw_verify_system_time",
    )

    def test_atoms_and_adapter_entries_are_linked(self) -> None:
        adapter = yaml.safe_load(
            (self.ROOT / "adapters/ngfw/default.yaml").read_text(encoding="utf-8")
        )
        for op_id in self.OP_IDS:
            atom_path = self.ROOT / f"atoms/fw/{op_id}.yaml"
            atom = yaml.safe_load(atom_path.read_text(encoding="utf-8"))
            self.assertEqual(atom["op_id"], op_id)
            ref = atom["adapter_contract_ref"]
            self.assertTrue(ref.endswith(f"#/operations/{op_id}"))
            operation = adapter["operations"][op_id]
            self.assertEqual(operation["atom_ref"], f"atoms/fw/{op_id}.yaml")

    def test_pair_mutations_declare_post_verify(self) -> None:
        for op_id in (
            "fw_config_interface_pair",
            "fw_update_interface_pair",
            "fw_delete_interface_pair",
        ):
            atom = yaml.safe_load(
                (self.ROOT / f"atoms/fw/{op_id}.yaml").read_text(encoding="utf-8")
            )
            self.assertEqual(atom["post_verify"]["op_id"], "fw_verify_interface_pair")

    def test_delete_pair_stays_non_idempotent_and_declares_not_found(self) -> None:
        atom = yaml.safe_load(
            (self.ROOT / "atoms/fw/fw_delete_interface_pair.yaml").read_text(
                encoding="utf-8"
            )
        )
        # 真实重复删除返回 400 eObjGetNoExist：不声明幂等成功。
        self.assertIs(atom["idempotent"], False)
        self.assertIn("RESOURCE_NOT_FOUND", atom["error_types"])

    def test_config_and_update_pair_declare_name_rule(self) -> None:
        for op_id in ("fw_config_interface_pair", "fw_update_interface_pair"):
            atom = yaml.safe_load(
                (self.ROOT / f"atoms/fw/{op_id}.yaml").read_text(encoding="utf-8")
            )
            description = atom["parameters"]["params"]["description"]
            self.assertIn("[一-龥a-zA-Z0-9.-]{1,31}", description)
            self.assertIn("underscore", description)


class L2PreparationSequenceTests(unittest.TestCase):
    """最小 L2 序列：先 Switch/BVI，再接口对；不新增 L2 专用 op。"""

    def test_switch_bvi_then_pair_sequence(self) -> None:
        # 1. 物理成员口先切 Switch 模式，pvid 对齐 BVI instance，linkType=1（access）。
        member_port = build_interface_payload(
            interface_kind="physical",
            entry_id="GE0_1",
            mode="Switch",
            pvid=10,
            link_type=1,
            ip_addresses=[],
        )
        self.assertEqual(member_port["val"]["mode"], "Switch")
        self.assertEqual(member_port["val"]["pvid"], 10)
        self.assertEqual(member_port["val"]["linkType"], 1)
        self.assertEqual(member_port["val"]["type"], 3)

        # 2. 再创建 BVI（type 14），bridge.interfaces 引用已准备好的成员口。
        bvi = build_interface_payload(
            interface_kind="bvi",
            entry_id="bvi10",
            mode="Route",
            bvi_instance=10,
            parent_name="GE0_1",
            ip_addresses=[],
        )
        self.assertEqual(bvi["val"]["type"], 14)
        self.assertEqual(bvi["val"]["bvi"]["instance"], 10)
        self.assertEqual(bvi["val"]["bvi"]["bridge"]["interfaces"][0]["name"], "GE0_1")

        # 3. 最后创建接口对；两个物理口已具备 pair 模式所需字段。
        pair = build_interface_pair_payload(
            name="pair1",
            receive_interface="GE0_1",
            transmit_interface="GE0_2",
            allowed_vlan="0",
        )
        self.assertEqual(pair["val"]["receive_interface"], "GE0_1")
        self.assertEqual(pair["val"]["transmit_interface"], "GE0_2")

    def test_pair_atom_documents_preparation_order(self) -> None:
        atom = yaml.safe_load(PAIR_ATOM.read_text(encoding="utf-8"))
        preconditions = "\n".join(atom["preconditions"])
        self.assertIn("fw_update_interface", preconditions)
        self.assertIn("mode=\"Pair\"", preconditions)
        self.assertIn("fw_config_interface", preconditions)
        self.assertIn("before", preconditions)


if __name__ == "__main__":
    unittest.main()
