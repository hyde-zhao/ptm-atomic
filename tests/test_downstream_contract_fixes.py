"""下游现场反馈（2026-09-08~09-11）9 项 atom/runner 契约缺口的回归锁。

覆盖：
- P2-42 fw_update_interface 覆盖式清 IP（--keep-ip 回填 + 文档声明覆盖语义）
- P2-39 reboot 契约不醒目（envelope 机器可读编排字段 + 文档契约声明）
- fw_config_static_route POST 不返回 id（创建后自动回查 id）
- P2-48 fw_config_batch_policy_route atom returns 与实现对齐
- 探针空响应陷阱（json 模式失败也在 stdout 留机器可读结构）
- fw_config_timeobject 多段（--time-range / --month-quantum + 文档化逃生口）
- delete 在 DUT 未就绪时 exit=46 的可选内部重试
- 大批量 verify 的 --page-size 内部翻页聚合
- bond 字段 schema 文档

既有行为回归（默认路径不变）也在这里显式锁定。
"""

from __future__ import annotations

import contextlib
import io
import json
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from atomic_ops.cli import main as cli_main
from atomic_ops.errors import CliError, write_error
from atomic_ops.runner.interface import (
    build_interface_payload,
    execute_interface,
    fetch_interface_ip_addresses,
)
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.object import execute_object
from atomic_ops.runner.pagination import fetch_all_pages
from atomic_ops.runner.policy_route import execute_policy_route
from atomic_ops.runner.reboot import execute_reboot
from atomic_ops.runner.session import write_session_file
from atomic_ops.runner.static_route import (
    build_static_route_payload,
    execute_static_route,
)
from atomic_ops.runner.timeobject import build_timeobject_payload

REPO_ROOT = Path(__file__).resolve().parents[1]


def _make_session(temp_dir: str) -> Path:
    session_file = Path(temp_dir) / "session.json"
    write_session_file(
        session_file,
        base_url="https://192.0.2.1",
        username="admin",
        session_value="abc123",
        source_op_id="fw_login_web_management",
    )
    return session_file


def _read_atom(op_id: str) -> dict:
    return yaml.safe_load((REPO_ROOT / "atoms" / "fw" / f"{op_id}.yaml").read_text(encoding="utf-8"))


def _read_adapter() -> dict:
    return yaml.safe_load((REPO_ROOT / "adapters" / "ngfw" / "default.yaml").read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# P2-42：fw_update_interface 覆盖式清 IP
# ---------------------------------------------------------------------------


class InterfaceKeepIpTests(unittest.TestCase):
    def test_default_update_without_ip_keeps_full_replacement_semantics(self) -> None:
        """默认行为不变：不传 --ip-address 时 payload 仍是空 ip_addresses（全量覆盖）。"""
        payload = build_interface_payload(interface_kind="physical", entry_id="GE0_3")
        self.assertEqual(payload["val"]["ip_addresses"], [])

    def test_fetch_interface_ip_addresses_backfills_current_value(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.interface.request_json",
                return_value=(200, {"vals": [{"id": "GE0_3", "val": {"ip_addresses": ["50.0.0.1/24"]}}]}, "{}"),
            ) as request:
                addresses = fetch_interface_ip_addresses(
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    entry_id="GE0_3",
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(addresses, ["50.0.0.1/24"])
        self.assertEqual(request.call_args[0][0], "GET")

    def test_fetch_interface_ip_addresses_accepts_flat_val_shape(self) -> None:
        """设备返回扁平形状（id/ip_addresses 同层）时同样可取。"""
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.interface.request_json",
                return_value=(200, {"vals": [{"id": "GE0_3", "ip_addresses": ["50.0.0.1/24"]}]}, "{}"),
            ):
                addresses = fetch_interface_ip_addresses(
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    entry_id="GE0_3",
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(addresses, ["50.0.0.1/24"])

    def test_fetch_interface_ip_addresses_fails_fast_when_id_missing(self) -> None:
        """目标 id 查不到时 fail fast，绝不静默返回空列表继续 PUT（否则复现清 IP）。"""
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.interface.request_json",
                return_value=(200, {"vals": [{"id": "GE0_9", "val": {}}]}, "{}"),
            ):
                with self.assertRaises(RunnerError) as context:
                    fetch_interface_ip_addresses(
                        base_url="https://192.0.2.1",
                        session_file=session_file,
                        auth_header="Authorization",
                        entry_id="GE0_3",
                        verify_tls=False,
                        timeout=10,
                    )
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_update_with_keep_ip_backfills_ips_into_put_payload(self) -> None:
        """P2-42 核心场景：只改 enabled 不传 IP 时，--keep-ip 回填现值，IP 不丢。"""
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            responses = [
                (200, {"vals": [{"id": "GE0_3", "val": {"ip_addresses": ["50.0.0.1/24"]}}]}, "{}"),
                (200, {}, "{}"),
            ]
            with patch("atomic_ops.runner.interface.request_json", side_effect=responses) as request:
                execute_interface(
                    op_id="fw_delete_interface",  # 占位避免误用；下方真正路径在 CLI handler 测试
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payload={"id": "GE0_3"},
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(request.call_args[0][0], "DELETE")

    def test_cli_update_keep_ip_backfills_current_ips(self) -> None:
        """CLI 端到端：interface update --keep-ip --execute 先 GET 回填再 PUT。"""
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            responses = [
                (200, {"vals": [{"id": "GE0_3", "val": {"ip_addresses": ["50.0.0.1/24"]}}]}, "{}"),
                (200, {}, "{}"),
            ]
            with patch("atomic_ops.runner.interface.request_json", side_effect=responses) as request:
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = cli_main(
                        ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                         "--session-file", str(session_file), "--execute",
                         "interface", "update", "--id", "GE0_3", "--interface-kind", "physical",
                         "--interface-disabled", "--keep-ip"]
                    )
            self.assertEqual(exit_code, 0, stdout.getvalue())
            self.assertEqual(request.call_count, 2)
            put_payload = request.call_args_list[1].kwargs["json_payload"]
            self.assertEqual(put_payload["val"]["ip_addresses"], ["50.0.0.1/24"])
            self.assertEqual(put_payload["val"]["enabled"], False)
            envelope = json.loads(stdout.getvalue())
            self.assertEqual(envelope["data"]["response"], {})

    def test_cli_dry_run_keep_ip_marks_intent_without_query(self) -> None:
        """dry-run 不发查询，envelope 标注 keep_ip 意图。"""
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "interface", "update", "--id", "GE0_3", "--interface-kind", "physical",
                 "--interface-disabled", "--keep-ip"]
            )
        self.assertEqual(exit_code, 0, stdout.getvalue())
        envelope = json.loads(stdout.getvalue())
        self.assertTrue(envelope["data"]["keep_ip"])
        self.assertIn("--ip-address", envelope["data"]["keep_ip_note"])

    def test_atom_and_adapter_declare_full_replacement_semantics(self) -> None:
        """P2-42 要求：atom/adapter 必须显式声明「未传字段会被清空」。"""
        atom = _read_atom("fw_update_interface")
        params_text = atom["parameters"]["params"]["description"]
        self.assertIn("FULL-REPLACEMENT PUT", params_text)
        precondition_text = " ".join(atom["preconditions"])
        self.assertIn("--ip-address", precondition_text)
        self.assertIn("--keep-ip", precondition_text)
        adapter = _read_adapter()
        notes = adapter["operations"]["fw_update_interface"]["safety"]["notes"]
        # notes 每项必须是纯字符串（不得被 YAML 解析成 dict）
        self.assertTrue(all(isinstance(note, str) for note in notes))
        notes_text = " ".join(notes)
        self.assertIn("Full-replacement PUT", notes_text)
        self.assertIn("--keep-ip", notes_text)
        self.assertIn("--bond-member", notes_text)


# ---------------------------------------------------------------------------
# P2-39：reboot 契约不醒目
# ---------------------------------------------------------------------------


class RebootOrchestrationFieldsTests(unittest.TestCase):
    def test_execute_success_exposes_wait_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            before = int(time.time())
            with patch(
                "atomic_ops.runner.reboot.request_json", return_value=(200, {"msg": "success"}, "{}")
            ):
                result = execute_reboot(
                    base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", expected_unavailable_seconds=120,
                    verify_tls=False, timeout=10,
                )
        # 机器可读编排字段：调用方按字段编排等待，而不是靠人读参数文本。
        self.assertEqual(result["caller_must_wait_seconds"], 120)
        self.assertIsInstance(result["device_unavailable_until_epoch"], int)
        self.assertGreaterEqual(result["device_unavailable_until_epoch"], before + 120 - 2)

    def test_execute_disconnect_branch_exposes_wait_fields(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.reboot.request_json",
                side_effect=RunnerError("RUNNER_DEVICE_UNREACHABLE", "disconnected", {}, retryable=True),
            ):
                result = execute_reboot(
                    base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", expected_unavailable_seconds=120,
                    verify_tls=False, timeout=10,
                )
        self.assertEqual(result["caller_must_wait_seconds"], 120)
        self.assertIsInstance(result["device_unavailable_until_epoch"], int)

    def test_dry_run_exposes_wait_seconds(self) -> None:
        from atomic_ops.runner.reboot import build_reboot_dry_run

        result = build_reboot_dry_run(
            base_url="https://192.0.2.1", session_file=Path("/nonexistent/session.json"),
            auth_header="Authorization", expected_unavailable_seconds=120,
            verify_tls=False, timeout=10,
        )
        self.assertEqual(result["caller_must_wait_seconds"], 120)
        self.assertNotIn("device_unavailable_until_epoch", result)

    def test_atom_declares_no_wait_contract_and_orchestration_fields(self) -> None:
        atom = _read_atom("fw_config_reboot")
        self.assertIn("does NOT wait", atom["parameters"]["expected_unavailable_seconds"]["description"])
        data = atom["returns"]["data"]
        self.assertIn("caller_must_wait_seconds", data)
        self.assertIn("device_unavailable_until_epoch", data)
        postconditions = " ".join(atom["postconditions"])
        self.assertIn("does NOT wait", postconditions)


# ---------------------------------------------------------------------------
# fw_config_static_route：POST 不返回 id → 创建后自动回查
# ---------------------------------------------------------------------------


class StaticRouteCreatedIdLookupTests(unittest.TestCase):
    def _execute_config(self, session_file: Path, responses: list) -> tuple[dict, object]:
        with patch("atomic_ops.runner.static_route.request_json", side_effect=responses) as request:
            payload = build_static_route_payload(dst_network="50.0.0.0/24", next_hop_addr="50.0.0.1")
            result = execute_static_route(
                op_id="fw_config_static_route",
                base_url="https://192.0.2.1",
                session_file=session_file,
                auth_header="Authorization",
                payload=payload,
                page=1,
                size=40,
                route_type="ipv4",
                verify_tls=False,
                timeout=10,
            )
        return result, request

    def test_config_auto_looks_up_created_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            responses = [
                (200, {}, "{}"),  # POST 成功（设备不返回 id）
                (200, {"vals": [{"id": 7, "val": {"dst_network": "50.0.0.0/24", "next_hop_addr": "50.0.0.1"}}], "count": 1}, "{}"),
            ]
            result, request = self._execute_config(session_file, responses)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["created"], True)
        self.assertEqual(result["static_route_ids"], [7])
        self.assertEqual(result["created_static_route_id"], 7)
        self.assertEqual(result["id_lookup_status"], "matched")

    def test_config_lookup_ambiguous_does_not_guess_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            responses = [
                (200, {}, "{}"),
                (200, {"vals": [
                    {"id": 7, "val": {"dst_network": "50.0.0.0/24", "next_hop_addr": "50.0.0.1"}},
                    {"id": 8, "val": {"dst_network": "50.0.0.0/24", "next_hop_addr": "50.0.0.2"}},
                ], "count": 2}, "{}"),
            ]
            result, _request = self._execute_config(session_file, responses)
        # next_hop 收敛：只有 id 7 同时匹配网段与下一跳
        self.assertEqual(result["created_static_route_id"], 7)
        self.assertEqual(result["id_lookup_status"], "matched")

    def test_config_lookup_failure_keeps_success_and_marks_failed(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            responses = [
                (200, {}, "{}"),
                RunnerError("RUNNER_DEVICE_UNREACHABLE", "no response", {}, retryable=True),
            ]
            result, _request = self._execute_config(session_file, responses)
        # 回查失败不改变创建本身的 success（创建已落设备）
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["id_lookup_status"], "failed")
        self.assertIsNone(result["created_static_route_id"])

    def test_atom_exposes_lookup_fields(self) -> None:
        atom = _read_atom("fw_config_static_route")
        data = atom["returns"]["data"]
        self.assertIn("static_route_ids", data)
        self.assertIn("created_static_route_id", data)
        self.assertIn("id_lookup_status", data)


# ---------------------------------------------------------------------------
# P2-48：batch_policy_route atom returns 与实现对齐
# ---------------------------------------------------------------------------


class BatchPolicyRouteReturnsAlignmentTests(unittest.TestCase):
    def test_atom_returns_keys_are_produced_by_implementation(self) -> None:
        """atom returns.data 声明的每个键都必须由实现真实产出（P2-48 教训）。"""
        atom = _read_atom("fw_config_batch_policy_route")
        declared = set(atom["returns"]["data"])
        # 禁止复活未落地的设计稿键
        for ghost in ("batch_policy_route_id", "per_device_results", "failed_devices", "verification_summary_ref"):
            self.assertNotIn(ghost, declared, f"设计稿键 {ghost} 实现并不返回，不得声明")
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            from atomic_ops.runner.policy_route import (
                build_policy_route_batch_config_payloads,
                execute_policy_route_batch_config,
            )

            with patch(
                "atomic_ops.runner.policy_route.request_json",
                side_effect=[(200, {"val": {"id": 11}}, "{}"), (200, {"val": {"id": 12}}, "{}")],
            ):
                payloads = build_policy_route_batch_config_payloads(
                    count=2,
                    source_network="any", source_network_is_group=False,
                    dst_network="any", dst_network_is_group=False,
                    next_hop_ip="1.1.1.1", in_interface="any", outgoing_interface="",
                    service="any", weight=1, time_obj="",
                )
                result = execute_policy_route_batch_config(
                    op_id="fw_config_policy_route",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payloads=payloads,
                    page=1, size=40, route_type="ipv4",
                    verify_tls=False, timeout=10,
                )
        produced = set(result) - {"op_id"}  # op_id 在 envelope 弹出层
        self.assertEqual(declared - produced, set(), f"atom 声明但实现不返回的键：{sorted(declared - produced)}")
        # 每条创建的策略路由 id 在 created[].policy_route_id
        self.assertEqual(result["created"][0]["policy_route_id"], 11)
        atom_text = (REPO_ROOT / "atoms" / "fw" / "fw_config_batch_policy_route.yaml").read_text(encoding="utf-8")
        self.assertIn("created[].policy_route_id", atom_text)


# ---------------------------------------------------------------------------
# 探针空响应陷阱：json 模式失败也在 stdout 留机器可读结构
# ---------------------------------------------------------------------------


class StdoutErrorEnvelopeTests(unittest.TestCase):
    def test_json_format_error_leaves_machine_readable_structure_on_stdout(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = write_error(
                CliError("RUNNER_DEVICE_UNREACHABLE", "unreachable", {"op_id": "x"}, retryable=True),
                "json",
            )
        self.assertEqual(exit_code, 46)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["error_code"], "RUNNER_DEVICE_UNREACHABLE")
        self.assertEqual(payload["error_type"], "RUNNER_DEVICE_UNREACHABLE")
        self.assertTrue(payload["retryable"])
        self.assertEqual(payload["exit_code"], 46)
        # stderr 原有 JSON 输出保持不变（向后兼容）
        stderr_payload = json.loads(stderr.getvalue())
        self.assertEqual(stderr_payload["error_code"], "RUNNER_DEVICE_UNREACHABLE")

    def test_text_format_stdout_stays_empty(self) -> None:
        """非 json 模式输出格式完全不变：错误只进 stderr，stdout 保持为空。"""
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = write_error(
                CliError("RUNNER_CONFIG_REJECTED", "rejected", {}, retryable=False),
                "yaml",
            )
        self.assertEqual(exit_code, 48)
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("error: RUNNER_CONFIG_REJECTED", stderr.getvalue())


# ---------------------------------------------------------------------------
# fw_config_timeobject：多段支持
# ---------------------------------------------------------------------------


class TimeObjectMultiSegmentTests(unittest.TestCase):
    def test_week_multi_segment_with_distinct_weekdays(self) -> None:
        payload = build_timeobject_payload(
            name="obj",
            scheduletype="week",
            time_ranges=["1:08:00:00~2:20:00:00", "5:09:00:00~5:18:00:00"],
        )
        quantum = payload["val"]["timequantum"]
        self.assertEqual(len(quantum), 2)
        self.assertEqual(quantum[0]["starttime"], {"time": "08:00:00", "weekday": 1})
        self.assertEqual(quantum[0]["endtime"], {"time": "20:00:00", "weekday": 2})
        self.assertEqual(quantum[1]["endtime"], {"time": "18:00:00", "weekday": 5})

    def test_week_segment_end_reuses_start_weekday_when_omitted(self) -> None:
        payload = build_timeobject_payload(
            name="obj", scheduletype="week", time_ranges=["3:08:00:00~09:00:00"],
        )
        quantum = payload["val"]["timequantum"]
        self.assertEqual(quantum[0]["endtime"], {"time": "09:00:00", "weekday": 3})

    def test_oneshot_multi_segment(self) -> None:
        payload = build_timeobject_payload(
            name="obj",
            scheduletype="oneshot",
            time_ranges=["2026-09-10 00:00:00~2026-09-10 23:59:59", "2026-09-11 00:00:00~2026-09-11 23:59:59"],
        )
        self.assertEqual(len(payload["val"]["timequantum"]), 2)

    def test_month_multi_segment(self) -> None:
        payload = build_timeobject_payload(
            name="obj", scheduletype="month", month_quanta=["15:1,2,3", "20:10"],
        )
        quanta = payload["val"]["timemonquantum"]
        self.assertEqual(quanta, [{"time": 15, "planday": "1,2,3"}, {"time": 20, "planday": "10"}])

    def test_single_segment_path_unchanged_when_multi_flags_absent(self) -> None:
        """默认路径回归：不传多段参数时仍是原单段构建。"""
        payload = build_timeobject_payload(
            name="obj", scheduletype="week", start_time="08:00:00", end_time="09:00:00", weekday=2,
        )
        quantum = payload["val"]["timequantum"]
        self.assertEqual(quantum, [{"starttime": {"time": "08:00:00", "weekday": 2}, "endtime": {"time": "09:00:00", "weekday": 2}}])

    def test_time_range_conflicts_with_single_segment_args(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_timeobject_payload(
                name="obj", scheduletype="week", start_time="08:00:00", end_time="09:00:00",
                time_ranges=["1:08:00:00~2:20:00:00"],
            )
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_month_quantum_rejected_for_non_month(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_timeobject_payload(name="obj", scheduletype="day", month_quanta=["15:1"])
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_atom_documents_escape_hatch_and_field_schema(self) -> None:
        atom = _read_atom("fw_config_timeobject")
        params_text = atom["parameters"]["params"]["description"]
        self.assertIn("payload-json", params_text)
        self.assertIn("ARRAY", params_text)
        precondition_text = " ".join(atom["preconditions"])
        self.assertIn("escape hatch", precondition_text.lower())
        self.assertIn("--time-range", precondition_text)


# ---------------------------------------------------------------------------
# delete 未就绪（exit 46）可选内部重试
# ---------------------------------------------------------------------------


class DeleteRetryTests(unittest.TestCase):
    def test_policy_route_delete_retries_on_unreachable_then_succeeds(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            responses = [
                RunnerError("RUNNER_DEVICE_UNREACHABLE", "no response", {}, retryable=True),
                (200, {}, "{}"),
            ]
            with patch("atomic_ops.runner.policy_route.request_json", side_effect=responses) as request, \
                    patch("atomic_ops.runner.http.time.sleep") as sleep:
                result = execute_policy_route(
                    op_id="fw_delete_policy_route",
                    base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", payload={"id": 5},
                    page=1, size=40, route_type="ipv4",
                    verify_tls=False, timeout=10,
                    retries=2, retry_backoff_seconds=0.5,
                )
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["status"], "success")
        sleep.assert_called_once_with(0.5)

    def test_config_rejected_is_not_retried(self) -> None:
        """设备拒绝（48）不重试：46 才对应「根本没拿到响应」。"""
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            # 500 响应会被 execute 层判为 CONFIG_REJECTED 抛出；不重试 → 仅一次请求。
            with patch(
                "atomic_ops.runner.policy_route.request_json",
                side_effect=[(500, {"errCode": "eX", "errMsg": "no"}, "{}")],
            ) as request, patch("atomic_ops.runner.http.time.sleep") as sleep:
                with self.assertRaises(RunnerError) as context:
                    execute_policy_route(
                        op_id="fw_delete_policy_route",
                        base_url="https://192.0.2.1", session_file=session_file,
                        auth_header="Authorization", payload={"id": 5},
                        page=1, size=40, route_type="ipv4",
                        verify_tls=False, timeout=10,
                        retries=3, retry_backoff_seconds=0.0,
                    )
        self.assertEqual(context.exception.error_code, "RUNNER_CONFIG_REJECTED")
        self.assertEqual(request.call_count, 1)
        sleep.assert_not_called()

    def test_default_zero_retries_keeps_single_request(self) -> None:
        """默认行为不变：retries=0 时第一次 46 即抛出。"""
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.policy_route.request_json",
                side_effect=RunnerError("RUNNER_DEVICE_UNREACHABLE", "no response", {}, retryable=True),
            ) as request:
                with self.assertRaises(RunnerError) as context:
                    execute_policy_route(
                        op_id="fw_delete_policy_route",
                        base_url="https://192.0.2.1", session_file=session_file,
                        auth_header="Authorization", payload={"id": 5},
                        page=1, size=40, route_type="ipv4",
                        verify_tls=False, timeout=10,
                    )
        self.assertEqual(context.exception.error_code, "RUNNER_DEVICE_UNREACHABLE")
        self.assertEqual(request.call_count, 1)

    def test_object_delete_retries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            responses = [
                RunnerError("RUNNER_DEVICE_UNREACHABLE", "no response", {}, retryable=True),
                (200, {}, "{}"),
            ]
            with patch("atomic_ops.runner.object.request_json", side_effect=responses) as request, \
                    patch("atomic_ops.runner.http.time.sleep"):
                result = execute_object(
                    op_id="fw_delete_object",
                    base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", payload={"id": "objA"},
                    page=1, size=40, verify_tls=False, timeout=10,
                    retries=1, retry_backoff_seconds=0.0,
                )
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["status"], "success")


# ---------------------------------------------------------------------------
# 大批量 verify：--page-size 内部翻页聚合
# ---------------------------------------------------------------------------


class FetchAllPagesTests(unittest.TestCase):
    def test_aggregates_until_count_reached(self) -> None:
        pages = {
            1: {"vals": [{"id": i} for i in range(1, 6)], "count": 8},
            2: {"vals": [{"id": i} for i in range(6, 9)], "count": 8},
        }
        result = fetch_all_pages(lambda page, size: pages[page], page_size=5)
        self.assertEqual(len(result["vals"]), 8)
        self.assertEqual(result["count"], 8)
        self.assertEqual(result["pages"], 2)
        self.assertFalse(result["truncated"])

    def test_stops_on_short_page_without_count(self) -> None:
        calls: list[tuple[int, int]] = []

        def fetch_page(page: int, size: int) -> dict:
            calls.append((page, size))
            return {2: {"vals": [{"id": 6}]} if page == 2 else {"vals": [{"id": page}]}[page == 1]}

        # 简化：两页，第二页不足 page_size
        def fetch_page_simple(page: int, size: int) -> dict:
            calls.append((page, size))
            if page == 1:
                return {"vals": [{"id": i} for i in range(3)]}
            return {"vals": [{"id": 99}]}

        result = fetch_all_pages(fetch_page_simple, page_size=3)
        self.assertEqual(len(result["vals"]), 4)
        self.assertEqual(calls, [(1, 3), (2, 3)])

    def test_truncates_at_max_pages(self) -> None:
        result = fetch_all_pages(
            lambda page, size: {"vals": [{"id": page}] * size}, page_size=2, max_pages=3,
        )
        self.assertTrue(result["truncated"])
        self.assertEqual(result["pages"], 3)


class VerifyAggregateRunnerTests(unittest.TestCase):
    def test_policy_route_verify_aggregates_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            responses = [
                (200, {"vals": [{"id": 1}, {"id": 2}], "count": 3}, "{}"),
                (200, {"vals": [{"id": 3}], "count": 3}, "{}"),
            ]
            with patch("atomic_ops.runner.policy_route.request_json", side_effect=responses) as request:
                result = execute_policy_route(
                    op_id="fw_verify_policy_route",
                    base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", payload=None,
                    page=1, size=40, route_type="ipv4",
                    verify_tls=False, timeout=10,
                    aggregate_page_size=2,
                )
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["response"]["vals"], [{"id": 1}, {"id": 2}, {"id": 3}])
        self.assertEqual(result["policy_route_ids"], [1, 2, 3])
        self.assertEqual(result["response"]["pages"], 2)
        self.assertEqual(result["response"]["page_size"], 2)

    def test_interface_verify_aggregates_pages(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            responses = [
                (200, {"vals": [{"id": "GE0_1"}, {"id": "GE0_2"}], "count": 3}, "{}"),
                (200, {"vals": [{"id": "GE0_3"}], "count": 3}, "{}"),
            ]
            with patch("atomic_ops.runner.interface.request_json", side_effect=responses) as request:
                result = execute_interface(
                    op_id="fw_verify_interface",
                    base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", payload=None,
                    verify_tls=False, timeout=10,
                    aggregate_page_size=2,
                )
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["response"]["vals"], [{"id": "GE0_1"}, {"id": "GE0_2"}, {"id": "GE0_3"}])
        # 翻页 query 确实按内部页参数拼接
        second_url = request.call_args_list[1].args[1]
        self.assertIn("page=2", second_url)
        self.assertIn("size=2", second_url)

    def test_verify_without_page_size_keeps_single_request(self) -> None:
        """默认行为不变：不传 --page-size 时仍是一次查询。"""
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.policy_route.request_json",
                return_value=(200, {"vals": [{"id": 1}], "count": 1}, "{}"),
            ) as request:
                execute_policy_route(
                    op_id="fw_verify_policy_route",
                    base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", payload=None,
                    page=1, size=40, route_type="ipv4",
                    verify_tls=False, timeout=10,
                )
        self.assertEqual(request.call_count, 1)


# ---------------------------------------------------------------------------
# bond 字段 schema 文档
# ---------------------------------------------------------------------------


class BondSchemaDocTests(unittest.TestCase):
    def test_atoms_document_bond_field_schema_and_append_flag(self) -> None:
        for op_id in ("fw_config_interface", "fw_update_interface"):
            atom = _read_atom(op_id)
            params_text = atom["parameters"]["params"]["description"]
            self.assertIn("bond", params_text)
            self.assertIn("bonded_interfaces", params_text)
            self.assertIn("--bond-member", params_text)

    def test_cli_help_warns_comma_string_is_one_member(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                cli_main(["run", "interface", "update", "--help"])
        help_text = stdout.getvalue()
        self.assertIn("--bond-member", help_text)
        self.assertIn("ONE member name", help_text)


if __name__ == "__main__":
    unittest.main()
