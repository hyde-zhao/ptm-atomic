"""STORY-REM-08-03 R1｜策略路由出接口归因建议（区域 #outif-attribution）验收测试。

**现场事实来源（只读复算，2026-09-15 落盘 run）**：
`run-20260915-171836-78782e` 中五条用例（`PC-STRATEGYROUTE-CFG-OUTINTF-012/013`、
`PC-STRATEGYROUTE-ROUTING-OUTINTFFWD-002/003/008`）首因步同构 ——
`fw_config_policy_route` / HTTP 400 / `ePolicyRouteOutIfNotExist` /
「新增ipv4策略路由1失败，出接口网卡名输入错误」；同环境同日对照 run
`run-20260915-094156-662333` 同五条全 PASS（排除型号能力问题）。
下列 fixture 取自该 run 的 step envelope（`details` 段），逐字面内联。

**本通道的纪律**：归因建议**附加**在原始错误之上 —— `error_code` / `message` /
`details`（原始 `err_code` / `err_msg` / `status_code` / `op_id` / `response_keys`）
逐字保留，`suggestion` 为新增字段；无匹配错误码一律不产生建议（不猜测、不误报）。
"""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from atomic_ops.cli import main as cli_main
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.interface import _interface_error_suggestion, execute_interface
from atomic_ops.runner.policy_route import (
    build_policy_route_payload,
    execute_policy_route,
    _outgoing_interface_name,
    _policy_route_error_suggestion,
)
from atomic_ops.runner.session import write_session_file


# 现场设备原始返回体（run-20260915-171836-78782e / STEP-004 的 `details` 段逐字面）。
FIELD_ERR_CODE = "ePolicyRouteOutIfNotExist"
FIELD_ERR_MSG = "新增ipv4策略路由1失败，出接口网卡名输入错误"
FIELD_STATUS_CODE = 400


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


def _config_payload(*, outgoing_interface: str = "tunnel0") -> dict:
    return build_policy_route_payload(
        source_network="any",
        source_network_is_group=False,
        dst_network="any",
        dst_network_is_group=False,
        next_hop_ip="",
        in_interface="any",
        outgoing_interface=outgoing_interface,
        service="any",
        weight=100,
        time_obj="",
    )


def _device_rejection(extra: dict | None = None) -> dict:
    """现场设备响应体形态（errCode / errMsg 逐字面；message* 为现场 response_keys 键集）。"""
    body = {
        "errCode": FIELD_ERR_CODE,
        "errMsg": FIELD_ERR_MSG,
        "message": "",
        "messageDetails": "",
    }
    if extra:
        body.update(extra)
    return body


class PolicyRouteOutIfAttributionUnitTests(unittest.TestCase):
    """① 可达面（`execute_policy_route`）确实产出归因建议；② 原始错误逐字保留。"""

    def test_suggestion_triggers_on_policy_route_config_rejection(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.policy_route.request_json",
                return_value=(FIELD_STATUS_CODE, _device_rejection(), "{}"),
            ):
                with self.assertRaises(RunnerError) as context:
                    execute_policy_route(
                        op_id="fw_config_policy_route",
                        base_url="https://192.0.2.1",
                        session_file=session_file,
                        auth_header="Authorization",
                        payload=_config_payload(outgoing_interface="tunnel0"),
                        page=1,
                        size=40,
                        route_type="ipv4",
                        verify_tls=False,
                        timeout=10,
                    )

        error = context.exception
        # 归因建议：非空、点名对象、含期望动作、点明设备错误码依据
        self.assertIsNotNone(error.suggestion)
        self.assertIn("'tunnel0'", error.suggestion)
        self.assertIn("precondition", error.suggestion)
        self.assertIn(FIELD_ERR_CODE, error.suggestion)
        # 结论面（映射后码）与原始面（设备码）分层可见，suggestion 不替代任何一方
        self.assertEqual(error.error_code, "RUNNER_CONFIG_REJECTED")
        self.assertEqual(error.details["err_code"], FIELD_ERR_CODE)

    def test_original_error_fields_are_preserved_verbatim(self) -> None:
        """原始 message / 错误码 / HTTP 状态逐字保留（用户 2026-09-17 裁定的硬要求）。"""
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.policy_route.request_json",
                return_value=(FIELD_STATUS_CODE, _device_rejection(), "{}"),
            ):
                with self.assertRaises(RunnerError) as context:
                    execute_policy_route(
                        op_id="fw_config_policy_route",
                        base_url="https://192.0.2.1",
                        session_file=session_file,
                        auth_header="Authorization",
                        payload=_config_payload(),
                        page=1,
                        size=40,
                        route_type="ipv4",
                        verify_tls=False,
                        timeout=10,
                    )

        error = context.exception
        self.assertEqual(
            error.message,
            "Policy-route device request did not return a success status.",
        )
        self.assertEqual(
            error.details,
            {
                "op_id": "fw_config_policy_route",
                "status_code": FIELD_STATUS_CODE,
                "err_code": FIELD_ERR_CODE,
                "err_msg": FIELD_ERR_MSG,
                "response_keys": ["errCode", "errMsg", "message", "messageDetails"],
            },
        )
        # suggestion 与 message 是**两个**字段（不是把 message 换掉）
        self.assertNotEqual(error.suggestion, error.message)

    def test_update_op_shares_the_same_channel(self) -> None:
        """同族 op（update）走同一错误信封 → 同一归因通道（非 config 专属）。"""
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.policy_route.request_json",
                return_value=(FIELD_STATUS_CODE, _device_rejection(), "{}"),
            ):
                with self.assertRaises(RunnerError) as context:
                    execute_policy_route(
                        op_id="fw_update_policy_route",
                        base_url="https://192.0.2.1",
                        session_file=session_file,
                        auth_header="Authorization",
                        payload=_config_payload(outgoing_interface="ipsec0"),
                        page=1,
                        size=40,
                        route_type="ipv4",
                        verify_tls=False,
                        timeout=10,
                    )
        self.assertIn("'ipsec0'", context.exception.suggestion)

    def test_success_path_carries_no_suggestion(self) -> None:
        """成功路径零变化（不新增 result 键）。"""
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.policy_route.request_json",
                return_value=(200, {"val": {"id": 11}}, "{}"),
            ):
                result = execute_policy_route(
                    op_id="fw_config_policy_route",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=_config_payload(),
                    page=1,
                    size=40,
                    route_type="ipv4",
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["status"], "success")
        self.assertNotIn("suggestion", result)


class PolicyRouteOutIfAttributionNegativeTests(unittest.TestCase):
    """反例：不可达 / 不匹配路径不得误触发（不猜测、不误报）。"""

    def test_other_error_code_has_no_suggestion(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.policy_route.request_json",
                return_value=(400, {"errCode": "eRequestParam", "errMsg": "参数错误"}, "{}"),
            ):
                with self.assertRaises(RunnerError) as context:
                    execute_policy_route(
                        op_id="fw_config_policy_route",
                        base_url="https://192.0.2.1",
                        session_file=session_file,
                        auth_header="Authorization",
                        payload=_config_payload(),
                        page=1,
                        size=40,
                        route_type="ipv4",
                        verify_tls=False,
                        timeout=10,
                    )
        self.assertIsNone(context.exception.suggestion)
        # 原始错误照旧保留（不因无建议而丢字段）
        self.assertEqual(context.exception.details["err_code"], "eRequestParam")

    def test_response_without_err_code_has_no_suggestion(self) -> None:
        self.assertIsNone(
            _policy_route_error_suggestion("fw_config_policy_route", _config_payload(), {})
        )
        self.assertIsNone(
            _policy_route_error_suggestion(
                "fw_config_policy_route", _config_payload(), {"errCode": None}
            )
        )

    def test_get_op_rejection_maps_to_response_invalid_without_suggestion(self) -> None:
        """读取类 op 收到同码属异常形态（错因不明）→ 不产生建议（不猜测）。"""
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.policy_route.request_json",
                return_value=(500, _device_rejection(), "{}"),
            ):
                with self.assertRaises(RunnerError) as context:
                    execute_policy_route(
                        op_id="fw_verify_policy_route",
                        base_url="https://192.0.2.1",
                        session_file=session_file,
                        auth_header="Authorization",
                        payload=None,
                        page=1,
                        size=40,
                        route_type="ipv4",
                        verify_tls=False,
                        timeout=10,
                    )
        self.assertEqual(context.exception.error_code, "RUNNER_RESPONSE_INVALID")
        self.assertIsNone(context.exception.suggestion)
        # 触发面收窄是建议侧的约束，原始错误仍逐字保留
        self.assertEqual(context.exception.details["err_code"], FIELD_ERR_CODE)

    def test_former_landing_surface_is_structurally_unreachable(self) -> None:
        """原 LLD 落点（interface 族）对现场失败 op 结构性不可达 —— 反例留证。"""
        # ① 现场失败 op 不在 interface 族端点集内 → 执行器直接拒绝
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with self.assertRaises(RunnerError) as context:
                execute_interface(
                    op_id="fw_config_policy_route",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="AuthorizationToken",
                    payload=_config_payload(),
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(context.exception.error_code, "RUNNER_UNSUPPORTED_OP")
        # ② interface 族的建议函数对该 errCode 永不产出建议（未改动、也不该由它承接）
        self.assertIsNone(
            _interface_error_suggestion(_config_payload(), _device_rejection())
        )

    def test_missing_outgoing_interface_name_falls_back_to_generic_text(self) -> None:
        """出接口名为空（next-hop 模式等）时仍给建议，但不点名不存在的对象。"""
        self.assertIsNone(_outgoing_interface_name(None))
        self.assertIsNone(_outgoing_interface_name({"val": {}}))
        self.assertIsNone(
            _outgoing_interface_name({"val": {"forwarding_paths": [{"outgoing_interface": ""}]}})
        )
        suggestion = _policy_route_error_suggestion(
            "fw_config_policy_route",
            {"val": {"forwarding_paths": [{"outgoing_interface": ""}]}},
            _device_rejection(),
        )
        self.assertIn("the referenced interface", suggestion)

    def test_suggestion_text_avoids_redaction_trigger_words(self) -> None:
        """文案安全口径（errors.py SENSITIVE_LINE_PATTERN）：不得含被整行 REDACT 的独立词。"""
        suggestion = _policy_route_error_suggestion(
            "fw_config_policy_route", _config_payload(), _device_rejection()
        )
        lowered = suggestion.lower()
        for word in ("password", "passwd", "pwd", "secret", "token", "authorization", "header"):
            self.assertNotIn(word, lowered)


class PolicyRouteOutIfAttributionOutputTests(unittest.TestCase):
    """输出层：原始错误与归因建议在同一次输出中同时可见（CLI json 双通道）。"""

    def test_cli_json_shows_original_error_and_suggestion_together(self) -> None:
        stdout, stderr = io.StringIO(), io.StringIO()
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.policy_route.request_json",
                return_value=(FIELD_STATUS_CODE, _device_rejection(), "{}"),
            ):
                with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
                    exit_code = cli_main(
                        [
                            "run",
                            "--format",
                            "json",
                            "--base-url",
                            "https://192.0.2.1",
                            "--session-file",
                            str(session_file),
                            "--execute",
                            # canonical 子命令形态（legacy `run <op_id>` 形状在 argparse
                            # 层即被拒：`run fw_config_policy_route` 会命中
                            # `invalid choice`，故端到端必须走 `run policy-route config`）
                            "policy-route",
                            "config",
                            "--in-interface",
                            "any",
                            "--outgoing-interface",
                            "tunnel0",
                        ]
                    )

        self.assertEqual(exit_code, 48)  # RUNNER_CONFIG_REJECTED
        stdout_payload = json.loads(stdout.getvalue())
        # stderr 首行是 TLS 警告，末行是错误 payload（既有输出纪律：错误写 stderr）
        stderr_lines = [line for line in stderr.getvalue().splitlines() if line.strip()]
        stderr_payload = json.loads(stderr_lines[-1])
        for payload in (stdout_payload, stderr_payload):
            # 原始错误：设备错误码 / 设备原文 / HTTP 状态
            self.assertEqual(payload["details"]["err_code"], FIELD_ERR_CODE)
            self.assertEqual(payload["details"]["err_msg"], FIELD_ERR_MSG)
            self.assertEqual(payload["details"]["status_code"], FIELD_STATUS_CODE)
            self.assertEqual(payload["error_code"], "RUNNER_CONFIG_REJECTED")
            # 归因建议：同一份输出里附加可见
            self.assertIn("'tunnel0'", payload["suggestion"])
            self.assertIn("precondition", payload["suggestion"])


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
