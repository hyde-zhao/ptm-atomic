"""CR-059：session 文件 base_url 绑定校验与设备侧会话失效错误分类的单元测试。"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from atomic_ops.runner.errors import (
    RunnerError,
    device_session_rejection_error,
    is_device_session_rejection,
    raise_if_device_session_rejected,
)
from atomic_ops.runner.object import execute_address_object
from atomic_ops.runner.session import normalize_base_url, read_session_file, write_session_file


def _write_session(path: Path, *, base_url: str, session_value: str = "abc123") -> None:
    write_session_file(
        path,
        base_url=base_url,
        username="admin",
        session_value=session_value,
        source_op_id="fw_login_web_management",
    )


class NormalizeBaseUrlTests(unittest.TestCase):
    def test_strips_trailing_slash_and_whitespace(self) -> None:
        self.assertEqual(normalize_base_url("https://10.0.0.1/"), "https://10.0.0.1")
        self.assertEqual(normalize_base_url("  https://10.0.0.1/  "), "https://10.0.0.1")
        self.assertEqual(normalize_base_url("https://10.0.0.1///"), "https://10.0.0.1")

    def test_lowercases_scheme_and_host_keeps_path(self) -> None:
        self.assertEqual(normalize_base_url("HTTPS://Example.COM/Api/V1"), "https://example.com/Api/V1")
        self.assertEqual(normalize_base_url("HTTP://Example.COM"), "http://example.com")

    def test_default_https_port_is_normalized(self) -> None:
        # 关键回归：既有正常流程 https://host 与 https://host:443 必须等价
        self.assertEqual(normalize_base_url("https://10.0.0.1:443"), "https://10.0.0.1")
        self.assertEqual(normalize_base_url("https://10.0.0.1:443/"), "https://10.0.0.1")

    def test_default_http_port_is_normalized(self) -> None:
        self.assertEqual(normalize_base_url("http://10.0.0.1:80"), "http://10.0.0.1")

    def test_non_default_ports_are_kept(self) -> None:
        self.assertEqual(normalize_base_url("https://10.0.0.1:8443"), "https://10.0.0.1:8443")
        self.assertEqual(normalize_base_url("http://10.0.0.1:8080/"), "http://10.0.0.1:8080")

    def test_url_without_scheme_is_kept_as_is(self) -> None:
        # 无 scheme 的输入按原样处理（不强加 scheme，也不做端口归一）
        self.assertEqual(normalize_base_url("10.0.0.1:8443"), "10.0.0.1:8443")

    def test_non_string_input_returns_empty_string(self) -> None:
        self.assertEqual(normalize_base_url(None), "")
        self.assertEqual(normalize_base_url(123), "")
        self.assertEqual(normalize_base_url(""), "")

    def test_ipv6_default_port_is_normalized(self) -> None:
        self.assertEqual(normalize_base_url("https://[::1]:443/x"), "https://[::1]/x")
        self.assertEqual(normalize_base_url("https://[::1]:8443/x"), "https://[::1]:8443/x")


class ReadSessionFileBindingTests(unittest.TestCase):
    def test_expect_none_behaves_identically_to_no_argument(self) -> None:
        # 向后兼容断言：expect_base_url=None 与不传参数的返回值逐字段一致
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            _write_session(path, base_url="https://10.0.0.1")
            self.assertEqual(read_session_file(path), read_session_file(path, expect_base_url=None))

    def test_expect_none_does_not_validate_mismatch(self) -> None:
        # 缺省（None）时文件 base_url 与期望设备不同也不校验（历史行为）
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            _write_session(path, base_url="https://10.0.0.2")
            payload = read_session_file(path)
            self.assertEqual(payload["base_url"], "https://10.0.0.2")

    def test_matching_base_url_passes_with_normalization(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            _write_session(path, base_url="https://10.0.0.1")
            # 大小写 / 尾斜杠 / 默认端口差异双向归一后应通过
            for expected in (
                "https://10.0.0.1",
                "https://10.0.0.1/",
                "HTTPS://10.0.0.1",
                "https://10.0.0.1:443",
            ):
                payload = read_session_file(path, expect_base_url=expected)
                self.assertEqual(payload["session_value"], "abc123")

    def test_http_default_port_equivalence(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            _write_session(path, base_url="http://10.0.0.1:80")
            read_session_file(path, expect_base_url="http://10.0.0.1")

    def test_written_with_443_read_with_bare_host_is_accepted(self) -> None:
        # 防止既有正常流程被误判：登录时带 :443，后续使用裸 host 必须互认
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            _write_session(path, base_url="https://10.0.0.1:443")
            read_session_file(path, expect_base_url="https://10.0.0.1")

    def test_mismatch_raises_session_invalid_with_details(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            _write_session(path, base_url="https://10.0.0.2")
            with self.assertRaises(RunnerError) as context:
                read_session_file(path, expect_base_url="https://10.0.0.1")
            error = context.exception
            self.assertEqual(error.error_code, "RUNNER_SESSION_INVALID")
            # details 必须同时携带三个键
            self.assertIn("session_file", error.details)
            self.assertIn("session_base_url", error.details)
            self.assertIn("expected_base_url", error.details)
            self.assertEqual(error.details["session_base_url"], "https://10.0.0.2")
            self.assertEqual(error.details["expected_base_url"], "https://10.0.0.1")
            self.assertIsNotNone(error.suggestion)

    def test_non_default_port_mismatch_still_rejected(self) -> None:
        # 非默认端口不参与归一，端口不同视为不同设备
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            _write_session(path, base_url="https://10.0.0.1:8443")
            with self.assertRaises(RunnerError) as context:
                read_session_file(path, expect_base_url="https://10.0.0.1")
            self.assertEqual(context.exception.error_code, "RUNNER_SESSION_INVALID")

    def test_missing_base_url_field_is_rejected_when_expected(self) -> None:
        # 旧格式/被篡改文件缺少 base_url 时，绑定校验必须失败而不是静默通过
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            path.write_text('{"session_value": "abc123"}', encoding="utf-8")
            os.chmod(path, 0o600)
            with self.assertRaises(RunnerError) as context:
                read_session_file(path, expect_base_url="https://10.0.0.1")
            self.assertEqual(context.exception.error_code, "RUNNER_SESSION_INVALID")


class DeviceSessionRejectionTests(unittest.TestCase):
    def test_http_401_and_403_are_session_rejections(self) -> None:
        self.assertTrue(is_device_session_rejection(401))
        self.assertTrue(is_device_session_rejection(403, {"errCode": "eOk"}))

    def test_body_markers_are_session_rejections(self) -> None:
        self.assertTrue(is_device_session_rejection(400, {"errCode": "eTokenCheck"}))
        self.assertTrue(is_device_session_rejection(200, {"errCode": "eTokenParse"}))
        self.assertTrue(is_device_session_rejection(500, {"errMsg": "Expire check failed"}))

    def test_business_400_is_not_a_session_rejection(self) -> None:
        # 业务错误（400 + 业务 errCode）不得误判为会话失效
        self.assertFalse(is_device_session_rejection(400, {"errCode": "eParamInvalid", "errMsg": "invalid param"}))
        self.assertFalse(is_device_session_rejection(500, {"errCode": "eInternalError"}))
        self.assertFalse(is_device_session_rejection(404, {}))

    def test_rejection_error_shape(self) -> None:
        error = device_session_rejection_error(401, {"errCode": "eTokenCheck"})
        self.assertEqual(error.error_code, "RUNNER_SESSION_INVALID")
        self.assertEqual(error.details["status_code"], 401)
        self.assertEqual(error.details["err_code"], "eTokenCheck")

    def test_raise_helper_raises_and_passes_through(self) -> None:
        with self.assertRaises(RunnerError) as context:
            raise_if_device_session_rejected(403, {"errCode": "eOk"})
        self.assertEqual(context.exception.error_code, "RUNNER_SESSION_INVALID")
        # 未命中时原样返回，不抛错
        raise_if_device_session_rejected(400, {"errCode": "eParamInvalid"})


class RunnerIntegrationTests(unittest.TestCase):
    """端到端：runner 非成功状态分支接入会话失效判定 + session 绑定校验。"""

    def test_execute_address_object_maps_401_to_session_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            _write_session(path, base_url="https://10.0.0.1")
            with patch(
                "atomic_ops.runner.object.request_json",
                return_value=(401, {"errCode": "eOk"}, ""),
            ):
                with self.assertRaises(RunnerError) as context:
                    execute_address_object(
                        base_url="https://10.0.0.1",
                        session_file=path,
                        auth_header="Authorization",
                        payload={"val": {}},
                        verify_tls=False,
                        timeout=5,
                    )
            self.assertEqual(context.exception.error_code, "RUNNER_SESSION_INVALID")

    def test_execute_address_object_maps_token_expired_body_to_session_invalid(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            _write_session(path, base_url="https://10.0.0.1")
            with patch(
                "atomic_ops.runner.object.request_json",
                return_value=(400, {"errCode": "eTokenCheck", "errMsg": "session check failed"}, ""),
            ):
                with self.assertRaises(RunnerError) as context:
                    execute_address_object(
                        base_url="https://10.0.0.1",
                        session_file=path,
                        auth_header="Authorization",
                        payload={"val": {}},
                        verify_tls=False,
                        timeout=5,
                    )
            self.assertEqual(context.exception.error_code, "RUNNER_SESSION_INVALID")

    def test_execute_address_object_keeps_business_400_as_config_rejected(self) -> None:
        # 业务 400 不误判：保持 RUNNER_CONFIG_REJECTED
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            _write_session(path, base_url="https://10.0.0.1")
            with patch(
                "atomic_ops.runner.object.request_json",
                return_value=(400, {"errCode": "eParamInvalid", "errMsg": "invalid mask"}, ""),
            ):
                with self.assertRaises(RunnerError) as context:
                    execute_address_object(
                        base_url="https://10.0.0.1",
                        session_file=path,
                        auth_header="Authorization",
                        payload={"val": {}},
                        verify_tls=False,
                        timeout=5,
                    )
            self.assertEqual(context.exception.error_code, "RUNNER_CONFIG_REJECTED")

    def test_execute_address_object_rejects_foreign_session_file(self) -> None:
        # session 文件属于其它设备：请求发出前即被绑定校验拦截
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            _write_session(path, base_url="https://10.0.0.2")
            with patch("atomic_ops.runner.object.request_json") as mock_request:
                with self.assertRaises(RunnerError) as context:
                    execute_address_object(
                        base_url="https://10.0.0.1",
                        session_file=path,
                        auth_header="Authorization",
                        payload={"val": {}},
                        verify_tls=False,
                        timeout=5,
                    )
            self.assertEqual(context.exception.error_code, "RUNNER_SESSION_INVALID")
            self.assertIn("session_base_url", context.exception.details)
            self.assertEqual(context.exception.details["expected_base_url"], "https://10.0.0.1")
            mock_request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
