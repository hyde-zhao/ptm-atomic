from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.ngfw_login import login
from atomic_ops.runner.object import build_address_object_payload
from atomic_ops.runner.policy_route import build_policy_route_payload
from atomic_ops.runner.session import read_session_file, write_session_file


class PolicyRoutePayloadTests(unittest.TestCase):
    def test_build_ipv4_policy_route_payload(self) -> None:
        payload = build_policy_route_payload(
            source_network="策略路由源IP1",
            source_network_is_group=False,
            dst_network="any",
            dst_network_is_group=False,
            next_hop_ip="18.18.2.2",
            in_interface="GE0_12",
            outgoing_interface="",
            service="any",
            weight=1,
            time_obj="",
        )

        self.assertEqual(payload["id"], 0)
        self.assertEqual(payload["val"]["type"], "ipv4")
        self.assertEqual(payload["val"]["source_network"], "策略路由源IP1")
        self.assertEqual(payload["val"]["dst_network"], "any")
        self.assertEqual(payload["val"]["forwarding_paths"][0]["next_hop_ip"], "18.18.2.2")

    def test_rejects_ipv6_next_hop(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_policy_route_payload(
                source_network="src",
                source_network_is_group=False,
                dst_network="any",
                dst_network_is_group=False,
                next_hop_ip="2115:101:2::11",
                in_interface="GE0_12",
                outgoing_interface="",
                service="any",
                weight=1,
                time_obj="",
            )

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_build_policy_route_payload_with_address_groups(self) -> None:
        payload = build_policy_route_payload(
            source_network="srcGroup",
            source_network_is_group=True,
            dst_network="dstGroup",
            dst_network_is_group=True,
            next_hop_ip="1.1.1.1",
            in_interface="GE0_12",
            outgoing_interface="",
            service="any",
            weight=1,
            time_obj="",
        )

        self.assertTrue(payload["val"]["source_network_is_group"])
        self.assertTrue(payload["val"]["dst_network_is_group"])


class AddressObjectPayloadTests(unittest.TestCase):
    def test_build_ipv4_address_object_payload(self) -> None:
        payload = build_address_object_payload(
            object_name="atomicSrc1921680016",
            ipaddr="192.168.0.0",
            mask="16",
            object_desc=None,
        )

        self.assertEqual(payload["val"]["name"], "atomicSrc1921680016")
        self.assertEqual(payload["val"]["type"], 4)
        self.assertEqual(payload["val"]["networks"][0]["ipaddr"], "192.168.0.0")
        self.assertEqual(payload["val"]["networks"][0]["mask"], "16")

    def test_rejects_address_object_name_with_underscore(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_address_object_payload(
                object_name="atomic_src",
                ipaddr="192.168.0.0",
                mask="16",
                object_desc=None,
            )

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")


class SessionFileTests(unittest.TestCase):
    def test_write_and_read_session_file_with_private_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            write_session_file(
                path,
                base_url="https://10.0.0.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )

            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            payload = read_session_file(path)
            self.assertEqual(payload["session_value"], "abc123")

    def test_rejects_broad_session_file_permissions(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            path = Path(temp_dir) / "session.json"
            path.write_text(json.dumps({"session_value": "abc123"}), encoding="utf-8")
            os.chmod(path, 0o644)

            with self.assertRaises(RunnerError) as context:
                read_session_file(path)

        self.assertEqual(context.exception.error_code, "RUNNER_SESSION_INVALID")


class NgfwLoginTests(unittest.TestCase):
    def test_login_returns_session_value_from_auth_response(self) -> None:
        with patch("atomic_ops.runner.ngfw_login._encrypt_password", return_value="encrypted"):
            with patch(
                "atomic_ops.runner.ngfw_login.request_json",
                return_value=(200, {"token": "abc123"}, "{}"),
            ):
                result = login(
                    base_url="https://10.0.0.1",
                    username="admin",
                    password_value="pw",
                    timeout=10,
                    verify_tls=False,
                    change_default_password=False,
                    replacement_value=None,
                )

        self.assertEqual(result["session_value"], "abc123")

    def test_login_requires_explicit_default_password_change(self) -> None:
        with patch("atomic_ops.runner.ngfw_login._encrypt_password", return_value="encrypted"):
            with patch(
                "atomic_ops.runner.ngfw_login.request_json",
                return_value=(200, {"errCode": "eChangDeafPwd"}, "{}"),
            ):
                with self.assertRaises(RunnerError) as context:
                    login(
                        base_url="https://10.0.0.1",
                        username="admin",
                        password_value="pw",
                        timeout=10,
                        verify_tls=False,
                        change_default_password=False,
                        replacement_value=None,
                    )

        self.assertEqual(context.exception.error_code, "RUNNER_LOGIN_FAILED")


if __name__ == "__main__":
    unittest.main()
