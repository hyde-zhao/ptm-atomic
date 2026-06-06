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
from atomic_ops.commands.run import _to_run_envelope
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.interface import (
    build_interface_batch_delete_payload,
    build_interface_payload,
    execute_interface,
)
from atomic_ops.runner.ngfw_login import login
from atomic_ops.runner.object import build_address_object_payload
from atomic_ops.runner.ospfv2 import (
    build_ospfv2_delete_payload,
    build_ospfv2_global_payload,
    build_ospfv2_interface_payload,
    build_ospfv2_network_payload,
    build_ospfv2_payload,
    build_ospfv2_redistribution_payload,
    execute_ospfv2,
)
from atomic_ops.runner.ospfv3_bfd import (
    build_bfd_global_payload,
    build_ospfv3_bfd_payload,
    build_ospfv3_global_payload,
    build_ospfv3_interface_payload,
    build_ospfv3_network_payload,
    build_ospfv3_redistribution_payload,
    execute_ospfv3_bfd,
)
from atomic_ops.runner.policy_route import (
    build_policy_route_delete_payload,
    build_policy_route_payload,
    build_policy_route_priority_payload,
)
from atomic_ops.runner.session import read_session_file, write_session_file


class InterfacePayloadTests(unittest.TestCase):
    def test_build_bvi_route_payload(self) -> None:
        payload = build_interface_payload(
            interface_kind="bvi",
            entry_id="bvi109",
            ip_addresses=["191.109.0.31/24", "2091:109::31/64"],
        )

        self.assertEqual(payload["id"], "bvi109")
        self.assertEqual(payload["val"]["name"], "bvi109")
        self.assertEqual(payload["val"]["type"], 14)
        self.assertEqual(payload["val"]["mode"], "Route")
        self.assertEqual(payload["val"]["bvi"]["instance"], 109)
        self.assertEqual(payload["val"]["bvi"]["bridge"]["name"], "bvi109")
        self.assertEqual(payload["val"]["ip_addresses"], ["191.109.0.31/24", "2091:109::31/64"])

    def test_build_subinterface_route_payload(self) -> None:
        payload = build_interface_payload(
            interface_kind="sub",
            entry_id="GE0_2.106",
            ip_addresses=["192.106.0.31/24", "2092:106::31/64"],
        )

        self.assertEqual(payload["val"]["type"], 1)
        self.assertEqual(payload["val"]["sub"], {"parent_name": "GE0_2", "sub_id": 106})
        self.assertEqual(payload["val"]["ip6_nd"], {"ip_prefix": []})
        self.assertEqual(payload["val"]["ip6_racfg"], {"suppress": 0})

    def test_build_physical_monitor_payload(self) -> None:
        payload = build_interface_payload(interface_kind="physical", entry_id="GE0_18", mode="Monitor")

        self.assertEqual(payload["val"]["type"], 3)
        self.assertEqual(payload["val"]["mode"], "Monitor")
        self.assertEqual(payload["val"]["allowPass"], "1-4094")
        self.assertEqual(payload["val"]["linkType"], 2)

    def test_build_bond_switch_payload(self) -> None:
        payload = build_interface_payload(
            interface_kind="bond",
            entry_id="bond1",
            mode="Switch",
            bond_members=["GE0_3"],
            ip_addresses=["3.3.3.3/22"],
        )

        self.assertEqual(payload["val"]["type"], 10)
        self.assertEqual(payload["val"]["bond"]["id"], 1)
        self.assertEqual(payload["val"]["bond"]["bonded_interfaces"][0]["name"], "GE0_3")
        self.assertEqual(payload["val"]["pvid"], 1)

    def test_rejects_bvi_non_route_mode(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_interface_payload(interface_kind="bvi", entry_id="bvi109", mode="Switch")

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_build_batch_delete_payload(self) -> None:
        payload = build_interface_batch_delete_payload(entry_ids=["bvi109", "GE0_2.106"])

        self.assertEqual(payload["batch"][0]["method"], "DELETE")
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/intf")
        self.assertEqual(payload["batch"][0]["body"], {"id": ["bvi109"]})
        self.assertEqual(payload["batch"][1]["body"], {"id": ["GE0_2.106"]})


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

    def test_build_ipv6_policy_route_payload(self) -> None:
        payload = build_policy_route_payload(
            source_network="any",
            source_network_is_group=False,
            dst_network="any",
            dst_network_is_group=False,
            next_hop_ip="2091::1",
            in_interface="any",
            outgoing_interface="",
            service="any",
            weight=100,
            time_obj="",
            route_type="ipv6",
        )

        self.assertEqual(payload["val"]["type"], "ipv6")
        self.assertTrue(payload["val"]["active"])
        self.assertEqual(payload["val"]["forwarding_paths"][0]["next_hop_ip"], "2091::1")
        self.assertEqual(payload["val"]["forwarding_paths"][0]["health_check"], {})
        self.assertEqual(payload["val"]["config_source"], 0)

    def test_build_ipv4_policy_route_payload_with_outgoing_interface_only(self) -> None:
        payload = build_policy_route_payload(
            source_network="any",
            source_network_is_group=False,
            dst_network="any",
            dst_network_is_group=False,
            next_hop_ip="",
            in_interface="GE0_2.106",
            outgoing_interface="tunnel2",
            service="any",
            weight=123,
            time_obj="",
            route_type="ipv4",
        )

        forwarding_path = payload["val"]["forwarding_paths"][0]
        self.assertEqual(payload["val"]["type"], "ipv4")
        self.assertEqual(payload["val"]["in_interface"], "GE0_2.106")
        self.assertEqual(forwarding_path["next_hop_ip"], "")
        self.assertEqual(forwarding_path["outgoing_interface"], "tunnel2")
        self.assertEqual(forwarding_path["weight"], 123)

    def test_build_ipv6_policy_route_payload_with_outgoing_interface_only(self) -> None:
        payload = build_policy_route_payload(
            source_network="any",
            source_network_is_group=False,
            dst_network="any",
            dst_network_is_group=False,
            next_hop_ip="",
            in_interface="GE0_4",
            outgoing_interface="tunnel64",
            service="any",
            weight=100,
            time_obj="",
            route_type="ipv6",
        )

        forwarding_path = payload["val"]["forwarding_paths"][0]
        self.assertEqual(payload["val"]["type"], "ipv6")
        self.assertEqual(forwarding_path["next_hop_ip"], "")
        self.assertEqual(forwarding_path["outgoing_interface"], "tunnel64")

    def test_rejects_policy_route_without_next_hop_or_outgoing_interface(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_policy_route_payload(
                source_network="any",
                source_network_is_group=False,
                dst_network="any",
                dst_network_is_group=False,
                next_hop_ip="",
                in_interface="GE0_12",
                outgoing_interface="",
                service="any",
                weight=1,
                time_obj="",
            )

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_rejects_next_hop_version_mismatch(self) -> None:
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
                route_type="ipv4",
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

    def test_build_policy_route_delete_payload(self) -> None:
        self.assertEqual(build_policy_route_delete_payload(entry_id="15"), {"id": 15})

    def test_update_policy_route_payload_includes_val_id(self) -> None:
        payload = build_policy_route_payload(
            source_network="any",
            source_network_is_group=False,
            dst_network="any",
            dst_network_is_group=False,
            next_hop_ip="2092:106::32",
            in_interface="GE0_12",
            outgoing_interface="",
            service="any",
            weight=2,
            time_obj="",
            route_type="ipv6",
            entry_id=3,
        )

        self.assertEqual(payload["id"], 3)
        self.assertEqual(payload["val"]["id"], 3)

    def test_build_policy_route_priority_payload(self) -> None:
        payload = build_policy_route_priority_payload(
            targetsite="before",
            targetid="1",
            moveid="15",
            route_type="ipv6",
        )

        self.assertEqual(
            payload,
            {"val": {"targetsite": "before", "targetid": 1, "moveid": 15, "is_ip6": True}},
        )


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


class Ospfv2PayloadTests(unittest.TestCase):
    def test_build_global_payload(self) -> None:
        payload = build_ospfv2_global_payload(
            entry_id="0",
            enable=True,
            router_id="<DUT_IP>",
            originate=True,
            always=True,
        )

        self.assertEqual(
            payload,
            {
                "id": "0",
                "val": {
                    "enable": True,
                    "routerId": "<DUT_IP>",
                    "originate": True,
                    "always": True,
                },
            },
        )

    def test_rejects_invalid_router_id(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_ospfv2_global_payload(
                entry_id="0",
                enable=True,
                router_id="not-an-ip",
                originate=True,
                always=True,
            )

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_build_redistribution_payload(self) -> None:
        payload = build_ospfv2_redistribution_payload(
            entry_id="0",
            redistribute=["connected=333", "static=666", "rip=333"],
        )

        self.assertEqual(payload["id"], "0")
        self.assertEqual(
            payload["val"]["redistribute"],
            [
                {"protocol": "connected", "metric": "333"},
                {"protocol": "static", "metric": "666"},
                {"protocol": "rip", "metric": "333"},
            ],
        )

    def test_rejects_unsupported_redistribution_protocol(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_ospfv2_redistribution_payload(entry_id="0", redistribute=["bgp=10"])

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_build_network_create_and_update_payloads(self) -> None:
        create_payload = build_ospfv2_network_payload(network="191.0.0.0/24", area="0")
        update_payload = build_ospfv2_network_payload(network="191.0.0.0/24", area="0", entry_id="7")

        self.assertEqual(create_payload, {"val": {"network": "191.0.0.0/24", "area": "0"}})
        self.assertEqual(update_payload["id"], "7")
        self.assertEqual(update_payload["val"]["network"], "191.0.0.0/24")

    def test_rejects_invalid_network_cidr(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_ospfv2_network_payload(network="999.0.0.0/24", area="0")

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_build_delete_payload(self) -> None:
        self.assertEqual(build_ospfv2_delete_payload(entry_id="12"), {"id": "12"})

    def test_build_interface_payload(self) -> None:
        payload = build_ospfv2_interface_payload(
            interface="bvi109",
            cost="1",
            priority="1",
            hello_interval="10",
            retransmit_interval="5",
            dead_interval="40",
            transmit_delay="1",
            type_network=0,
            int_auth_mode=0,
            bfd_enable=True,
            detect_multiplier=3,
            min_rx_interval=300,
            min_tx_interval=300,
            entry_id="9",
        )

        self.assertEqual(payload["id"], "9")
        self.assertEqual(payload["val"]["interface"], "bvi109")
        self.assertEqual(payload["val"]["helloInterval"], "10")
        self.assertEqual(payload["val"]["typeNetwork"], 0)
        self.assertTrue(payload["val"]["bfdEnable"])

    def test_update_op_requires_id(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_ospfv2_payload(
                "fw_config_ospfv2_network_update",
                {"network": "191.0.0.0/24", "area": "0"},
            )

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")


class Ospfv3BfdPayloadTests(unittest.TestCase):
    def test_build_ospfv3_global_payload(self) -> None:
        payload = build_ospfv3_global_payload(entry_id="0", enable=True, router_id="<DUT_IP>")

        self.assertEqual(payload, {"id": "0", "val": {"enable": True, "routerId": "<DUT_IP>"}})

    def test_build_ospfv3_redistribution_payload(self) -> None:
        payload = build_ospfv3_redistribution_payload(entry_id="0", redistribute=["connected=333", "static=333"])

        self.assertEqual(
            payload,
            {
                "id": "0",
                "val": {
                    "redistribute": [
                        {"protocol": "connected", "metric": "333"},
                        {"protocol": "static", "metric": "333"},
                    ]
                },
            },
        )

    def test_rejects_ospfv3_rip_redistribution(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_ospfv3_redistribution_payload(entry_id="0", redistribute=["rip=333"])

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_build_ospfv3_network_create_and_update_payloads(self) -> None:
        create_payload = build_ospfv3_network_payload(interface="bvi109", area="0")
        update_payload = build_ospfv3_network_payload(interface="bvi109", area="0", entry_id="8")

        self.assertEqual(create_payload, {"val": {"interface": "bvi109", "area": "0"}})
        self.assertEqual(update_payload["id"], "8")

    def test_build_ospfv3_interface_payload(self) -> None:
        payload = build_ospfv3_interface_payload(
            interface="bvi109",
            cost="1",
            priority="1",
            hello_interval="10",
            retransmit_interval="5",
            dead_interval="40",
            transmit_delay="1",
            type_network=0,
            entry_id="9",
        )

        self.assertEqual(payload["id"], "9")
        self.assertEqual(payload["val"]["interface"], "bvi109")
        self.assertEqual(payload["val"]["typeNetwork"], 0)

    def test_build_bfd_global_payload(self) -> None:
        payload = build_bfd_global_payload(entry_id="0", enable=True)

        self.assertEqual(payload, {"id": "0", "val": {"enable": True}})

    def test_ospfv3_update_op_requires_id(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_ospfv3_bfd_payload(
                "fw_config_ospfv3_network_update",
                {"interface": "bvi109", "area": "0"},
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


class RunCommandEnvelopeTests(unittest.TestCase):
    def test_wraps_runner_payload_in_fixed_envelope(self) -> None:
        envelope = _to_run_envelope(
            {
                "op_id": "fw_config_object",
                "status": "dry_run",
                "execute_required": True,
                "request": {"method": "POST"},
            }
        )

        self.assertEqual(envelope["op_id"], "fw_config_object")
        self.assertEqual(envelope["status"], "dry_run")
        self.assertEqual(envelope["error_type"], "NONE")
        self.assertEqual(envelope["diag_snapshot_ref"], "")
        self.assertEqual(envelope["data"], {"execute_required": True, "request": {"method": "POST"}})

    def test_cli_dry_run_json_uses_fixed_envelope(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_config_object",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--object-name",
                    "srcObj",
                    "--ipaddr",
                    "192.168.0.0",
                    "--mask",
                    "16",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_object")
        self.assertEqual(payload["status"], "dry_run")
        self.assertEqual(payload["error_type"], "NONE")
        self.assertEqual(payload["diag_snapshot_ref"], "")
        self.assertNotIn("request", payload)
        self.assertTrue(payload["data"]["execute_required"])
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())

    def test_cli_interface_bvi_post_generates_payload(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_config_interface",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--interface-kind",
                    "bvi",
                    "--id",
                    "bvi109",
                    "--ip-address",
                    "191.109.0.31/24",
                    "--ip-address",
                    "2091:109::31/64",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_interface")
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/intf"))
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["type"], 14)
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["bvi"]["instance"], 109)
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())

    def test_cli_interface_get_sends_no_body(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_verify_interface",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["data"]["request"]["method"], "GET")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/intf"))
        self.assertIsNone(payload["data"]["request"]["payload"])

    def test_cli_interface_delete_uses_query_id_and_no_body(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_delete_interface",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--id",
                    "GE0_2.106",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["data"]["request"]["method"], "DELETE")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/intf?id=GE0_2.106"))
        self.assertIsNone(payload["data"]["request"]["payload"])

    def test_cli_interface_batch_delete_uses_batch_body(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_delete_batch_interface",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--id",
                    "bvi109",
                    "--id",
                    "GE0_2.106",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/batch"))
        self.assertEqual(payload["data"]["request"]["payload"]["batch"][0]["body"], {"id": ["bvi109"]})
        self.assertEqual(payload["data"]["request"]["payload"]["batch"][1]["body"], {"id": ["GE0_2.106"]})

    def test_cli_ospfv2_post_dry_run_json_uses_fixed_envelope(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_config_ospfv2_network",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--network",
                    "191.0.0.0/24",
                    "--area",
                    "0",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_ospfv2_network")
        self.assertEqual(payload["status"], "dry_run")
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["network"], "191.0.0.0/24")
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())

    def test_cli_policy_route_ipv6_post_dry_run_json_uses_fixed_envelope(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_config_policy_route",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--policy-route-type",
                    "ipv6",
                    "--source-network",
                    "any",
                    "--dst-network",
                    "any",
                    "--next-hop-ip",
                    "2091::1",
                    "--in-interface",
                    "any",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_policy_route")
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["type"], "ipv6")
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["forwarding_paths"][0]["weight"], 100)
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())

    def test_cli_policy_route_outgoing_interface_only_dry_run_json(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_config_policy_route",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--source-network",
                    "any",
                    "--dst-network",
                    "any",
                    "--in-interface",
                    "GE0_2.106",
                    "--outgoing-interface",
                    "tunnel2",
                    "--weight",
                    "123",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        forwarding_path = payload["data"]["request"]["payload"]["val"]["forwarding_paths"][0]
        self.assertEqual(payload["op_id"], "fw_config_policy_route")
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["type"], "ipv4")
        self.assertEqual(forwarding_path["next_hop_ip"], "")
        self.assertEqual(forwarding_path["outgoing_interface"], "tunnel2")
        self.assertEqual(forwarding_path["weight"], 123)
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())

    def test_cli_policy_route_get_uses_query_and_no_body(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_verify_policy_route",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--policy-route-type",
                    "ipv6",
                    "--page",
                    "1",
                    "--size",
                    "40",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["data"]["request"]["method"], "GET")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/policyroute?page=1&size=40&is_ip6=true"))
        self.assertIsNone(payload["data"]["request"]["payload"])
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())

    def test_cli_policy_route_delete_uses_query_id_and_no_body(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_delete_policy_route",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--id",
                    "15",
                    "--policy-route-type",
                    "ipv6",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["data"]["request"]["method"], "DELETE")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/policyroute?id=15&is_ip6=true"))
        self.assertIsNone(payload["data"]["request"]["payload"])
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())

    def test_cli_policy_route_priority_uses_pridpriconf(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_update_policy_route_priority",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--targetsite",
                    "before",
                    "--targetid",
                    "1",
                    "--moveid",
                    "15",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/pridpriconf"))
        self.assertEqual(
            payload["data"]["request"]["payload"],
            {"val": {"targetsite": "before", "targetid": 1, "moveid": 15, "is_ip6": False}},
        )
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())

    def test_cli_ospfv2_network_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_delete_ospfv2_network",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--id",
                    "7",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_ospfv2_network")
        self.assertEqual(payload["data"]["request"]["method"], "DELETE")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/ospfnetwork?id=7"))
        self.assertIsNone(payload["data"]["request"]["payload"])
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())

    def test_cli_ospfv2_interface_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_delete_ospfv2_interface",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--id",
                    "GE0_12",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["data"]["request"]["method"], "DELETE")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/ospfinterface?id=GE0_12"))
        self.assertIsNone(payload["data"]["request"]["payload"])
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())

    def test_cli_ospfv2_paginated_get_dry_run_json_uses_fixed_envelope(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_verify_ospfv2_neighbor",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--page",
                    "2",
                    "--size",
                    "10",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_verify_ospfv2_neighbor")
        self.assertEqual(payload["data"]["request"]["method"], "GET")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/ospfneighbor?page=2&size=10"))
        self.assertIsNone(payload["data"]["request"]["payload"])
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())

    def test_cli_ospfv3_post_dry_run_json_uses_fixed_envelope(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_config_ospfv3_network",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--interface",
                    "bvi109",
                    "--area",
                    "0",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_ospfv3_network")
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertEqual(payload["data"]["request"]["payload"], {"val": {"interface": "bvi109", "area": "0"}})
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())

    def test_cli_bfd_paginated_get_dry_run_json_uses_fixed_envelope(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "fw_verify_bfd_session",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "--page",
                    "3",
                    "--size",
                    "20",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_verify_bfd_session")
        self.assertEqual(payload["data"]["request"]["method"], "GET")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/bfdsession?page=3&size=20"))
        self.assertIsNone(payload["data"]["request"]["payload"])
        self.assertIn("TLS_VERIFY_DISABLED", stderr.getvalue())


class Ospfv2ExecuteTests(unittest.TestCase):
    def test_execute_get_sends_no_json_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.ospfv2.request_json", return_value=(200, {"items": []}, "{}")) as request:
                result = execute_ospfv2(
                    op_id="fw_verify_ospfv2_neighbor",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=None,
                    page=1,
                    size=40,
                    verify_tls=False,
                    timeout=10,
                )

        self.assertEqual(result["status"], "success")
        request.assert_called_once()
        args, kwargs = request.call_args
        self.assertEqual(args[0], "GET")
        self.assertTrue(args[1].endswith("/api/v1/ospfneighbor?page=1&size=40"))
        self.assertIsNone(kwargs["json_payload"])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer abc123")

    def test_execute_ospfv2_network_delete_uses_query_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.ospfv2.request_json", return_value=(200, {"ok": True}, "{}")) as request:
                result = execute_ospfv2(
                    op_id="fw_delete_ospfv2_network",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="AuthorizationToken",
                    payload={"id": "7"},
                    page=1,
                    size=40,
                    verify_tls=False,
                    timeout=10,
                )

        self.assertEqual(result["status"], "success")
        request.assert_called_once()
        args, kwargs = request.call_args
        self.assertEqual(args[0], "DELETE")
        self.assertTrue(args[1].endswith("/api/v1/ospfnetwork?id=7"))
        self.assertIsNone(kwargs["json_payload"])
        self.assertEqual(kwargs["headers"]["AuthorizationToken"], "abc123")

    def test_execute_ospfv2_interface_delete_uses_query_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.ospfv2.request_json", return_value=(200, {"ok": True}, "{}")) as request:
                result = execute_ospfv2(
                    op_id="fw_delete_ospfv2_interface",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payload={"id": "GE0_12"},
                    page=1,
                    size=40,
                    verify_tls=False,
                    timeout=10,
                )

        self.assertEqual(result["status"], "success")
        args, kwargs = request.call_args
        self.assertEqual(args[0], "DELETE")
        self.assertTrue(args[1].endswith("/api/v1/ospfinterface?id=GE0_12"))
        self.assertIsNone(kwargs["json_payload"])


class InterfaceExecuteTests(unittest.TestCase):
    def test_execute_interface_get_sends_no_json_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.interface.request_json", return_value=(200, {"vals": []}, "{}")) as request:
                result = execute_interface(
                    op_id="fw_verify_interface",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=None,
                    verify_tls=False,
                    timeout=10,
                )

        self.assertEqual(result["status"], "success")
        args, kwargs = request.call_args
        self.assertEqual(args[0], "GET")
        self.assertTrue(args[1].endswith("/api/v1/intf"))
        self.assertIsNone(kwargs["json_payload"])

    def test_execute_interface_delete_uses_query_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.interface.request_json", return_value=(200, {"ok": True}, "{}")) as request:
                result = execute_interface(
                    op_id="fw_delete_interface",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="AuthorizationToken",
                    payload={"id": "GE0_2.106"},
                    verify_tls=False,
                    timeout=10,
                )

        self.assertEqual(result["status"], "success")
        args, kwargs = request.call_args
        self.assertEqual(args[0], "DELETE")
        self.assertTrue(args[1].endswith("/api/v1/intf?id=GE0_2.106"))
        self.assertIsNone(kwargs["json_payload"])
        self.assertEqual(kwargs["headers"]["AuthorizationToken"], "abc123")


class Ospfv3BfdExecuteTests(unittest.TestCase):
    def test_execute_ospfv3_get_sends_no_json_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.ospfv3_bfd.request_json", return_value=(200, {"items": []}, "{}")) as request:
                result = execute_ospfv3_bfd(
                    op_id="fw_verify_ospfv3_neighbor",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=None,
                    page=1,
                    size=40,
                    verify_tls=False,
                    timeout=10,
                )

        self.assertEqual(result["status"], "success")
        args, kwargs = request.call_args
        self.assertEqual(args[0], "GET")
        self.assertTrue(args[1].endswith("/api/v1/ospf6neighbor?page=1&size=40"))
        self.assertIsNone(kwargs["json_payload"])

    def test_execute_bfd_put_sends_enable_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.ospfv3_bfd.request_json", return_value=(200, {"ok": True}, "{}")) as request:
                result = execute_ospfv3_bfd(
                    op_id="fw_config_bfd_global",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payload={"id": "0", "val": {"enable": True}},
                    page=1,
                    size=40,
                    verify_tls=False,
                    timeout=10,
                )

        self.assertEqual(result["status"], "success")
        args, kwargs = request.call_args
        self.assertEqual(args[0], "PUT")
        self.assertTrue(args[1].endswith("/api/v1/bfdconfig"))
        self.assertEqual(kwargs["json_payload"], {"id": "0", "val": {"enable": True}})


if __name__ == "__main__":
    unittest.main()
