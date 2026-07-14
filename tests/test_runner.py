from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

from atomic_ops.cli import main as cli_main
from atomic_ops.commands.run import _to_run_envelope
from atomic_ops.rollback import readiness_report, validate_rollback_contract
from atomic_ops.aliases_lookup import extract_alias_keywords, find_ops_by_alias
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.interface import (
    build_interface_batch_delete_payload,
    build_interface_payload,
    execute_interface,
    validate_interface_payload,
)
from atomic_ops.runner.iptun import (
    build_iptun_batch_delete_payload,
    build_iptun_payload,
    validate_iptun_payload,
)
from atomic_ops.runner.ngfw_login import login
from atomic_ops.runner.object import (
    build_address_object_payload,
    build_address_object_update_payload,
    build_object_batch_delete_payload,
    build_object_dry_run,
    execute_object,
    validate_object_payload,
)
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
    build_policy_route_batch_delete_payload,
    build_policy_route_delete_payload,
    build_policy_route_payload,
    build_policy_route_priority_payload,
    validate_policy_route_payload,
)
from atomic_ops.runner.session import read_session_file, write_session_file
from atomic_ops.runner.config_transfer import (
    build_export_payload,
    build_import_handle_payload,
    execute_export_file,
    execute_import_file,
)
from atomic_ops.runner.reboot import execute_reboot
from atomic_ops.runner.polling import poll_until
from atomic_ops.runner.ha import (
    build_hasync_payload,
    build_haconfig_payload,
    build_hainterface_payload,
    build_havrrp_payload,
    build_havrrp_update_payload,
    build_hainterface_batch_delete_payload,
    build_havrrp_batch_delete_payload,
    execute_ha,
)
from atomic_ops.runner.ha_iplink import (
    build_haiplink_payload,
    build_halinkgroup_payload,
    build_haiplink_batch_delete_payload,
    build_halinkgroup_batch_delete_payload,
    execute_ha_iplink,
)


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

    def test_build_policy_route_batch_delete_payload_ipv4(self) -> None:
        payload = build_policy_route_batch_delete_payload(
            entry_ids=["1", "2"],
            route_type="ipv4",
        )

        self.assertEqual(len(payload["batch"]), 2)
        self.assertEqual(
            payload["batch"][0],
            {
                "method": "DELETE",
                "resource": "/api/v1/policyroute",
                "body": {"id": ["1"], "is_ip6": ["false"]},
            },
        )
        self.assertEqual(payload["batch"][1]["body"], {"id": ["2"], "is_ip6": ["false"]})

    def test_build_policy_route_batch_delete_payload_ipv6(self) -> None:
        payload = build_policy_route_batch_delete_payload(
            entry_ids=["7"],
            route_type="ipv6",
        )

        self.assertEqual(payload["batch"][0]["body"], {"id": ["7"], "is_ip6": ["true"]})

    def test_policy_route_batch_delete_rejects_empty(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_policy_route_batch_delete_payload(entry_ids=[], route_type="ipv4")

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_validate_policy_route_batch_payload_rejects_wrong_resource(self) -> None:
        payload = {
            "batch": [
                {
                    "method": "DELETE",
                    "resource": "/api/v1/ippool",
                    "body": {"id": ["1"], "is_ip6": ["false"]},
                }
            ]
        }
        with self.assertRaises(RunnerError) as context:
            validate_policy_route_payload(payload, op_id="fw_delete_batch_policy_route")

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_extract_policy_route_ids_from_verify_response(self) -> None:
        from atomic_ops.runner.policy_route import _extract_policy_route_summary

        response = {
            "count": 3,
            "vals": [
                {"id": 1, "type": "ipv4"},
                {"id": 2, "type": "ipv4"},
                {"id": 3, "type": "ipv4"},
            ],
        }
        summary = _extract_policy_route_summary("fw_verify_policy_route", response)

        self.assertEqual(summary["policy_route_ids"], [1, 2, 3])
        self.assertEqual(summary["count"], 3)

    def test_extract_policy_route_id_from_config_response(self) -> None:
        from atomic_ops.runner.policy_route import _extract_policy_route_summary

        summary = _extract_policy_route_summary(
            "fw_config_policy_route", {"val": {"id": 2}, "msg": "success"}
        )

        self.assertEqual(summary["policy_route_id"], 2)

    def test_extract_summary_empty_for_delete_response(self) -> None:
        from atomic_ops.runner.policy_route import _extract_policy_route_summary

        summary = _extract_policy_route_summary("fw_delete_policy_route", {"msg": "success"})

        self.assertEqual(summary, {})


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

    def test_wraps_rollback_context_when_contract_exists(self) -> None:
        fake_repo = SimpleNamespace(
            read_operation=lambda op_id: SimpleNamespace(
                data={
                    "side_effect": "state_mutation",
                    "rollback_strategy": {
                        "type": "inverse_op",
                        "op_id": "fw_delete_policy_route",
                        "snapshot_required": False,
                        "required_inputs": ["policy_route_id"],
                    },
                }
            )
        )
        with patch("atomic_ops.commands.run.Repository.from_default_cache", return_value=fake_repo):
            envelope = _to_run_envelope(
                {
                    "op_id": "fw_config_policy_route",
                    "status": "success",
                    "policy_route_id": "pbr-001",
                }
            )

        rollback_context = envelope["metadata"]["rollback_context"]
        self.assertEqual(rollback_context["strategy"], "inverse_op")
        self.assertEqual(rollback_context["op_id"], "fw_delete_policy_route")
        self.assertEqual(rollback_context["inputs"], {"policy_route_id": "pbr-001"})

    def test_cli_dry_run_json_uses_fixed_envelope(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                [
                    "run",
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "object",
                    "config",
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
                    "--format",
                    "json",
                    "--base-url",
                    "https://192.0.2.1",
                    "interface",
                    "create",
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


class RollbackContractTests(unittest.TestCase):
    def test_readiness_passes_inverse_policy_route_contract(self) -> None:
        data = {
            "side_effect": "state_mutation",
            "parameters": {},
            "returns": {"data": {"policy_route_id": "<id>"}},
            "rollback_strategy": {
                "type": "inverse_op",
                "op_id": "fw_delete_policy_route",
                "snapshot_required": False,
                "required_inputs": ["policy_route_id"],
            },
            "post_verify": {"op_id": "fw_verify_policy_route", "expected_state": "absent"},
        }

        report = readiness_report(
            "fw_config_policy_route",
            data,
            {"fw_delete_policy_route", "fw_verify_policy_route"}.__contains__,
        )

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["rollback_strategy"], "inverse_op")
        self.assertEqual(report["missing"], [])

    def test_validate_blocks_restore_snapshot_without_snapshot(self) -> None:
        data = {
            "side_effect": "state_mutation",
            "rollback_strategy": {
                "type": "restore_snapshot",
                "snapshot_required": True,
                "required_inputs": [],
            },
        }

        findings = validate_rollback_contract("fw_update_policy_route", data, set().__contains__)

        self.assertIn("ROLLBACK_PRE_SNAPSHOT_MISSING", {finding.finding_type for finding in findings})
        self.assertIn("ROLLBACK_APPLY_MISSING", {finding.finding_type for finding in findings})

    def test_cli_validate_rollback_uses_repo_contracts(self) -> None:
        fake_repo = _FakeRepo(
            {
                "fw_config_policy_route": {
                    "side_effect": "state_mutation",
                    "returns": {"data": {"policy_route_id": "<id>"}},
                    "rollback_strategy": {
                        "type": "inverse_op",
                        "op_id": "fw_delete_policy_route",
                        "snapshot_required": False,
                        "required_inputs": ["policy_route_id"],
                    },
                    "post_verify": {"op_id": "fw_verify_policy_route", "expected_state": "absent"},
                },
                "fw_delete_policy_route": {"side_effect": "observation"},
                "fw_verify_policy_route": {"side_effect": "observation"},
            }
        )
        stdout = io.StringIO()

        with patch("atomic_ops.commands.validate.Repository.from_default_cache", return_value=fake_repo):
            with contextlib.redirect_stdout(stdout):
                exit_code = cli_main(["validate", "--check", "rollback", "--format", "json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["status"], "passed")
        self.assertEqual(payload["error_count"], 0)

    def test_cli_rollback_check_blocks_irreversible_contract(self) -> None:
        fake_repo = _FakeRepo(
            {
                "fw_clear_policy_route_hitcount": {
                    "side_effect": "destructive",
                    "rollback_strategy": {
                        "type": "irreversible",
                        "snapshot_required": False,
                        "required_inputs": [],
                        "notes": "hitcount cannot be restored after clear",
                    },
                    "post_verify": {"op_id": "fw_verify_policy_route", "expected_state": "hitcount_zero"},
                },
                "fw_verify_policy_route": {"side_effect": "observation"},
            }
        )
        stdout = io.StringIO()

        with patch("atomic_ops.commands.rollback.Repository.from_default_cache", return_value=fake_repo):
            with contextlib.redirect_stdout(stdout):
                exit_code = cli_main(
                    [
                        "rollback",
                        "check",
                        "--op",
                        "fw_clear_policy_route_hitcount",
                        "--format",
                        "json",
                    ]
                )

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["status"], "blocked")
        self.assertEqual(payload["rollback_strategy"], "irreversible")


class _FakeRepo:
    def __init__(self, documents: dict[str, dict[str, object]]) -> None:
        self.documents = documents
        self.is_stale = False

    def metadata_summary(self) -> dict[str, object]:
        return {"last_sync_status": "SYNCED"}

    def list_operations(self, device: str | None = None) -> list[object]:
        return [SimpleNamespace(op_id=op_id) for op_id in sorted(self.documents)]

    def read_operation(self, op_id: str) -> object:
        return SimpleNamespace(data=self.documents[op_id])
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


class IptunPayloadTests(unittest.TestCase):
    def test_build_4over6_payload(self) -> None:
        payload = build_iptun_payload(
            tunnel_type="4over6", entry_id="tunnel1",
            src_addr="2001::1", dst_addr="2001::2", ip_addresses=["13.0.0.1/24"],
        )
        self.assertEqual(payload["id"], "tunnel1")
        self.assertEqual(payload["val"]["type"], 15)
        self.assertEqual(payload["val"]["ipip"], {"src_addr": "2001::1", "dst_addr": "2001::2"})
        self.assertNotIn("gre", payload["val"])

    def test_build_gre_payload(self) -> None:
        payload = build_iptun_payload(
            tunnel_type="gre", entry_id="tunnel3",
            src_addr="7.7.7.1", dst_addr="7.7.7.2", ip_addresses=["6.6.6.6/24"], gre_key=0,
        )
        self.assertEqual(payload["val"]["type"], 11)
        self.assertEqual(payload["val"]["gre"]["tunnel_type"], 1)
        self.assertEqual(payload["val"]["gre"]["key"], 0)
        self.assertNotIn("ipip", payload["val"])

    def test_rejects_4over6_with_ipv4_endpoints(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_iptun_payload(
                tunnel_type="4over6", entry_id="tunnel1",
                src_addr="1.1.1.1", dst_addr="2.2.2.2", ip_addresses=["13.0.0.1/24"],
            )
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_rejects_gre_payload_with_ipip_subobject(self) -> None:
        with self.assertRaises(RunnerError):
            validate_iptun_payload(
                {"id": "tunnel3", "val": {"name": "tunnel3", "type": 11, "ipip": {"src_addr": "1.1.1.1", "dst_addr": "2.2.2.2"}}},
                op_id="fw_config_iptun",
            )

    def test_build_batch_delete_payload(self) -> None:
        payload = build_iptun_batch_delete_payload(entry_ids=["tunnel1", "tunnel2"])
        self.assertEqual(len(payload["batch"]), 2)
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/iptun")
        self.assertEqual(payload["batch"][0]["body"], {"id": ["tunnel1"]})

    def test_rejects_batch_delete_with_wrong_resource(self) -> None:
        with self.assertRaises(RunnerError):
            validate_iptun_payload(
                {"batch": [{"method": "DELETE", "resource": "/api/v1/intf", "body": {"id": ["tunnel1"]}}]},
                op_id="fw_delete_batch_iptun",
            )


class InterfaceTunnelPayloadTests(unittest.TestCase):
    def test_build_tunnel_4over6_payload(self) -> None:
        payload = build_interface_payload(
            interface_kind="tunnel", entry_id="tunnel1",
            tunnel_type="4over6", src_addr="2001::1", dst_addr="2001::2",
            ip_addresses=["3.3.3.3/24"],
        )
        self.assertEqual(payload["val"]["type"], 15)
        self.assertEqual(payload["val"]["mode"], "Route")
        self.assertEqual(payload["val"]["ipip"]["src_addr"], "2001::1")
        self.assertIn("ipv4_address_mode_config", payload["val"])

    def test_rejects_tunnel_create_via_post(self) -> None:
        payload = build_interface_payload(
            interface_kind="tunnel", entry_id="tunnel1",
            tunnel_type="4over6", src_addr="2001::1", dst_addr="2001::2",
        )
        with self.assertRaises(RunnerError) as context:
            validate_interface_payload(payload, op_id="fw_config_interface")
        self.assertIn("PUT and GET only", context.exception.message)

    def test_rejects_tunnel_non_route_mode(self) -> None:
        with self.assertRaises(RunnerError):
            build_interface_payload(
                interface_kind="tunnel", entry_id="tunnel1", mode="Switch",
                tunnel_type="gre", src_addr="1.1.1.1", dst_addr="2.2.2.2",
            )


class AliasLookupTests(unittest.TestCase):
    def test_extract_keywords(self) -> None:
        self.assertEqual(extract_alias_keywords("fw_config_pppoe"), ["pppoe"])
        self.assertEqual(extract_alias_keywords("fw_config_security_policy"), ["security-policy"])
        self.assertEqual(extract_alias_keywords("fw_config_southbound_interface"), ["southbound-interface"])
        self.assertEqual(extract_alias_keywords("fw_config_batch_acl_policy"), ["acl-policy"])
        self.assertEqual(extract_alias_keywords("fw_delete_batch_iptun"), ["iptun"])

    def test_find_ops_by_alias_matches_aliases(self) -> None:
        operations = [
            SimpleNamespace(op_id="fw_config_interface", aliases=["pppoe", "subinterface"], tags=["interface"], description="Create interface."),
            SimpleNamespace(op_id="fw_config_acl_policy", aliases=["security-policy"], tags=["acl"], description="ACL policy."),
        ]
        matches = find_ops_by_alias("pppoe", operations)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0]["op_id"], "fw_config_interface")
        self.assertEqual(matches[0]["matched_field"], "aliases")
        self.assertIn("pppoe", matches[0]["matched_aliases"])

    def test_find_ops_by_alias_matches_description(self) -> None:
        operations = [
            SimpleNamespace(op_id="fw_config_iptun", aliases=[], tags=["iptun"], description="Create an IP tunnel."),
        ]
        matches = find_ops_by_alias("tunnel", operations)
        self.assertEqual(matches[0]["op_id"], "fw_config_iptun")
        self.assertEqual(matches[0]["matched_field"], "description")


class IptunCliDryRunTests(unittest.TestCase):
    def test_cli_iptun_config_4over6_dry_run(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "iptun", "config", "--id", "tunnel1", "--tunnel-type", "4over6",
                 "--src-addr", "2001::1", "--dst-addr", "2001::2", "--ip-address", "13.0.0.1/24"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_iptun")
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["type"], 15)

    def test_cli_iptun_verify_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(["run", "--format", "json", "--base-url", "https://192.0.2.1", "iptun", "verify"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_verify_iptun")
        self.assertEqual(payload["data"]["request"]["method"], "GET")

    def test_cli_iptun_delete_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(["run", "--format", "json", "--base-url", "https://192.0.2.1", "iptun", "delete", "--id", "tunnel6"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/iptun?id=tunnel6"))


class InterfaceTunnelCliTests(unittest.TestCase):
    def test_cli_interface_update_tunnel_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "interface", "update", "--interface-kind", "tunnel", "--id", "tunnel1",
                 "--tunnel-type", "4over6", "--src-addr", "2001::1", "--dst-addr", "2001::2",
                 "--ip-address", "3.3.3.3/24"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_update_interface")
        self.assertEqual(payload["data"]["request"]["method"], "PUT")
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["type"], 15)

    def test_cli_interface_create_tunnel_rejected(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1", "--verify-tls",
                 "interface", "create", "--interface-kind", "tunnel", "--id", "tunnel1",
                 "--tunnel-type", "4over6", "--src-addr", "2001::1", "--dst-addr", "2001::2",
                 "--ip-address", "3.3.3.3/24"]
            )
        self.assertNotEqual(exit_code, 0)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["error_code"], "RUNNER_VALIDATION_FAILED")
        self.assertIn("PUT and GET only", payload["message"])

    def test_cli_interface_delete_tunnel_rejected(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1", "--verify-tls",
                 "interface", "delete", "--id", "tunnel1"]
            )
        self.assertNotEqual(exit_code, 0)
        payload = json.loads(stderr.getvalue())
        self.assertEqual(payload["error_code"], "RUNNER_VALIDATION_FAILED")


class _FakeAliasOp:
    def __init__(self, op_id, aliases, tags, description):
        self.op_id = op_id
        self.aliases = aliases
        self.tags = tags
        self.description = description

    def to_dict(self):
        return {"op_id": self.op_id, "aliases": self.aliases, "tags": self.tags, "description": self.description}


class _FakeAliasRepo:
    def __init__(self, operations):
        self.operations = operations
        self.is_stale = False

    def metadata_summary(self):
        return {"last_sync_status": "SYNCED"}

    def list_operations(self, device=None):
        return self.operations

    def read_operation(self, op_id):
        from atomic_ops.repository import ERROR_OP_NOT_FOUND, ReadError
        raise ReadError(ERROR_OP_NOT_FOUND, f"Operation not found: {op_id}", {"op_id": op_id})


class ListQueryTests(unittest.TestCase):
    def test_list_query_filters_by_alias(self) -> None:
        operations = [
            _FakeAliasOp("fw_config_interface", ["pppoe", "subinterface"], ["interface"], "Create interface."),
            _FakeAliasOp("fw_config_acl_policy", ["security-policy"], ["acl"], "ACL policy."),
        ]
        fake_repo = _FakeAliasRepo(operations)
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout), patch(
            "atomic_ops.commands.list_ops.Repository.from_default_cache", return_value=fake_repo
        ):
            exit_code = cli_main(["list", "--query", "pppoe", "--format", "json"])
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        op_ids = [op["op_id"] for op in payload["operations"]]
        self.assertEqual(op_ids, ["fw_config_interface"])


class ValidateAliasTests(unittest.TestCase):
    def test_validate_reports_alias_suggestions_for_missing_op(self) -> None:
        operations = [
            _FakeAliasOp("fw_config_interface", ["pppoe", "subinterface"], ["interface"], "Create interface."),
            _FakeAliasOp("fw_config_acl_policy", ["security-policy"], ["acl"], "ACL policy."),
        ]
        fake_repo = _FakeAliasRepo(operations)
        with tempfile.TemporaryDirectory() as tmp:
            case_path = Path(tmp) / "case.yaml"
            case_path.write_text(
                "test_case_id: tc\n"
                "steps:\n  - step: s\n    op_id: fw_config_pppoe\n    device: fw\n"
                "tight_sequence:\n  enabled: true\n  steps:\n"
                "    - step: s2\n      op_id: fw_config_security_policy\n      device: fw\n",
                encoding="utf-8",
            )
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr), patch(
                "atomic_ops.commands.validate.Repository.from_default_cache", return_value=fake_repo
            ):
                exit_code = cli_main(["validate", str(case_path), "--format", "json"])
        self.assertNotEqual(exit_code, 0)
        data = json.loads(stderr.getvalue())
        refs = {ref["op_id"]: ref for ref in data["details"]["missing_refs"]}
        pppoe_suggestions = [s["op_id"] for s in refs["fw_config_pppoe"]["alias_suggestions"]]
        security_suggestions = [s["op_id"] for s in refs["fw_config_security_policy"]["alias_suggestions"]]
        self.assertIn("fw_config_interface", pppoe_suggestions)
        self.assertIn("fw_config_acl_policy", security_suggestions)


class ConfigTransferPayloadTests(unittest.TestCase):
    def test_build_export_payload(self) -> None:
        payload = build_export_payload(moduletype="systemconfig", filetype="tgz", data_id=["a", "b"])
        self.assertEqual(payload["val"]["moduletype"], "systemconfig")
        self.assertEqual(payload["val"]["filetype"], "tgz")
        self.assertEqual(payload["val"]["dataId"], ["a", "b"])

    def test_build_import_handle_payload(self) -> None:
        payload = build_import_handle_payload(
            moduletype="systemconfig", filetype="tgz", operationtype="override", chunkornot=False,
        )
        self.assertEqual(payload["val"]["operationtype"], "override")
        self.assertFalse(payload["val"]["chunkornot"])

    def test_rejects_empty_moduletype(self) -> None:
        with self.assertRaises(RunnerError):
            build_export_payload(moduletype="", filetype="tgz")


class PollingTests(unittest.TestCase):
    def test_poll_until_returns_when_done(self) -> None:
        responses = iter([{"vals": []}, {"vals": [{"filename": "systemconfig/systemconfig.tgz"}]}])
        result = poll_until(lambda: next(responses), timeout_ms=1000, interval_ms=0, is_done=lambda r: bool(r.get("vals")))
        self.assertEqual(result["vals"][0]["filename"], "systemconfig/systemconfig.tgz")

    def test_poll_until_times_out(self) -> None:
        with self.assertRaises(RunnerError) as context:
            poll_until(lambda: {"vals": []}, timeout_ms=50, interval_ms=5, is_done=lambda r: bool(r.get("vals")))
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")


class ExportFileExecuteTests(unittest.TestCase):
    def test_execute_export_file_downloads_and_writes_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            out_path = Path(temp_dir) / "systemconfig.tgz"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )

            def json_side_effect(method, url, **kwargs):
                # POST 发起返回 taskid；GET 轮询返回 filename
                if method == "POST":
                    return (200, {"msg": "success", "vals": [{"downloadtaskid": 1}]}, "{}")
                return (200, {"msg": "success", "vals": [{"filename": "systemconfig/systemconfig.tgz"}]}, "{}")

            with patch("atomic_ops.runner.config_transfer.request_json", side_effect=json_side_effect) as json_mock, \
                 patch("atomic_ops.runner.config_transfer.request_bytes", return_value=(200, b"fake-tgz-bytes")) as bytes_mock:
                result = execute_export_file(
                    base_url="https://192.0.2.1", session_file=session_file, auth_header="Authorization",
                    moduletype="systemconfig", filetype="tgz", output_path=str(out_path),
                    data_id=[], poll_timeout_ms=2000, poll_interval_ms=0,
                    verify_tls=False, timeout=10,
                )
                self.assertEqual(result["op_id"], "fw_config_export_file")
                self.assertEqual(result["status"], "success")
                self.assertEqual(result["moduletype"], "systemconfig")
                self.assertEqual(result["download_task_id"], 1)
                self.assertEqual(result["file_size"], len(b"fake-tgz-bytes"))
                self.assertEqual(out_path.read_bytes(), b"fake-tgz-bytes")
                self.assertEqual(len(json_mock.call_args_list), 2)
                self.assertEqual(bytes_mock.call_args_list[0].args[0], "GET")
                self.assertIn("downloadfile?id=systemconfig", bytes_mock.call_args_list[0].args[1])

    def test_execute_export_file_times_out_when_filename_never_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            out_path = Path(temp_dir) / "out.tgz"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )

            def json_side_effect(method, url, **kwargs):
                # POST 发起返回 taskid；GET 轮询永远返回空 vals（filename 未就绪）
                if url.endswith("/downloadfilehandle"):
                    return (200, {"msg": "success", "vals": [{"downloadtaskid": 1}]}, "{}")
                return (200, {"msg": "success", "vals": []}, "{}")

            with patch("atomic_ops.runner.config_transfer.request_json", side_effect=json_side_effect):
                with self.assertRaises(RunnerError) as context:
                    execute_export_file(
                        base_url="https://192.0.2.1", session_file=session_file, auth_header="Authorization",
                        moduletype="systemconfig", filetype="tgz", output_path=str(out_path),
                        data_id=[], poll_timeout_ms=50, poll_interval_ms=5,
                        verify_tls=False, timeout=10,
                    )
            self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")


class ImportFileExecuteTests(unittest.TestCase):
    def test_execute_import_file_runs_full_workflow(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            in_path = Path(temp_dir) / "systemconfig.tgz"
            in_path.write_bytes(b"fake-tgz-bytes")
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )

            def json_side_effect(method, url, **kwargs):
                if url.endswith("/uploadfilehandle") and method == "POST":
                    return (200, {"msg": "success", "vals": [{"uploadtaskid": 1}]}, "{}")
                if url.endswith("/uploadfilehandle"):  # GET 轮询
                    return (200, {"msg": "success"}, "{}")
                if url.endswith("/importfile"):  # 确认
                    return (200, {"msg": "success", "vals": [{"havefile": True}]}, "{}")
                return (200, {"msg": "success"}, "{}")

            with patch("atomic_ops.runner.config_transfer.request_multipart", return_value=(200, {"msg": "success"}, "{}")) as mp_mock, \
                 patch("atomic_ops.runner.config_transfer.request_json", side_effect=json_side_effect):
                result = execute_import_file(
                    base_url="https://192.0.2.1", session_file=session_file, auth_header="Authorization",
                    moduletype="systemconfig", filetype="tgz", operationtype="override",
                    input_path=str(in_path), chunkornot=False,
                    poll_timeout_ms=2000, poll_interval_ms=0,
                    verify_tls=False, timeout=10,
                )

        self.assertEqual(result["op_id"], "fw_config_import_file")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["upload_task_id"], 1)
        self.assertTrue(result["import_confirmed"])
        self.assertTrue(result["havefile"])
        # multipart 上传字段
        _args, kwargs = mp_mock.call_args
        self.assertEqual(kwargs["fields"]["file_name"], "systemconfig.tgz")
        self.assertEqual(kwargs["fields"]["chunkornot"], "no")
        self.assertIn("filename", kwargs["files"])

    def test_execute_import_file_rejects_missing_input(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            with self.assertRaises(RunnerError) as context:
                execute_import_file(
                    base_url="https://192.0.2.1", session_file=session_file, auth_header="Authorization",
                    moduletype="systemconfig", filetype="tgz", operationtype="override",
                    input_path=str(Path(temp_dir) / "missing.tgz"), chunkornot=False,
                    poll_timeout_ms=2000, poll_interval_ms=0, verify_tls=False, timeout=10,
                )
            self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")


class RebootExecuteTests(unittest.TestCase):
    def test_execute_reboot_success_invalidates_session(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.reboot.request_json", return_value=(200, {"msg": "success"}, "{}")):
                result = execute_reboot(
                    base_url="https://192.0.2.1", session_file=session_file, auth_header="Authorization",
                    expected_unavailable_seconds=300, verify_tls=False, timeout=10,
                )

        self.assertEqual(result["op_id"], "fw_config_reboot")
        self.assertEqual(result["status"], "success")
        self.assertTrue(result["reboot_initiated"])
        self.assertTrue(result["session_invalidated"])
        self.assertEqual(result["expected_unavailable_seconds"], 300)

    def test_execute_reboot_treats_disconnect_as_initiated(self) -> None:
        from atomic_ops.runner.errors import RunnerError as _RunnerError
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            # 模拟 reboot 已触发但设备在响应前断连
            with patch("atomic_ops.runner.reboot.request_json", side_effect=_RunnerError("RUNNER_DEVICE_UNREACHABLE", "disconnected", {}, retryable=True)):
                result = execute_reboot(
                    base_url="https://192.0.2.1", session_file=session_file, auth_header="Authorization",
                    expected_unavailable_seconds=300, verify_tls=False, timeout=10,
                )

        self.assertTrue(result["reboot_initiated"])
        self.assertTrue(result["session_invalidated"])
        self.assertEqual(result["response"]["disconnected_before_response"], True)


class ConfigTransferCliDryRunTests(unittest.TestCase):
    def test_cli_export_file_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "export-file", "config", "--moduletype", "systemconfig", "--output-path", "/tmp/sc.tgz"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_export_file")
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["moduletype"], "systemconfig")

    def test_cli_import_file_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "import-file", "config", "--moduletype", "systemconfig", "--input-path", "/tmp/sc.tgz"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_import_file")
        self.assertEqual(payload["data"]["handle_request"]["payload"]["val"]["operationtype"], "override")


class RebootCliDryRunTests(unittest.TestCase):
    def test_cli_reboot_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1", "reboot", "config"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_reboot")
        self.assertEqual(payload["data"]["expected_unavailable_seconds"], 300)
        self.assertEqual(payload["data"]["request"]["method"], "GET")


class HaPayloadTests(unittest.TestCase):
    def test_build_hasync_payload(self) -> None:
        payload = build_hasync_payload(module="all")
        self.assertEqual(payload["id"], 0)
        self.assertEqual(payload["val"]["module"], "all")

    def test_build_haconfig_payload(self) -> None:
        payload = build_haconfig_payload(
            enable=True, role="BACKUP", mode="MB", hb_interface="HA",
            local_addr="1.1.1.2", remote_addr="1.1.1.1",
        )
        self.assertEqual(payload["id"], "haconfig")
        self.assertEqual(payload["val"]["role"], "BACKUP")
        self.assertEqual(payload["val"]["hb"]["interface"], "HA")
        self.assertEqual(payload["val"]["hb"]["localAddr"], "1.1.1.2")

    def test_build_hainterface_payload(self) -> None:
        payload = build_hainterface_payload(track_intf="GE0_1")
        self.assertEqual(payload["val"]["trackIntf"], "GE0_1")

    def test_build_havrrp_payload(self) -> None:
        payload = build_havrrp_payload(
            interface="GE0_9", vr_id=1, vr_role="MASTER", vips=["3.3.3.3/24"],
        )
        self.assertEqual(payload["val"]["vrId"], 1)
        self.assertEqual(payload["val"]["vrRole"], "MASTER")
        self.assertEqual(payload["val"]["vips"], ["3.3.3.3/24"])
        self.assertTrue(payload["val"]["enable"])

    def test_build_havrrp_update_payload(self) -> None:
        payload = build_havrrp_update_payload(
            entry_id="GE0_9_1", interface="GE0_9", vr_id=1, vr_role="MASTER", vips=["6.6.6.5/24"],
        )
        self.assertEqual(payload["id"], "GE0_9_1")
        self.assertNotIn("enable", payload["val"])
        self.assertNotIn("useVirtualMac", payload["val"])

    def test_build_hainterface_batch_delete_payload(self) -> None:
        payload = build_hainterface_batch_delete_payload(entry_ids=["1", "2"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/hainterface")
        self.assertEqual(payload["batch"][0]["body"]["id"], ["1"])

    def test_build_havrrp_batch_delete_payload(self) -> None:
        payload = build_havrrp_batch_delete_payload(entry_ids=["GE0_9_1"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/havrrp")


class HaIplinkPayloadTests(unittest.TestCase):
    def test_build_haiplink_payload(self) -> None:
        payload = build_haiplink_payload(
            name="iplink1", destination="3.3.3.3", interface="any",
        )
        self.assertEqual(payload["val"]["name"], "iplink1")
        self.assertEqual(payload["val"]["destination"], "3.3.3.3")
        self.assertEqual(payload["val"]["detectType"], 0)

    def test_build_halinkgroup_payload(self) -> None:
        payload = build_halinkgroup_payload(name="iplinkgroup", link_name=["iplink1"])
        self.assertEqual(payload["val"]["name"], "iplinkgroup")
        self.assertEqual(payload["val"]["link_name"], ["iplink1"])
        self.assertFalse(payload["val"]["mode_strict"])

    def test_haiplink_batch_delete_has_is_group_undefined(self) -> None:
        payload = build_haiplink_batch_delete_payload(entry_ids=["iplink1"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/ha/iplink")
        self.assertEqual(payload["batch"][0]["body"]["isGroup"], ["undefined"])

    def test_halinkgroup_batch_delete_has_is_group_true(self) -> None:
        payload = build_halinkgroup_batch_delete_payload(entry_ids=["iplinkgroup"])
        self.assertEqual(payload["batch"][0]["body"]["isGroup"], ["true"])

    def test_halinkgroup_batch_delete_rejects_empty(self) -> None:
        with self.assertRaises(RunnerError):
            build_halinkgroup_batch_delete_payload(entry_ids=[])


class HaExecuteTests(unittest.TestCase):
    def test_execute_hasync_put_success(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.ha.request_json", return_value=(200, {"msg": "success"}, "{}")) as request:
                result = execute_ha(
                    op_id="fw_config_hasync", base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", payload=build_hasync_payload(module="all"),
                    verify_tls=False, timeout=10,
                )
            args, kwargs = request.call_args
            self.assertEqual(args[0], "PUT")
            self.assertTrue(args[1].endswith("/api/v1/hasync"))
        self.assertEqual(result["op_id"], "fw_config_hasync")
        self.assertEqual(result["status"], "success")

    def test_execute_hasynclist_get_returns_menu_list(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.ha.request_json", return_value=(200, {"menuList": [{"name": "INTERFACE"}]}, "{}")):
                result = execute_ha(
                    op_id="fw_verify_hasynclist", base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", payload=None, verify_tls=False, timeout=10,
                )
        self.assertEqual(result["response"]["menuList"][0]["name"], "INTERFACE")

    def test_execute_hainterface_delete_uses_query_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.ha.request_json", return_value=(200, {"msg": "success"}, "{}")) as request:
                execute_ha(
                    op_id="fw_delete_hainterface", base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", payload={"id": "1"}, verify_tls=False, timeout=10,
                )
            args, kwargs = request.call_args
            self.assertEqual(args[0], "DELETE")
            self.assertIn("id=1", args[1])


class HaIplinkExecuteTests(unittest.TestCase):
    def test_execute_halinkgroup_delete_carries_is_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.ha_iplink.request_json", return_value=(200, {"msg": "success"}, "{}")) as request:
                execute_ha_iplink(
                    op_id="fw_delete_halinkgroup", base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", payload={"id": "iplinkgroup"},
                    page=1, size=100, verify_tls=False, timeout=10,
                )
            args, kwargs = request.call_args
            self.assertEqual(args[0], "DELETE")
            self.assertIn("id=iplinkgroup", args[1])
            self.assertIn("isGroup=true", args[1])

    def test_execute_haiplink_delete_has_no_is_group(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.ha_iplink.request_json", return_value=(200, {"msg": "success"}, "{}")) as request:
                execute_ha_iplink(
                    op_id="fw_delete_haiplink", base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", payload={"id": "iplink1"},
                    page=1, size=100, verify_tls=False, timeout=10,
                )
            args, kwargs = request.call_args
            self.assertNotIn("isGroup", args[1])

    def test_execute_haiplink_verify_uses_pagination(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.ha_iplink.request_json", return_value=(200, {"count": 0, "vals": []}, "{}")) as request:
                execute_ha_iplink(
                    op_id="fw_verify_haiplink", base_url="https://192.0.2.1", session_file=session_file,
                    auth_header="Authorization", payload=None,
                    page=2, size=50, verify_tls=False, timeout=10,
                )
            args, kwargs = request.call_args
            self.assertIn("page=2", args[1])
            self.assertIn("size=50", args[1])


class HaCliDryRunTests(unittest.TestCase):
    def test_cli_hasync_config_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ha", "hasync-config", "--module", "all"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_hasync")
        self.assertEqual(payload["data"]["request"]["method"], "PUT")

    def test_cli_havrrp_config_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ha", "havrrp-config", "--interface", "GE0_9", "--vr-id", "1",
                 "--vr-role", "MASTER", "--vip", "3.3.3.3/24"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_havrrp")
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["vrId"], 1)

    def test_cli_halinkgroup_delete_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "halinkgroup", "delete", "--id", "iplinkgroup"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_halinkgroup")
        self.assertIn("isGroup=true", payload["data"]["request"]["url"])


class ObjectDeleteVerifyTests(unittest.TestCase):
    def test_build_delete_dry_run_url_carries_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            result = build_object_dry_run(
                op_id="fw_delete_object",
                base_url="https://192.0.2.1",
                session_file=session_file,
                auth_header="Authorization",
                payload={"id": "srcObj"},
                page=1,
                size=40,
                verify_tls=False,
                timeout=10.0,
            )
        self.assertEqual(result["op_id"], "fw_delete_object")
        self.assertEqual(result["request"]["method"], "DELETE")
        self.assertTrue(result["request"]["url"].endswith("/api/v1/ippool?id=srcObj"))
        self.assertIsNone(result["request"]["payload"])

    def test_build_verify_dry_run_url_carries_pagination(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            result = build_object_dry_run(
                op_id="fw_verify_object",
                base_url="https://192.0.2.1",
                session_file=session_file,
                auth_header="Authorization",
                payload=None,
                page=2,
                size=20,
                verify_tls=False,
                timeout=10.0,
            )
        self.assertEqual(result["op_id"], "fw_verify_object")
        self.assertEqual(result["request"]["method"], "GET")
        self.assertTrue(result["request"]["url"].endswith("/api/v1/ippool?page=2&size=20"))
        self.assertIsNone(result["request"]["payload"])

    def test_execute_verify_get_sends_no_json_payload(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.object.request_json", return_value=(200, {"count": 1, "vals": []}, "{}")) as request:
                result = execute_object(
                    op_id="fw_verify_object",
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
        self.assertTrue(args[1].endswith("/api/v1/ippool?page=1&size=40"))
        self.assertIsNone(kwargs["json_payload"])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer abc123")

    def test_execute_delete_uses_query_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.object.request_json", return_value=(200, {"ok": True}, "{}")) as request:
                result = execute_object(
                    op_id="fw_delete_object",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="AuthorizationToken",
                    payload={"id": "srcObj"},
                    page=1,
                    size=40,
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["status"], "success")
        request.assert_called_once()
        args, kwargs = request.call_args
        self.assertEqual(args[0], "DELETE")
        self.assertTrue(args[1].endswith("/api/v1/ippool?id=srcObj"))
        self.assertIsNone(kwargs["json_payload"])
        self.assertEqual(kwargs["headers"]["AuthorizationToken"], "abc123")

    def test_rejects_delete_with_empty_id(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            with self.assertRaises(RunnerError) as context:
                build_object_dry_run(
                    op_id="fw_delete_object",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payload={"id": ""},
                    page=1,
                    size=40,
                    verify_tls=False,
                    timeout=10.0,
                )
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_cli_object_delete_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "object", "delete", "--object-name", "srcObj"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_object")
        self.assertEqual(payload["data"]["request"]["method"], "DELETE")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/ippool?id=srcObj"))

    def test_cli_object_verify_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "object", "verify", "--page", "1", "--size", "40"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_verify_object")
        self.assertEqual(payload["data"]["request"]["method"], "GET")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/ippool?page=1&size=40"))

    def test_build_update_payload_carries_id_and_val(self) -> None:
        payload = build_address_object_update_payload(
            object_name="srcObj", ipaddr="192.168.0.0", mask="16", object_desc=None,
        )
        self.assertEqual(payload["id"], "srcObj")
        self.assertEqual(payload["val"]["name"], "srcObj")
        self.assertEqual(payload["val"]["type"], 4)
        self.assertEqual(payload["val"]["networks"][0]["ipaddr"], "192.168.0.0")
        self.assertEqual(payload["val"]["networks"][0]["mask"], "16")

    def test_build_batch_delete_payload(self) -> None:
        payload = build_object_batch_delete_payload(entry_ids=["srcObj", "dstObj"])
        self.assertEqual(len(payload["batch"]), 2)
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/ippool")
        self.assertEqual(payload["batch"][0]["body"], {"id": ["srcObj"]})

    def test_rejects_batch_delete_with_wrong_resource(self) -> None:
        with self.assertRaises(RunnerError):
            validate_object_payload(
                {"batch": [{"method": "DELETE", "resource": "/api/v1/intf", "body": {"id": ["srcObj"]}}]},
                op_id="fw_delete_batch_object",
            )

    def test_build_update_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            result = build_object_dry_run(
                op_id="fw_update_object",
                base_url="https://192.0.2.1",
                session_file=session_file,
                auth_header="Authorization",
                payload={"id": "srcObj", "val": {"name": "srcObj"}},
                page=1,
                size=40,
                verify_tls=False,
                timeout=10.0,
            )
        self.assertEqual(result["op_id"], "fw_update_object")
        self.assertEqual(result["request"]["method"], "PUT")
        self.assertTrue(result["request"]["url"].endswith("/api/v1/ippool"))
        self.assertEqual(result["request"]["payload"]["id"], "srcObj")

    def test_build_batch_delete_dry_run(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            result = build_object_dry_run(
                op_id="fw_delete_batch_object",
                base_url="https://192.0.2.1",
                session_file=session_file,
                auth_header="Authorization",
                payload={"batch": [{"method": "DELETE", "resource": "/api/v1/ippool", "body": {"id": ["srcObj"]}}]},
                page=1,
                size=40,
                verify_tls=False,
                timeout=10.0,
            )
        self.assertEqual(result["op_id"], "fw_delete_batch_object")
        self.assertEqual(result["request"]["method"], "POST")
        self.assertTrue(result["request"]["url"].endswith("/api/v1/batch"))
        self.assertEqual(len(result["request"]["payload"]["batch"]), 1)

    def test_cli_object_update_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "object", "update", "--object-name", "srcObj", "--ipaddr", "192.168.0.0", "--mask", "16"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_update_object")
        self.assertEqual(payload["data"]["request"]["method"], "PUT")
        self.assertEqual(payload["data"]["request"]["payload"]["id"], "srcObj")

    def test_cli_object_delete_batch_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "object", "delete-batch", "--object-name", "srcObj", "--object-name", "dstObj"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_batch_object")
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/batch"))
        self.assertEqual(len(payload["data"]["request"]["payload"]["batch"]), 2)


if __name__ == "__main__":
    unittest.main()
