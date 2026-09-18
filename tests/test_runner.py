from __future__ import annotations

import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from types import SimpleNamespace
from pathlib import Path
from unittest.mock import patch

import yaml

from atomic_ops.cli import main as cli_main
from atomic_ops.commands.run import _read_secret_env, _to_run_envelope
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
from atomic_ops.runner.nat import (
    SUPPORTED_NAT_TYPES,
    build_nat_batch_delete_payload,
    build_nat_delete_payload,
    build_nat_hitcount_payload,
    build_nat_rule_payload,
    validate_nat_payload,
)
from atomic_ops.runner.ipsec import (
    IPSEC_PORT_ID,
    build_ipsec_batch_delete_payload,
    build_ipsec_policy_payload,
    build_ipsec_port_payload,
    validate_ipsec_payload,
)
from atomic_ops.runner.ngfw_login import login
from atomic_ops.runner.object import (
    IP6POOL_OBJECT_RESOURCE,
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
    build_policy_route_batch_config_payloads,
    build_policy_route_batch_delete_payload,
    build_policy_route_delete_payload,
    build_policy_route_payload,
    build_policy_route_priority_payload,
    execute_policy_route_batch_config,
    increment_value,
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
from atomic_ops.runner._payload import load_json_payload
from atomic_ops.runner.customappobj import (
    build_customappobj_payload,
    build_customappobj_update_payload,
    build_customappobj_batch_delete_payload,
    build_customappobj_dry_run,
    validate_customappobj_payload,
)
from atomic_ops.runner.customappobjtag import (
    build_customappobjtag_payload,
    build_customappobjtag_update_payload,
    build_customappobjtag_batch_delete_payload,
    validate_customappobjtag_payload,
)
from atomic_ops.runner.servicepool import (
    build_servicepool_payload,
    build_servicepool_update_payload,
    build_servicepool_group_payload,
    build_servicepool_group_update_payload,
    build_servicepool_batch_delete_payload,
    build_servicepool_group_batch_delete_payload,
    build_servicepool_dry_run,
    validate_servicepool_payload,
)
from atomic_ops.runner.ippool_group import (
    build_ippool_group_payload,
    build_ippool_group_update_payload,
    build_ippool_group_batch_delete_payload,
    validate_ippool_group_payload,
)
from atomic_ops.runner.ip6pool_group import (
    build_ip6pool_group_payload,
    build_ip6pool_group_update_payload,
    build_ip6pool_group_batch_delete_payload,
    validate_ip6pool_group_payload,
)
from atomic_ops.runner.timeobject import (
    build_timeobject_payload,
    build_timeobject_update_payload,
    build_timeobject_batch_delete_payload,
    validate_timeobject_payload,
)
from atomic_ops.runner.macpool import (
    build_macpool_payload,
    build_macpool_update_payload,
    build_macpool_batch_delete_payload,
    validate_macpool_payload,
)
from atomic_ops.runner.domainpool import (
    build_domainpool_payload,
    build_domainpool_update_payload,
    build_domainpool_batch_delete_payload,
    validate_domainpool_payload,
)
from atomic_ops.runner.filetype import (
    build_filetype_payload,
    build_filetype_update_payload,
    build_filetypeobj_payload,
    build_filetypeobj_update_payload,
    build_filetype_batch_delete_payload,
    validate_filetype_payload,
)
from atomic_ops.runner.cert import (
    build_localcert_payload,
    build_localcert_update_payload,
    build_localcert_issue_payload,
    build_localcacert_payload,
    build_cert_batch_delete_payload,
    validate_cert_payload,
)
from atomic_ops.runner.geoip import (
    build_geoip_payload,
    build_geoip_update_payload,
    build_geoip_delete_payload,
    build_geoip_batch_delete_payload,
    validate_geoip_payload,
)
from atomic_ops.runner.trex import (
    IDEMPOTENT_ERROR_TYPES,
    execute_trex,
    idempotent_error_details,
    validate_idempotent_registry,
)


class StopStreamIdempotentContractTests(unittest.TestCase):
    """幂等停流契约（CT-REM-ATOM-STOP v1.1）— UT-RB-08a~d + UT-RB-07（分层）。

    覆盖：停流失败信封统一键（UT-RB-08a）、契约双形态矩阵（UT-RB-08b）、
    非幂等 / 非命中路径逐键回归反例（UT-RB-08c）、登记表守卫反例（UT-RB-08d）。
    全程离线：mock 设备响应 + 只读解析仓内 atom 源文件；不触真机、不读凭据。
    """

    STOP_OP = "tg_stop_traffic_stream"
    NON_IDEMPOTENT_OP = "tg_start_traffic_stream"
    NOT_FOUND = "RESOURCE_NOT_FOUND"
    SOURCE_REF = "atoms/tg/tg_stop_traffic_stream.yaml#idempotent"
    # 改动前的失败信封键集合（逐键回归基线；新键只允许追加）
    BASELINE_DETAIL_KEYS = ["data", "diag_snapshot_ref", "envelope_status", "error_type", "op_id"]

    @classmethod
    def _atom_declaration(cls, op_id: str) -> dict:
        """只读解析仓内 atom 源文件（不走 cache，保证离线可判定）。"""
        device = op_id.split("_", 1)[0]
        path = Path(__file__).resolve().parents[1] / "atoms" / device / f"{op_id}.yaml"
        return yaml.safe_load(path.read_text(encoding="utf-8"))

    def _execute_failure(self, op_id: str, error_type: str) -> RunnerError:
        """以 mock 的 trex-api 失败信封驱动 execute_trex，返回捕获到的 RunnerError。"""
        envelope = {"status": "error", "error_type": error_type, "data": {"name": "demo"}}
        with patch("atomic_ops.runner.trex.request_json", return_value=(200, envelope, "")):
            with self.assertRaises(RunnerError) as ctx:
                execute_trex(
                    op_id=op_id,
                    base_url="http://127.0.0.1:4500",
                    payload={},
                    verify_tls=False,
                    timeout=1.0,
                )
        return ctx.exception

    # ── UT-RB-08a：停流失败信封暴露统一键 ─────────────────────────────────
    def test_ut_rb_08a_stop_failure_envelope_exposes_unified_key(self) -> None:
        error = self._execute_failure(self.STOP_OP, self.NOT_FOUND)

        # error_code / retryable 与改动前一致（NFR-01：不改映射、不新增退出码）
        self.assertEqual(error.error_code, "RUNNER_VALIDATION_FAILED")
        self.assertFalse(error.retryable)
        # 既有键保持原样 + 新增幂等标记（追加而非替换）
        self.assertEqual(error.details["error_type"], self.NOT_FOUND)
        self.assertEqual(error.details["op_id"], self.STOP_OP)
        self.assertIs(error.details["idempotent"], True)
        self.assertEqual(error.details["idempotent_source"], self.SOURCE_REF)
        # 消费方判定式（双条件同时成立才判「幂等成功」）
        self.assertTrue(
            error.details.get("error_type") == self.NOT_FOUND
            and error.details.get("idempotent") is True
        )
        self.assertEqual(
            sorted(set(error.details) - {"idempotent", "idempotent_source"}),
            self.BASELINE_DETAIL_KEYS,
        )

    # ── UT-RB-08c：非命中路径逐键回归（反例）─────────────────────────────
    def test_ut_rb_08c_non_idempotent_op_details_unchanged(self) -> None:
        error = self._execute_failure(self.NON_IDEMPOTENT_OP, self.NOT_FOUND)

        self.assertEqual(sorted(error.details), self.BASELINE_DETAIL_KEYS)
        self.assertNotIn("idempotent", error.details)
        self.assertNotIn("idempotent_source", error.details)

    def test_ut_rb_08c_registered_op_with_other_error_type_is_not_marked(self) -> None:
        """登记 op 但错误类型不属于幂等集合 → 不标记（避免把参数错判成幂等成功）。"""
        error = self._execute_failure(self.STOP_OP, "INVALID_PARAM")

        self.assertEqual(error.details["error_type"], "INVALID_PARAM")
        self.assertNotIn("idempotent", error.details)
        self.assertNotIn("idempotent_source", error.details)

    def test_detail_helper_hit_and_miss(self) -> None:
        self.assertEqual(
            idempotent_error_details(self.STOP_OP, self.NOT_FOUND),
            {"idempotent": True, "idempotent_source": self.SOURCE_REF},
        )
        self.assertEqual(idempotent_error_details(self.STOP_OP, "TIMEOUT"), {})
        self.assertEqual(idempotent_error_details(self.NON_IDEMPOTENT_OP, self.NOT_FOUND), {})

    # ── UT-RB-08b：契约双形态矩阵 ────────────────────────────────────────
    def test_ut_rb_08b_contract_declares_both_forms(self) -> None:
        """① 语义键 `idempotent` 与错误枚举 `error_types` 同时成立（二选一自洽判据）。"""
        declaration = self._atom_declaration(self.STOP_OP)

        self.assertIs(declaration.get("idempotent"), True)
        self.assertIn(self.NOT_FOUND, declaration.get("error_types") or [])
        # 收敛不新增顶层字段（schema `additionalProperties: false`）
        self.assertEqual(declaration.get("schema_version"), "1.1")

    def test_ut_rb_08b_registry_guard_reports_no_inconsistency(self) -> None:
        """② 登记表 ↔ 声明面一致（返回空列表）。"""
        surface = {self.STOP_OP: self._atom_declaration(self.STOP_OP)}

        self.assertEqual(validate_idempotent_registry(surface), [])

    def test_ut_rb_08b_registry_guard_reads_declaration_via_repository(self) -> None:
        """无注入时的生产路径：经 Repository 只读读取声明并判定一致。"""
        surface = {self.STOP_OP: self._atom_declaration(self.STOP_OP)}

        with patch(
            "atomic_ops.runner.trex.Repository.from_default_cache",
            return_value=_FakeRepo(surface),
        ):
            self.assertEqual(validate_idempotent_registry(), [])

    # ── UT-RB-08d：登记守卫反例（不静默通过）─────────────────────────────
    def test_ut_rb_08d_unreadable_declaration_is_explicit(self) -> None:
        with patch(
            "atomic_ops.runner.trex.Repository.from_default_cache",
            side_effect=RuntimeError("cache unavailable"),
        ):
            self.assertEqual(
                validate_idempotent_registry(),
                [f"decl-unavailable:{self.STOP_OP}"],
            )

    def test_ut_rb_08d_injected_undeclared_op_is_reported(self) -> None:
        surface = {
            self.STOP_OP: self._atom_declaration(self.STOP_OP),
            "tg_no_such_op": {"idempotent": False, "error_types": ["INVALID_PARAM"]},
        }

        with patch.dict(
            IDEMPOTENT_ERROR_TYPES, {"tg_no_such_op": frozenset({self.NOT_FOUND})}
        ):
            findings = validate_idempotent_registry(surface)

        self.assertEqual(
            sorted(findings),
            [
                "idempotent-not-declared:tg_no_such_op",
                "undeclared-error-type:tg_no_such_op:RESOURCE_NOT_FOUND",
            ],
        )

    def test_ut_rb_08d_missing_registration_is_reported(self) -> None:
        """声明面内具幂等停流语义却未登记 → 漏登记（不静默通过）。"""
        surface = {
            self.STOP_OP: self._atom_declaration(self.STOP_OP),
            "tg_delete_traffic_template": {
                "idempotent": True,
                "error_types": ["INVALID_PARAM", self.NOT_FOUND],
            },
        }

        self.assertEqual(
            validate_idempotent_registry(surface),
            ["missing-registration:tg_delete_traffic_template"],
        )

    # ── UT-RB-07（分层）：契约侧可证 / 框架侧 deferred ───────────────────
    def test_ut_rb_07_contract_side_decision_rule(self) -> None:
        """契约侧可证：命中统一键 → 判「幂等成功」；未命中 → 维持真残留信号。

        框架侧断言（`case_runner._normalize_rollback_envelope` 逆序回滚不判
        `cleanup_failed`）**不在本 Story 所有权内**，按设计分层 deferred 至
        `STORY-REM-03-01`（消费方采纳）—— 本用例不冒充该最终结论。
        """
        hit = self._execute_failure(self.STOP_OP, self.NOT_FOUND)
        self.assertTrue(
            hit.details.get("error_type") == self.NOT_FOUND
            and hit.details.get("idempotent") is True
        )

        miss = self._execute_failure(self.STOP_OP, "TIMEOUT")
        self.assertFalse(bool(miss.details.get("idempotent")))


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
        self.assertEqual(payload["val"]["bvi"]["bridge"]["interfaces"], [])
        self.assertEqual(payload["val"]["ip_addresses"], ["191.109.0.31/24", "2091:109::31/64"])

    def test_build_bvi_route_payload_with_parent_name(self) -> None:
        payload = build_interface_payload(
            interface_kind="bvi",
            entry_id="bvi88",
            bvi_instance=11,
            parent_name="GE0_2",
            ip_addresses=["192.88.0.31/24"],
        )

        self.assertEqual(payload["val"]["type"], 14)
        self.assertEqual(payload["val"]["bvi"]["instance"], 11)
        self.assertEqual(
            payload["val"]["bvi"]["bridge"]["interfaces"],
            [{"name": "GE0_2", "bridged_virtual_interface": False, "split_horizon_group": 0}],
        )
        self.assertEqual(payload["val"]["bvi"]["bridge"]["name"], "bvi88")

    def test_build_subinterface_route_payload(self) -> None:
        payload = build_interface_payload(
            interface_kind="sub",
            entry_id="GE0_2.106",
            ip_addresses=["192.106.0.31/24", "2092:106::31/64"],
        )

        self.assertEqual(payload["val"]["type"], 1)
        self.assertEqual(payload["val"]["sub"], {"parent_name": "GE0_2", "sub_id": 106})
        self.assertNotIn("ip6_nd", payload["val"])
        self.assertNotIn("ip6_racfg", payload["val"])

    def test_build_bvi_payload_with_ip6_nd_and_racfg(self) -> None:
        payload = build_interface_payload(
            interface_kind="bvi",
            entry_id="bvi88",
            ip6_nd_prefixes=["66::/96"],
            ip6_racfg_suppress=1,
        )

        self.assertEqual(payload["val"]["ip6_nd"], {"ip_prefix": ["66::/96"]})
        self.assertEqual(payload["val"]["ip6_racfg"], {"suppress": 1})

    def test_build_sub_payload_with_ip6_nd_only(self) -> None:
        payload = build_interface_payload(
            interface_kind="sub",
            entry_id="GE0_2.106",
            ip6_nd_prefixes=["66::/96", "2001:db8::/64"],
        )

        self.assertEqual(payload["val"]["ip6_nd"], {"ip_prefix": ["66::/96", "2001:db8::/64"]})
        self.assertNotIn("ip6_racfg", payload["val"])

    def test_rejects_invalid_ip6_nd_prefix(self) -> None:
        for bad in ("192.0.2.0/24", "66::", "not-a-prefix"):
            with self.assertRaises(RunnerError) as context:
                build_interface_payload(
                    interface_kind="bvi",
                    entry_id="bvi88",
                    ip6_nd_prefixes=[bad],
                )
            self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_rejects_invalid_ip6_racfg_suppress(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_interface_payload(
                interface_kind="bvi",
                entry_id="bvi88",
                ip6_racfg_suppress=2,
            )
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_rejects_ip6_nd_on_unsupported_kind(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_interface_payload(
                interface_kind="bond",
                entry_id="bond1",
                bond_members=["GE0_3"],
                ip6_nd_prefixes=["66::/96"],
            )
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_validate_payload_rejects_invalid_ip6_racfg_suppress(self) -> None:
        payload = {
            "id": "bvi88",
            "val": {
                "name": "bvi88",
                "type": 14,
                "mode": "Route",
                "bvi": {"instance": 11, "bridge": {"name": "bvi88", "interfaces": []}},
                "ip6_nd": {"ip_prefix": ["66::/96"]},
                "ip6_racfg": {"suppress": 9},
            },
        }
        with self.assertRaises(RunnerError) as context:
            validate_interface_payload(payload, op_id="fw_config_interface")
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_validate_payload_accepts_ip6_nd_and_racfg(self) -> None:
        payload = {
            "id": "bvi88",
            "val": {
                "name": "bvi88",
                "type": 14,
                "mode": "Route",
                "bvi": {"instance": 11, "bridge": {"name": "bvi88", "interfaces": []}},
                "ip6_nd": {"ip_prefix": ["66::/96"]},
                "ip6_racfg": {"suppress": 1},
            },
        }
        self.assertEqual(validate_interface_payload(payload, op_id="fw_config_interface"), payload)

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
        # STORY-REM-02-04（#batch-id-list）：主形态 = 单 item 承载 N 个 id。
        # 旧「N item × 每 item 1 个 id」形态见 tests/test_batch.py 的 per_id_item 回归。
        payload = build_interface_batch_delete_payload(entry_ids=["bvi109", "GE0_2.106"])

        self.assertEqual(len(payload["batch"]), 1)
        self.assertEqual(payload["batch"][0]["method"], "DELETE")
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/intf")
        self.assertEqual(payload["batch"][0]["body"], {"id": ["bvi109", "GE0_2.106"]})


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

    def test_rejects_policy_route_with_both_next_hop_and_outgoing_interface(self) -> None:
        """P2-14（2026-09-14 下游反馈升级项）：两种转发模式互斥，二者同时提供必须前置拒绝。

        现场背景：DUT 对越界组合只给晦涩错误（「仅出接口」ePolicyRouteOutIfModeError、
        「网关+出接口」ePolicyRouteOutIfNextHopError，两批次 6+5 次一致），且型号能力不同
        （DAS-TGFW-290 实测仅支持「仅网关」）→ 工具侧显式声明限制并前置拒绝，
        调用方据 details.fields 立即定位，无需等设备回错。
        """
        with self.assertRaises(RunnerError) as context:
            build_policy_route_payload(
                source_network="any",
                source_network_is_group=False,
                dst_network="any",
                dst_network_is_group=False,
                next_hop_ip="18.18.2.2",
                in_interface="GE0_12",
                outgoing_interface="tunnel2",
                service="any",
                weight=1,
                time_obj="",
            )

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")
        self.assertEqual(
            context.exception.details.get("fields"),
            ["next_hop_ip", "outgoing_interface"],
        )

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

    def test_build_policy_route_payload_with_applist_and_app_tag(self) -> None:
        payload = build_policy_route_payload(
            source_network="any",
            source_network_is_group=False,
            dst_network="any",
            dst_network_is_group=False,
            next_hop_ip="2.2.2.2",
            in_interface="any",
            outgoing_interface="",
            service="any",
            weight=213,
            time_obj="",
            applist=[{"appname": "UDP应用", "appid": "479"}],
            app_tag_name=["限速应用"],
        )

        self.assertEqual(payload["val"]["applist"], [{"appname": "UDP应用", "appid": "479"}])
        self.assertEqual(payload["val"]["app_tag_name"], ["限速应用"])

    def test_build_policy_route_payload_with_ip_link(self) -> None:
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
            ip_link_name="13-96",
        )

        self.assertEqual(
            payload["val"]["forwarding_paths"][0]["health_check"],
            {"type": "iplink", "name": "13-96"},
        )

    def test_build_policy_route_payload_health_check_defaults_empty(self) -> None:
        payload = build_policy_route_payload(
            source_network="any",
            source_network_is_group=False,
            dst_network="any",
            dst_network_is_group=False,
            next_hop_ip="1.1.1.1",
            in_interface="GE0_12",
            outgoing_interface="",
            service="any",
            weight=1,
            time_obj="",
        )

        self.assertEqual(payload["val"]["forwarding_paths"][0]["health_check"], {})

    def test_build_policy_route_payload_applist_defaults_empty(self) -> None:
        payload = build_policy_route_payload(
            source_network="any",
            source_network_is_group=False,
            dst_network="any",
            dst_network_is_group=False,
            next_hop_ip="1.1.1.1",
            in_interface="GE0_12",
            outgoing_interface="",
            service="any",
            weight=1,
            time_obj="",
        )

        self.assertEqual(payload["val"]["applist"], [])
        self.assertEqual(payload["val"]["app_tag_name"], [])

    def test_accepts_policy_route_applist_with_appname_only(self) -> None:
        """appid 不作强制（透传原则）：仅含 appname 的项原样透传，不自动补全 appid。

        真相源：runner/policy_route.py `_validate_applist` 注释 —— DUT 实测 2026-08-19
        接受仅含 appname 的项（如 {"appname":"HTTP"}），强制 appid 会拒绝 DUT 合法请求。

        本测试替代原 `test_rejects_policy_route_applist_missing_appid`：原断言要求
        「缺 appid 必须拒绝」，与现行透传语义矛盾，属历史整改后的陈旧测试
        （2026-09-14 经下游反馈核对后改写，非放宽校验）。
        """
        payload = build_policy_route_payload(
            source_network="any",
            source_network_is_group=False,
            dst_network="any",
            dst_network_is_group=False,
            next_hop_ip="1.1.1.1",
            in_interface="GE0_12",
            outgoing_interface="",
            service="any",
            weight=1,
            time_obj="",
            applist=[{"appname": "UDP应用"}],
        )

        # 原样透传：既不拒绝，也不自动补 appid（补全会引入 DUT 未请求的匹配条件）
        self.assertEqual(payload["val"]["applist"], [{"appname": "UDP应用"}])

    def test_rejects_policy_route_app_tag_name_empty_item(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_policy_route_payload(
                source_network="any",
                source_network_is_group=False,
                dst_network="any",
                dst_network_is_group=False,
                next_hop_ip="1.1.1.1",
                in_interface="GE0_12",
                outgoing_interface="",
                service="any",
                weight=1,
                time_obj="",
                app_tag_name=["限速应用", ""],
            )

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

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
        # STORY-REM-02-04（#batch-id-list）：主形态 = 单 item 承载 N 个 id。
        # 旧「N item × 每 item 1 个 id」形态见 tests/test_batch.py 的 per_id_item 回归。
        payload = build_policy_route_batch_delete_payload(
            entry_ids=["1", "2"],
            route_type="ipv4",
        )

        self.assertEqual(len(payload["batch"]), 1)
        self.assertEqual(
            payload["batch"][0],
            {
                "method": "DELETE",
                "resource": "/api/v1/policyroute",
                "body": {"id": ["1", "2"], "is_ip6": ["false", "false"]},
            },
        )

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

    def test_normalizes_empty_source_in_interface_dst_network_to_any(self) -> None:
        payload = build_policy_route_payload(
            source_network="",
            source_network_is_group=False,
            dst_network="",
            dst_network_is_group=False,
            next_hop_ip="2.2.2.2",
            in_interface="",
            outgoing_interface="",
            service="any",
            weight=1,
            time_obj="",
        )
        self.assertEqual(payload["val"]["source_network"], "any")
        self.assertEqual(payload["val"]["in_interface"], "any")
        self.assertEqual(payload["val"]["dst_network"], "any")

    def test_extract_created_from_config_response(self) -> None:
        from atomic_ops.runner.policy_route import _extract_policy_route_summary

        # 设备未显式返回 created -> 默认 True（成功 POST 即新建）
        summary = _extract_policy_route_summary(
            "fw_config_policy_route", {"val": {"id": 2}, "msg": "success"}
        )
        self.assertEqual(summary["policy_route_id"], 2)
        self.assertTrue(summary["created"])

        # 设备显式返回 created -> 用设备值
        summary2 = _extract_policy_route_summary(
            "fw_config_policy_route", {"val": {"id": 3}, "created": False}
        )
        self.assertFalse(summary2["created"])

    def test_update_response_has_no_created(self) -> None:
        from atomic_ops.runner.policy_route import _extract_policy_route_summary

        summary = _extract_policy_route_summary("fw_update_policy_route", {"val": {"id": 5}})
        self.assertEqual(summary["policy_route_id"], 5)
        self.assertNotIn("created", summary)

    def test_increment_value_trailing_digits(self) -> None:
        self.assertEqual(increment_value("GE0_1", 1), "GE0_1")
        self.assertEqual(increment_value("GE0_1", 2), "GE0_2")
        self.assertEqual(increment_value("GE0_1", 10), "GE0_10")
        self.assertEqual(increment_value("test001", 3), "test003")

    def test_increment_value_padded_name(self) -> None:
        self.assertEqual(increment_value("test", 1), "test0001")
        self.assertEqual(increment_value("test", 2), "test0002")
        self.assertEqual(increment_value("test", 12), "test0012")

    def test_increment_value_ipv4_host_and_carry(self) -> None:
        self.assertEqual(increment_value("1.1.1.1", 1), "1.1.1.1")
        self.assertEqual(increment_value("1.1.1.1", 2), "1.1.1.2")
        self.assertEqual(increment_value("1.1.1.1", 254), "1.1.1.254")
        # 主机位超过 254 进位到网段位：1.1.1.254 -> 1.1.2.1
        self.assertEqual(increment_value("1.1.1.1", 255), "1.1.2.1")

    def test_build_policy_route_batch_config_payloads_unchanged(self) -> None:
        payloads = build_policy_route_batch_config_payloads(
            count=3,
            source_network="srcNet",
            source_network_is_group=False,
            dst_network="any",
            dst_network_is_group=False,
            next_hop_ip="2.2.2.2",
            in_interface="any",
            outgoing_interface="",
            service="any",
            weight=100,
            time_obj="",
        )

        self.assertEqual(len(payloads), 3)
        self.assertEqual(payloads[0]["val"]["source_network"], "srcNet")
        self.assertEqual(payloads[1]["val"]["source_network"], "srcNet")
        self.assertEqual(payloads[2]["val"]["source_network"], "srcNet")
        self.assertEqual(payloads[0]["id"], 0)

    def test_build_policy_route_batch_config_payloads_increment(self) -> None:
        payloads = build_policy_route_batch_config_payloads(
            count=3,
            increment=True,
            source_network="srcNet",
            source_network_is_group=False,
            dst_network="any",
            dst_network_is_group=False,
            next_hop_ip="1.1.1.1",
            in_interface="any",
            outgoing_interface="",
            service="any",
            weight=100,
            time_obj="",
        )

        self.assertEqual(len(payloads), 3)
        self.assertEqual(payloads[0]["val"]["source_network"], "srcNet0001")
        self.assertEqual(payloads[1]["val"]["source_network"], "srcNet0002")
        self.assertEqual(payloads[2]["val"]["source_network"], "srcNet0003")
        self.assertEqual(payloads[1]["val"]["forwarding_paths"][0]["next_hop_ip"], "1.1.1.2")

    def test_build_policy_route_batch_config_payloads_rejects_non_positive_count(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_policy_route_batch_config_payloads(
                count=0,
                source_network="any",
                source_network_is_group=False,
                dst_network="any",
                dst_network_is_group=False,
                next_hop_ip="1.1.1.1",
                in_interface="any",
                outgoing_interface="",
                service="any",
                weight=1,
                time_obj="",
            )

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_build_policy_route_batch_config_payloads_keeps_empty_strings_unchanged(self) -> None:
        payloads = build_policy_route_batch_config_payloads(
            count=2,
            increment=True,
            source_network="srcNet",
            source_network_is_group=False,
            dst_network="any",
            dst_network_is_group=False,
            next_hop_ip="",
            in_interface="GE0_4",
            outgoing_interface="tunnel64",
            service="any",
            weight=100,
            time_obj="",
            ip_link_name="13-96",
        )

        self.assertEqual(len(payloads), 2)
        self.assertEqual(payloads[0]["val"]["forwarding_paths"][0]["next_hop_ip"], "")
        self.assertEqual(payloads[1]["val"]["forwarding_paths"][0]["next_hop_ip"], "")
        # 非空字符串仍参与编号
        self.assertEqual(
            payloads[1]["val"]["forwarding_paths"][0]["health_check"],
            {"type": "iplink", "name": "13-97"},
        )

    def test_execute_policy_route_batch_config(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            payloads = build_policy_route_batch_config_payloads(
                count=2,
                source_network="srcNet",
                source_network_is_group=False,
                dst_network="any",
                dst_network_is_group=False,
                next_hop_ip="1.1.1.1",
                in_interface="any",
                outgoing_interface="",
                service="any",
                weight=1,
                time_obj="",
            )
            with patch(
                "atomic_ops.runner.policy_route.request_json",
                side_effect=[(200, {"val": {"id": 11}}, "{}"), (200, {"val": {"id": 12}}, "{}")],
            ) as request:
                result = execute_policy_route_batch_config(
                    op_id="fw_config_policy_route",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payloads=payloads,
                    page=1,
                    size=40,
                    route_type="ipv4",
                    verify_tls=False,
                    timeout=10,
                )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["created_count"], 2)
        self.assertEqual(result["failed_count"], 0)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(result["created"][0]["policy_route_id"], 11)
        self.assertEqual(result["created"][1]["policy_route_id"], 12)

    def test_execute_policy_route_batch_config_partial_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            payloads = build_policy_route_batch_config_payloads(
                count=2,
                source_network="srcNet",
                source_network_is_group=False,
                dst_network="any",
                dst_network_is_group=False,
                next_hop_ip="1.1.1.1",
                in_interface="any",
                outgoing_interface="",
                service="any",
                weight=1,
                time_obj="",
            )
            with patch(
                "atomic_ops.runner.policy_route.request_json",
                side_effect=[(200, {"val": {"id": 21}}, "{}"), (500, {"errCode": 1, "errMsg": "rejected"}, "{}")],
            ) as request:
                result = execute_policy_route_batch_config(
                    op_id="fw_config_policy_route",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payloads=payloads,
                    page=1,
                    size=40,
                    route_type="ipv4",
                    verify_tls=False,
                    timeout=10,
                )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["created_count"], 1)
        self.assertEqual(result["failed_count"], 1)
        self.assertEqual(result["failed"][0]["index"], 2)
        self.assertEqual(result["failed"][0]["error_code"], "RUNNER_CONFIG_REJECTED")


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

    def test_accepts_address_object_name_with_dot_chinese_hyphen(self) -> None:
        for name in ("OBJ-SRC-192", "name.1", "测试对象", "a"):
            payload = build_address_object_payload(
                object_name=name,
                ipaddr="192.168.0.0",
                mask="16",
                object_desc=None,
            )
            self.assertEqual(payload["val"]["name"], name)

    def test_rejects_address_object_name_too_long(self) -> None:
        with self.assertRaises(RunnerError):
            build_address_object_payload(
                object_name="a" * 32,
                ipaddr="192.168.0.0",
                mask="16",
                object_desc=None,
            )

    def test_rejects_address_object_name_dot_or_double_dot(self) -> None:
        for name in (".", ".."):
            with self.assertRaises(RunnerError):
                build_address_object_payload(
                    object_name=name,
                    ipaddr="192.168.0.0",
                    mask="16",
                    object_desc=None,
                )

    def test_rejects_address_object_name_with_idmc_prefix(self) -> None:
        with self.assertRaises(RunnerError):
            build_address_object_payload(
                object_name="IDMC-xxx",
                ipaddr="192.168.0.0",
                mask="16",
                object_desc=None,
            )

    def test_build_ipv4_payload_with_excluded_networks(self) -> None:
        payload = build_address_object_payload(
            object_name="srcWithExcl",
            ipaddr="192.168.0.0",
            mask="16",
            object_desc=None,
            exclnetworks=[{"ipaddr": "192.168.0.5", "mask": ""}],
        )
        self.assertEqual(payload["val"]["exclranges"], [])
        self.assertEqual(payload["val"]["exclnetworks"], [{"ipaddr": "192.168.0.5", "mask": ""}])

    def test_build_ipv4_payload_with_excluded_ranges(self) -> None:
        payload = build_address_object_payload(
            object_name="srcWithExclRng",
            ipaddr="192.168.0.0",
            mask="16",
            object_desc=None,
            exclranges=[{"s_start": 1, "s_end": 10}],
        )
        self.assertEqual(payload["val"]["exclranges"], [{"s_start": 1, "s_end": 10}])
        self.assertEqual(payload["val"]["exclnetworks"], [])

    def test_build_ipv6_payload_with_excluded_networks(self) -> None:
        payload = build_address_object_payload(
            object_name="v6SrcWithExcl",
            ipaddr="2001::",
            mask="64",
            object_desc=None,
            ip_version=6,
            exclnetworks=[{"ipaddr": "2001::1", "mask": ""}],
        )
        self.assertEqual(payload["val"]["networks"][0]["ipaddr"], "2001::")
        self.assertEqual(payload["val"]["networks"][0]["mask"], "64")
        self.assertEqual(payload["val"]["exclnetworks"], [{"ipaddr": "2001::1", "mask": ""}])

    def test_rejects_ipv6_mask_beyond_128(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_address_object_payload(
                object_name="v6BadMask",
                ipaddr="2001::",
                mask="129",
                object_desc=None,
                ip_version=6,
            )
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_rejects_ipv4_ipaddr_for_ipv6_payload(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_address_object_payload(
                object_name="v6WrongIp",
                ipaddr="192.168.0.0",
                mask="24",
                object_desc=None,
                ip_version=6,
            )
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_rejects_exclnetworks_non_list(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_address_object_payload(
                object_name="badExcl",
                ipaddr="192.168.0.0",
                mask="16",
                object_desc=None,
                exclnetworks="not-a-list",
            )
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_rejects_exclnetworks_missing_ipaddr(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_address_object_payload(
                object_name="badExcl",
                ipaddr="192.168.0.0",
                mask="16",
                object_desc=None,
                exclnetworks=[{"mask": "24"}],
            )
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_rejects_exclnetworks_wrong_ip_version(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_address_object_payload(
                object_name="badExcl",
                ipaddr="192.168.0.0",
                mask="16",
                object_desc=None,
                ip_version=6,
                exclnetworks=[{"ipaddr": "192.168.0.5", "mask": ""}],
            )
        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_build_ipv6_update_payload(self) -> None:
        payload = build_address_object_update_payload(
            object_name="v6Src",
            ipaddr="2001::",
            mask="64",
            object_desc=None,
            ip_version=6,
            exclnetworks=[{"ipaddr": "2001::1", "mask": ""}],
        )
        self.assertEqual(payload["id"], "v6Src")
        self.assertEqual(payload["val"]["networks"][0]["ipaddr"], "2001::")
        self.assertEqual(payload["val"]["exclnetworks"], [{"ipaddr": "2001::1", "mask": ""}])


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
    @unittest.skipIf(sys.platform == "win32", "Windows ACL 模型下 Unix 权限位无意义，仅 Linux/macOS 验证")
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

    @unittest.skipIf(sys.platform == "win32", "Windows ACL 模型下 Unix 权限位无意义，仅 Linux/macOS 验证")
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


class InterfaceCliTests(unittest.TestCase):
    def test_cli_interface_get_with_page_and_size(self) -> None:
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
                    "verify",
                    "--page",
                    "2",
                    "--size",
                    "20",
                ]
            )

        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["data"]["request"]["method"], "GET")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/intf?page=2&size=20"))
        self.assertEqual(payload["data"]["request"]["query"], {"page": 2, "size": 20})
        self.assertIsNone(payload["data"]["request"]["payload"])

    def test_cli_interface_get_rejects_invalid_page(self) -> None:
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
                    "verify",
                    "--page",
                    "0",
                ]
            )

        self.assertNotEqual(exit_code, 0)
        self.assertIn("must be a positive integer", stderr.getvalue())


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

    def test_execute_interface_get_applies_page_and_size_query(self) -> None:
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
                    query={"page": 2, "size": 20},
                )

        self.assertEqual(result["status"], "success")
        self.assertEqual(result["request"]["query"], {"page": 2, "size": 20})
        args, kwargs = request.call_args
        self.assertEqual(args[0], "GET")
        self.assertTrue(args[1].endswith("/api/v1/intf?page=2&size=20"))
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

    def test_execute_interface_bvi_member_rejection_suggests_member_port_setup(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            payload = build_interface_payload(
                interface_kind="bvi",
                entry_id="bvi67",
                mode="Route",
                ip_addresses=[],
                name=None,
                desc="",
                enabled=True,
                parent_name="GE0_2",
                sub_id=None,
                bvi_instance=67,
                bond_id=None,
                bond_members=[],
                bond_mode=5,
                bond_lb=0,
                link_type=None,
                pvid=1,
                allow_pass=None,
                tunnel_type=None,
                src_addr=None,
                dst_addr=None,
                gre_tunnel_type=1,
                gre_key=0,
                gre_check_sum=False,
                gre_keepalive_enable=False,
            )
            with patch(
                "atomic_ops.runner.interface.request_json",
                return_value=(400, {"errCode": "eRequestParam", "errMsg": "添加Vlan接口失败"}, "{}"),
            ):
                with self.assertRaises(RunnerError) as context:
                    execute_interface(
                        op_id="fw_config_interface",
                        base_url="https://192.0.2.1",
                        session_file=session_file,
                        auth_header="AuthorizationToken",
                        payload=payload,
                        verify_tls=False,
                        timeout=10,
                    )

        self.assertEqual(context.exception.error_code, "RUNNER_CONFIG_REJECTED")
        self.assertIsNotNone(context.exception.suggestion)
        self.assertIn("Switch mode", context.exception.suggestion)
        self.assertIn("linkType 1", context.exception.suggestion)

    def test_execute_interface_bvi_without_member_rejection_has_no_member_suggestion(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file,
                base_url="https://192.0.2.1",
                username="admin",
                session_value="abc123",
                source_op_id="fw_login_web_management",
            )
            payload = build_interface_payload(
                interface_kind="bvi",
                entry_id="bvi67",
                mode="Route",
                ip_addresses=[],
                name=None,
                desc="",
                enabled=True,
                parent_name=None,
                sub_id=None,
                bvi_instance=67,
                bond_id=None,
                bond_members=[],
                bond_mode=5,
                bond_lb=0,
                link_type=None,
                pvid=1,
                allow_pass=None,
                tunnel_type=None,
                src_addr=None,
                dst_addr=None,
                gre_tunnel_type=1,
                gre_key=0,
                gre_check_sum=False,
                gre_keepalive_enable=False,
            )
            with patch(
                "atomic_ops.runner.interface.request_json",
                return_value=(400, {"errCode": "eRequestParam", "errMsg": "添加Vlan接口失败"}, "{}"),
            ):
                with self.assertRaises(RunnerError) as context:
                    execute_interface(
                        op_id="fw_config_interface",
                        base_url="https://192.0.2.1",
                        session_file=session_file,
                        auth_header="AuthorizationToken",
                        payload=payload,
                        verify_tls=False,
                        timeout=10,
                    )

        self.assertIsNone(context.exception.suggestion)


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

    def test_cli_interface_delete_tunnel_is_passed_through(self) -> None:
        """delete 的 id 不做类别强校验（透传原则）：物理口/tunnel 是否可删由 DUT 决定。

        真相源：runner/interface.py `_validate_deletable_interface_id` 注释 ——
        「物理口/tunnel 是否可删由 DUT 决定，runner 不再拦截」，仅要求 id 非空。

        本测试替代原 `test_cli_interface_delete_tunnel_rejected`：原断言要求 tunnel delete
        被 runner 拦截，与现行透传语义矛盾，属历史整改后的陈旧测试
        （2026-09-14 经下游反馈核对后改写，非放宽校验）。
        """
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1", "--verify-tls",
                 "interface", "delete", "--id", "tunnel1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_interface")
        self.assertEqual(payload["data"]["request"]["method"], "DELETE")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/intf?id=tunnel1"))


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

    def test_execute_verify_ip6pool_with_filters(self) -> None:
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
                    op_id="fw_verify_ip6pool_object",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=None,
                    page=1,
                    size=40,
                    keywords="v6test",
                    types=["ANY", "CUSTOM"],
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["status"], "success")
        request.assert_called_once()
        args, kwargs = request.call_args
        self.assertEqual(args[0], "GET")
        self.assertTrue(
            args[1].endswith("/api/v1/ip6pool?page=1&size=40&type=ANY&type=CUSTOM&keywords=v6test")
        )
        self.assertIsNone(kwargs["json_payload"])
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer abc123")

    def test_execute_delete_ip6pool_uses_query_id(self) -> None:
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
                    op_id="fw_delete_ip6pool_object",
                    base_url="https://192.0.2.1",
                    session_file=session_file,
                    auth_header="Authorization",
                    payload={"id": "v6Src"},
                    page=1,
                    size=40,
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["status"], "success")
        args, kwargs = request.call_args
        self.assertEqual(args[0], "DELETE")
        self.assertTrue(args[1].endswith("/api/v1/ip6pool?id=v6Src"))

    def test_build_ip6pool_batch_delete_payload(self) -> None:
        payload = build_object_batch_delete_payload(
            entry_ids=["v6Obj1", "v6Obj2"],
            resource=IP6POOL_OBJECT_RESOURCE,
        )
        self.assertEqual(
            payload["batch"],
            [
                {"method": "DELETE", "resource": "/api/v1/ip6pool", "body": {"id": ["v6Obj1"]}},
                {"method": "DELETE", "resource": "/api/v1/ip6pool", "body": {"id": ["v6Obj2"]}},
            ],
        )
        validated = validate_object_payload(payload, op_id="fw_delete_batch_ip6pool_object")
        self.assertEqual(validated["batch"][0]["resource"], "/api/v1/ip6pool")

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
                    size=40,                    verify_tls=False,
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


class CustomAppObjPayloadTests(unittest.TestCase):
    def test_build_customappobj_payload(self) -> None:
        payload = build_customappobj_payload(
            name_cn="testObj",
            pid="268435599",
            protocol="TCP",
            pattern_type="Ascii",
            pattern="222",
            platform="Windows、MacOS",
        )
        self.assertEqual(payload["val"]["name_cn"], "testObj")
        self.assertEqual(payload["val"]["pid"], "268435599")
        self.assertEqual(payload["val"]["tcpudpcfg"]["direct"], "client")
        self.assertTrue(payload["val"]["customflag"])

    def test_name_en_defaults_to_name_cn(self) -> None:
        payload = build_customappobj_payload(
            name_cn="testObj", pid="1", protocol="TCP", pattern_type="Ascii", pattern="p"
        )
        self.assertEqual(payload["val"]["name_en"], "testObj")

    def test_update_payload_uses_name_cn_as_top_id_and_appid_in_val(self) -> None:
        payload = build_customappobj_update_payload(
            name_cn="testObj", appid="2000000",
            pid="1", protocol="TCP", pattern_type="Ascii", pattern="p",
        )
        # 顶层 id 为 name_cn（设备 delete/update 的 id 语义），val.id 为数字 appid
        self.assertEqual(payload["id"], "testObj")
        self.assertEqual(payload["val"]["id"], "2000000")

    def test_rejects_missing_required_fields(self) -> None:
        with self.assertRaises(RunnerError):
            build_customappobj_payload(name_cn="", pid="1", protocol="TCP", pattern_type="Ascii", pattern="p")

    def test_build_batch_delete_payload(self) -> None:
        payload = build_customappobj_batch_delete_payload(entry_ids=["2000000", "ikun"])
        self.assertEqual(len(payload["batch"]), 2)
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/customappobj")
        self.assertEqual(payload["batch"][0]["body"]["id"], ["2000000"])

    def test_batch_delete_rejects_empty(self) -> None:
        with self.assertRaises(RunnerError):
            build_customappobj_batch_delete_payload(entry_ids=[])

    def test_validate_batch_rejects_wrong_resource(self) -> None:
        payload = {"batch": [{"method": "DELETE", "resource": "/api/v1/ippool", "body": {"id": ["x"]}}]}
        with self.assertRaises(RunnerError):
            validate_customappobj_payload(payload, op_id="fw_delete_batch_customappobj")


class CustomAppObjTagPayloadTests(unittest.TestCase):
    def test_build_customappobjtag_payload(self) -> None:
        payload = build_customappobjtag_payload(
            name_cn="myTag",
            desc="desc",
            appobjkeys=[{"appname": "914CG", "appid": "4"}],
        )
        self.assertEqual(payload["val"]["name_cn"], "myTag")
        self.assertEqual(payload["val"]["appobjkeys"][0]["appid"], "4")

    def test_appobjkeys_normalizes_appid_to_string(self) -> None:
        payload = build_customappobjtag_payload(
            name_cn="myTag", appobjkeys=[{"appname": "x", "appid": 7}]
        )
        self.assertEqual(payload["val"]["appobjkeys"][0]["appid"], "7")

    def test_appobjkeys_rejects_missing_appname(self) -> None:
        with self.assertRaises(RunnerError):
            build_customappobjtag_payload(name_cn="myTag", appobjkeys=[{"appid": "7"}])

    def test_update_payload_wraps_id_and_val(self) -> None:
        payload = build_customappobjtag_update_payload(
            entry_id="myTag", name_cn="myTag", appobjkeys=[{"appname": "x", "appid": "1"}]
        )
        self.assertEqual(payload["id"], "myTag")
        self.assertEqual(payload["val"]["name_cn"], "myTag")

    def test_build_batch_delete_payload(self) -> None:
        payload = build_customappobjtag_batch_delete_payload(entry_ids=["tag1", "tag2"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/customappobjtag")
        self.assertEqual(len(payload["batch"]), 2)

    def test_validate_batch_rejects_wrong_resource(self) -> None:
        payload = {"batch": [{"method": "DELETE", "resource": "/api/v1/customappobj", "body": {"id": ["x"]}}]}
        with self.assertRaises(RunnerError):
            validate_customappobjtag_payload(payload, op_id="fw_delete_batch_customappobjtag")


class ServicePoolPayloadTests(unittest.TestCase):
    def test_build_servicepool_payload_forces_custom_type(self) -> None:
        payload = build_servicepool_payload(
            name="mypool",
            ranges=[{"proto": 6, "s_start": 0, "s_end": 65535, "d_start": 0, "d_end": 65535}],
        )
        self.assertEqual(payload["val"]["type"], "CUSTOM")
        self.assertEqual(payload["val"]["ranges"][0]["proto"], 6)

    def test_ranges_rejects_non_int_proto(self) -> None:
        with self.assertRaises(RunnerError):
            build_servicepool_payload(name="p", ranges=[{"proto": "TCP", "s_start": 0, "s_end": 0, "d_start": 0, "d_end": 0}])

    def test_update_payload_includes_config_source(self) -> None:
        payload = build_servicepool_update_payload(
            entry_id="mypool", name="mypool",
            ranges=[{"proto": 6, "s_start": 0, "s_end": 0, "d_start": 0, "d_end": 0}],
        )
        self.assertEqual(payload["id"], "mypool")
        self.assertEqual(payload["val"]["config_source"], 0)

    def test_build_servicepool_group_payload(self) -> None:
        payload = build_servicepool_group_payload(name="g1", servicepools=["ah", "bgp"])
        self.assertEqual(payload["val"]["servicepools"], ["ah", "bgp"])

    def test_servicepools_rejects_non_string(self) -> None:
        with self.assertRaises(RunnerError):
            build_servicepool_group_payload(name="g1", servicepools=["ah", 5])

    def test_servicepool_batch_delete_resource(self) -> None:
        payload = build_servicepool_batch_delete_payload(entry_ids=["p1"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/servicepool")

    def test_servicepool_group_batch_delete_resource_has_group_suffix(self) -> None:
        payload = build_servicepool_group_batch_delete_payload(entry_ids=["g1"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/servicepool/group")

    def test_validate_servicepool_batch_rejects_group_resource_mismatch(self) -> None:
        # 服务对象的 batch 校验应拒绝服务组的 resource
        payload = {"batch": [{"method": "DELETE", "resource": "/api/v1/servicepool/group", "body": {"id": ["g1"]}}]}
        with self.assertRaises(RunnerError):
            validate_servicepool_payload(payload, op_id="fw_delete_batch_servicepool")

    def test_validate_servicepool_group_batch_rejects_plain_resource(self) -> None:
        # 服务组的 batch 校验应拒绝服务对象的 resource（漏 /group 后缀）
        payload = {"batch": [{"method": "DELETE", "resource": "/api/v1/servicepool", "body": {"id": ["g1"]}}]}
        with self.assertRaises(RunnerError):
            validate_servicepool_payload(payload, op_id="fw_delete_batch_servicepool_group")

    def test_verify_preset_dry_run_without_filters_only_type_preset(self) -> None:
        # 无搜索参数时保持既有行为：只带 type=PRESET，不出现关键字/端口
        dry = build_servicepool_dry_run(
            op_id="fw_verify_servicepool_preset",
            base_url="https://fw.test",
            session_file=Path("/tmp/s.json"),
            auth_header="Authorization",
            payload=None,
            page=1,
            size=40,
            keywords="",
            verify_tls=False,
            timeout=10.0,
        )
        url = dry["request"]["url"]
        self.assertIn("type=PRESET", url)
        self.assertNotIn("keywords", url)
        self.assertNotIn("sport", url)

    def test_verify_preset_dry_run_maps_search_params(self) -> None:
        # preset_query 的 CLI 字段经 PRESET_QUERY_FIELD_MAP 映射为设备查询参数
        dry = build_servicepool_dry_run(
            op_id="fw_verify_servicepool_preset",
            base_url="https://fw.test",
            session_file=Path("/tmp/s.json"),
            auth_header="Authorization",
            payload=None,
            page=1,
            size=40,
            keywords="",
            preset_query={"keywords": "http", "src_port": "80", "dst_port": "8080", "protocol": "6"},
            verify_tls=False,
            timeout=10.0,
        )
        url = dry["request"]["url"]
        self.assertIn("type=PRESET", url)
        self.assertIn("keywords=http", url)
        self.assertIn("sport=80", url)
        self.assertIn("dport=8080", url)
        self.assertIn("protocol=6", url)

    def test_verify_preset_dry_run_drops_empty_fields(self) -> None:
        # 空值字段不进入 URL；未知字段被映射跳过
        dry = build_servicepool_dry_run(
            op_id="fw_verify_servicepool_preset",
            base_url="https://fw.test",
            session_file=Path("/tmp/s.json"),
            auth_header="Authorization",
            payload=None,
            page=1,
            size=40,
            keywords="",
            preset_query={"keywords": "ssh", "src_port": "", "dst_port": "22", "protocol": "", "bogus_field": "x"},
            verify_tls=False,
            timeout=10.0,
        )
        url = dry["request"]["url"]
        self.assertIn("keywords=ssh", url)
        self.assertIn("dport=22", url)
        self.assertNotIn("sport=", url)
        self.assertNotIn("bogus_field", url)

    def test_verify_custom_dry_run_maps_port_protocol_params(self) -> None:
        # 自定义服务搜索：keywords 直接进 URL，端口/协议经映射进 URL（设备忽略但接受）
        dry = build_servicepool_dry_run(
            op_id="fw_verify_servicepool",
            base_url="https://fw.test",
            session_file=Path("/tmp/s.json"),
            auth_header="Authorization",
            payload=None,
            page=1,
            size=40,
            keywords="my-svc",
            preset_query={"keywords": "my-svc", "src_port": "65535", "dst_port": "65535", "protocol": "6"},
            verify_tls=False,
            timeout=10.0,
        )
        url = dry["request"]["url"]
        self.assertIn("type=CUSTOM", url)
        self.assertIn("keywords=my-svc", url)
        self.assertIn("sport=65535", url)
        self.assertIn("dport=65535", url)
        self.assertIn("protocol=6", url)
        self.assertEqual(url.count("keywords"), 1)

    def test_verify_group_dry_run_maps_port_protocol_params(self) -> None:
        # 服务组搜索：keywords 直接进 URL，端口/协议参数经映射进 URL
        dry = build_servicepool_dry_run(
            op_id="fw_verify_servicepool_group",
            base_url="https://fw.test",
            session_file=Path("/tmp/s.json"),
            auth_header="Authorization",
            payload=None,
            page=1,
            size=40,
            keywords="",
            preset_query={"src_port": "80", "protocol": "6"},
            verify_tls=False,
            timeout=10.0,
        )
        url = dry["request"]["url"]
        self.assertIn("/api/v1/servicepool/group?", url)
        self.assertIn("sport=80", url)
        self.assertIn("protocol=6", url)
        self.assertNotIn("keywords", url)


class LoadJsonPayloadTests(unittest.TestCase):
    def test_returns_none_when_both_empty(self) -> None:
        self.assertIsNone(load_json_payload(payload_file=None, payload_json=None))

    def test_rejects_both_provided(self) -> None:
        with self.assertRaises(RunnerError):
            load_json_payload(payload_file="x", payload_json="{}")

    def test_rejects_invalid_json(self) -> None:
        with self.assertRaises(RunnerError):
            load_json_payload(payload_file=None, payload_json="{not json")

    def test_rejects_non_dict_root(self) -> None:
        with self.assertRaises(RunnerError):
            load_json_payload(payload_file=None, payload_json="[1,2,3]")

    def test_parses_json_string(self) -> None:
        result = load_json_payload(payload_file=None, payload_json='{"val":{"name":"x"}}')
        self.assertEqual(result["val"]["name"], "x")

    def test_parses_file(self) -> None:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write('{"val":{"name":"x"}}')
            path = f.name
        try:
            result = load_json_payload(payload_file=path, payload_json=None)
            self.assertEqual(result["val"]["name"], "x")
        finally:
            os.unlink(path)


class NewModuleCliDryRunTests(unittest.TestCase):
    def test_cli_app_obj_config_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "app-obj", "config", "--name-cn", "testObj", "--pid", "1",
                 "--protocol", "TCP", "--pattern-type", "Ascii", "--pattern", "222"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_customappobj")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/customappobj"))
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["name_cn"], "testObj")

    def test_cli_app_obj_verify_url_has_search_params(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "app-obj", "verify", "--search-keyword", "QQ", "--tag-custom", "1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/appobjsearch?", url)
        self.assertIn("searchkeyword=QQ", url)
        self.assertIn("istagcustom=1", url)

    def test_cli_app_tag_verify_url_has_pagination(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "app-tag", "verify", "--keywords", "3", "--page", "1", "--size", "40"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/customappobjtag?", url)
        self.assertIn("keywords=3", url)

    def test_cli_service_pool_verify_preset_url(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "service-pool", "verify-preset"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        url = payload["data"]["request"]["url"]
        self.assertIn("type=PRESET", url)
        self.assertNotIn("keywords", url)

    def test_cli_service_pool_verify_custom_search_params(self) -> None:
        # 自定义服务搜索：--src-port/--dst-port/--protocol 透传到设备查询参数
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "service-pool", "verify", "--src-port", "65535", "--dst-port", "65535",
                 "--protocol", "6"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        url = payload["data"]["request"]["url"]
        self.assertIn("type=CUSTOM", url)
        self.assertIn("sport=65535", url)
        self.assertIn("dport=65535", url)
        self.assertIn("protocol=6", url)

    def test_cli_service_pool_group_verify_search_params(self) -> None:
        # 服务组搜索：--protocol 透传到 /api/v1/servicepool/group
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "service-pool", "group-verify", "--protocol", "6"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/servicepool/group?", url)
        self.assertIn("protocol=6", url)

    def test_cli_service_pool_group_delete_uses_group_resource(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "service-pool", "group-delete", "--id", "g1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_servicepool_group")
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/servicepool/group?id=g1", url)
        self.assertIsNone(payload["data"]["request"]["payload"])

    def test_cli_service_pool_config_forces_custom_type(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "service-pool", "config", "--name", "mypool",
                 "--ranges", '[{"proto":6,"s_start":0,"s_end":65535,"d_start":0,"d_end":65535}]']
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["type"], "CUSTOM")


class IpPoolGroupPayloadTests(unittest.TestCase):
    def test_build_ippool_group_payload(self) -> None:
        payload = build_ippool_group_payload(name="g1", ippools=["any"])
        self.assertEqual(payload["val"]["name"], "g1")
        self.assertEqual(payload["val"]["ippools"], ["any"])

    def test_ippools_rejects_non_string(self) -> None:
        with self.assertRaises(RunnerError):
            build_ippool_group_payload(name="g1", ippools=["any", 5])

    def test_update_payload_includes_id_and_val(self) -> None:
        payload = build_ippool_group_update_payload(entry_id="g1", name="g1", ippools=["any"])
        self.assertEqual(payload["id"], "g1")
        self.assertEqual(payload["val"]["ippools"], ["any"])

    def test_batch_delete_resource(self) -> None:
        payload = build_ippool_group_batch_delete_payload(entry_ids=["g1"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/ippool/group")

    def test_validate_batch_rejects_wrong_resource(self) -> None:
        payload = {"batch": [{"method": "DELETE", "resource": "/api/v1/servicepool", "body": {"id": ["g1"]}}]}
        with self.assertRaises(RunnerError):
            validate_ippool_group_payload(payload, op_id="fw_delete_batch_ippool_group")


class Ip6PoolGroupPayloadTests(unittest.TestCase):
    def test_build_ip6pool_group_payload(self) -> None:
        payload = build_ip6pool_group_payload(name="g1", ip6pools=["any"])
        self.assertEqual(payload["val"]["ip6pools"], ["any"])

    def test_batch_delete_resource(self) -> None:
        payload = build_ip6pool_group_batch_delete_payload(entry_ids=["g1"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/ip6pool/group")


class TimeObjectPayloadTests(unittest.TestCase):
    def test_build_oneshot_payload(self) -> None:
        payload = build_timeobject_payload(
            name="t1", scheduletype="oneshot",
            start_time="2026-07-24 00:00:00", end_time="2026-07-24 23:59:59",
        )
        self.assertEqual(payload["val"]["scheduletype"], "oneshot")
        self.assertEqual(payload["val"]["timequantum"][0]["starttime"]["time"], "2026-07-24 00:00:00")

    def test_build_day_payload(self) -> None:
        payload = build_timeobject_payload(
            name="t1", scheduletype="day", start_time="00:00:00", end_time="23:59:59",
        )
        self.assertEqual(payload["val"]["timequantum"][0]["endtime"]["time"], "23:59:59")

    def test_build_week_payload_includes_weekday(self) -> None:
        payload = build_timeobject_payload(
            name="t1", scheduletype="week", start_time="00:30:00", end_time="21:30:00", weekday=1,
        )
        self.assertEqual(payload["val"]["timequantum"][0]["starttime"]["weekday"], 1)
        self.assertEqual(payload["val"]["timequantum"][0]["endtime"]["weekday"], 1)

    def test_build_month_payload_uses_timemonquantum(self) -> None:
        payload = build_timeobject_payload(
            name="t1", scheduletype="month", month_time=24, planday="11",
        )
        self.assertEqual(payload["val"]["timemonquantum"][0]["time"], 24)
        self.assertEqual(payload["val"]["timemonquantum"][0]["planday"], "11")
        self.assertNotIn("timequantum", payload["val"])

    def test_oneshot_rejects_time_only_format(self) -> None:
        with self.assertRaises(RunnerError):
            build_timeobject_payload(
                name="t1", scheduletype="oneshot", start_time="00:00:00", end_time="23:59:59",
            )

    def test_month_requires_month_time(self) -> None:
        with self.assertRaises(RunnerError):
            build_timeobject_payload(name="t1", scheduletype="month", planday="11")

    def test_week_requires_weekday(self) -> None:
        with self.assertRaises(RunnerError):
            build_timeobject_payload(
                name="t1", scheduletype="week", start_time="00:30:00", end_time="21:30:00",
            )

    def test_invalid_scheduletype(self) -> None:
        with self.assertRaises(RunnerError):
            build_timeobject_payload(
                name="t1", scheduletype="yearly", start_time="00:00:00", end_time="23:59:59",
            )

    def test_batch_delete_resource(self) -> None:
        payload = build_timeobject_batch_delete_payload(entry_ids=["t1"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/timeobject")


class NewModuleV2CliDryRunTests(unittest.TestCase):
    def test_cli_ippool_group_config_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ippool-group", "config", "--name", "g1", "--ippools", "any"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_ippool_group")
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["ippools"], ["any"])

    def test_cli_ippool_group_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ippool-group", "delete", "--id", "g1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_ippool_group")
        self.assertIn("/api/v1/ippool/group?id=g1", payload["data"]["request"]["url"])
        self.assertIsNone(payload["data"]["request"]["payload"])

    def test_cli_ippool_group_verify_url_has_repeatable_type(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ippool-group", "verify", "--type", "ANY", "--type", "CUSTOM", "--keywords", "g1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        url = payload["data"]["request"]["url"]
        self.assertIn("type=ANY", url)
        self.assertIn("type=CUSTOM", url)
        self.assertIn("keywords=g1", url)

    def test_cli_ip6pool_group_config_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ip6pool-group", "config", "--name", "g1", "--ip6pools", "any"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_ip6pool_group")
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["ip6pools"], ["any"])

    def test_cli_ip6pool_group_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ip6pool-group", "delete", "--id", "g1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_ip6pool_group")
        self.assertIn("/api/v1/ip6pool/group?id=g1", payload["data"]["request"]["url"])

    def test_cli_timeobject_config_oneshot(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "time-object", "config", "--name", "t1", "--scheduletype", "oneshot",
                 "--start-time", "2026-07-24 00:00:00", "--end-time", "2026-07-24 23:59:59"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_timeobject")
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["scheduletype"], "oneshot")

    def test_cli_timeobject_config_month(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "time-object", "config", "--name", "t1", "--scheduletype", "month",
                 "--month-time", "24", "--planday", "11"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        val = payload["data"]["request"]["payload"]["val"]
        self.assertEqual(val["timemonquantum"][0]["time"], 24)
        self.assertNotIn("timequantum", val)

    def test_cli_timeobject_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "time-object", "delete", "--id", "t1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_timeobject")
        self.assertIn("/api/v1/timeobject?id=t1", payload["data"]["request"]["url"])

    def test_cli_timeobject_verify_url(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "time-object", "verify", "--keywords", "t1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/timeobject?", url)
        self.assertIn("keywords=t1", url)

    def test_cli_service_pool_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "service-pool", "delete", "--id", "p1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_servicepool")
        self.assertIn("/api/v1/servicepool?id=p1", payload["data"]["request"]["url"])
        self.assertIsNone(payload["data"]["request"]["payload"])

    def test_cli_app_obj_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "app-obj", "delete", "--id", "obj1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_customappobj")
        self.assertIn("/api/v1/customappobj?id=obj1", payload["data"]["request"]["url"])

    def test_cli_app_tag_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "app-tag", "delete", "--id", "tag1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_customappobjtag")
        self.assertIn("/api/v1/customappobjtag?id=tag1", payload["data"]["request"]["url"])


class MacPoolPayloadTests(unittest.TestCase):
    def test_config_payload_forces_type_two(self) -> None:
        payload = build_macpool_payload(name="m1", macs=["02:03:0a:00:53:0c"])
        self.assertEqual(payload["val"]["type"], 2)
        self.assertEqual(payload["val"]["macaddrs"], [{"mac": "02:03:0a:00:53:0c"}])

    def test_macs_rejects_non_string(self) -> None:
        with self.assertRaises(RunnerError):
            build_macpool_payload(name="m1", macs=["02:03:0a:00:53:0c", 5])

    def test_update_payload_includes_id_and_val(self) -> None:
        payload = build_macpool_update_payload(
            entry_id="m1", name="m1", desc="d", macs=["00:00:5e:00:53:01"]
        )
        self.assertEqual(payload["id"], "m1")
        self.assertEqual(payload["val"]["desc"], "d")
        self.assertEqual(payload["val"]["macaddrs"][0]["mac"], "00:00:5e:00:53:01")

    def test_batch_delete_resource(self) -> None:
        payload = build_macpool_batch_delete_payload(entry_ids=["m1"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/macpool")
        self.assertEqual(payload["batch"][0]["body"]["id"], ["m1"])

    def test_validate_batch_rejects_wrong_resource(self) -> None:
        payload = {"batch": [{"method": "DELETE", "resource": "/api/v1/servicepool", "body": {"id": ["m1"]}}]}
        with self.assertRaises(RunnerError):
            validate_macpool_payload(payload, op_id="fw_delete_batch_macpool")

    def test_delete_dry_run_uses_query_id(self) -> None:
        from atomic_ops.runner.macpool import build_macpool_dry_run
        dry = build_macpool_dry_run(
            op_id="fw_delete_macpool",
            base_url="https://fw.test",
            session_file=Path("/tmp/s.json"),
            auth_header="Authorization",
            payload={"id": "m1"},
            page=1,
            size=40,
            keywords="",
            types=[],
            verify_tls=False,
            timeout=10.0,
        )
        self.assertIn("/api/v1/macpool?id=m1", dry["request"]["url"])
        self.assertIsNone(dry["request"]["payload"])


class NewModuleV3CliDryRunTests(unittest.TestCase):
    def test_cli_macpool_config_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "mac-pool", "config", "--name", "m1", "--mac", "02:03:0a:00:53:0c"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_macpool")
        val = payload["data"]["request"]["payload"]["val"]
        self.assertEqual(val["type"], 2)
        self.assertEqual(val["macaddrs"][0]["mac"], "02:03:0a:00:53:0c")

    def test_cli_macpool_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "mac-pool", "delete", "--id", "m1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_macpool")
        self.assertIn("/api/v1/macpool?id=m1", payload["data"]["request"]["url"])

    def test_cli_macpool_delete_batch_resource(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "mac-pool", "delete-batch", "--id", "m1", "--id", "m2"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_batch_macpool")
        self.assertIn("/api/v1/batch", payload["data"]["request"]["url"])

    def test_cli_macpool_verify_url_has_pagination(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "mac-pool", "verify", "--keywords", "m1", "--page", "1", "--size", "40"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/macpool?", url)
        self.assertIn("keywords=m1", url)


class DomainPoolPayloadTests(unittest.TestCase):
    def test_config_payload_uses_domainaddrs(self) -> None:
        payload = build_domainpool_payload(name="d1", domains=["example.com"])
        self.assertEqual(payload["val"]["domainaddrs"], [{"domain": "example.com"}])

    def test_domains_rejects_non_string(self) -> None:
        with self.assertRaises(RunnerError):
            build_domainpool_payload(name="d1", domains=["example.com", 5])

    def test_update_payload_includes_id_and_val(self) -> None:
        payload = build_domainpool_update_payload(
            entry_id="d1", name="d1", desc="d", domains=["example.org"]
        )
        self.assertEqual(payload["id"], "d1")
        self.assertEqual(payload["val"]["desc"], "d")
        self.assertEqual(payload["val"]["domainaddrs"][0]["domain"], "example.org")

    def test_batch_delete_resource(self) -> None:
        payload = build_domainpool_batch_delete_payload(entry_ids=["d1"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/domainpool")
        self.assertEqual(payload["batch"][0]["body"]["id"], ["d1"])

    def test_validate_batch_rejects_wrong_resource(self) -> None:
        payload = {"batch": [{"method": "DELETE", "resource": "/api/v1/servicepool", "body": {"id": ["d1"]}}]}
        with self.assertRaises(RunnerError):
            validate_domainpool_payload(payload, op_id="fw_delete_batch_domainpool")

    def test_delete_dry_run_uses_query_id(self) -> None:
        from atomic_ops.runner.domainpool import build_domainpool_dry_run
        dry = build_domainpool_dry_run(
            op_id="fw_delete_domainpool",
            base_url="https://fw.test",
            session_file=Path("/tmp/s.json"),
            auth_header="Authorization",
            payload={"id": "d1"},
            page=1,
            size=40,
            keywords="",
            verify_tls=False,
            timeout=10.0,
        )
        self.assertIn("/api/v1/domainpool?id=d1", dry["request"]["url"])
        self.assertIsNone(dry["request"]["payload"])


class NewModuleV4CliDryRunTests(unittest.TestCase):
    def test_cli_domainpool_config_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "domain-pool", "config", "--name", "d1", "--domain", "example.com"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_domainpool")
        val = payload["data"]["request"]["payload"]["val"]
        self.assertEqual(val["domainaddrs"][0]["domain"], "example.com")

    def test_cli_domainpool_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "domain-pool", "delete", "--id", "d1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_domainpool")
        self.assertIn("/api/v1/domainpool?id=d1", payload["data"]["request"]["url"])

    def test_cli_domainpool_delete_batch_resource(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "domain-pool", "delete-batch", "--id", "d1", "--id", "d2"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_batch_domainpool")
        self.assertIn("/api/v1/batch", payload["data"]["request"]["url"])

    def test_cli_domainpool_verify_url_has_pagination(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "domain-pool", "verify", "--keywords", "d1", "--page", "1", "--size", "40"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/domainpool?", url)
        self.assertIn("keywords=d1", url)


class FileTypePayloadTests(unittest.TestCase):
    def test_single_config_payload_has_id_zero(self) -> None:
        payload = build_filetype_payload(name="ft1", description="d")
        self.assertEqual(payload["id"], 0)
        self.assertEqual(payload["val"]["name"], "ft1")
        self.assertEqual(payload["val"]["type"], True)
        self.assertEqual(payload["val"]["classify"], [0])
        self.assertEqual(payload["val"]["refcnt"], 0)

    def test_single_update_payload_includes_id(self) -> None:
        payload = build_filetype_update_payload(entry_id="ft1", name="ft1", description="d2")
        self.assertEqual(payload["id"], "ft1")
        self.assertEqual(payload["val"]["description"], "d2")

    def test_group_config_payload_has_filetype_members(self) -> None:
        payload = build_filetypeobj_payload(name="g1", des="desc", filetypes=["PGD", "TAR"])
        self.assertEqual(payload["id"], 0)
        self.assertEqual(payload["val"]["des"], "desc")
        self.assertEqual(payload["val"]["filetype"], [{"name": "PGD", "type": False}, {"name": "TAR", "type": False}])

    def test_group_update_payload_includes_id(self) -> None:
        payload = build_filetypeobj_update_payload(entry_id="g1", name="g1", des="d", filetypes=["PGD"])
        self.assertEqual(payload["id"], "g1")
        self.assertEqual(payload["val"]["filetype"][0]["name"], "PGD")

    def test_group_delete_batch_resource(self) -> None:
        payload = build_filetype_batch_delete_payload(entry_ids=["g1"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/appsec/filetypeObj")
        self.assertEqual(payload["batch"][0]["body"]["id"], ["g1"])

    def test_validate_batch_rejects_wrong_resource(self) -> None:
        payload = {"batch": [{"method": "DELETE", "resource": "/api/v1/appsec/filetype", "body": {"id": ["g1"]}}]}
        with self.assertRaises(RunnerError):
            validate_filetype_payload(payload, op_id="fw_delete_batch_filetypeobj")

    def test_delete_dry_run_uses_query_id(self) -> None:
        from atomic_ops.runner.filetype import build_filetype_dry_run
        dry = build_filetype_dry_run(
            op_id="fw_delete_filetype",
            base_url="https://fw.test",
            session_file=Path("/tmp/s.json"),
            auth_header="Authorization",
            payload={"id": "ft1"},
            page=1,
            size=40,
            keywords="",
            verify_tls=False,
            timeout=10.0,
        )
        self.assertIn("/api/v1/appsec/filetype?id=ft1", dry["request"]["url"])
        self.assertIsNone(dry["request"]["payload"])


class NewModuleV5CliDryRunTests(unittest.TestCase):
    def test_cli_filetype_config_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "filetype", "config", "--name", "ft1", "--description", "d"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_filetype")
        val = payload["data"]["request"]["payload"]["val"]
        self.assertEqual(val["name"], "ft1")
        self.assertEqual(val["type"], True)

    def test_cli_filetype_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "filetype", "delete", "--id", "ft1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_filetype")
        self.assertIn("/api/v1/appsec/filetype?id=ft1", payload["data"]["request"]["url"])

    def test_cli_filetype_group_config_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "filetype", "group-config", "--name", "g1", "--filetype", "PGD"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_filetypeobj")
        val = payload["data"]["request"]["payload"]["val"]
        self.assertEqual(val["filetype"][0]["name"], "PGD")

    def test_cli_filetype_group_verify_url_has_pagination(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "filetype", "group-verify", "--keywords", "g1", "--page", "1", "--size", "40"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/appsec/filetypeObj?", url)
        self.assertIn("keywords=g1", url)

    def test_cli_filetype_group_delete_batch_resource(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "filetype", "group-delete-batch", "--id", "g1", "--id", "g2"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_batch_filetypeobj")
        self.assertIn("/api/v1/batch", payload["data"]["request"]["url"])


class CertPayloadTests(unittest.TestCase):
    def test_localcert_rsa_payload_has_subject_and_option(self) -> None:
        payload = build_localcert_payload(
            name="c1", subject={"country": "CN", "state": "SC", "location": "CD", "organization": "A", "organUnit": "QA"}
        )
        self.assertEqual(payload["val"]["subject"]["country"], "CN")
        self.assertEqual(payload["val"]["option"], {"type": "RSA", "keyLenth": 2048})

    def test_localcert_sm2_payload_omits_key_length(self) -> None:
        payload = build_localcert_payload(name="c1", key_type="SM2")
        self.assertEqual(payload["val"]["option"], {"type": "SM2"})

    def test_localcert_issue_payload(self) -> None:
        payload = build_localcert_issue_payload(entry_id="5", cacert="defaultLocalCA.crt", time_length=30)
        self.assertEqual(payload["id"], "5")
        self.assertEqual(payload["val"], {"option": "1", "cacert": "defaultLocalCA.crt", "timeLenth": 30})

    def test_localcacert_payload_is_flat(self) -> None:
        payload = build_localcacert_payload(name="ca1", key_type="RSA", time_length=30)
        self.assertEqual(payload["val"]["type"], "RSA")
        self.assertEqual(payload["val"]["timeLenth"], 30)
        self.assertNotIn("option", payload["val"])

    def test_batch_delete_casts_ids_to_string(self) -> None:
        payload = build_cert_batch_delete_payload(entry_ids=["3", "4"], resource="/api/v1/cert/localcert")
        self.assertEqual(payload["batch"][0]["body"]["id"], ["3"])
        self.assertEqual(payload["batch"][1]["body"]["id"], ["4"])

    def test_validate_batch_rejects_wrong_resource(self) -> None:
        payload = {"batch": [{"method": "DELETE", "resource": "/api/v1/cert/localcacert", "body": {"id": ["3"]}}]}
        with self.assertRaises(RunnerError):
            validate_cert_payload(payload, op_id="fw_delete_batch_localcert")

    def test_delete_dry_run_uses_query_id(self) -> None:
        from atomic_ops.runner.cert import build_cert_dry_run
        dry = build_cert_dry_run(
            op_id="fw_delete_localcert",
            base_url="https://fw.test",
            session_file=Path("/tmp/s.json"),
            auth_header="Authorization",
            payload={"id": "5"},
            page=1,
            size=40,
            keywords="",
            verify_tls=False,
            timeout=10.0,
        )
        self.assertIn("/api/v1/cert/localcert?id=5", dry["request"]["url"])
        self.assertIsNone(dry["request"]["payload"])


class NewModuleV6CliDryRunTests(unittest.TestCase):
    def test_cli_localcert_config_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "cert", "localcert-config", "--name", "c1", "--key-type", "RSA"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_localcert")
        val = payload["data"]["request"]["payload"]["val"]
        self.assertEqual(val["option"]["type"], "RSA")

    def test_cli_localcert_issue_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "cert", "localcert-issue", "--id", "5", "--cacert", "defaultLocalCA.crt"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_update_localcert")
        val = payload["data"]["request"]["payload"]["val"]
        self.assertEqual(val["option"], "1")
        self.assertEqual(val["timeLenth"], 30)

    def test_cli_localcert_delete_batch_resource(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "cert", "localcert-delete-batch", "--id", "3", "--id", "4"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_batch_localcert")
        self.assertIn("/api/v1/batch", payload["data"]["request"]["url"])

    def test_cli_localcacert_config_dry_run_flat(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "cert", "localcacert-config", "--name", "ca1", "--key-type", "RSA"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_localcacert")
        val = payload["data"]["request"]["payload"]["val"]
        self.assertEqual(val["type"], "RSA")
        self.assertNotIn("option", val)

    def test_cli_localcacert_verify_url_has_pagination(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "cert", "localcacert-verify", "--keywords", "ca1", "--page", "1", "--size", "40"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/cert/localcacert?", url)
        self.assertIn("keywords=ca1", url)


class GeoipPayloadTests(unittest.TestCase):
    def test_config_payload_has_region_fields(self) -> None:
        payload = build_geoip_payload(
            ip="FEC0::2-FEC0::3", country="CN", province="Hunan", city="Changsha", desc="d"
        )
        self.assertEqual(payload["val"]["accuracy"], 2)
        self.assertEqual(payload["val"]["ip"], "FEC0::2-FEC0::3")
        self.assertEqual(payload["val"]["country"], "CN")
        self.assertEqual(payload["val"]["province"], "Hunan")
        self.assertEqual(payload["val"]["city"], "Changsha")
        self.assertEqual(payload["val"]["desc"], "d")

    def test_config_payload_requires_ip_and_country(self) -> None:
        with self.assertRaises(RunnerError):
            build_geoip_payload(country="CN")
        with self.assertRaises(RunnerError):
            build_geoip_payload(ip="FEC0::2-FEC0::3")

    def test_config_payload_rejects_negative_accuracy(self) -> None:
        with self.assertRaises(RunnerError):
            build_geoip_payload(ip="FEC0::2", country="CN", accuracy=-1)

    def test_update_payload_includes_id_and_val(self) -> None:
        payload = build_geoip_update_payload(
            entry_id="4", ip="FEC0::2-FEC0::4", country="CN", province="Hunan", city="Changsha", desc="upd"
        )
        self.assertEqual(payload["id"], "4")
        self.assertEqual(payload["val"]["ip"], "FEC0::2-FEC0::4")
        self.assertEqual(payload["val"]["desc"], "upd")
        # Device requires the unique id both at top level and inside val.
        self.assertEqual(payload["val"]["id"], "4")

    def test_config_payload_requires_province_and_city(self) -> None:
        with self.assertRaises(RunnerError):
            build_geoip_payload(ip="FEC0::2", country="CN")
        with self.assertRaises(RunnerError):
            build_geoip_payload(ip="FEC0::2", country="CN", province="Hunan")

    def test_delete_payload_carries_numeric_id(self) -> None:
        payload = build_geoip_delete_payload(entry_id="4")
        self.assertEqual(payload, {"id": "4"})

    def test_batch_delete_casts_ids_to_string_and_uses_custom_resource(self) -> None:
        payload = build_geoip_batch_delete_payload(entry_ids=[4, "5"])
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/geoip/custom")
        self.assertEqual(payload["batch"][0]["body"]["id"], ["4"])
        self.assertEqual(payload["batch"][1]["body"]["id"], ["5"])

    def test_validate_batch_rejects_wrong_resource(self) -> None:
        payload = {"batch": [{"method": "DELETE", "resource": "/api/v1/geoip", "body": {"id": ["4"]}}]}
        with self.assertRaises(RunnerError):
            validate_geoip_payload(payload, op_id="fw_delete_batch_geoip")

    def test_delete_dry_run_uses_query_id(self) -> None:
        from atomic_ops.runner.geoip import build_geoip_dry_run
        dry = build_geoip_dry_run(
            op_id="fw_delete_geoip",
            base_url="https://fw.test",
            session_file=Path("/tmp/s.json"),
            auth_header="Authorization",
            payload={"id": "4"},
            page=1,
            size=40,
            keywords="",
            verify_tls=False,
            timeout=10.0,
        )
        self.assertIn("/api/v1/geoip/custom?id=4", dry["request"]["url"])
        self.assertIsNone(dry["request"]["payload"])


class NewModuleV7CliDryRunTests(unittest.TestCase):
    def test_cli_geoip_config_dry_run(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "geoip", "config", "--ip", "FEC0::2-FEC0::3", "--country", "CN",
                 "--province", "Hunan", "--city", "Changsha", "--desc", "d"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_geoip")
        self.assertIn("/api/v1/geoip/custom", payload["data"]["request"]["url"])
        val = payload["data"]["request"]["payload"]["val"]
        self.assertEqual(val["ip"], "FEC0::2-FEC0::3")
        self.assertEqual(val["country"], "CN")
        self.assertEqual(val["accuracy"], 2)

    def test_cli_geoip_update_dry_run_includes_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "geoip", "update", "--id", "4", "--ip", "FEC0::2-FEC0::4",
                 "--country", "CN", "--province", "Hunan", "--city", "Changsha"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_update_geoip")
        self.assertIn("/api/v1/geoip/custom", payload["data"]["request"]["url"])
        req = payload["data"]["request"]["payload"]
        self.assertEqual(req["id"], "4")
        self.assertEqual(req["val"]["ip"], "FEC0::2-FEC0::4")
        self.assertEqual(req["val"]["id"], "4")

    def test_cli_geoip_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "geoip", "delete", "--id", "4"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_geoip")
        self.assertIn("/api/v1/geoip/custom?id=4", payload["data"]["request"]["url"])
        self.assertIsNone(payload["data"]["request"]["payload"])

    def test_cli_geoip_delete_batch_uses_string_ids(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "geoip", "delete-batch", "--id", "4", "--id", "5"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_batch_geoip")
        self.assertIn("/api/v1/batch", payload["data"]["request"]["url"])
        batch = payload["data"]["request"]["payload"]["batch"]
        self.assertEqual(batch[0]["resource"], "/api/v1/geoip/custom")
        self.assertEqual(batch[0]["body"]["id"], ["4"])
        self.assertEqual(batch[1]["body"]["id"], ["5"])

    def test_cli_geoip_verify_url_has_pagination(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "geoip", "verify", "--keywords", "d", "--page", "1", "--size", "40"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/geoip/custom?", url)
        self.assertIn("keywords=d", url)

    def test_cli_geoip_config_requires_ip(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "geoip", "config", "--country", "CN"]
            )
        self.assertNotEqual(exit_code, 0)


class StaticDnsPayloadTests(unittest.TestCase):
    def test_config_payload_wraps_val_object(self) -> None:
        from atomic_ops.runner.dns_static import build_static_dns_payload
        payload = build_static_dns_payload(name="www.example.com", ip4addr="10.10.10.10")
        self.assertEqual(payload, {"val": {"name": "www.example.com", "ip4addr": "10.10.10.10"}})

    def test_config_payload_includes_optional_ip6addr(self) -> None:
        from atomic_ops.runner.dns_static import build_static_dns_payload
        payload = build_static_dns_payload(name="v6.example.com", ip4addr="10.10.10.11", ip6addr="2001:db8::1")
        self.assertEqual(payload["val"]["ip6addr"], "2001:db8::1")

    def test_validate_requires_name_and_ip4addr(self) -> None:
        from atomic_ops.runner.dns_static import validate_static_dns_payload
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError):
            validate_static_dns_payload({"val": {"name": "", "ip4addr": "10.10.10.10"}})
        with self.assertRaises(RunnerError):
            validate_static_dns_payload({"val": {"name": "www.example.com"}})
        with self.assertRaises(RunnerError):
            validate_static_dns_payload({"val": None})

    def test_delete_payload_requires_id(self) -> None:
        from atomic_ops.runner.dns_static import build_static_dns_dry_run
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError):
            build_static_dns_dry_run(
                op_id="fw_delete_static_dns", base_url="https://192.0.2.1",
                session_file=Path("x"), auth_header="Authorization", payload=None,
                verify_tls=False, timeout=10.0,
            )


class StaticDnsCliTests(unittest.TestCase):
    def test_cli_static_dns_config_posts_val_body(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "static-dns-config", "--name", "www.example.com", "--ip4addr", "10.10.10.10"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_static_dns")
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/dns/cache"))
        self.assertEqual(
            payload["data"]["request"]["payload"],
            {"val": {"name": "www.example.com", "ip4addr": "10.10.10.10"}},
        )

    def test_cli_static_dns_delete_uses_query_id_and_no_body(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "static-dns-delete", "--id", "www.example.com"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_static_dns")
        self.assertEqual(payload["data"]["request"]["method"], "DELETE")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/dns/cache?id=www.example.com"))
        self.assertIsNone(payload["data"]["request"]["payload"])

    def test_cli_static_dns_update_puts_id_and_val_body(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "static-dns-update", "--id", "old.example.com",
                 "--name", "new.example.com", "--ip4addr", "10.10.10.20"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_update_static_dns")
        self.assertEqual(payload["data"]["request"]["method"], "PUT")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/dns/cache"))
        self.assertEqual(
            payload["data"]["request"]["payload"],
            {"id": "old.example.com", "val": {"name": "new.example.com", "ip4addr": "10.10.10.20"}},
        )

    def test_cli_static_dns_delete_batch_posts_batch_body(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "static-dns-delete-batch", "--id", "a.example.com", "--id", "b.example.com"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_batch_static_dns")
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/batch"))
        self.assertEqual(
            payload["data"]["request"]["payload"],
            {"batch": [
                {"method": "DELETE", "resource": "/api/v1/dns/cache", "body": {"id": ["a.example.com"]}},
                {"method": "DELETE", "resource": "/api/v1/dns/cache", "body": {"id": ["b.example.com"]}},
            ]},
        )

    def test_cli_static_dns_verify_uses_static_query_no_payload(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "static-dns-verify"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_verify_static_dns")
        self.assertEqual(payload["data"]["request"]["method"], "GET")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/dns/cache?type=static"))
        self.assertIsNone(payload["data"]["request"]["payload"])

    def test_cli_dynamic_cache_verify_uses_paged_dynamic_query_no_payload(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "dynamic-cache-verify", "--page", "2", "--size", "20"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_verify_dns_cache_entry")
        self.assertEqual(payload["data"]["request"]["method"], "GET")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/dns/cache?page=2&size=20&type=dynamic"))
        self.assertIsNone(payload["data"]["request"]["payload"])


class StaticDnsGroup1Tests(unittest.TestCase):
    def test_update_payload_wraps_id_and_val(self) -> None:
        from atomic_ops.runner.dns_static import build_static_dns_update_payload
        payload = build_static_dns_update_payload(
            entry_id="old.example.com", name="new.example.com", ip4addr="10.10.10.20"
        )
        self.assertEqual(
            payload,
            {"id": "old.example.com", "val": {"name": "new.example.com", "ip4addr": "10.10.10.20"}},
        )

    def test_update_payload_includes_optional_ip6addr(self) -> None:
        from atomic_ops.runner.dns_static import build_static_dns_update_payload
        payload = build_static_dns_update_payload(
            entry_id="v6.example.com", name="v6.example.com", ip4addr="10.10.10.21", ip6addr="2001:db8::2"
        )
        self.assertEqual(payload["val"]["ip6addr"], "2001:db8::2")

    def test_validate_update_requires_id(self) -> None:
        from atomic_ops.runner.dns_static import validate_static_dns_update_payload
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError):
            validate_static_dns_update_payload(
                {"val": {"name": "new.example.com", "ip4addr": "10.10.10.20"}}
            )

    def test_batch_delete_payload_builds_one_item_per_domain(self) -> None:
        from atomic_ops.runner.dns_static import build_static_dns_batch_delete_payload
        payload = build_static_dns_batch_delete_payload(["a.example.com", "b.example.com"])
        self.assertEqual(len(payload["batch"]), 2)
        self.assertEqual(
            payload["batch"][0],
            {"method": "DELETE", "resource": "/api/v1/dns/cache", "body": {"id": ["a.example.com"]}},
        )

    def test_validate_batch_rejects_bad_item(self) -> None:
        from atomic_ops.runner.dns_static import validate_batch_payload
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError):
            validate_batch_payload({"batch": [{"method": "GET", "resource": "/api/v1/dns/cache", "body": {"id": ["x"]}}]})
        with self.assertRaises(RunnerError):
            validate_batch_payload({"batch": [{"method": "DELETE", "resource": "/api/v1/dns/cache", "body": {"id": []}}]})
        with self.assertRaises(RunnerError):
            validate_batch_payload({"batch": []})

    def test_dynamic_verify_dry_run_builds_paged_url(self) -> None:
        from atomic_ops.runner.dns_static import build_static_dns_dry_run
        result = build_static_dns_dry_run(
            op_id="fw_verify_dns_cache_entry", base_url="https://192.0.2.1",
            session_file=Path("x"), auth_header="Authorization", payload={"page": 2, "size": 20},
            verify_tls=False, timeout=10.0,
        )
        self.assertTrue(result["request"]["url"].endswith("/api/v1/dns/cache?page=2&size=20&type=dynamic"))
        self.assertIsNone(result["request"]["payload"])

    def test_dynamic_verify_rejects_non_positive_paging(self) -> None:
        from atomic_ops.runner.dns_static import build_static_dns_dry_run
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError):
            build_static_dns_dry_run(
                op_id="fw_verify_dns_cache_entry", base_url="https://192.0.2.1",
                session_file=Path("x"), auth_header="Authorization", payload={"page": 0, "size": 20},
                verify_tls=False, timeout=10.0,
            )


class DnsSysPayloadTests(unittest.TestCase):
    def test_dns_server_payload_puts_id_zero_and_serveraddr(self) -> None:
        from atomic_ops.runner.dns_sys import build_dns_server_payload
        payload = build_dns_server_payload(["11.11.11.11", "12.12.12.12"])
        self.assertEqual(payload, {"id": 0, "val": {"serveraddr": ["11.11.11.11", "12.12.12.12"]}})

    def test_dns_proxy_payload_puts_dns_server_id_and_enable(self) -> None:
        from atomic_ops.runner.dns_sys import build_dns_proxy_payload
        self.assertEqual(build_dns_proxy_payload(True), {"id": "dnsServer", "val": {"enable": True}})
        self.assertEqual(build_dns_proxy_payload(False), {"id": "dnsServer", "val": {"enable": False}})

    def test_dns_proxy_server_payload_wraps_addr_entries(self) -> None:
        from atomic_ops.runner.dns_sys import build_dns_proxy_server_payload
        payload = build_dns_proxy_server_payload(["<DNS_SERVER_IP>", "<DNS_SERVER_IP>"])
        self.assertEqual(
            payload,
            {"val": {"servers": [{"addr": "<DNS_SERVER_IP>"}, {"addr": "<DNS_SERVER_IP>"}]}},
        )

    def test_dns_proxy_server_batch_payload_builds_one_item_per_addr(self) -> None:
        from atomic_ops.runner.dns_sys import build_dns_proxy_server_batch_delete_payload
        payload = build_dns_proxy_server_batch_delete_payload(["<DNS_SERVER_IP>", "<DNS_SERVER_IP>"])
        self.assertEqual(len(payload["batch"]), 2)
        self.assertEqual(
            payload["batch"][0],
            {"method": "DELETE", "resource": "/api/v1/dns/globalserver", "body": {"id": ["<DNS_SERVER_IP>"]}},
        )

    def test_validate_dns_server_requires_id_zero_and_nonempty_list(self) -> None:
        from atomic_ops.runner.dns_sys import validate_dns_server_payload
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError):
            validate_dns_server_payload({"id": 1, "val": {"serveraddr": ["11.11.11.11"]}})
        with self.assertRaises(RunnerError):
            validate_dns_server_payload({"id": 0, "val": {"serveraddr": []}})
        with self.assertRaises(RunnerError):
            validate_dns_server_payload({"id": 0, "val": {"serveraddr": [""]}})

    def test_validate_dns_proxy_requires_boolean_enable(self) -> None:
        from atomic_ops.runner.dns_sys import validate_dns_proxy_payload
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError):
            validate_dns_proxy_payload({"id": "dnsServer", "val": {"enable": "yes"}})
        with self.assertRaises(RunnerError):
            validate_dns_proxy_payload({"id": "other", "val": {"enable": True}})

    def test_validate_proxy_server_requires_addr_entries(self) -> None:
        from atomic_ops.runner.dns_sys import validate_dns_proxy_server_payload
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError):
            validate_dns_proxy_server_payload({"val": {"servers": []}})
        with self.assertRaises(RunnerError):
            validate_dns_proxy_server_payload({"val": {"servers": [{"addr": ""}]}})

    def test_validate_batch_rejects_bad_item(self) -> None:
        from atomic_ops.runner.dns_sys import validate_dns_proxy_server_batch_payload
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError):
            validate_dns_proxy_server_batch_payload(
                {"batch": [{"method": "DELETE", "resource": "/api/v1/dns/cache", "body": {"id": ["x"]}}]}
            )
        with self.assertRaises(RunnerError):
            validate_dns_proxy_server_batch_payload({"batch": [{"method": "DELETE", "resource": "/api/v1/dns/globalserver", "body": {"id": []}}]})

    def test_delete_dry_run_builds_query_url_no_body(self) -> None:
        from atomic_ops.runner.dns_sys import build_dns_sys_dry_run
        result = build_dns_sys_dry_run(
            op_id="fw_delete_dns_proxy_server", base_url="https://192.0.2.1",
            session_file=Path("x"), auth_header="Authorization", payload={"id": "<DNS_SERVER_IP>"},
            verify_tls=False, timeout=10.0,
        )
        self.assertTrue(result["request"]["url"].endswith("/api/v1/dns/globalserver?id=<DNS_SERVER_IP>"))
        self.assertIsNone(result["request"]["payload"])

    def test_verify_dry_run_builds_plain_url_no_body(self) -> None:
        from atomic_ops.runner.dns_sys import build_dns_sys_dry_run
        for op_id in ("fw_verify_dns_server", "fw_verify_dns_proxy_server"):
            result = build_dns_sys_dry_run(
                op_id=op_id, base_url="https://192.0.2.1",
                session_file=Path("x"), auth_header="Authorization", payload=None,
                verify_tls=False, timeout=10.0,
            )
            self.assertTrue(result["request"]["url"].endswith("/api/v1/sysdns" if op_id == "fw_verify_dns_server" else "/api/v1/dns/globalserver"))
            self.assertIsNone(result["request"]["payload"])


class DnsSysCliTests(unittest.TestCase):
    def test_cli_dns_server_config_puts_id_zero_and_serveraddr(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "dns-server-config", "--serveraddr", "11.11.11.11", "--serveraddr", "12.12.12.12"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_dns_server")
        self.assertEqual(payload["data"]["request"]["method"], "PUT")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/sysdns"))
        self.assertEqual(
            payload["data"]["request"]["payload"],
            {"id": 0, "val": {"serveraddr": ["11.11.11.11", "12.12.12.12"]}},
        )

    def test_cli_dns_proxy_config_parses_enable(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "dns-proxy-config", "--enable", "true"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_dns_proxy")
        self.assertEqual(
            payload["data"]["request"]["payload"],
            {"id": "dnsServer", "val": {"enable": True}},
        )

    def test_cli_dns_proxy_server_config_posts_val_servers(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "dns-proxy-server-config", "--addr", "<DNS_SERVER_IP>"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_dns_proxy_server")
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/dns/globalserver"))
        self.assertEqual(
            payload["data"]["request"]["payload"],
            {"val": {"servers": [{"addr": "<DNS_SERVER_IP>"}]}},
        )

    def test_cli_dns_proxy_server_delete_uses_query_id_and_no_body(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "dns-proxy-server-delete", "--id", "<DNS_SERVER_IP>"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_dns_proxy_server")
        self.assertEqual(payload["data"]["request"]["method"], "DELETE")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/dns/globalserver?id=<DNS_SERVER_IP>"))
        self.assertIsNone(payload["data"]["request"]["payload"])

    def test_cli_dns_proxy_server_delete_batch_posts_batch_body(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "dns-proxy-server-delete-batch", "--id", "<DNS_SERVER_IP>", "--id", "<DNS_SERVER_IP>"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_batch_dns_proxy_server")
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/batch"))
        self.assertEqual(
            payload["data"]["request"]["payload"],
            {"batch": [
                {"method": "DELETE", "resource": "/api/v1/dns/globalserver", "body": {"id": ["<DNS_SERVER_IP>"]}},
                {"method": "DELETE", "resource": "/api/v1/dns/globalserver", "body": {"id": ["<DNS_SERVER_IP>"]}},
            ]},
        )

    def test_cli_dns_server_verify_uses_plain_get_no_payload(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "dns-server-verify"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_verify_dns_server")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/sysdns"))
        self.assertIsNone(payload["data"]["request"]["payload"])

    def test_cli_dns_proxy_server_verify_uses_plain_get_no_payload(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "dns", "dns-proxy-server-verify"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_verify_dns_proxy_server")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/dns/globalserver"))
        self.assertIsNone(payload["data"]["request"]["payload"])


class PppoeCliTests(unittest.TestCase):
    def test_cli_pppoe_config_dry_run_builds_interface_body_with_placeholder(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "interface", "pppoe-config", "--id", "TE0_21", "--username", "user01"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_pppoe")
        self.assertEqual(payload["data"]["request"]["method"], "PUT")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/intf"))
        request_payload = payload["data"]["request"]["payload"]
        self.assertEqual(request_payload["id"], "TE0_21")
        self.assertEqual(request_payload["val"]["type"], 3)
        self.assertEqual(request_payload["val"]["pppoe"]["username"], "user01")
        self.assertEqual(request_payload["val"]["pppoe"]["password"], "<encrypted-at-execute>")

    def test_cli_pppoe_config_dry_run_never_leaks_password(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "interface", "pppoe-config", "--id", "TE0_21", "--username", "user01"]
            )
        self.assertEqual(exit_code, 0)
        self.assertNotIn("Pass@123", stdout.getvalue())

    def test_execute_pppoe_config_requires_password_env(self) -> None:
        from atomic_ops.runner.pppoe import execute_pppoe_config
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError) as context:
            execute_pppoe_config(
                base_url="https://192.0.2.1", session_file=Path("x"),
                auth_header="Authorization", intf_id="TE0_21", username="user01",
                password_env="PTM_PPPOE_PASSWORD_UNSET", verify_tls=False, timeout=10.0,
            )
        self.assertEqual(context.exception.error_code, "RUNNER_CREDENTIAL_MISSING")

    def test_pppoe_payload_requires_nonempty_fields(self) -> None:
        from atomic_ops.runner.pppoe import build_pppoe_config_dry_run
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError):
            build_pppoe_config_dry_run(
                base_url="https://192.0.2.1", session_file=Path("x"),
                auth_header="Authorization", intf_id="", username="user01",
                verify_tls=False, timeout=10.0,
            )


class InterfacePppoeSecretTests(unittest.TestCase):
    """interface create/update --interface-kind pppoe 的密码密文化（方案 A）。

    覆盖：构建期占位符（明文参数已删除）、--pppoe-password 拒绝指路、execute 时
    env -> RSA 加密注入、env/参数缺失的凭据分层出口（对齐 CredentialAuthSplit）。
    """

    PPPOE_ENV = "PTM_TEST_INTERFACE_PPPOE_PW"

    def test_cli_interface_pppoe_kind_dry_run_uses_placeholder(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "interface", "create", "--id", "TE0_8", "--interface-kind", "pppoe",
                 "--pppoe-username", "user01"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        request_payload = payload["data"]["request"]["payload"]
        self.assertEqual(request_payload["id"], "TE0_8")
        self.assertEqual(request_payload["val"]["type"], 3)
        self.assertEqual(request_payload["val"]["mode"], "Route")
        self.assertEqual(request_payload["val"]["pppoe"]["username"], "user01")
        self.assertEqual(
            request_payload["val"]["pppoe"]["password"], "<encrypted-at-execute>"
        )

    def test_cli_interface_rejects_removed_plaintext_pppoe_password_flag(self) -> None:
        with self.assertRaises(SystemExit) as context:
            cli_main(
                ["run", "--base-url", "https://192.0.2.1",
                 "interface", "create", "--id", "TE0_8", "--interface-kind", "pppoe",
                 "--pppoe-username", "user01", "--pppoe-password", "Pass@123"]
            )
        self.assertEqual(context.exception.code, 2)

    def _build_pppoe_payload(self) -> dict:
        from atomic_ops.runner.interface import build_interface_payload

        return build_interface_payload(
            interface_kind="pppoe", entry_id="TE0_8",
            pppoe_username="user01",
        )

    def test_execute_interface_pppoe_injects_encrypted_secret(self) -> None:
        from atomic_ops.runner.interface import execute_interface

        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.interface._encrypt_password", return_value="CIPHERTEXT") as encrypt:
                with patch("atomic_ops.runner.interface.request_json", return_value=(200, {"ok": True}, "{}")) as request:
                    with patch.dict(os.environ, {self.PPPOE_ENV: "Pass@123"}, clear=False):
                        result = execute_interface(
                            op_id="fw_config_interface",
                            base_url="https://192.0.2.1",
                            session_file=session_file,
                            auth_header="Authorization",
                            payload=self._build_pppoe_payload(),
                            verify_tls=False,
                            timeout=10,
                            pppoe_password_env=self.PPPOE_ENV,
                        )

        self.assertEqual(result["status"], "success")
        self.assertTrue(result["password_encrypted"])
        _, kwargs = request.call_args
        sent = kwargs["json_payload"]["val"]["pppoe"]
        self.assertEqual(sent["username"], "user01")
        self.assertEqual(sent["password"], "CIPHERTEXT")
        self.assertNotIn("Pass@123", json.dumps(kwargs["json_payload"]))
        encrypt.assert_called_once()
        self.assertEqual(encrypt.call_args.args[1], "Pass@123")

    def test_execute_interface_pppoe_requires_password_env_name(self) -> None:
        from atomic_ops.runner.interface import execute_interface

        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.interface.request_json", return_value=(200, {"ok": True}, "{}")) as request:
                with self.assertRaises(RunnerError) as context:
                    execute_interface(
                        op_id="fw_config_interface",
                        base_url="https://192.0.2.1",
                        session_file=session_file,
                        auth_header="Authorization",
                        payload=self._build_pppoe_payload(),
                        verify_tls=False,
                        timeout=10,
                        pppoe_password_env=None,
                    )
        self.assertEqual(context.exception.error_code, "RUNNER_CREDENTIAL_MISSING")
        self.assertEqual(context.exception.details["missing"], "pppoe_password_env")
        request.assert_not_called()

    def test_execute_interface_pppoe_env_unset_uses_credential_missing_error(self) -> None:
        from atomic_ops.runner.interface import execute_interface

        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.interface.request_json", return_value=(200, {"ok": True}, "{}")) as request:
                with self.assertRaises(RunnerError) as context:
                    execute_interface(
                        op_id="fw_update_interface",
                        base_url="https://192.0.2.1",
                        session_file=session_file,
                        auth_header="Authorization",
                        payload=self._build_pppoe_payload(),
                        verify_tls=False,
                        timeout=10,
                        pppoe_password_env="PTM_TEST_INTERFACE_PPPOE_PW_UNSET",
                    )
        self.assertEqual(context.exception.error_code, "RUNNER_CREDENTIAL_MISSING")
        self.assertEqual(
            context.exception.details["env"], "PTM_TEST_INTERFACE_PPPOE_PW_UNSET"
        )
        request.assert_not_called()

    def test_execute_interface_non_pppoe_payload_ignores_env(self) -> None:
        """非 pppoe payload 传了 pppoe env 名也不触发注入/报错（no-op）。"""
        from atomic_ops.runner.interface import build_interface_payload, execute_interface

        payload = build_interface_payload(
            interface_kind="bvi", entry_id="bvi1", bvi_instance=1,
            ip_addresses=["10.0.0.1/24"],
        )
        self.assertNotIn("pppoe", payload["val"])
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = Path(temp_dir) / "session.json"
            write_session_file(
                session_file, base_url="https://192.0.2.1", username="admin",
                session_value="abc123", source_op_id="fw_login_web_management",
            )
            with patch("atomic_ops.runner.interface.request_json", return_value=(200, {"ok": True}, "{}")) as request:
                with patch.dict(os.environ, {self.PPPOE_ENV: "Pass@123"}, clear=False):
                    result = execute_interface(
                        op_id="fw_config_interface",
                        base_url="https://192.0.2.1",
                        session_file=session_file,
                        auth_header="Authorization",
                        payload=payload,
                        verify_tls=False,
                        timeout=10,
                        pppoe_password_env=self.PPPOE_ENV,
                    )
        self.assertEqual(result["status"], "success")
        self.assertNotIn("password_encrypted", result)
        _, kwargs = request.call_args
        self.assertEqual(kwargs["json_payload"]["val"]["type"], 14)


class SshDnsOpsCliTests(unittest.TestCase):
    def test_cli_verify_process_state_dry_run_builds_anchored_pgrep(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "cli", "verify-process-state", "--process", "vpp"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_verify_process_state")
        self.assertIn("pgrep -f", payload["data"]["request"]["command"])
        self.assertIn("^/opt/dbappsecurity/bin/vpp -c /appdata/etc/vpp/startup.conf", payload["data"]["request"]["command"])
        self.assertEqual(payload["data"]["request"]["success_pattern"], "\\d+")

    def test_cli_verify_process_state_dnsmasq_uses_anchored_pattern(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "cli", "verify-process-state", "--process", "dnsmasq"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertIn("^/opt/dbappsecurity/bin/dnsmasq -k -C /appdata/etc/dns/dnsmasq.conf", payload["data"]["request"]["command"])

    def test_cli_kill_process_dry_run_builds_escaped_kill(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "cli", "kill-process", "--process", "vpp", "--pid", "2249"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_kill_process")
        self.assertEqual(payload["data"]["request"]["command"], "kill -9 2249")

    def test_kill_pid_is_shell_escaped(self) -> None:
        from atomic_ops.runner.ssh import build_kill_process_dry_run
        result = build_kill_process_dry_run(
            base_url="https://192.0.2.1", session_file=Path("x"), transport="ssh",
            host=None, port=None, process="vpp", pid="2249; rm -rf /", timeout=10.0,
        )
        command = result["request"]["command"]
        self.assertEqual(command, "kill -9 '2249; rm -rf /'")

    def test_cli_config_dns_diag_ping_mode(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "cli", "config-dns-diag", "--domain", "www.baidu.com", "--mode", "ping"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_dns_diag")
        self.assertEqual(payload["data"]["request"]["command"], "ping -c 3 www.baidu.com")
        self.assertEqual(payload["data"]["request"]["success_pattern"], "\\d+ bytes from")

    def test_cli_config_dns_diag_traceroute_mode(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "cli", "config-dns-diag", "--domain", "www.baidu.com", "--mode", "traceroute"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["data"]["request"]["command"], "traceroute www.baidu.com")
        self.assertEqual(payload["data"]["request"]["success_pattern"], "\\d+ hops max")

    def test_unsupported_process_raises_validation_error(self) -> None:
        from atomic_ops.runner.ssh import build_verify_process_state_dry_run
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError):
            build_verify_process_state_dry_run(
                base_url="https://192.0.2.1", session_file=Path("x"), transport="ssh",
                host=None, port=None, process="unknown", timeout=10.0,
            )

    def test_unsupported_diag_mode_raises_validation_error(self) -> None:
        from atomic_ops.runner.ssh import build_dns_diag_dry_run
        from atomic_ops.runner.errors import RunnerError
        with self.assertRaises(RunnerError):
            build_dns_diag_dry_run(
                base_url="https://192.0.2.1", session_file=Path("x"), transport="ssh",
                host=None, port=None, domain="www.baidu.com", mode="nslookup", timeout=10.0,
            )


class UesPayloadTests(unittest.TestCase):
    """UES 原子操作 runner 载荷构造测试（期望值对齐 UESAPI.txt 录制请求体）。"""

    def test_access_payload_matches_recording(self) -> None:
        from atomic_ops.runner.ues import build_ues_access_payload
        payload = build_ues_access_payload(
            uesswitch=True,
            uesip="<UES_IP>",
            port="53443",
            securitykey="",
            thirdpartycode="tgfw",
        )
        self.assertEqual(payload["id"], "uesaccess")
        self.assertEqual(
            payload["val"],
            {"uesswitch": True, "uesip": "<UES_IP>", "port": "53443",
             "securitykey": "", "thirdpartycode": "tgfw"},
        )

    def test_connection_payload_matches_recording(self) -> None:
        from atomic_ops.runner.ues import build_ues_connection_payload
        payload = build_ues_connection_payload(
            uesip="<UES_IP>",
            port="53443",
            securitykey="",
            thirdpartycode="tgfw",
        )
        self.assertEqual(payload["id"], "ues")
        self.assertEqual(payload["val"]["uesip"], "<UES_IP>")
        self.assertEqual(payload["val"]["port"], "53443")

    def test_global_payload_matches_recording(self) -> None:
        from atomic_ops.runner.ues import build_ues_global_payload
        payload = build_ues_global_payload(
            httpdstport=[80],
            httpsdstport=[443],
            blackadd=True,
            blocktime=300,
            hashadd=True,
            uesurl="https://<UES_IP>:53443/publish/index.html?language=zh-CN",
            notipstate=True,
            open_service=["DNS", "DHCP"],
        )
        self.assertEqual(payload["id"], "uesglobal")
        self.assertEqual(payload["val"]["httpdstport"], [80])
        self.assertEqual(payload["val"]["httpsdstport"], [443])
        self.assertEqual(payload["val"]["blocktime"], 300)
        self.assertEqual(payload["val"]["open_service"], ["DNS", "DHCP"])

    def test_ip_policy_create_payload_matches_recording(self) -> None:
        from atomic_ops.runner.ues import build_ues_ip_policy_payload
        payload = build_ues_ip_policy_payload(
            entry_id=0,
            name="hh",
            enable=True,
            action=0,
            log=False,
            cycletime=0,
            desc="",
            srcip="any",
            srcipisgroup=False,
            dstip="any",
            dstipisgroup=False,
        )
        self.assertEqual(payload["id"], 0)
        self.assertNotIn("id", payload["val"])  # 新建时不携带 val.id
        self.assertEqual(payload["val"]["name"], "hh")
        self.assertEqual(payload["val"]["action"], 0)
        self.assertFalse(payload["val"]["log"])

    def test_ip_policy_update_payload_carries_val_id(self) -> None:
        from atomic_ops.runner.ues import build_ues_ip_policy_payload
        payload = build_ues_ip_policy_payload(
            entry_id=1,
            name="zyz",
            enable=True,
            action=2,
            log=True,
            cycletime=1,
            desc="",
            srcip="any",
            srcipisgroup=False,
            dstip="any",
            dstipisgroup=False,
        )
        self.assertEqual(payload["id"], 1)
        self.assertEqual(payload["val"]["id"], 1)
        self.assertEqual(payload["val"]["action"], 2)
        self.assertEqual(payload["val"]["cycletime"], 1)

    def test_ip_policy_srcip_dstip_empty_normalized_to_any(self) -> None:
        from atomic_ops.runner.ues import build_ues_ip_policy_payload
        payload = build_ues_ip_policy_payload(
            entry_id=0,
            name="n",
            enable=True,
            action=0,
            log=False,
            cycletime=0,
            desc="",
            srcip="",
            srcipisgroup=False,
            dstip=None,
            dstipisgroup=False,
        )
        self.assertEqual(payload["val"]["srcip"], "any")
        self.assertEqual(payload["val"]["dstip"], "any")

    def test_delete_payload(self) -> None:
        from atomic_ops.runner.ues import build_ues_delete_payload
        self.assertEqual(build_ues_delete_payload(entry_id=2), {"id": 2})

    def test_priority_payload_matches_recording_without_targetid(self) -> None:
        from atomic_ops.runner.ues import build_ues_priority_payload
        payload = build_ues_priority_payload(targetsite="first", moveid=1, targetid=None)
        self.assertEqual(payload, {"val": {"targetsite": "first", "moveid": 1}})
        self.assertNotIn("targetid", payload["val"])

    def test_priority_payload_includes_targetid_when_provided(self) -> None:
        from atomic_ops.runner.ues import build_ues_priority_payload
        payload = build_ues_priority_payload(targetsite="before", moveid=3, targetid=1)
        self.assertEqual(payload["val"]["targetid"], 1)

    def test_action_out_of_range_rejected(self) -> None:
        from atomic_ops.runner.ues import build_ues_ip_policy_payload
        with self.assertRaises(RunnerError):
            build_ues_ip_policy_payload(
                entry_id=0, name="n", enable=True, action=3, log=False,
                cycletime=0, desc="", srcip="any", srcipisgroup=False,
                dstip="any", dstipisgroup=False,
            )

    def test_required_fields_rejected(self) -> None:
        from atomic_ops.runner.ues import (
            build_ues_access_payload,
            build_ues_global_payload,
            build_ues_ip_policy_payload,
        )
        with self.assertRaises(RunnerError):
            build_ues_access_payload(uesswitch=True, uesip="", port="53443", securitykey="", thirdpartycode="tgfw")
        with self.assertRaises(RunnerError):
            build_ues_access_payload(uesswitch=True, uesip="10.0.0.1", port="", securitykey="", thirdpartycode="tgfw")
        with self.assertRaises(RunnerError):
            build_ues_global_payload(httpdstport=[], httpsdstport=[443], blackadd=True, blocktime=300, hashadd=True,
                                     uesurl="https://x/y", notipstate=True, open_service=["DNS"])
        with self.assertRaises(RunnerError):
            build_ues_global_payload(httpdstport=[80], httpsdstport=[70000], blackadd=True, blocktime=300, hashadd=True,
                                     uesurl="https://x/y", notipstate=True, open_service=["DNS"])
        with self.assertRaises(RunnerError):
            build_ues_ip_policy_payload(
                entry_id=0, name="", enable=True, action=0, log=False,
                cycletime=0, desc="", srcip="any", srcipisgroup=False,
                dstip="any", dstipisgroup=False,
            )
        with self.assertRaises(RunnerError):
            build_ues_ip_policy_payload(
                entry_id=-1, name="n", enable=True, action=0, log=False,
                cycletime=0, desc="", srcip="any", srcipisgroup=False,
                dstip="any", dstipisgroup=False,
            )

    def test_unsupported_targetsite_rejected(self) -> None:
        from atomic_ops.runner.ues import build_ues_priority_payload
        with self.assertRaises(RunnerError):
            build_ues_priority_payload(targetsite="middle", moveid=1, targetid=None)

    def test_priority_moveid_must_be_positive(self) -> None:
        from atomic_ops.runner.ues import build_ues_priority_payload
        with self.assertRaises(RunnerError):
            build_ues_priority_payload(targetsite="first", moveid=0, targetid=None)


class UesSummaryExtractionTests(unittest.TestCase):
    """响应摘要提取（returns.data 契约兑现）测试。"""

    def setUp(self) -> None:
        from atomic_ops.runner.ues import _extract_ues_summary
        self._extract = _extract_ues_summary

    def test_verify_ip_policy_extracts_ids_count_hitcount(self) -> None:
        response = {"count": 2, "vals": [
            {"id": 1, "name": "zyz", "hitcount": "0", "action": 2},
            {"id": 2, "name": "hh", "hitcount": "5", "action": 0},
        ]}
        summary = self._extract("fw_verify_ues_ip_policy", None, response)
        self.assertEqual(summary["count"], 2)
        self.assertEqual(summary["ip_policy_ids"], [1, 2])
        self.assertEqual(summary["hitcount"], "0")

    def test_verify_order_extracts_ordered_ids(self) -> None:
        response = {"count": 1, "page": 1, "size": 300, "vals": [1]}
        summary = self._extract("fw_verify_ues_ip_policy_order", None, response)
        self.assertEqual(summary["count"], 1)
        self.assertEqual(summary["policy_order_ids"], [1])

    def test_verify_access_global_existence(self) -> None:
        self.assertTrue(self._extract("fw_verify_ues_access", None, {"uesswitch": True})["existence"])
        self.assertFalse(self._extract("fw_verify_ues_global", None, {})["existence"])

    def test_config_ip_policy_created_flag(self) -> None:
        summary = self._extract("fw_config_ues_ip_policy", {"id": 0, "val": {}}, {"msg": "success"})
        self.assertTrue(summary["created"])
        self.assertNotIn("ip_policy_id", summary)

    def test_update_and_delete_carry_ip_policy_id(self) -> None:
        summary = self._extract("fw_update_ues_ip_policy", {"id": 1, "val": {}}, {"msg": "success"})
        self.assertEqual(summary["ip_policy_id"], 1)
        self.assertNotIn("created", summary)
        summary = self._extract("fw_delete_ues_ip_policy", {"id": 2}, {"msg": "success"})
        self.assertEqual(summary["ip_policy_id"], 2)


class UesRequestUrlTests(unittest.TestCase):
    """请求 URL 构造测试。"""

    def test_verify_ip_policy_url_with_page_size(self) -> None:
        from atomic_ops.runner.ues import _request_url
        url = _request_url("https://192.0.2.1", "fw_verify_ues_ip_policy", page=1, size=40, config_source=0)
        self.assertEqual(url, "https://192.0.2.1/api/v1/uesippolicy?page=1&size=40")

    def test_verify_order_url_with_config_source(self) -> None:
        from atomic_ops.runner.ues import _request_url
        url = _request_url("https://192.0.2.1", "fw_verify_ues_ip_policy_order", page=1, size=300, config_source=0)
        self.assertEqual(url, "https://192.0.2.1/api/v1/uesippolicyorder?page=1&size=300&config_source=0")

    def test_delete_url_with_id(self) -> None:
        from atomic_ops.runner.ues import _request_url
        url = _request_url("https://192.0.2.1", "fw_delete_ues_ip_policy", page=1, size=40, config_source=0, payload={"id": 2})
        self.assertEqual(url, "https://192.0.2.1/api/v1/uesippolicy?id=2")

    def test_flat_verify_ops_have_no_query(self) -> None:
        from atomic_ops.runner.ues import _request_url
        url = _request_url("https://192.0.2.1", "fw_verify_ues_access", page=1, size=40, config_source=0)
        self.assertEqual(url, "https://192.0.2.1/api/v1/uesaccess")

    def test_unsupported_op_rejected(self) -> None:
        from atomic_ops.runner.ues import _request_url
        with self.assertRaises(RunnerError):
            _request_url("https://192.0.2.1", "fw_config_nat", page=1, size=40, config_source=0)


class UesCliTests(unittest.TestCase):
    """run ues 命令族 dry-run CLI 测试。"""

    def test_cli_access_puts_uesaccess_body(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ues", "access", "--ues-ip", "<UES_IP>", "--ues-port", "53443"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_ues_access")
        self.assertEqual(payload["data"]["request"]["method"], "PUT")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/uesaccess"))
        self.assertEqual(payload["data"]["request"]["payload"]["id"], "uesaccess")

    def test_cli_connection_posts_ues_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ues", "connection", "--ues-ip", "<UES_IP>", "--ues-port", "53443"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_check_ues_connection")
        self.assertEqual(payload["data"]["request"]["method"], "POST")
        self.assertEqual(payload["data"]["request"]["payload"]["id"], "ues")

    def test_cli_policy_creates_with_id_zero(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ues", "policy", "--name", "hh", "--action", "2", "--cycletime", "1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_ues_ip_policy")
        self.assertEqual(payload["data"]["request"]["payload"]["id"], 0)
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["action"], 2)
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["cycletime"], 1)

    def test_cli_policy_update_requires_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ues", "policy-update", "--id", "1", "--name", "zyz", "--action", "0"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_update_ues_ip_policy")
        self.assertEqual(payload["data"]["request"]["payload"]["id"], 1)
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["id"], 1)

    def test_cli_policy_delete_uses_query_id(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ues", "policy-delete", "--id", "2"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_delete_ues_ip_policy")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/uesippolicy?id=2"))
        self.assertIsNone(payload["data"]["request"]["payload"])

    def test_cli_policy_verify_queries_page_size(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ues", "policy-verify", "--page", "1", "--size", "40"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_verify_ues_ip_policy")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/uesippolicy?page=1&size=40"))

    def test_cli_global_puts_uesglobal_body(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ues", "global", "--ues-url", "https://<UES_IP>:53443/publish/index.html?language=zh-CN"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_config_ues_global")
        self.assertEqual(payload["data"]["request"]["payload"]["id"], "uesglobal")
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["httpdstport"], [80])
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["open_service"], ["DNS", "DHCP"])

    def test_cli_priority_posts_move_payload(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ues", "priority", "--targetsite", "first", "--moveid", "1"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_update_ues_ip_policy_priority")
        self.assertEqual(payload["data"]["request"]["payload"], {"val": {"targetsite": "first", "moveid": 1}})

    def test_cli_order_queries_with_config_source(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ues", "order"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_verify_ues_ip_policy_order")
        self.assertTrue(payload["data"]["request"]["url"].endswith("/api/v1/uesippolicyorder?page=1&size=40&config_source=0"))

    def test_cli_verify_access_flat_get(self) -> None:
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ues", "access-verify"]
            )
        self.assertEqual(exit_code, 0)
        payload = json.loads(stdout.getvalue())
        self.assertEqual(payload["op_id"], "fw_verify_ues_access")
        self.assertEqual(payload["data"]["request"]["method"], "GET")

    def test_cli_invalid_action_returns_validation_error(self) -> None:
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            exit_code = cli_main(
                ["run", "--format", "json", "--base-url", "https://192.0.2.1",
                 "ues", "policy", "--name", "hh", "--action", "9"]
            )
        self.assertEqual(exit_code, 49)  # ERROR_RUNNER_VALIDATION_FAILED 退出码
        payload = json.loads(stderr.getvalue().splitlines()[-1])
        self.assertEqual(payload["error_code"], "RUNNER_VALIDATION_FAILED")


class CredentialAuthSplitTests(unittest.TestCase):
    """STORY-S6-02：凭据缺失（环境变量未注入/为空）与认证失败（口令/凭据被拒）分层出口。

    - 凭据缺失 -> RUNNER_CREDENTIAL_MISSING（exit 43），消息点名环境变量并附注入指引；
    - 认证失败 -> RUNNER_LOGIN_FAILED（exit 44），消息说明被设备拒绝（认证环节）；
    - 文案安全口径：不出现独立词 password/token（输出层整行 REDACT），不回显凭据值。
    """

    def test_read_secret_env_missing_var_is_credential_class_with_hint(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RunnerError) as context:
                _read_secret_env("FW_WEB_PASSWORD", "password_env")
        self.assertEqual(context.exception.error_code, "RUNNER_CREDENTIAL_MISSING")
        # 消息点名未注入的环境变量并附注入指引
        self.assertIn("FW_WEB_PASSWORD", context.exception.message)
        self.assertIn("credential not injected", context.exception.message)
        self.assertIn("set -a; source .env; set +a", context.exception.suggestion or "")

    def test_read_secret_env_empty_value_is_credential_class(self) -> None:
        with patch.dict(os.environ, {"FW_SSH_PASSWORD": ""}):
            with self.assertRaises(RunnerError) as context:
                _read_secret_env("FW_SSH_PASSWORD", "password_env")
        self.assertEqual(context.exception.error_code, "RUNNER_CREDENTIAL_MISSING")
        self.assertEqual(context.exception.details.get("env"), "FW_SSH_PASSWORD")

    def test_read_secret_env_set_value_returns_value(self) -> None:
        with patch.dict(os.environ, {"FW_SSH_PASSWORD": "unit-test-value"}):
            self.assertEqual(_read_secret_env("FW_SSH_PASSWORD", "password_env"), "unit-test-value")

    def test_ssh_read_credential_env_missing_is_credential_class(self) -> None:
        from atomic_ops.runner.ssh import _read_credential_env

        with patch("atomic_ops.runner.ssh._load_dotenv"), patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(RunnerError) as context:
                _read_credential_env("FW_TELNET_PASSWORD")
        self.assertEqual(context.exception.error_code, "RUNNER_CREDENTIAL_MISSING")
        self.assertIn("FW_TELNET_PASSWORD", context.exception.message)
        self.assertIn("set -a; source .env; set +a", context.exception.suggestion or "")

    def test_login_wrong_credential_is_auth_rejected_class(self) -> None:
        # 设备返回 errCode（口令错/凭据失效）-> RUNNER_LOGIN_FAILED，与凭据缺失（43）分层
        with patch("atomic_ops.runner.ngfw_login._encrypt_password", return_value="encrypted"):
            with patch(
                "atomic_ops.runner.ngfw_login.request_json",
                return_value=(200, {"errCode": "eUserOrPwdError", "errMsg": "unit"}, "{}"),
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
        self.assertIn("Authentication rejected", context.exception.message)
        self.assertEqual(context.exception.details.get("err_code"), "eUserOrPwdError")

    def test_login_http_401_is_auth_rejected_class(self) -> None:
        with patch("atomic_ops.runner.ngfw_login._encrypt_password", return_value="encrypted"):
            with patch(
                "atomic_ops.runner.ngfw_login.request_json",
                return_value=(401, {}, "{}"),
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
        self.assertIn("Authentication rejected", context.exception.message)
        self.assertIn("401", context.exception.message)

    def test_login_without_err_code_keeps_response_message(self) -> None:
        # 无 errCode 也无会话引用：保持响应异常语义（非认证被拒）
        with patch("atomic_ops.runner.ngfw_login._encrypt_password", return_value="encrypted"):
            with patch(
                "atomic_ops.runner.ngfw_login.request_json",
                return_value=(200, {"foo": "bar"}, "{}"),
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
        self.assertIn("did not contain a session reference", context.exception.message)

    def test_credential_message_survives_output_redaction(self) -> None:
        # 凭据缺失文案可安全通过输出脱敏层（不被整行 REDACT），且只含变量名不含凭据值
        from atomic_ops.errors import CliError, write_error
        from atomic_ops.runner.errors import credential_missing_error

        error = credential_missing_error("FW_WEB_PASSWORD", field_name="password_env")
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            write_error(
                CliError(error.error_code, error.message, error.details, suggestion=error.suggestion),
                "json",
            )
        payload = json.loads(stderr.getvalue())
        self.assertIn("FW_WEB_PASSWORD", payload["message"])
        self.assertIn("set -a; source .env; set +a", payload["suggestion"])


class NatPayloadTests(unittest.TestCase):
    """NAT 请求构造：端点分歧、id 类型、协议参数。"""

    def test_config_snat_wraps_val_without_id(self) -> None:
        payload = build_nat_rule_payload(op_id="fw_config_nat_snat", val={"srcName": "any"})
        self.assertEqual(payload, {"val": {"srcName": "any", "natType": "nat44"}})

    def test_update_carries_integer_id(self) -> None:
        payload = build_nat_rule_payload(op_id="fw_update_nat_dnat", val={"dstName": ""}, entry_id="3")
        self.assertEqual(payload["id"], 3)
        self.assertIsInstance(payload["id"], int)

    def test_delete_carries_string_id(self) -> None:
        payload = build_nat_delete_payload(op_id="fw_delete_nat_static", entry_id="2")
        self.assertEqual(payload, {"id": "2"})
        self.assertIsInstance(payload["id"], str)

    def test_update_rejects_non_numeric_id(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_nat_rule_payload(op_id="fw_update_nat_snat", val={"srcName": "any"}, entry_id="rule-a")
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_read_modify_write_fields_pass_through_unchanged(self) -> None:
        """PUT 需要原样回传设备只读回显字段，不做任何归一化。"""
        val = {
            "dstName": "",
            "config_source": 0,
            "effect_type": "None",
            "enable_status": True,
            "hitcount": 0,
            "auto_disable": False,
            "originRow": {"id": 2, "natType": "nat44"},
        }
        payload = build_nat_rule_payload(op_id="fw_update_nat_dnat", val=val, entry_id=2)
        self.assertEqual(payload["val"]["originRow"], {"id": 2, "natType": "nat44"})
        self.assertEqual(payload["val"]["effect_type"], "None")
        self.assertEqual(payload["val"]["enable_status"], True)

    def test_relate_is_ipv6_spelling_is_preserved(self) -> None:
        """创建/修改 payload 用 relate.isIpv6，回读记录用 relate.is_ipv6，两侧不可共用键名。"""
        payload = build_nat_rule_payload(
            op_id="fw_config_nat_snat",
            val={"relate": {"isIpv6": False, "VRRPId": 0}},
        )
        self.assertEqual(payload["val"]["relate"], {"isIpv6": False, "VRRPId": 0})
        self.assertNotIn("is_ipv6", payload["val"]["relate"])

    def test_nat_type_conflict_is_rejected(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_nat_rule_payload(op_id="fw_config_nat_snat", val={"natType": "nat66"})
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_unsupported_nat_type_is_rejected(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_nat_rule_payload(op_id="fw_config_nat_snat", val={"srcName": "any"}, nat_type="nat46")
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")
        self.assertEqual(ctx.exception.details["allowed"], list(SUPPORTED_NAT_TYPES))

    def test_nat44_is_the_only_registered_protocol(self) -> None:
        self.assertEqual(list(SUPPORTED_NAT_TYPES), ["nat44"])

    def test_hitcount_payload_shape(self) -> None:
        payload = build_nat_hitcount_payload(family="snat", rule_ids=["1", "2"])
        self.assertEqual(payload, {"id": 0, "val": {"type": "snat", "is_ipv6": False, "rule_ids": ["1", "2"]}})

    def test_hitcount_rejects_unknown_family(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_nat_hitcount_payload(family="cross")
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_batch_delete_uses_family_resource(self) -> None:
        payload = build_nat_batch_delete_payload(family="dnat", entry_ids=["1", "2"])
        self.assertEqual(
            payload["batch"],
            [
                {"method": "DELETE", "resource": "/api/v1/iterate/natdnat", "body": {"id": ["1"]}},
                {"method": "DELETE", "resource": "/api/v1/iterate/natdnat", "body": {"id": ["2"]}},
            ],
        )

    def test_batch_delete_requires_ids(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_nat_batch_delete_payload(family="snat", entry_ids=[])
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_validate_rejects_non_nat_delete_resource(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            validate_nat_payload(
                {"batch": [{"method": "DELETE", "resource": "/api/v1/ipsec", "body": {"id": ["p1"]}}]},
                op_id="fw_delete_batch_nat",
            )
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_validate_coerces_update_id_to_integer(self) -> None:
        """回滚重放的快照记录带字符串 id，PUT 契约只认整数，校验时写回整数形态。"""
        payload = validate_nat_payload(
            {"id": "7", "val": {"natType": "nat44", "srcName": "any"}},
            op_id="fw_update_nat_snat",
        )
        self.assertEqual(payload["id"], 7)
        self.assertIsInstance(payload["id"], int)

    def test_validate_strips_id_from_create_payload(self) -> None:
        """创建抓包 body 只有 {"val": {...}}，id 由设备分配 —— 重放带来的 id 不下发。"""
        payload = validate_nat_payload(
            {"id": "9", "val": {"natType": "nat44", "srcName": "any"}},
            op_id="fw_config_nat_snat",
        )
        self.assertNotIn("id", payload)
        self.assertEqual(payload["val"]["srcName"], "any")


class NatCliDryRunTests(unittest.TestCase):
    """NAT CLI dry-run：端点、方法、id 类型与查询参数。"""

    BASE = "https://192.0.2.1"

    def _dry_run(self, argv: list[str]) -> dict:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(["run", "--format", "json", "--base-url", self.BASE, "nat", *argv])
        self.assertEqual(exit_code, 0, stderr.getvalue())
        return json.loads(stdout.getvalue())

    def _dry_run_error(self, argv: list[str]) -> dict:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(["run", "--format", "json", "--base-url", self.BASE, "nat", *argv])
        self.assertEqual(exit_code, 49)
        return json.loads(stdout.getvalue()) if stdout.getvalue().strip() else json.loads(stderr.getvalue())

    def test_config_snat_dry_run(self) -> None:
        payload = self._dry_run(["config-snat", "--val-json", '{"srcName":"any","outInterfaceName":"TE0_7"}'])
        self.assertEqual(payload["op_id"], "fw_config_nat_snat")
        self.assertEqual(payload["status"], "dry_run")
        self.assertEqual(payload["error_type"], "NONE")
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "POST")
        self.assertTrue(request["url"].endswith("/api/v1/natsnat"))
        self.assertEqual(request["payload"]["val"]["outInterfaceName"], "TE0_7")
        self.assertIsNone(request["query"])

    def test_config_dnat_uses_iterate_endpoint(self) -> None:
        payload = self._dry_run(["config-dnat", "--val-json", '{"dstName":"","dstIp":"4.4.4.4"}'])
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "POST")
        self.assertTrue(request["url"].endswith("/api/v1/iterate/natdnat"))

    def test_update_static_sends_integer_id(self) -> None:
        payload = self._dry_run(["update-static", "--id", "1", "--val-json", '{"external_ip":"6.6.6.6"}'])
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "PUT")
        self.assertEqual(request["payload"]["id"], 1)
        self.assertIsInstance(request["payload"]["id"], int)

    def test_delete_snat_sends_string_id_in_body_and_no_query(self) -> None:
        payload = self._dry_run(["delete-snat", "--id", "4"])
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "DELETE")
        self.assertEqual(request["payload"], {"id": "4"})
        self.assertIsInstance(request["payload"]["id"], str)
        self.assertEqual(request["url"], f"{self.BASE}/api/v1/natsnat")

    def test_delete_dnat_keeps_iterate_endpoint_and_body_id(self) -> None:
        payload = self._dry_run(["delete-dnat", "--id", "3"])
        request = payload["data"]["request"]
        self.assertEqual(request["url"], f"{self.BASE}/api/v1/iterate/natdnat")
        self.assertEqual(request["payload"], {"id": "3"})

    def test_verify_sends_query_and_no_body(self) -> None:
        payload = self._dry_run(["verify-static", "--page", "1", "--size", "10"])
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "GET")
        self.assertIsNone(request["payload"])
        self.assertEqual(request["url"], f"{self.BASE}/api/v1/natstatic?page=1&size=10&natType=nat44")

    def test_verify_rejects_unsupported_nat_type(self) -> None:
        error = self._dry_run_error(["verify-snat", "--nat-type", "nat64"])
        self.assertEqual(error["error_code"], "RUNNER_VALIDATION_FAILED")

    def test_update_hitcount_dry_run(self) -> None:
        payload = self._dry_run(["update-hitcount", "--nat-family", "dnat"])
        request = payload["data"]["request"]
        self.assertEqual(payload["op_id"], "fw_update_nat_hitcount")
        self.assertEqual(request["method"], "PUT")
        self.assertTrue(request["url"].endswith("/api/v1/nathitcount"))
        self.assertEqual(request["payload"], {"id": 0, "val": {"type": "dnat", "is_ipv6": False}})

    def test_delete_batch_dry_run(self) -> None:
        payload = self._dry_run(["delete-batch", "--nat-family", "snat", "--id", "1"])
        request = payload["data"]["request"]
        self.assertEqual(payload["op_id"], "fw_delete_batch_nat")
        self.assertEqual(request["method"], "POST")
        self.assertTrue(request["url"].endswith("/api/v1/batch"))
        self.assertEqual(
            request["payload"]["batch"],
            [{"method": "DELETE", "resource": "/api/v1/natsnat", "body": {"id": ["1"]}}],
        )

    def test_envelope_shape(self) -> None:
        payload = self._dry_run(["verify-snat"])
        self.assertEqual(
            sorted(payload.keys()),
            ["data", "diag_snapshot_ref", "error_type", "op_id", "status"],
        )

    # 回滚重放路径（op_mapper 只给 payload_json，不给 --id）：update 的 --id 因此改为
    # 「除非直传 payload 否则必填」，形状取自 ptm-atomic 既有 timeobject 先例。
    def test_update_payload_replay_needs_no_id_flag(self) -> None:
        payload = self._dry_run(
            ["update-snat", "--payload-json", '{"id":"1","val":{"srcName":"any","natType":"nat44"}}']
        )
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "PUT")
        self.assertEqual(request["payload"]["id"], 1)
        self.assertIsInstance(request["payload"]["id"], int)

    def test_update_payload_without_id_requires_the_flag(self) -> None:
        error = self._dry_run_error(
            ["update-snat", "--payload-json", '{"val":{"srcName":"any","natType":"nat44"}}']
        )
        self.assertEqual(error["error_code"], "RUNNER_VALIDATION_FAILED")

    def test_update_payload_injects_id_flag(self) -> None:
        payload = self._dry_run(
            ["update-snat", "--id", "5", "--payload-json", '{"val":{"srcName":"any","natType":"nat44"}}']
        )
        self.assertEqual(payload["data"]["request"]["payload"]["id"], 5)

    def test_update_structured_path_still_requires_id(self) -> None:
        error = self._dry_run_error(["update-snat", "--val-json", '{"srcName":"any"}'])
        self.assertEqual(error["error_code"], "RUNNER_VALIDATION_FAILED")

    def test_config_payload_replay_drops_device_id(self) -> None:
        payload = self._dry_run(
            ["config-snat", "--payload-json", '{"id":"9","val":{"srcName":"any","natType":"nat44"}}']
        )
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "POST")
        self.assertNotIn("id", request["payload"])
        self.assertEqual(request["payload"]["val"]["srcName"], "any")


class IpsecPayloadTests(unittest.TestCase):
    """IPsec 请求构造：upsert 信封、固定端口 id、批量删除形状、无 body 的 op。"""

    def test_policy_upsert_keeps_id_and_passes_val_through(self) -> None:
        """PUT /api/v1/ipsec 是 upsert：id 即策略名，val 整体直传（两种 scene 形状共用）。"""
        envelope = {
            "id": "p2mp",
            "val": {"scene": "PTMP", "name": "p2mp", "ike": {"ptmp_remote_psk": [{"psk": "<psk-ref>"}]}},
        }
        payload = build_ipsec_policy_payload(op_id="fw_config_ipsec_policy", envelope=envelope)
        self.assertEqual(payload["id"], "p2mp")
        self.assertIsInstance(payload["id"], str)
        self.assertEqual(payload["val"]["scene"], "PTMP")
        self.assertEqual(payload["val"]["ike"]["ptmp_remote_psk"], [{"psk": "<psk-ref>"}])

    def test_policy_upsert_requires_id(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_ipsec_policy_payload(op_id="fw_config_ipsec_policy", envelope={"val": {"scene": "PTMP"}})
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_policy_upsert_requires_val(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_ipsec_policy_payload(op_id="fw_config_ipsec_policy", envelope={"id": "p2mp"})
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_policy_upsert_rejects_empty_val(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_ipsec_policy_payload(op_id="fw_config_ipsec_policy", envelope={"id": "p2mp", "val": {}})
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_unknown_policy_field_passes_through(self) -> None:
        """抓包里多处枚举标「(推断)」——不做白名单校验，字段原样透传。"""
        envelope = {
            "id": "p1",
            "val": {"scene": "PTP", "name": "p1", "remote_type": ["UNRECORDED_VALUE"]},
        }
        payload = build_ipsec_policy_payload(op_id="fw_config_ipsec_policy", envelope=envelope)
        self.assertEqual(payload["val"]["remote_type"], ["UNRECORDED_VALUE"])

    def test_port_payload_uses_fixed_id(self) -> None:
        payload = build_ipsec_port_payload(val={"local_port": 500, "ip_protocol": "ipv4", "nat_t": "enable"})
        self.assertEqual(payload["id"], IPSEC_PORT_ID)
        self.assertEqual(IPSEC_PORT_ID, "0")
        self.assertEqual(payload["val"]["local_port"], 500)

    def test_port_payload_requires_val(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_ipsec_port_payload(val=None)
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_validate_rejects_non_fixed_port_id(self) -> None:
        """端口信封 id 是设备契约的固定字面量，不是选择器 —— 非 0 一律拒绝。"""
        with self.assertRaises(RunnerError) as ctx:
            validate_ipsec_payload(
                {"id": "1", "val": {"local_port": 500}}, op_id="fw_update_ipsec_port"
            )
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")
        self.assertEqual(ctx.exception.details["expected"], "0")

    def test_validate_accepts_fixed_port_id(self) -> None:
        payload = validate_ipsec_payload(
            {"id": "0", "val": {"local_port": 4500}}, op_id="fw_update_ipsec_port"
        )
        self.assertEqual(payload["id"], "0")

    def test_no_body_ops_return_none(self) -> None:
        """GET 四个查询与 delete-policy 都不下发 body（delete 的 id 走查询串）。"""
        for op_id in (
            "fw_verify_ipsec_policy",
            "fw_verify_ipsec_port",
            "fw_verify_ipsec_ikesa",
            "fw_verify_ipsec_sa",
            "fw_delete_ipsec_policy",
        ):
            with self.subTest(op_id=op_id):
                self.assertIsNone(validate_ipsec_payload({"unexpected": True}, op_id=op_id))

    def test_batch_delete_shape(self) -> None:
        payload = build_ipsec_batch_delete_payload(policy_names=["p2mp", "p2mp2"])
        self.assertEqual(
            payload["batch"],
            [
                {
                    "method": "DELETE",
                    "resource": "/api/v1/ipsec",
                    "body": {"id": ["p2mp", "p2mp2"]},
                }
            ],
        )

    def test_batch_delete_requires_names(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_ipsec_batch_delete_payload(policy_names=[])
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_batch_delete_rejects_unregistered_resource(self) -> None:
        """批量契约只认 /api/v1/ipsec；NAT 端点由 fw_delete_batch_nat 承接。"""
        with self.assertRaises(RunnerError) as ctx:
            validate_ipsec_payload(
                {"batch": [{"method": "DELETE", "resource": "/api/v1/natsnat", "body": {"id": ["1"]}}]},
                op_id="fw_delete_batch_ipsec",
            )
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_batch_delete_rejects_non_delete_method(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            validate_ipsec_payload(
                {"batch": [{"method": "POST", "resource": "/api/v1/ipsec", "body": {"id": ["p1"]}}]},
                op_id="fw_delete_batch_ipsec",
            )
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")


class IpsecCliDryRunTests(unittest.TestCase):
    """IPsec CLI dry-run：端点、方法、DELETE 形态差异与固定端口 id。"""

    BASE = "https://192.0.2.1"

    def _dry_run(self, argv: list[str]) -> dict:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(["run", "--format", "json", "--base-url", self.BASE, "ipsec", *argv])
        self.assertEqual(exit_code, 0, stderr.getvalue())
        return json.loads(stdout.getvalue())

    def _dry_run_error(self, argv: list[str]) -> dict:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(["run", "--format", "json", "--base-url", self.BASE, "ipsec", *argv])
        self.assertEqual(exit_code, 49)
        return json.loads(stdout.getvalue()) if stdout.getvalue().strip() else json.loads(stderr.getvalue())

    def test_config_policy_dry_run(self) -> None:
        payload = self._dry_run(
            ["config-policy", "--id", "p2mp", "--val-json", '{"scene":"PTMP","name":"p2mp"}']
        )
        self.assertEqual(payload["op_id"], "fw_config_ipsec_policy")
        self.assertEqual(payload["status"], "dry_run")
        self.assertEqual(payload["error_type"], "NONE")
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "PUT")
        self.assertEqual(request["url"], f"{self.BASE}/api/v1/ipsec")
        self.assertEqual(request["payload"]["id"], "p2mp")
        self.assertEqual(request["payload"]["val"]["scene"], "PTMP")
        self.assertIsNone(request["query"])

    def test_config_policy_result_carries_no_created_flag(self) -> None:
        """响应只有 {"msg":"success"}：upsert 无法区分新建/覆盖，故不得臆造 created。"""
        payload = self._dry_run(
            ["config-policy", "--id", "p1", "--val-json", '{"scene":"PTMP","name":"p1"}']
        )
        self.assertNotIn("created", payload["data"])

    def test_config_policy_payload_replay_needs_no_id_flag(self) -> None:
        """回滚重放只给 payload_json（op_mapper 不传 --id）。"""
        payload = self._dry_run(
            ["config-policy", "--payload-json", '{"id":"p2mp","val":{"scene":"PTMP","name":"p2mp"}}']
        )
        self.assertEqual(payload["data"]["request"]["payload"]["id"], "p2mp")

    def test_config_policy_requires_id_without_payload(self) -> None:
        error = self._dry_run_error(["config-policy", "--val-json", '{"scene":"PTMP"}'])
        self.assertEqual(error["error_code"], "RUNNER_VALIDATION_FAILED")

    def test_delete_policy_sends_query_id_and_no_body(self) -> None:
        """DELETE 形态差异：IPsec 用 ?id=，NAT 三族用 JSON body —— 不得互相类比。"""
        payload = self._dry_run(["delete-policy", "--id", "p2mp"])
        request = payload["data"]["request"]
        self.assertEqual(payload["op_id"], "fw_delete_ipsec_policy")
        self.assertEqual(request["method"], "DELETE")
        self.assertEqual(request["url"], f"{self.BASE}/api/v1/ipsec?id=p2mp")
        self.assertIsNone(request["payload"])

    def test_verify_policy_sends_no_body_and_no_query(self) -> None:
        payload = self._dry_run(["verify-policy"])
        request = payload["data"]["request"]
        self.assertEqual(payload["op_id"], "fw_verify_ipsec_policy")
        self.assertEqual(request["method"], "GET")
        self.assertEqual(request["url"], f"{self.BASE}/api/v1/ipsec")
        self.assertIsNone(request["payload"])
        self.assertIsNone(request["query"])

    def test_verify_port_sends_no_body_and_no_query(self) -> None:
        payload = self._dry_run(["verify-port"])
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "GET")
        self.assertEqual(request["url"], f"{self.BASE}/api/v1/ipsec/port")
        self.assertIsNone(request["payload"])
        self.assertIsNone(request["query"])

    def test_update_port_dry_run_from_flat_flags(self) -> None:
        payload = self._dry_run(
            ["update-port", "--local-port", "4500", "--remote-port", "4500",
             "--ip-protocol", "ipv4", "--nat-t", "disable"]
        )
        request = payload["data"]["request"]
        self.assertEqual(payload["op_id"], "fw_update_ipsec_port")
        self.assertEqual(request["method"], "PUT")
        self.assertEqual(request["url"], f"{self.BASE}/api/v1/ipsec/port")
        self.assertEqual(
            request["payload"],
            {
                "id": "0",
                "val": {
                    "local_port": 4500,
                    "remote_port": 4500,
                    "ip_protocol": "ipv4",
                    "nat_t": "disable",
                },
            },
        )

    def test_update_port_payload_replay_keeps_fixed_id(self) -> None:
        """回滚快照重放：信封 id 必须是 0，val 是整条端口记录。"""
        payload = self._dry_run(
            ["update-port", "--payload-json", '{"id":"0","val":{"local_port":500,"ip_protocol":"ipv6","nat_t":"enable"}}']
        )
        request = payload["data"]["request"]
        self.assertEqual(request["payload"]["id"], "0")
        self.assertEqual(request["payload"]["val"]["ip_protocol"], "ipv6")

    def test_update_port_rejects_foreign_id_in_replay(self) -> None:
        error = self._dry_run_error(
            ["update-port", "--payload-json", '{"id":"1","val":{"local_port":500}}']
        )
        self.assertEqual(error["error_code"], "RUNNER_VALIDATION_FAILED")

    def test_verify_ikesa_sends_paging_query(self) -> None:
        payload = self._dry_run(["verify-ikesa", "--page", "2", "--size", "5"])
        request = payload["data"]["request"]
        self.assertEqual(payload["op_id"], "fw_verify_ipsec_ikesa")
        self.assertEqual(request["url"], f"{self.BASE}/api/v1/ipsec/ikesa?page=2&size=5")
        self.assertIsNone(request["payload"])

    def test_verify_sa_sends_paging_query(self) -> None:
        payload = self._dry_run(["verify-sa"])
        request = payload["data"]["request"]
        self.assertEqual(payload["op_id"], "fw_verify_ipsec_sa")
        self.assertEqual(request["url"], f"{self.BASE}/api/v1/ipsec/ipsecsa?page=1&size=10")
        self.assertIsNone(request["payload"])

    def test_delete_batch_dry_run(self) -> None:
        payload = self._dry_run(["delete-batch", "--id", "p2mp", "--id", "p2mp2"])
        request = payload["data"]["request"]
        self.assertEqual(payload["op_id"], "fw_delete_batch_ipsec")
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["url"], f"{self.BASE}/api/v1/batch")
        self.assertEqual(request["payload"]["batch"][0]["resource"], "/api/v1/ipsec")
        self.assertEqual(request["payload"]["batch"][0]["body"]["id"], ["p2mp", "p2mp2"])

    def test_delete_batch_requires_at_least_one_id(self) -> None:
        error = self._dry_run_error(["delete-batch"])
        self.assertEqual(error["error_code"], "RUNNER_VALIDATION_FAILED")

    def test_envelope_shape(self) -> None:
        payload = self._dry_run(["verify-policy"])
        self.assertEqual(
            sorted(payload.keys()),
            ["data", "diag_snapshot_ref", "error_type", "op_id", "status"],
        )


if __name__ == "__main__":
    unittest.main()
