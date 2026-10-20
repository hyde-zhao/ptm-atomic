"""IPS atom/runner 回归测试（离线：构造 + dry-run + mock 设备响应）。

覆盖：
- 规则/防护模板的载荷构造与校验；
- 规则 GET/DELETE 携带 JSON body 的形态；
- 批量删除的 per-id item 形态与结果摘要；
- acl-policy 的 IPS sec_obj_data 便捷字段与向后兼容空列表；
- CLI ``run ips ...`` dry-run 路径。
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
from atomic_ops.runner.acl_policy import build_acl_policy_payload
from atomic_ops.runner.errors import RunnerError, is_resource_not_found
from atomic_ops.runner.ips import (
    SECLOG_GIDS,
    build_ips_evidence_query,
    build_ips_log_query,
    build_ips_pcap_download_id,
    build_ips_profile_batch_delete_payload,
    build_ips_profile_delete_payload,
    build_ips_profile_payload,
    build_ips_profile_query_payload,
    build_ips_profile_update_payload,
    build_ips_rule_batch_delete_payload,
    build_ips_rule_delete_payload,
    build_ips_rule_payload,
    build_ips_rule_query_payload,
    build_ips_rule_update_payload,
    build_log_cache_payload,
    execute_ips,
    execute_ips_evidence,
    execute_ips_log,
    execute_ips_pcap_download,
    execute_log_cache,
    validate_ips_payload,
)
from atomic_ops.runner.license import execute_license
from atomic_ops.runner.log_ops import (
    build_clear_ips_log_query,
    build_ips_log_export_query,
    build_log_backup_list_query,
    build_log_download_task_payload,
    build_log_time_set_payload,
    execute_clear_ips_log,
    execute_download_log_file,
    execute_ips_log_export,
    execute_log_backup_list,
    execute_log_cache_verify,
    execute_log_download_task,
    execute_log_download_task_verify,
    execute_log_time_set,
    execute_log_time_verify,
)
from atomic_ops.runner.session import write_session_file
from atomic_ops.runner.ssh import (
    PROCESS_RESTART_MAP,
    build_capture_system_log_dry_run,
    execute_capture_system_log,
    execute_verify_capture_storage,
    execute_verify_process_restart,
    execute_verify_system_resource,
)

BASE_URL = "https://192.0.2.1"
SNORT_RULE = 'alert tcp any any -> any any ( msg:"test"; rev:100; )'


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


class IpsRulePayloadTests(unittest.TestCase):
    def test_create_payload_uses_val_envelope(self) -> None:
        payload = build_ips_rule_payload(name="test1", desc=SNORT_RULE)
        self.assertEqual(
            payload,
            {"val": {"name": "test1", "desc": SNORT_RULE, "isProfenal": False}},
        )

    def test_profenal_rule_allows_empty_name(self) -> None:
        payload = build_ips_rule_payload(name="", desc=SNORT_RULE, is_profenal=True)
        self.assertEqual(payload["val"]["name"], "")
        self.assertTrue(payload["val"]["isProfenal"])

    def test_custom_rule_requires_name(self) -> None:
        with self.assertRaises(RunnerError):
            build_ips_rule_payload(name="", desc=SNORT_RULE, is_profenal=False)

    def test_rule_requires_desc(self) -> None:
        with self.assertRaises(RunnerError):
            build_ips_rule_payload(name="test1", desc="  ")

    def test_update_payload_carries_string_id_and_full_val(self) -> None:
        payload = build_ips_rule_update_payload(
            entry_id=5191533, name="test5", desc=SNORT_RULE
        )
        self.assertEqual(payload["id"], "5191533")
        self.assertEqual(payload["val"]["name"], "test5")

    def test_delete_payload_is_json_body_id(self) -> None:
        self.assertEqual(build_ips_rule_delete_payload(entry_id="5191533"), {"id": "5191533"})

    def test_batch_delete_emits_one_item_per_id(self) -> None:
        payload = build_ips_rule_batch_delete_payload(entry_ids=["9708128", 8207295])
        self.assertEqual(len(payload["batch"]), 2)
        self.assertEqual(payload["batch"][0]["resource"], "/api/v1/appsec/ips/rules")
        self.assertEqual(payload["batch"][0]["body"]["id"], ["9708128"])
        self.assertEqual(payload["batch"][1]["body"]["id"], ["8207295"])

    def test_batch_delete_rejects_empty_and_non_numeric_ids(self) -> None:
        with self.assertRaises(RunnerError):
            build_ips_rule_batch_delete_payload(entry_ids=[])
        with self.assertRaises(RunnerError):
            build_ips_rule_batch_delete_payload(entry_ids=["rule-a"])

    def test_query_list_sends_string_pagination_and_scalar_single_filter(self) -> None:
        payload = build_ips_rule_query_payload(page=1, size=10, level="2")
        self.assertEqual(payload["page"], "1")
        self.assertEqual(payload["size"], "10")
        self.assertEqual(payload["level"], "2")

    def test_query_list_keeps_multi_value_filters_as_lists(self) -> None:
        payload = build_ips_rule_query_payload(
            level=["2", "3"], direct=["1", "2"], os="1", classtype=["3", "4"]
        )
        self.assertEqual(payload["level"], ["2", "3"])
        self.assertEqual(payload["direct"], ["1", "2"])
        self.assertEqual(payload["os"], "1")
        self.assertEqual(payload["classtype"], ["3", "4"])

    def test_query_ids_switches_to_detail_body(self) -> None:
        payload = build_ips_rule_query_payload(ids=[1600, "3783"], level=["2"])
        self.assertEqual(payload, {"id": ["1600", "3783"]})

    def test_query_config_source_semantics_and_no_is_custom_filter(self) -> None:
        no_filter = build_ips_rule_query_payload(config_source=0)
        predefined = build_ips_rule_query_payload(config_source=18)
        self.assertEqual(no_filter["config_source"], "0")
        self.assertEqual(predefined["config_source"], "18")
        self.assertNotIn("isCustom", no_filter)
        self.assertNotIn("isCustom", predefined)


class IpsProfilePayloadTests(unittest.TestCase):
    def test_profile_payload_defaults_all_lists(self) -> None:
        payload = build_ips_profile_payload(name="p1")
        self.assertEqual(
            payload["val"],
            {
                "name": "p1",
                "actionWrapper": [],
                "filters": [],
                "whiteList": [],
                "customAddRuleList": [],
                "desc": "",
            },
        )

    def test_profile_payload_keeps_nested_objects(self) -> None:
        payload = build_ips_profile_payload(
            name="p1",
            action_wrapper=[{"priority": 1, "action": 2}],
            filters=[{"classtype": [3], "action": 0, "capture_pkt": True}],
            white_list=[{"ruleId": 5450}],
            custom_add_rule_list=[{"id": 1600, "action": 1}],
            desc="d",
        )
        self.assertEqual(payload["val"]["actionWrapper"][0]["priority"], 1)
        self.assertEqual(payload["val"]["whiteList"], [{"ruleId": 5450}])

    def test_profile_update_payload_carries_id(self) -> None:
        payload = build_ips_profile_update_payload(entry_id=1001, name="p2")
        self.assertEqual(payload["id"], "1001")
        self.assertEqual(payload["val"]["name"], "p2")

    def test_profile_delete_and_batch_payloads(self) -> None:
        self.assertEqual(build_ips_profile_delete_payload(entry_id=1001), {"id": "1001"})
        batch = build_ips_profile_batch_delete_payload(entry_ids=["1000", "1002"])
        self.assertEqual(len(batch["batch"]), 2)
        self.assertTrue(
            all(item["resource"] == "/api/v1/appsec/ips/profiles" for item in batch["batch"])
        )

    def test_profile_name_required(self) -> None:
        with self.assertRaises(RunnerError):
            build_ips_profile_payload(name="")

    def test_profile_query_payload(self) -> None:
        payload = build_ips_profile_query_payload(page=2, size=50, key="web", config_source="0")
        self.assertEqual(
            payload,
            {"key": "web", "page": "2", "size": "50", "config_source": "0"},
        )

    def test_profile_query_config_source_18_and_no_is_custom_filter(self) -> None:
        payload = build_ips_profile_query_payload(config_source=18)
        self.assertEqual(payload["config_source"], "18")
        self.assertNotIn("isCustom", payload)

    def test_white_list_exception_entries_are_preserved_on_create_and_update(self) -> None:
        exceptions = [{"ruleId": 5450}, {"ruleId": 9519651}]
        created = build_ips_profile_payload(name="p1", white_list=exceptions)
        updated = build_ips_profile_update_payload(
            entry_id=1001, name="p1", white_list=exceptions
        )
        self.assertEqual(created["val"]["whiteList"], exceptions)
        self.assertEqual(updated["val"]["whiteList"], exceptions)

    def test_white_list_defaults_to_empty_list(self) -> None:
        payload = build_ips_profile_payload(name="p1")
        self.assertEqual(payload["val"]["whiteList"], [])

    def test_batch_validation_rejects_wrong_resource(self) -> None:
        payload = build_ips_profile_batch_delete_payload(entry_ids=["1000"])
        with self.assertRaises(RunnerError):
            validate_ips_payload(payload, op_id="fw_delete_batch_ips_rule")


class IpsProfileModelingTests(unittest.TestCase):
    def test_capture_pkt_true_and_false_are_preserved(self) -> None:
        payload = build_ips_profile_payload(
            name="p1",
            custom_add_rule_list=[
                {"id": 1600, "action": 1, "capture_pkt": True},
                {"id": 3783, "action": 1, "capture_pkt": False},
                {"id": 5450, "action": 0},
            ],
        )
        rules = payload["val"]["customAddRuleList"]
        self.assertTrue(rules[0]["capture_pkt"])
        self.assertFalse(rules[1]["capture_pkt"])
        self.assertNotIn("capture_pkt", rules[2])

    def test_filters_variants_are_preserved(self) -> None:
        filters = [
            {"protocols": ["file"]},
            {"classtype": [4]},
            {"builtintype": "dmz"},
            {"builtintype": "radom"},
            {},
        ]
        payload = build_ips_profile_payload(name="p1", filters=filters)
        self.assertEqual(payload["val"]["filters"], filters)

    def test_action_wrapper_models_priority_and_action_values(self) -> None:
        wrapper = [
            {"priority": 1, "action": 0},
            {"priority": 2, "action": 1},
            {"priority": 3, "action": 2},
            {"priority": 4, "action": 2},
            {"priority": 5, "action": 1},
        ]
        payload = build_ips_profile_payload(name="p1", action_wrapper=wrapper)
        self.assertEqual(payload["val"]["actionWrapper"], wrapper)

    def test_invalid_action_wrapper_priority_or_action_is_rejected(self) -> None:
        with self.assertRaises(RunnerError):
            build_ips_profile_payload(
                name="p1", action_wrapper=[{"priority": 6, "action": 1}]
            )
        with self.assertRaises(RunnerError):
            build_ips_profile_payload(
                name="p1", action_wrapper=[{"priority": 1, "action": 3}]
            )
        with self.assertRaises(RunnerError):
            build_ips_profile_payload(
                name="p1",
                action_wrapper=[
                    {"priority": 1, "action": 1},
                    {"priority": 1, "action": 2},
                ],
            )

    def test_invalid_capture_pkt_type_is_rejected(self) -> None:
        with self.assertRaises(RunnerError):
            build_ips_profile_payload(
                name="p1",
                custom_add_rule_list=[
                    {"id": 1600, "action": 1, "capture_pkt": "yes"}
                ],
            )

    def test_config_profile_summary_reports_capture_pkt_rule_ids(self) -> None:
        payload = build_ips_profile_payload(
            name="p1",
            action_wrapper=[{"priority": 1, "action": 1}],
            filters=[{"protocols": ["file"]}],
            custom_add_rule_list=[
                {"id": 1600, "action": 1, "capture_pkt": True},
                {"id": 3783, "action": 1, "capture_pkt": False},
            ],
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.ips.request_json",
                return_value=(200, {"vals": [{"Id": 1000, "Name": "p1"}]}, "{}"),
            ):
                result = execute_ips(
                    op_id="fw_config_ips_profile",
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=payload,
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["ips_profile_id"], 1000)
        self.assertEqual(result["requested_filter_count"], 1)
        self.assertEqual(result["capture_pkt_enabled_rule_ids"], [1600])
        self.assertEqual(result["capture_pkt_disabled_rule_ids"], [3783])

    def test_verify_profile_classifies_sources_by_id_and_config_source(self) -> None:
        response = {
            "count": 4,
            "vals": [
                {"id": 1, "name": "所有规则"},
                {"id": 6, "name": "dmz防护配置", "config_source": 18},
                {"id": 1000, "name": "custom-1000"},
                {"id": 1001, "name": "custom-1001", "config_source": 0},
            ],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.ips.request_json", return_value=(200, response, "{}")
            ):
                result = execute_ips(
                    op_id="fw_verify_ips_profile",
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload={"page": "1", "size": "10"},
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["predefined_profile_ids"], [1, 6])
        self.assertEqual(result["custom_profile_ids"], [1000, 1001])
        sources = {item["id"]: item["source"] for item in result["profile_sources"]}
        self.assertEqual(sources[1], "predefined")
        self.assertEqual(sources[6], "predefined")
        self.assertEqual(sources[1000], "custom")
        self.assertEqual(sources[1001], "custom")


class AclPolicyIpsTests(unittest.TestCase):
    def test_default_keeps_empty_sec_obj_data(self) -> None:
        payload = build_acl_policy_payload(name="p1", entry_id=None)
        self.assertEqual(payload["val"]["sec_obj_data"], [])

    def test_ips_convenience_fields_build_ips_entry(self) -> None:
        payload = build_acl_policy_payload(
            name="p1",
            entry_id=None,
            ips_enabled=True,
            ips_profile_id=1003,
            ips_profile_name="所有1",
        )
        self.assertEqual(
            payload["val"]["sec_obj_data"],
            [{"profile_id": 1003, "profile_name": "所有1", "model_name": "ips"}],
        )

    def test_ips_profile_fields_imply_enabled(self) -> None:
        payload = build_acl_policy_payload(
            name="p1",
            entry_id=None,
            ips_profile_id="1003",
            ips_profile_name="所有1",
        )
        self.assertEqual(payload["val"]["sec_obj_data"][0]["model_name"], "ips")

    def test_raw_sec_obj_data_is_preserved(self) -> None:
        raw = [{"profile_id": 7, "profile_name": "p7", "model_name": "ips"}]
        payload = build_acl_policy_payload(name="p1", entry_id=None, sec_obj_data=raw)
        self.assertEqual(payload["val"]["sec_obj_data"], raw)

    def test_raw_and_convenience_conflict(self) -> None:
        with self.assertRaises(RunnerError):
            build_acl_policy_payload(
                name="p1",
                entry_id=None,
                sec_obj_data=[],
                ips_enabled=True,
                ips_profile_id=1003,
                ips_profile_name="p",
            )

    def test_enable_requires_profile_id_and_name(self) -> None:
        with self.assertRaises(RunnerError):
            build_acl_policy_payload(name="p1", entry_id=None, ips_enabled=True)

    def test_no_ips_rejects_profile_reference(self) -> None:
        with self.assertRaises(RunnerError):
            build_acl_policy_payload(
                name="p1",
                entry_id=None,
                ips_enabled=False,
                ips_profile_id=1003,
            )


class IpsCliDryRunTests(_CliHarness):
    def test_rule_config_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["ips", "rule", "config", "--name", "test1", "--desc", SNORT_RULE]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["url"], f"{BASE_URL}/api/v1/appsec/ips/rules")
        self.assertEqual(request["payload"]["val"]["name"], "test1")

    def test_rule_verify_dry_run_sends_json_body(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["ips", "rule", "verify", "--page", "1", "--size", "10", "--level", "2", "--direct", "1"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "GET")
        self.assertEqual(request["payload"]["page"], "1")
        self.assertEqual(request["payload"]["level"], "2")

    def test_rule_verify_selected_ids(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["ips", "rule", "verify", "--id", "1600", "--id", "3783"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        self.assertEqual(payload["data"]["request"]["payload"], {"id": ["1600", "3783"]})

    def test_profile_config_val_json_dry_run(self) -> None:
        val = json.dumps(
            {
                "name": "p1",
                "actionWrapper": [{"priority": 1, "action": 2}],
                "filters": [],
                "whiteList": [],
                "customAddRuleList": [],
                "desc": "d",
            }
        )
        exit_code, payload, _stderr = self._cli(
            ["ips", "profile", "config", "--val-json", val]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        self.assertEqual(payload["data"]["request"]["payload"]["val"]["name"], "p1")

    def test_delete_batch_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["ips", "profile", "delete-batch", "--id", "1000", "--id", "1002"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["url"], f"{BASE_URL}/api/v1/batch")
        self.assertEqual(len(request["payload"]["batch"]), 2)

    def test_acl_policy_ips_flags_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            [
                "acl-policy",
                "config",
                "--name",
                "p1",
                "--ips-profile-id",
                "1003",
                "--ips-profile-name",
                "所有1",
            ]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        sec_obj_data = payload["data"]["request"]["payload"]["val"]["sec_obj_data"]
        self.assertEqual(sec_obj_data[0]["profile_id"], 1003)
        self.assertEqual(sec_obj_data[0]["model_name"], "ips")

    def test_profile_white_list_json_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            [
                "ips",
                "profile",
                "config",
                "--name",
                "p1",
                "--white-list-json",
                '[{"ruleId": 5450}, {"ruleId": 9519651}]',
            ]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        white_list = payload["data"]["request"]["payload"]["val"]["whiteList"]
        self.assertEqual(white_list, [{"ruleId": 5450}, {"ruleId": 9519651}])

    def test_log_capture_dry_run_url(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["ips", "log", "capture", "--page", "1", "--size", "10", "--timetype", "24h"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/monitor/seclog?", url)
        self.assertIn("gid=1", url)
        self.assertIn("timetype=24h", url)

    def test_log_capture_business_filters_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            [
                "ips",
                "log",
                "capture",
                "--rule-name",
                "CVE-2019-13720",
                "--level",
                "2",
                "--action",
                "1",
                "--xff",
                "192.0.2.10",
            ]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        url = payload["data"]["request"]["url"]
        self.assertIn("rule_name=CVE-2019-13720", url)
        self.assertIn("level=2", url)
        self.assertIn("action=1", url)
        self.assertIn("xff=192.0.2.10", url)

    def test_log_evidence_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["ips", "log", "evidence", "--meta-file", "ips_x.meta.json"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        url = payload["data"]["request"]["url"]
        self.assertEqual(
            url, f"{BASE_URL}/api/v1/seclog/evidence?meta_file=ips_x.meta.json"
        )

    def test_log_download_pcap_dry_run_url_is_encoded(self) -> None:
        exit_code, payload, _stderr = self._cli(
            [
                "ips",
                "log",
                "download-pcap",
                "--pcap-filename",
                "ips_x.pcap",
                "--output-path",
                "/tmp/ips_x.pcap",
            ]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        url = payload["data"]["request"]["url"]
        self.assertEqual(
            url, f"{BASE_URL}/api/v1/downloadfile?id=logpcap%2Fips_x.pcap"
        )

    def test_log_cache_set_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["ips", "log", "cache-set", "--id", "1", "--enable", "--time-set", "60"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "PUT")
        self.assertEqual(request["url"], f"{BASE_URL}/api/v1/logsetting/logcacheset")
        self.assertEqual(
            request["payload"], {"id": 1, "val": {"enable": True, "timeSet": 60}}
        )

    def test_log_export_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["ips", "log", "export", "--output-path", "/tmp/ipslog.csv"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/export?", url)
        self.assertIn("id=logexport", url)
        self.assertIn("logtype=ipslog", url)
        self.assertIn("type=csv", url)
        self.assertIn("timetype=24h", url)

    def test_log_clear_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(["ips", "log", "clear"])
        self.assertEqual(exit_code, 0)
        assert payload is not None
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "DELETE")
        self.assertEqual(
            request["url"], f"{BASE_URL}/api/v1/deletelog?logtype=ipslog"
        )

    def test_log_time_set_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["ips", "log", "time-set", "--id", "0", "--time-set", "180"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "PUT")
        self.assertEqual(request["url"], f"{BASE_URL}/api/v1/logsetting/logtimesetting")
        self.assertEqual(request["payload"], {"id": "0", "val": {"timeSet": 180}})

    def test_log_time_verify_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(["ips", "log", "time-verify"])
        self.assertEqual(exit_code, 0)
        assert payload is not None
        self.assertEqual(
            payload["data"]["request"]["url"],
            f"{BASE_URL}/api/v1/logsetting/logtimesetting",
        )

    def test_log_cache_verify_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(["ips", "log", "cache-verify"])
        self.assertEqual(exit_code, 0)
        assert payload is not None
        self.assertEqual(
            payload["data"]["request"]["url"],
            f"{BASE_URL}/api/v1/logsetting/logcacheset",
        )

    def test_log_backup_list_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["ips", "log", "backup-list", "--page", "2", "--size", "20", "--keywords", "ips"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/logsetting/logbackcsv?", url)
        self.assertIn("page=2", url)
        self.assertIn("size=20", url)

    def test_log_download_task_create_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["ips", "log", "download-task-create", "--data-id", "data-1"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        request = payload["data"]["request"]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(request["url"], f"{BASE_URL}/api/v1/downloadfilehandle")
        self.assertEqual(
            request["payload"],
            {
                "val": {
                    "dataId": ["data-1"],
                    "moduletype": "influxTask",
                    "filetype": "csv",
                }
            },
        )

    def test_log_download_task_verify_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["ips", "log", "download-task-verify", "--task-id", "77"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        self.assertEqual(
            payload["data"]["request"]["url"],
            f"{BASE_URL}/api/v1/downloadfilehandle?id=77",
        )

    def test_log_download_file_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            [
                "ips",
                "log",
                "download-file",
                "--file-id",
                "ips_export.csv",
                "--output-path",
                "/tmp/ips_export.csv",
            ]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        self.assertEqual(
            payload["data"]["request"]["url"],
            f"{BASE_URL}/api/v1/downloadfile?id=ips_export.csv",
        )

    def test_license_dev_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(["license", "dev"])
        self.assertEqual(exit_code, 0)
        assert payload is not None
        self.assertEqual(
            payload["data"]["request"]["url"], f"{BASE_URL}/api/v1/licensedev"
        )

    def test_license_verify_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(["license", "verify"])
        self.assertEqual(exit_code, 0)
        assert payload is not None
        self.assertEqual(
            payload["data"]["request"]["url"], f"{BASE_URL}/api/v1/license"
        )


class IpsExecuteTests(unittest.TestCase):
    def test_get_rule_query_sends_json_body(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.ips.request_json",
                return_value=(200, {"vals": [{"id": 1600, "name": "r1"}], "count": 1}, "{}"),
            ) as request:
                result = execute_ips(
                    op_id="fw_verify_ips_rule",
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload={"id": ["1600"]},
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(request.call_args[0][0], "GET")
        self.assertEqual(request.call_args.kwargs["json_payload"], {"id": ["1600"]})
        self.assertEqual(result["rule_ids"], [1600])

    def test_batch_delete_result_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            payload = build_ips_rule_batch_delete_payload(entry_ids=["1", "2"])
            with patch(
                "atomic_ops.runner.ips.request_json",
                return_value=(
                    200,
                    {"BatchResult": [{"msg": "success"}, {"msg": "success"}]},
                    "{}",
                ),
            ):
                result = execute_ips(
                    op_id="fw_delete_batch_ips_rule",
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=payload,
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["batch_result"]["status"], "succeeded")
        self.assertEqual(result["batch_result"]["count"], 2)
        self.assertEqual(result["batch_result"]["success_count"], 2)
        self.assertEqual(result["batch_result"]["failed_count"], 0)


class IpsLogTests(unittest.TestCase):
    def test_only_gid_1_is_registered_for_this_scope(self) -> None:
        self.assertEqual(SECLOG_GIDS, {1: "ips"})

    def test_log_query_defaults_gid_to_1(self) -> None:
        query = build_ips_log_query()
        self.assertEqual(query["gid"], 1)

    def test_log_query_defaults_and_types(self) -> None:
        query = build_ips_log_query(gid=1)
        self.assertEqual(
            query,
            {"gid": 1, "page": 1, "size": 10, "timetype": "24h"},
        )

    def test_log_query_business_filters(self) -> None:
        query = build_ips_log_query(
            rule_name="CVE-2019-13720",
            level=["2", "3"],
            action="1",
            xff="192.0.2.10",
        )
        self.assertEqual(query["rule_name"], "CVE-2019-13720")
        self.assertEqual(query["level"], ["2", "3"])
        self.assertEqual(query["action"], "1")
        self.assertEqual(query["xff"], "192.0.2.10")

    def test_log_query_custom_requires_start_and_end(self) -> None:
        with self.assertRaises(RunnerError):
            build_ips_log_query(gid=1, timetype="custom")
        with self.assertRaises(RunnerError):
            build_ips_log_query(gid=1, timetype="custom", starttime=1000)
        query = build_ips_log_query(
            gid=1, timetype="custom", starttime=1000, endtime=2000
        )
        self.assertEqual(query["starttime"], 1000)
        self.assertEqual(query["endtime"], 2000)

    def test_log_query_non_custom_ignores_timestamps(self) -> None:
        query = build_ips_log_query(gid=1, timetype="24h", starttime=1000, endtime=2000)
        self.assertNotIn("starttime", query)
        self.assertNotIn("endtime", query)

    def test_log_query_rejects_other_gids(self) -> None:
        for unsupported in (2, 903, 909):
            with self.assertRaises(RunnerError):
                build_ips_log_query(gid=unsupported)

    def test_log_execute_exposes_count_and_page_count(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.ips.request_json",
                return_value=(200, {"count": 25, "page": 2, "size": 10, "vals": []}, "{}"),
            ):
                result = execute_ips_log(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    query=build_ips_log_query(gid=1, page=2, size=10),
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["count"], 25)
        self.assertEqual(result["page_count"], 3)
        self.assertEqual(result["page"], 2)

    def test_log_execute_uses_response_size_for_page_count(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.ips.request_json",
                return_value=(200, {"count": 25, "page": 1, "size": 5, "vals": []}, "{}"),
            ):
                result = execute_ips_log(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    query=build_ips_log_query(gid=1, page=1, size=10),
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["size"], 5)
        self.assertEqual(result["page_count"], 5)

    def test_evidence_query_requires_meta_file(self) -> None:
        self.assertEqual(
            build_ips_evidence_query(meta_file="ips_x.meta.json"),
            {"meta_file": "ips_x.meta.json"},
        )
        with self.assertRaises(RunnerError):
            build_ips_evidence_query(meta_file="  ")

    def test_evidence_execute_extracts_meta_and_packet_summary(self) -> None:
        response = {
            "vals": {
                "meta_file": "ips_x.meta.json",
                "meta": {
                    "pcap_filename": "ips_x.pcap",
                    "src_ip": "192.0.2.10",
                    "dst_ip": "192.0.2.20",
                    "rule": {"sid": "1001", "name": "test"},
                },
                "packet_data": "YWJjZA==",
            }
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.ips.request_json", return_value=(200, response, "{}")
            ):
                result = execute_ips_evidence(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    query=build_ips_evidence_query(meta_file="ips_x.meta.json"),
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["meta_file"], "ips_x.meta.json")
        self.assertEqual(result["pcap_filename"], "ips_x.pcap")
        self.assertTrue(result["packet_data_present"])
        self.assertEqual(result["packet_data_size"], len("YWJjZA=="))
        self.assertEqual(result["meta"]["rule"]["sid"], "1001")

    def test_pcap_id_prefixes_logpcap(self) -> None:
        self.assertEqual(
            build_ips_pcap_download_id(pcap_filename="ips_x.pcap"),
            "logpcap/ips_x.pcap",
        )
        self.assertEqual(
            build_ips_pcap_download_id(pcap_filename="logpcap/ips_x.pcap"),
            "logpcap/ips_x.pcap",
        )

    def test_pcap_download_writes_bytes_and_reports_hash(self) -> None:
        content = b"pcap-bytes"
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            output_path = Path(temp_dir) / "ips_x.pcap"
            with patch(
                "atomic_ops.runner.ips.request_bytes", return_value=(200, content)
            ):
                result = execute_ips_pcap_download(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    pcap_filename="ips_x.pcap",
                    output_path=str(output_path),
                    verify_tls=False,
                    timeout=10,
                )
            self.assertEqual(output_path.read_bytes(), content)
        self.assertEqual(result["download"]["file_size"], len(content))
        self.assertEqual(
            result["download"]["sha256"],
            "ee9338e23f71e4aaaccb58f34b0e07c029855ae1416c122bcdb0b7042809c474",
        )


class LicenseTests(unittest.TestCase):
    def test_license_dev_extracts_device_fields(self) -> None:
        response = {
            "vals": {
                "devType": "FW",
                "devSn": "SN-1",
                "devAuthType": "local",
                "userAuthType": "local",
                "cpuNum": 4,
                "memSize": 8192,
                "DeviceTypeName": "TGFW",
            }
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.license.request_json", return_value=(200, response, "{}")
            ):
                result = execute_license(
                    op_id="fw_verify_license_dev",
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["dev_type"], "FW")
        self.assertEqual(result["dev_sn"], "SN-1")
        self.assertEqual(result["cpu_num"], 4)
        self.assertEqual(result["device_type_name"], "TGFW")

    def test_license_extracts_ips_module(self) -> None:
        response = {
            "info": {"license_id": "L-1", "product_name": "TGFW"},
            "module": [
                {"name": "防病毒", "enabled": True},
                {"name": "入侵防御", "enabled": True, "license_left": 10},
            ],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.license.request_json", return_value=(200, response, "{}")
            ):
                result = execute_license(
                    op_id="fw_verify_license",
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["license_info"]["license_id"], "L-1")
        self.assertEqual(result["module_count"], 2)
        self.assertEqual(result["ips_module"]["name"], "入侵防御")
        self.assertTrue(result["ips_module"]["enabled"])


class IpsDeleteIdempotencyTests(unittest.TestCase):
    def test_scoped_not_found_pairs(self) -> None:
        self.assertTrue(
            is_resource_not_found(
                400,
                {"errCode": "eConfigWrite", "errMsg": "删除规则失败(C)"},
                op_id="fw_delete_ips_rule",
            )
        )
        self.assertTrue(
            is_resource_not_found(
                400,
                {"errCode": "eConfigWrite", "errMsg": "读取profile错误"},
                op_id="fw_delete_ips_profile",
            )
        )

    def test_scoped_not_found_is_limited_to_the_registered_op(self) -> None:
        rule_payload = {"errCode": "eConfigWrite", "errMsg": "删除规则失败(C)"}
        self.assertFalse(
            is_resource_not_found(400, rule_payload, op_id="fw_delete_ips_profile")
        )
        self.assertFalse(
            is_resource_not_found(
                400,
                {"errCode": "eConfigWrite", "errMsg": "other failure"},
                op_id="fw_delete_ips_rule",
            )
        )

    def test_delete_rule_duplicate_maps_to_resource_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.ips.request_json",
                return_value=(
                    400,
                    {"errCode": "eConfigWrite", "errMsg": "删除规则失败(C)"},
                    "{}",
                ),
            ):
                with self.assertRaises(RunnerError) as context:
                    execute_ips(
                        op_id="fw_delete_ips_rule",
                        base_url=BASE_URL,
                        session_file=session_file,
                        auth_header="Authorization",
                        payload={"id": "1"},
                        verify_tls=False,
                        timeout=10,
                    )
        details = context.exception.details
        self.assertEqual(details["error_type"], "RESOURCE_NOT_FOUND")
        self.assertTrue(details["idempotent"])
        self.assertEqual(
            details["idempotent_source"], "atoms/fw/fw_delete_ips_rule.yaml#idempotent"
        )

    def test_delete_profile_duplicate_maps_to_resource_not_found(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.ips.request_json",
                return_value=(
                    400,
                    {"errCode": "eConfigWrite", "errMsg": "读取profile错误"},
                    "{}",
                ),
            ):
                with self.assertRaises(RunnerError) as context:
                    execute_ips(
                        op_id="fw_delete_ips_profile",
                        base_url=BASE_URL,
                        session_file=session_file,
                        auth_header="Authorization",
                        payload={"id": "1001"},
                        verify_tls=False,
                        timeout=10,
                    )
        details = context.exception.details
        self.assertEqual(details["error_type"], "RESOURCE_NOT_FOUND")
        self.assertTrue(details["idempotent"])


class LogManagementTests(unittest.TestCase):
    def test_export_query_defaults_and_custom_window(self) -> None:
        query = build_ips_log_export_query()
        self.assertEqual(
            query,
            {
                "id": "logexport",
                "logtype": "ipslog",
                "type": "csv",
                "timetype": "24h",
            },
        )
        custom = build_ips_log_export_query(
            timetype="custom", starttime=1000, endtime=2000
        )
        self.assertEqual(custom["starttime"], 1000)
        self.assertEqual(custom["endtime"], 2000)
        with self.assertRaises(RunnerError):
            build_ips_log_export_query(logtype="avlog")
        with self.assertRaises(RunnerError):
            build_ips_log_export_query(export_type="json")
        with self.assertRaises(RunnerError):
            build_ips_log_export_query(timetype="custom")

    def test_export_execute_writes_csv_bytes(self) -> None:
        content = b"time,src,dst\n1,192.0.2.1,192.0.2.2\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            output_path = Path(temp_dir) / "ipslog.csv"
            with patch(
                "atomic_ops.runner.log_ops.request_bytes", return_value=(200, content)
            ):
                result = execute_ips_log_export(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    query=build_ips_log_export_query(),
                    output_path=str(output_path),
                    verify_tls=False,
                    timeout=10,
                )
            self.assertEqual(output_path.read_bytes(), content)
        self.assertEqual(result["download"]["file_size"], len(content))
        self.assertEqual(
            result["download"]["sha256"],
            "03a7b6d06ef4f66658f2379a36d063e7f95deaba3f65dce61b13f80b5c60173e",
        )

    def test_clear_execute_uses_delete_and_query(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.log_ops.request_json",
                return_value=(200, {"msg": "success"}, "{}"),
            ) as request:
                result = execute_clear_ips_log(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    query=build_clear_ips_log_query(),
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(request.call_args[0][0], "DELETE")
        self.assertTrue(result["cleared"])
        self.assertEqual(result["logtype"], "ipslog")

    def test_time_set_payload_and_execute(self) -> None:
        payload = build_log_time_set_payload()
        self.assertEqual(payload, {"id": "0", "val": {"timeSet": 180}})
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.log_ops.request_json",
                return_value=(200, {"msg": "success"}, "{}"),
            ) as request:
                result = execute_log_time_set(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=payload,
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(request.call_args[0][0], "PUT")
        self.assertEqual(result["requested_time_set"], 180)

    def test_time_verify_extracts_val_time_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.log_ops.request_json",
                return_value=(200, {"id": "0", "val": {"timeSet": 180}}, "{}"),
            ):
                result = execute_log_time_verify(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["time_set"], 180)

    def test_cache_verify_extracts_enable_and_time_set(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.log_ops.request_json",
                return_value=(200, {"id": 1, "val": {"enable": True, "timeSet": 60}}, "{}"),
            ):
                result = execute_log_cache_verify(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    verify_tls=False,
                    timeout=10,
                )
        self.assertTrue(result["enabled"])
        self.assertEqual(result["time_set"], 60)

    def test_backup_list_query_and_extraction(self) -> None:
        query = build_log_backup_list_query(page=2, size=20, keywords="ips")
        self.assertEqual(query, {"page": 2, "size": 20, "keywords": "ips"})
        response = {
            "count": 1,
            "vals": [
                {"name": "ips_20261019.csv", "mtime": "2026-10-19 12:00:00", "logtype": "ipslog"}
            ],
        }
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.log_ops.request_json", return_value=(200, response, "{}")
            ):
                result = execute_log_backup_list(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    query=query,
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["backup_files"][0]["name"], "ips_20261019.csv")
        self.assertEqual(result["backup_files"][0]["logtype"], "ipslog")

    def test_download_task_create_payload_and_extraction(self) -> None:
        payload = build_log_download_task_payload(data_ids=["data-1", "data-2"])
        self.assertEqual(
            payload,
            {
                "val": {
                    "dataId": ["data-1", "data-2"],
                    "moduletype": "influxTask",
                    "filetype": "csv",
                }
            },
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.log_ops.request_json",
                return_value=(200, {"vals": [{"downloadtaskid": 77}]}, "{}"),
            ) as request:
                result = execute_log_download_task(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=payload,
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(request.call_args[0][0], "POST")
        self.assertEqual(result["task_id"], 77)

    def test_download_task_verify_extraction(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            with patch(
                "atomic_ops.runner.log_ops.request_json",
                return_value=(200, {"vals": [{"filename": "ips_export.csv"}]}, "{}"),
            ):
                result = execute_log_download_task_verify(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    task_id="77",
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(result["task_id"], "77")
        self.assertEqual(result["filename"], "ips_export.csv")
        self.assertTrue(result["ready"])

    def test_download_log_file_writes_bytes(self) -> None:
        content = b"time,src,dst\n"
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            output_path = Path(temp_dir) / "ips_export.csv"
            with patch(
                "atomic_ops.runner.log_ops.request_bytes", return_value=(200, content)
            ):
                result = execute_download_log_file(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    file_id="ips_export.csv",
                    output_path=str(output_path),
                    verify_tls=False,
                    timeout=10,
                )
            self.assertEqual(output_path.read_bytes(), content)
        self.assertEqual(result["download"]["file_size"], len(content))


class LogCacheSettingTests(unittest.TestCase):
    def test_payload_matches_captured_shape(self) -> None:
        payload = build_log_cache_payload(id=1, enable=True, time_set=60)
        self.assertEqual(payload, {"id": 1, "val": {"enable": True, "timeSet": 60}})

    def test_payload_validation(self) -> None:
        with self.assertRaises(RunnerError):
            build_log_cache_payload(id=0)
        with self.assertRaises(RunnerError):
            build_log_cache_payload(id=2)
        with self.assertRaises(RunnerError):
            build_log_cache_payload(time_set=-1)
        with self.assertRaises(RunnerError):
            build_log_cache_payload(enable="yes")  # type: ignore[arg-type]

    def test_execute_puts_payload_and_echoes_requested_values(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            session_file = _make_session(temp_dir)
            payload = build_log_cache_payload(id=1, enable=True, time_set=60)
            with patch(
                "atomic_ops.runner.ips.request_json",
                return_value=(200, {"msg": "success"}, "{}"),
            ) as request:
                result = execute_log_cache(
                    base_url=BASE_URL,
                    session_file=session_file,
                    auth_header="Authorization",
                    payload=payload,
                    verify_tls=False,
                    timeout=10,
                )
        self.assertEqual(request.call_args[0][0], "PUT")
        self.assertEqual(request.call_args.kwargs["json_payload"], payload)
        self.assertEqual(result["log_cache_id"], 1)
        self.assertTrue(result["requested_enable"])
        self.assertEqual(result["requested_time_set"], 60)


class SshDetectionTests(unittest.TestCase):
    @staticmethod
    def _shell_result(op_id: str, raw_output: str) -> dict:
        return {
            "op_id": op_id,
            "status": "success",
            "transport": "ssh",
            "raw_output": raw_output,
            "request": {},
            "response": {},
            "diag_snapshot_ref": "",
        }

    def test_process_restart_mapping(self) -> None:
        self.assertEqual(set(PROCESS_RESTART_MAP), {"snort", "vpp"})
        self.assertEqual(PROCESS_RESTART_MAP["snort"]["patterns"], ("snort",))
        self.assertEqual(
            PROCESS_RESTART_MAP["vpp"]["patterns"],
            ("vpp-agent-init", "vpp-agent", "vpp"),
        )

    def test_snort_restart_detects_pid_change_and_evidence(self) -> None:
        raw = "\n".join(
            [
                "===PS_BEFORE===",
                "root 100 1 0 10:00 ? 00:00:01 /usr/bin/snort",
                "===PS_AFTER===",
                "root 200 1 0 10:01 ? 00:00:01 /usr/bin/snort",
                "===COREDUMP===",
                "snort.core.123",
                "other.core",
                "===DIELOG===",
                "-rw-r--r-- 1 root root 10 Oct 20 10:01 /trace/log/snort_die.log",
            ]
        )
        with patch(
            "atomic_ops.runner.ssh._execute_shell_op",
            return_value=self._shell_result("fw_verify_process_restart", raw),
        ):
            result = execute_verify_process_restart(
                base_url=BASE_URL,
                session_file=Path("/tmp/no-session.json"),
                transport="ssh",
                host=None,
                port=None,
                username="root",
                credential_env="FW_SSH_PASSWORD",
                process_type="snort",
                pid_before=None,
                wait_seconds=0,
                timeout=10,
            )
        self.assertEqual(result["pid_before"], [100])
        self.assertEqual(result["pid_after"], [200])
        self.assertTrue(result["pid_changed"])
        self.assertTrue(result["restarted"])
        self.assertEqual(result["core_file"], "snort.core.123")
        self.assertEqual(result["core_files"], ["snort.core.123"])
        self.assertIn("snort_die.log", result["die_log"])
        self.assertIn("pid_changed", result["restart_evidence"])
        self.assertIn("core_file", result["restart_evidence"])
        self.assertIn("die_log", result["restart_evidence"])

    def test_vpp_multi_process_pid_comparison(self) -> None:
        raw = "\n".join(
            [
                "===PS_BEFORE===",
                "root 10 1 0 10:00 ? 00:00:01 vpp-agent-init",
                "root 11 1 0 10:00 ? 00:00:01 vpp-agent",
                "root 12 1 0 10:00 ? 00:00:01 vpp",
                "===PS_AFTER===",
                "root 10 1 0 10:00 ? 00:00:01 vpp-agent-init",
                "root 11 1 0 10:00 ? 00:00:01 vpp-agent",
                "root 12 1 0 10:00 ? 00:00:01 vpp",
                "===COREDUMP===",
                "===DIELOG===",
            ]
        )
        with patch(
            "atomic_ops.runner.ssh._execute_shell_op",
            return_value=self._shell_result("fw_verify_process_restart", raw),
        ):
            result = execute_verify_process_restart(
                base_url=BASE_URL,
                session_file=Path("/tmp/no-session.json"),
                transport="ssh",
                host=None,
                port=None,
                username="root",
                credential_env="FW_SSH_PASSWORD",
                process_type="vpp",
                pid_before=None,
                wait_seconds=0,
                timeout=10,
            )
        self.assertEqual(result["pid_before"], [10, 11, 12])
        self.assertEqual(result["pid_after"], [10, 11, 12])
        self.assertFalse(result["restarted"])
        self.assertIsNone(result["core_file"])
        self.assertIsNone(result["die_log"])

        with patch(
            "atomic_ops.runner.ssh._execute_shell_op",
            return_value=self._shell_result("fw_verify_process_restart", raw),
        ):
            changed = execute_verify_process_restart(
                base_url=BASE_URL,
                session_file=Path("/tmp/no-session.json"),
                transport="ssh",
                host=None,
                port=None,
                username="root",
                credential_env="FW_SSH_PASSWORD",
                process_type="vpp",
                pid_before=[1, 2],
                wait_seconds=0,
                timeout=10,
            )
        self.assertTrue(changed["restarted"])

    def test_unsupported_process_type_is_rejected(self) -> None:
        with self.assertRaises(RunnerError):
            execute_verify_process_restart(
                base_url=BASE_URL,
                session_file=Path("/tmp/no-session.json"),
                transport="ssh",
                host=None,
                port=None,
                username="root",
                credential_env="FW_SSH_PASSWORD",
                process_type="nginx",
                pid_before=None,
                wait_seconds=0,
                timeout=10,
            )

    def test_system_resource_metrics_and_trend(self) -> None:
        raw = "\n".join(
            [
                "===MEM===",
                "              total        used        free      shared  buff/cache   available",
                "Mem:           8000        3000        1000         100        4000        5000",
                "Swap:             0           0           0",
                "===LOAD===",
                "0.50 0.40 0.30 1/100 12345",
                "===CPU===",
                "%Cpu(s):  5.0 us,  3.0 sy,  0.0 ni, 92.0 id,  0.0 wa,  0.0 hi,  0.0 si,  0.0 st",
                "===DISK===",
                "Filesystem     1024-blocks    Used Available Capacity Mounted on",
                "/dev/sda1         10000000 4000000   6000000      40% /",
                "===MEM2===",
                "Mem:           8000        3500         500         100        4000        4500",
                "===DISK2===",
                "Filesystem     1024-blocks    Used Available Capacity Mounted on",
                "/dev/sda1         10000000 4100000   5900000      41% /",
            ]
        )
        with patch(
            "atomic_ops.runner.ssh._execute_shell_op",
            return_value=self._shell_result("fw_verify_system_resource", raw),
        ):
            result = execute_verify_system_resource(
                base_url=BASE_URL,
                session_file=Path("/tmp/no-session.json"),
                transport="ssh",
                host=None,
                port=None,
                username="root",
                credential_env="FW_SSH_PASSWORD",
                sample_interval_seconds=1,
                timeout=10,
            )
        self.assertEqual(result["memory"]["total_mb"], 8000)
        self.assertEqual(result["memory"]["used_mb"], 3000)
        self.assertEqual(result["memory_used_delta_mb"], 500)
        self.assertEqual(result["load"]["load_1m"], 0.5)
        self.assertEqual(result["cpu_usage_percent"], 8.0)
        self.assertEqual(result["disks"][0]["mount"], "/")
        self.assertEqual(result["disk_used_delta_kb"], 100000)

    def test_capture_storage_device_forms(self) -> None:
        with_disk_raw = "\n".join(
            [
                "===DF_USERDATA===",
                "Filesystem 1024-blocks Used Available Capacity Mounted on",
                "/dev/sdb1 2000000 500000 1500000 25% /userdata",
                "===DU_USERDATA===",
                "500000 /userdata",
                "===MOUNTS===",
                "/dev/sdb1 on /userdata type ext4 (rw)",
                "===LS===",
                "drwxr-xr-x 2 root root 4096 Oct 20 10:00 /userdata",
                "===DF_ALL===",
                "Filesystem 1024-blocks Used Available Capacity Mounted on",
                "/dev/sdb1 2000000 500000 1500000 25% /userdata",
            ]
        )
        no_disk_raw = "\n".join(
            [
                "===DF_USERDATA===",
                "Filesystem 1024-blocks Used Available Capacity Mounted on",
                "tmpfs 1000000 100000 900000 10% /userdata",
                "===DU_USERDATA===",
                "50000 /userdata",
                "===MOUNTS===",
                "tmpfs on /userdata type tmpfs (rw)",
                "===LS===",
                "drwxr-xr-x 2 root root 40 Oct 20 10:00 /userdata",
                "===DF_ALL===",
                "Filesystem 1024-blocks Used Available Capacity Mounted on",
                "tmpfs 1000000 100000 900000 10% /userdata",
            ]
        )
        exdisk_raw = "\n".join(
            [
                "===DF_USERDATA===",
                "Filesystem 1024-blocks Used Available Capacity Mounted on",
                "/dev/sdc1 3000000 600000 2400000 20% /userdata",
                "===DU_USERDATA===",
                "600000 /userdata",
                "===MOUNTS===",
                "/dev/sdc1 on /userdata type ext4 (rw)",
                "/dev/sdd1 on /exdisk type ext4 (rw)",
                "===LS===",
                "drwxr-xr-x 2 root root 4096 Oct 20 10:00 /userdata",
                "drwxr-xr-x 2 root root 4096 Oct 20 10:00 /exdisk",
                "===DF_ALL===",
                "Filesystem 1024-blocks Used Available Capacity Mounted on",
                "/dev/sdc1 3000000 600000 2400000 20% /userdata",
            ]
        )
        for raw, expected in (
            (with_disk_raw, "with_disk"),
            (no_disk_raw, "no_disk"),
            (exdisk_raw, "exdisk"),
        ):
            with patch(
                "atomic_ops.runner.ssh._execute_shell_op",
                return_value=self._shell_result("fw_verify_capture_storage", raw),
            ):
                result = execute_verify_capture_storage(
                    base_url=BASE_URL,
                    session_file=Path("/tmp/no-session.json"),
                    transport="ssh",
                    host=None,
                    port=None,
                    username="root",
                    credential_env="FW_SSH_PASSWORD",
                    timeout=10,
                )
            self.assertEqual(result["device_form"], expected)

    def test_capture_system_log_matches_policy_keywords(self) -> None:
        raw = "\n".join(
            [
                "===SOURCE:/var/log/messages===",
                "Oct 20 10:00:00 fw kernel: hello",
                "Oct 20 10:00:01 fw app: 后台加载IPv4控制策略成功(system:0)",
                "Oct 20 10:00:02 fw app: 后台加载IPv6控制策略成功(system:0)",
            ]
        )
        with patch(
            "atomic_ops.runner.ssh._execute_shell_op",
            return_value=self._shell_result("fw_capture_system_log", raw),
        ):
            result = execute_capture_system_log(
                base_url=BASE_URL,
                session_file=Path("/tmp/no-session.json"),
                transport="ssh",
                host=None,
                port=None,
                username="root",
                credential_env="FW_SSH_PASSWORD",
                lines=200,
                log_path=None,
                keywords=None,
                timeout=10,
            )
        self.assertEqual(result["log_source"], "/var/log/messages")
        self.assertTrue(result["ipv4_policy_loaded"])
        self.assertTrue(result["ipv6_policy_loaded"])
        self.assertEqual(len(result["matched_keywords"]), 2)
        self.assertEqual(result["line_count"], 3)

    def test_capture_system_log_rejects_path_outside_allowed_roots(self) -> None:
        with self.assertRaises(RunnerError):
            build_capture_system_log_dry_run(
                base_url=BASE_URL,
                session_file=Path("/tmp/no-session.json"),
                transport="ssh",
                host=None,
                port=None,
                username="root",
                lines=10,
                log_path="/etc/passwd",
                keywords=None,
                timeout=10,
            )


class SshCliDryRunTests(_CliHarness):
    def test_process_restart_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["cli", "verify-process-restart", "--process-type", "snort"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        command = payload["data"]["request"]["command"]
        self.assertIn("===PS_BEFORE===", command)
        self.assertIn("snort", command)

    def test_system_resource_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(["cli", "verify-system-resource"])
        self.assertEqual(exit_code, 0)
        assert payload is not None
        command = payload["data"]["request"]["command"]
        self.assertIn("free -m", command)
        self.assertIn("df -P -k", command)

    def test_capture_storage_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(["cli", "verify-capture-storage"])
        self.assertEqual(exit_code, 0)
        assert payload is not None
        self.assertIn("===DF_USERDATA===", payload["data"]["request"]["command"])

    def test_capture_system_log_dry_run(self) -> None:
        exit_code, payload, _stderr = self._cli(
            ["cli", "capture-system-log", "--lines", "50"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        command = payload["data"]["request"]["command"]
        self.assertIn("===SOURCE:", command)
        self.assertIn("tail -n 50", command)


if __name__ == "__main__":
    unittest.main()
