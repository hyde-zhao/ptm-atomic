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
from atomic_ops.runner.session import write_session_file

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
            ["ips", "log", "capture", "--gid", "1", "--page", "1", "--size", "10", "--timetype", "24h"]
        )
        self.assertEqual(exit_code, 0)
        assert payload is not None
        url = payload["data"]["request"]["url"]
        self.assertIn("/api/v1/monitor/seclog?", url)
        self.assertIn("gid=1", url)
        self.assertIn("timetype=24h", url)

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
    def test_gid_mapping_contains_documented_modules(self) -> None:
        self.assertEqual(SECLOG_GIDS[1], "ips")
        self.assertEqual(SECLOG_GIDS[903], "antivirus")
        self.assertEqual(SECLOG_GIDS[909], "weak_credential")

    def test_log_query_defaults_and_types(self) -> None:
        query = build_ips_log_query(gid=1)
        self.assertEqual(
            query,
            {"gid": 1, "page": 1, "size": 10, "timetype": "24h"},
        )

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

    def test_log_query_rejects_unknown_gid(self) -> None:
        with self.assertRaises(RunnerError):
            build_ips_log_query(gid=2)

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


class LogCacheSettingTests(unittest.TestCase):
    def test_payload_matches_captured_shape(self) -> None:
        payload = build_log_cache_payload(id=1, enable=True, time_set=60)
        self.assertEqual(payload, {"id": 1, "val": {"enable": True, "timeSet": 60}})

    def test_payload_validation(self) -> None:
        with self.assertRaises(RunnerError):
            build_log_cache_payload(id=0)
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


if __name__ == "__main__":
    unittest.main()
