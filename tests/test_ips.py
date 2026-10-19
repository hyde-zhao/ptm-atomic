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
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.ips import (
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
    execute_ips,
    validate_ips_payload,
)
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

    def test_query_config_source_is_string(self) -> None:
        payload = build_ips_rule_query_payload(config_source=0)
        self.assertEqual(payload["config_source"], "0")


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


if __name__ == "__main__":
    unittest.main()
