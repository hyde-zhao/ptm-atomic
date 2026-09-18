"""STORY-REM-02-04「id 列表承载能力（runner 主路径 + CLI 双通道）」专项单测。

覆盖（Feature TEST-PLAN §3 的 UT-BULK 用例，区域 ``#batch-id-list``）：

- UT-BULK-03：runner 单 item 承载 N 个 id（N=2048，不再分块）；
- UT-BULK-04a~h：CLI ``--id`` 三形态（重复 / 逗号 / ``--id-file``）与单值兼容；
- UT-BULK-05：``--payload-json`` 直传零改写；
- UT-BULK-11a~d：``is_ip6`` 对齐策略（逐位对应 / 首值开关 / 长度不可对齐反例 /
  单值自动降级并告警）；
- UT-BULK-12：``carrier=per_id_item`` 与改动前（v1.0）载荷逐键一致；
- UT-BULK-13/14：空 id、空白元素、非法策略取值反例；
- UT-BULK-15：静态扫描——构造 ``body.id`` 列表的代码只存在于 ``runner/batch.py``
  （纳入族）；其余族为 G2 显式登记的「未纳入本轮」集合。

落点说明（LLD §15 G3）：``STORY-REM-03-06`` 的测试落点占 ``tests/test_runner.py``，
本 Story 改落**新建**的 ``tests/test_batch.py``（与 ``runner/batch.py`` 同名对应），
避免同文件跨区域并发写。

全程离线（构造 + dry-run）：不触设备、不读凭据、不联网；2048 条清单在测试内按
序号程序化构造（只读、不含现场敏感值）。
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from atomic_ops.cli import main as cli_main
from atomic_ops.runner.batch import (
    BATCH_ID_CARRIER,
    BATCH_ID_CARRIERS,
    BATCH_IS_IP6_ALIGNMENT,
    BATCH_IS_IP6_ALIGNMENTS,
    build_batch_delete_payload,
)
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.interface import build_interface_batch_delete_payload
from atomic_ops.runner.policy_route import build_policy_route_batch_delete_payload

BASE_URL = "https://192.0.2.1"
POLICY_ROUTE_RESOURCE = "/api/v1/policyroute"
INTERFACE_RESOURCE = "/api/v1/intf"
RUNNER_SRC_DIR = Path(__file__).resolve().parents[1] / "src" / "atomic_ops" / "runner"

# G2（LLD §15）显式登记的「未纳入本轮」族：其批量删除构造器仍为改动前的
# 「N item × 每 item 1 个 id」形态，按同款改造指引后续独立扩族。
UNINCLUDED_FAMILIES = {
    "acl_policy.py",
    "cert.py",
    "customappobj.py",
    "customappobjtag.py",
    "dns_static.py",
    "dns_sys.py",
    "domainpool.py",
    "filetype.py",
    "geoip.py",
    "ha.py",
    "ha_iplink.py",
    "ip6pool_group.py",
    "iplink.py",
    "ippool_group.py",
    "iptun.py",
    "macpool.py",
    "nat.py",
    "object.py",
    "servicepool.py",
    "timeobject.py",
}


def _v1_policy_route_batch_payload(entry_ids: list[str], is_ip6_str: str) -> dict[str, Any]:
    """改动前（v1.0）的 policy-route 批量删除载荷实现，作为 per_id_item 回归基准。"""
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        batch.append(
            {
                "method": "DELETE",
                "resource": POLICY_ROUTE_RESOURCE,
                "body": {"id": [str(entry_id)], "is_ip6": [is_ip6_str]},
            }
        )
    return {"batch": batch}


def _v1_interface_batch_payload(entry_ids: list[str]) -> dict[str, Any]:
    """改动前（v1.0）的 interface 批量删除载荷实现（无 is_ip6 键），作回归基准。"""
    batch: list[dict[str, Any]] = []
    for entry_id in entry_ids:
        batch.append({"method": "DELETE", "resource": INTERFACE_RESOURCE, "body": {"id": [entry_id]}})
    return {"batch": batch}


class _CliHarness(unittest.TestCase):
    """CLI 调用夹具：统一走 ``run --format json`` 的 dry-run 路径。"""

    def _cli(self, argv: list[str]) -> tuple[int, dict[str, Any] | None, str]:
        stdout = io.StringIO()
        stderr = io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            exit_code = cli_main(["run", "--format", "json", "--base-url", BASE_URL, *argv])
        raw = stdout.getvalue().strip() or stderr.getvalue().strip()
        payload = json.loads(raw.splitlines()[-1]) if raw else None
        return exit_code, payload, stderr.getvalue()


class BatchIdCarrierPayloadTests(unittest.TestCase):
    """UT-BULK-03 / 11 / 12 / 13 / 14：runner 侧承载形态与对齐策略。"""

    def test_ut_bulk_03_single_item_carries_2048_ids(self) -> None:
        entry_ids = [str(index) for index in range(1, 2049)]

        payload = build_policy_route_batch_delete_payload(entry_ids=entry_ids, route_type="ipv4")

        self.assertEqual(len(payload["batch"]), 1)
        item = payload["batch"][0]
        self.assertEqual(item["method"], "DELETE")
        self.assertEqual(item["resource"], POLICY_ROUTE_RESOURCE)
        self.assertEqual(item["body"]["id"], entry_ids)
        # 逐位对应的默认对齐下，批次级 route_type 复制成 N 元取值。
        self.assertEqual(item["body"]["is_ip6"], ["false"] * 2048)
        # 单 item 承载后不存在分块标记（框架侧不再按 200 逐元素展开）。
        self.assertNotIn("chunked", item)

    def test_ut_bulk_03_interface_single_item_carries_all_ids_without_is_ip6(self) -> None:
        payload = build_interface_batch_delete_payload(entry_ids=["GE0_1", "GE0_2", "bvi1"])

        self.assertEqual(len(payload["batch"]), 1)
        body = payload["batch"][0]["body"]
        self.assertEqual(body, {"id": ["GE0_1", "GE0_2", "bvi1"]})
        # 接口族非 v4/v6 二元：不生成 is_ip6 键，也不补空列表。
        self.assertNotIn("is_ip6", body)

    def test_ut_bulk_11a_per_item_alignment_is_positional(self) -> None:
        payload = build_batch_delete_payload(
            entry_ids=["1", "2"],
            resource=POLICY_ROUTE_RESOURCE,
            is_ip6_values=["false", "true"],
            alignment="per_item",
        )

        body = payload["batch"][0]["body"]
        self.assertEqual(len(body["is_ip6"]), len(body["id"]))
        self.assertEqual(body["is_ip6"], ["false", "true"])

    def test_ut_bulk_11b_first_value_alignment_yields_single_value(self) -> None:
        payload = build_batch_delete_payload(
            entry_ids=["1", "2", "3"],
            resource=POLICY_ROUTE_RESOURCE,
            is_ip6_values=["true", "true", "true"],
            alignment="first_value",
        )

        body = payload["batch"][0]["body"]
        self.assertEqual(body["is_ip6"], ["true"])

    def test_ut_bulk_11c_mismatched_length_raises(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_batch_delete_payload(
                entry_ids=["1", "2"],
                resource=POLICY_ROUTE_RESOURCE,
                is_ip6_values=["false", "true", "false"],
            )

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")
        self.assertEqual(context.exception.details["ids"], 2)
        self.assertEqual(context.exception.details["is_ip6"], 3)

    def test_ut_bulk_11d_single_value_degrades_to_first_value_with_warning(self) -> None:
        stderr = io.StringIO()

        with contextlib.redirect_stderr(stderr):
            payload = build_batch_delete_payload(
                entry_ids=["1", "2", "3"],
                resource=POLICY_ROUTE_RESOURCE,
                is_ip6_values=["false"],
                alignment="per_item",
            )

        self.assertEqual(payload["batch"][0]["body"]["is_ip6"], ["false"])
        # 降级必须显式告警（不静默）。
        self.assertIn("falling back to first_value alignment", stderr.getvalue())

    def test_ut_bulk_12_per_id_item_matches_v1_policy_route_payload(self) -> None:
        entry_ids = ["1", "2", "3"]

        payload = build_batch_delete_payload(
            entry_ids=entry_ids,
            resource=POLICY_ROUTE_RESOURCE,
            is_ip6_values=["false"] * len(entry_ids),
            carrier="per_id_item",
        )

        self.assertEqual(payload, _v1_policy_route_batch_payload(entry_ids, "false"))

    def test_ut_bulk_12_per_id_item_matches_v1_interface_payload(self) -> None:
        entry_ids = ["bvi109", "GE0_2.106"]

        payload = build_batch_delete_payload(
            entry_ids=entry_ids,
            resource=INTERFACE_RESOURCE,
            carrier="per_id_item",
        )

        self.assertEqual(payload, _v1_interface_batch_payload(entry_ids))

    def test_ut_bulk_13_empty_ids_raise(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_batch_delete_payload(entry_ids=[], resource=POLICY_ROUTE_RESOURCE)

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_ut_bulk_13_blank_element_raises(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_batch_delete_payload(entry_ids=["1", "   "], resource=POLICY_ROUTE_RESOURCE)

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")
        self.assertEqual(context.exception.details["field"], "id")

    def test_ut_bulk_13_non_string_element_raises(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_policy_route_batch_delete_payload(entry_ids=[1], route_type="ipv4")  # type: ignore[list-item]

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_ut_bulk_13_empty_is_ip6_list_raises(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_batch_delete_payload(
                entry_ids=["1"],
                resource=POLICY_ROUTE_RESOURCE,
                is_ip6_values=[],
            )

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")
        self.assertEqual(context.exception.details["field"], "is_ip6")

    def test_ut_bulk_14_invalid_carrier_raises_with_allowed_set(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_batch_delete_payload(
                entry_ids=["1"],
                resource=POLICY_ROUTE_RESOURCE,
                carrier="chunked",
            )

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")
        self.assertEqual(context.exception.details["allowed"], list(BATCH_ID_CARRIERS))

    def test_ut_bulk_14_invalid_alignment_raises_with_allowed_set(self) -> None:
        with self.assertRaises(RunnerError) as context:
            build_batch_delete_payload(
                entry_ids=["1"],
                resource=POLICY_ROUTE_RESOURCE,
                alignment="per_id",
            )

        self.assertEqual(context.exception.error_code, "RUNNER_VALIDATION_FAILED")
        self.assertEqual(context.exception.details["allowed"], list(BATCH_IS_IP6_ALIGNMENTS))

    def test_defaults_freeze_main_carrier_and_alignment(self) -> None:
        # 主形态与对齐策略的默认值为冻结契约（回退/切换 = 改这两个常量）。
        self.assertEqual(BATCH_ID_CARRIER, "single_item")
        self.assertEqual(BATCH_IS_IP6_ALIGNMENT, "per_item")


class BatchIdListCliTests(_CliHarness):
    """UT-BULK-04 / 05：CLI ``--id`` 三形态与 ``--payload-json`` 直传。"""

    def test_ut_bulk_04a_repeated_id_parses_as_list(self) -> None:
        exit_code, payload, _ = self._cli(["policy-route", "delete-batch", "--id", "1", "--id", "2"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["data"]["request"]["payload"]["batch"][0]["body"]["id"], ["1", "2"])

    def test_ut_bulk_04b_comma_separated_id_parses_as_list(self) -> None:
        exit_code, payload, _ = self._cli(["policy-route", "delete-batch", "--id", "1,2,3"])

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["data"]["request"]["payload"]["batch"][0]["body"]["id"], ["1", "2", "3"])

    def test_ut_bulk_04c_id_file_parses_line_order(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            id_file = Path(tmp) / "ids.txt"
            id_file.write_text("# 注释行\nGE0_1\r\n\r\n  GE0_2  \n# 尾部注释\nGE0_3\n", encoding="utf-8")

            exit_code, payload, _ = self._cli(
                ["interface", "delete-batch", "--id-file", str(id_file)]
            )

        self.assertEqual(exit_code, 0)
        body = payload["data"]["request"]["payload"]["batch"][0]["body"]
        self.assertEqual(body, {"id": ["GE0_1", "GE0_2", "GE0_3"]})

    def test_ut_bulk_04d_single_value_is_unchanged(self) -> None:
        for argv, expected in (
            (["policy-route", "delete-batch", "--id", "7"], ["7"]),
            (["interface", "delete-batch", "--id", "bvi109"], ["bvi109"]),
        ):
            with self.subTest(argv=argv):
                exit_code, payload, _ = self._cli(argv)
                self.assertEqual(exit_code, 0)
                body = payload["data"]["request"]["payload"]["batch"][0]["body"]
                self.assertEqual(body["id"], expected)

    def test_ut_bulk_04e_id_file_lines_precede_flag_values(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            id_file = Path(tmp) / "ids.txt"
            id_file.write_text("1\n2\n", encoding="utf-8")

            exit_code, payload, _ = self._cli(
                ["policy-route", "delete-batch", "--id-file", str(id_file), "--id", "3,4"]
            )

        self.assertEqual(exit_code, 0)
        body = payload["data"]["request"]["payload"]["batch"][0]["body"]
        self.assertEqual(body["id"], ["1", "2", "3", "4"])

    def test_ut_bulk_04f_missing_id_raises_structured_error(self) -> None:
        exit_code, payload, _ = self._cli(["policy-route", "delete-batch"])

        self.assertEqual(exit_code, 49)
        self.assertEqual(payload["error_code"], "RUNNER_VALIDATION_FAILED")
        self.assertEqual(payload["details"]["argument"], "--id")

    def test_ut_bulk_04g_blank_comma_element_raises(self) -> None:
        exit_code, payload, _ = self._cli(["policy-route", "delete-batch", "--id", "1,,2"])

        self.assertEqual(exit_code, 49)
        self.assertEqual(payload["error_code"], "RUNNER_VALIDATION_FAILED")
        self.assertEqual(payload["details"]["argument"], "--id")

    def test_ut_bulk_04h_unreadable_id_file_raises_with_path(self) -> None:
        missing = "/nonexistent-dir/ids.txt"

        exit_code, payload, _ = self._cli(["policy-route", "delete-batch", "--id-file", missing])

        self.assertEqual(exit_code, 49)
        self.assertEqual(payload["error_code"], "RUNNER_VALIDATION_FAILED")
        self.assertEqual(payload["details"]["path"], missing)

    def test_ut_bulk_04i_id_file_rejected_for_single_delete(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            id_file = Path(tmp) / "ids.txt"
            id_file.write_text("1\n", encoding="utf-8")

            for argv in (
                ["policy-route", "delete", "--id", "1", "--id-file", str(id_file)],
                ["interface", "delete", "--id", "bvi109", "--id-file", str(id_file)],
            ):
                with self.subTest(argv=argv):
                    exit_code, payload, _ = self._cli(argv)
                    self.assertEqual(exit_code, 49)
                    self.assertEqual(payload["error_code"], "RUNNER_VALIDATION_FAILED")
                    self.assertEqual(payload["details"]["argument"], "--id-file")

    def test_ut_bulk_05_payload_json_passthrough_is_verbatim(self) -> None:
        raw = {
            "batch": [
                {
                    "method": "DELETE",
                    "resource": INTERFACE_RESOURCE,
                    "body": {"id": ["GE0_1", "GE0_2"], "extra": {"nested": [1, None, "x"]}},
                }
            ]
        }

        exit_code, payload, _ = self._cli(
            ["interface", "delete-batch", "--payload-json", json.dumps(raw, ensure_ascii=False)]
        )

        self.assertEqual(exit_code, 0)
        # 直传通道零改写（不补键、不改序、不做字段级构造）。
        self.assertEqual(payload["data"]["request"]["payload"], raw)

    def test_ut_bulk_05_payload_json_wins_over_id_flags(self) -> None:
        raw = {
            "batch": [
                {"method": "DELETE", "resource": INTERFACE_RESOURCE, "body": {"id": ["GE0_9"]}}
            ]
        }

        exit_code, payload, _ = self._cli(
            [
                "interface",
                "delete-batch",
                "--payload-json",
                json.dumps(raw),
                "--id",
                "GE0_1",
            ]
        )

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["data"]["request"]["payload"], raw)

    def test_cli_interface_batch_delete_emits_single_item(self) -> None:
        exit_code, payload, _ = self._cli(
            ["interface", "delete-batch", "--id", "bvi109", "--id", "GE0_2.106"]
        )

        self.assertEqual(exit_code, 0)
        batch = payload["data"]["request"]["payload"]["batch"]
        self.assertEqual(len(batch), 1)
        self.assertEqual(batch[0]["body"], {"id": ["bvi109", "GE0_2.106"]})

    def test_cli_policy_route_batch_delete_emits_single_item_with_is_ip6(self) -> None:
        exit_code, payload, _ = self._cli(
            ["policy-route", "delete-batch", "--id", "1", "--id", "2", "--policy-route-type", "ipv6"]
        )

        self.assertEqual(exit_code, 0)
        batch = payload["data"]["request"]["payload"]["batch"]
        self.assertEqual(len(batch), 1)
        self.assertEqual(batch[0]["body"], {"id": ["1", "2"], "is_ip6": ["true", "true"]})


class BatchIdListStaticScanTests(unittest.TestCase):
    """UT-BULK-15：``body.id`` 列表构造的单点锚点（AST 级静态扫描）。"""

    @staticmethod
    def _constructs_body_id_list(path: Path) -> bool:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Dict):
                continue
            for key, value in zip(node.keys, node.values):
                if isinstance(key, ast.Constant) and key.value == "id" and isinstance(
                    value, (ast.List, ast.ListComp, ast.GeneratorExp)
                ):
                    return True
        return False

    def test_ut_bulk_15_included_families_have_no_duplicate_construction(self) -> None:
        for name in ("policy_route.py", "interface.py"):
            with self.subTest(module=name):
                self.assertFalse(
                    self._constructs_body_id_list(RUNNER_SRC_DIR / name),
                    f"{name} 仍重复实现 body.id 列表构造（应委托 runner/batch.py）",
                )

    def test_ut_bulk_15_batch_helper_is_the_single_included_site(self) -> None:
        hits = {
            path.name
            for path in sorted(RUNNER_SRC_DIR.glob("*.py"))
            if self._constructs_body_id_list(path)
        }

        self.assertIn("batch.py", hits)
        self.assertEqual(hits - {"batch.py"}, set(UNINCLUDED_FAMILIES))
        self.assertEqual(hits & {"policy_route.py", "interface.py"}, set())


if __name__ == "__main__":
    unittest.main()
