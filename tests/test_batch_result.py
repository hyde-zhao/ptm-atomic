"""STORY-REM-02-03「delete-batch 返回结构对齐 config-batch」专项单测。

覆盖（Feature TEST-PLAN §3 的 UT-BULK-06，区域 ``#batch-result``）：

- UT-BULK-06①：设备无逐条结果 -> ``per_item_result is False`` 且计数字段为 ``None``
  （不可得），**不是** ``0``；
- UT-BULK-06②：**反例** —— ``failed == []`` 本身不构成「无失败」结论；只有
  ``per_item_result is True`` 且 ``failed_count == 0`` 才可判「无失败」；
- UT-BULK-06③：逐条结果可得 -> ``per_item_result is True`` + ``failed[]`` 形状正确
  （``index`` / ``status`` / ``error_code`` / ``message``，对齐 ``config-batch.failed[]``）；
- UT-BULK-06④：回归 —— 五键**追加**式扩展：既有键不改名/不移动/不删除，输入响应
  对象零改动（摘要只读）。

契约依据：``CT-REM-ATOM-RESULT`` v1.0（`process/docs/features/feat-rem-bulk/DESIGN.md`
§3.2）+ Story 卡片技术说明。**区域边界**：``#batch-result``（本文件）与
``#batch-id-list``（``tests/test_batch.py``，STORY-REM-02-04）互不重叠。

落点说明：本 Story 的 ``primary`` 写面为 ``runner/batch.py#batch-result``；测试落点
按 Story 卡片「测试入口」段的第二分支取**新建** ``tests/test_batch_result.py``
（与 ``runner/batch.py`` 的同名区域对应；``tests/test_batch.py`` 是 STORY-REM-02-04
的 test_landing，不跨 Story 混写）。

全程离线：纯内存构造 + 断言，不触设备、不读凭据、不联网。
"""

from __future__ import annotations

import unittest

from atomic_ops.runner.batch import (
    BATCH_ITEM_FAILURE_MARKERS,
    BATCH_ITEM_SUCCESS_MARKERS,
    BATCH_RESULT_KEYS,
    summarize_batch_result,
)
from atomic_ops.runner.errors import RunnerError

# 契约五键（``CT-REM-ATOM-RESULT`` v1.0）；既有键一律不得出现在本摘要内。
CONTRACT_KEYS = {"count", "success_count", "failed_count", "failed", "per_item_result"}

# 失败条目形状（对齐 config-batch.failed[]）。
FAILED_ENTRY_KEYS = {"index", "status", "error_code", "message"}


def _consumer_may_conclude_no_failure(summary: dict) -> bool:
    """消费侧判定（**测试内契约镜像**，非实现产物）。

    契约强制（DESIGN §3.2 三情形表）：``per_item_result is False`` 时**不得**解读为
    「无失败」，须触发回查。真实采纳方是框架侧 STORY-REM-02-02（``#bulk-verdict``），
    不在本 Story 写面内；此处以同形判定固化契约语义（UT-BULK-06② 的反例锚点）。
    """
    return summary["per_item_result"] is True and summary["failed_count"] == 0


def _boundary_summary(response, requested_count: int) -> dict:
    """取一份「能力边界」摘要并做其形状自检（供反例与回归共用）。"""
    summary = summarize_batch_result(response, requested_count=requested_count)
    assert summary["per_item_result"] is False
    return summary


class BatchResultBoundaryTests(unittest.TestCase):
    """UT-BULK-06① / ⑥：设备不返回逐条结果时的能力边界声明。"""

    def test_ut_bulk_06a_no_per_item_result_declares_boundary_with_null_counts(self):
        """① 无逐条结果键 -> ``per_item_result: False`` + 计数 ``None``（不可得 != 0）。"""
        for response in (
            {"msg": "success"},  # 设备只回一句 success，无逐条结果
            {},  # 空响应体
            {"status_code": 200, "vals": []},  # 其它形状
        ):
            with self.subTest(response=response):
                summary = summarize_batch_result(response, requested_count=3)
                self.assertFalse(summary["per_item_result"])
                self.assertIsNone(summary["success_count"])  # 不可得 != 0
                self.assertIsNone(summary["failed_count"])
                self.assertEqual(summary["failed"], [])
                self.assertEqual(summary["count"], 3)  # count 恒可得（来自请求）
                self.assertEqual(set(summary), CONTRACT_KEYS)

    def test_ut_bulk_06a2_non_dict_response_degrades_conservatively(self):
        """① 响应非 dict（含 None / 列表 / 标量）-> 降级，**不抛异常、不臆造**。"""
        for response in (None, [], "success", 200, b"{}"):
            with self.subTest(response=response):
                summary = summarize_batch_result(response, requested_count=2)
                self.assertFalse(summary["per_item_result"])
                self.assertIsNone(summary["success_count"])
                self.assertIsNone(summary["failed_count"])
                self.assertEqual(summary["failed"], [])

    def test_ut_bulk_06a3_result_count_mismatch_is_capability_boundary(self):
        """① 条目数与请求条目数**无法一一对应** -> 边界（不放大成逐条结论）。

        主情形 = id 列表承载（``single_item``：1 个 batch item 承载 N 个 id）时，设备
        按 batch item 返回结果（1 条），与 N 个请求条目对不上 -> 必须 ``False``。
        """
        responses = (
            {"BatchResult": [{"msg": "success"}]},  # 1 条结果 vs 2048 个 id
            {"BatchResult": [{"msg": "success"}, {"msg": "success"}]},  # 2 vs 3
            {"BatchResult": []},  # 0 vs 1
        )
        for response, requested_count in zip(responses, (2048, 3, 1), strict=True):
            with self.subTest(response=response):
                summary = _boundary_summary(response, requested_count)
                self.assertIsNone(summary["success_count"])
                self.assertIsNone(summary["failed_count"])
                self.assertEqual(summary["failed"], [])
                self.assertEqual(summary["count"], requested_count)

    def test_ut_bulk_06a4_batch_result_key_must_be_a_list(self):
        """① ``BatchResult`` 存在但非列表 -> 不识别（不猜测其形状）。"""
        for value in ({"msg": "success"}, "success", None, 3):
            with self.subTest(value=value):
                summary = summarize_batch_result({"BatchResult": value}, requested_count=1)
                self.assertFalse(summary["per_item_result"])
                self.assertIsNone(summary["failed_count"])

    def test_ut_bulk_06a5_unclassifiable_entries_degrade_whole_summary(self):
        """① 任一条目不可判定 -> 整批降级（不产出半可信计数）。"""
        responses = (
            {"BatchResult": [{"val": 3}]},  # 无 status / msg 标记
            {"BatchResult": [{"msg": "success"}, 3]},  # 非 dict 元素
            {"BatchResult": [{"code": 0}]},
        )
        for response in responses:
            with self.subTest(response=response):
                summary = _boundary_summary(response, requested_count=len(response["BatchResult"]))
                self.assertIsNone(summary["success_count"])
                self.assertEqual(summary["failed"], [])

    def test_ut_bulk_06a6_is_ip6_field_never_leaks_into_summary(self):
        """① 设备额外字段（如 is_ip6 / errCode）不进入摘要（只有契约五键）。"""
        summary = summarize_batch_result(
            {"BatchResult": [{"msg": "success"}], "is_ip6": ["false"], "errCode": "eX"},
            requested_count=1,
        )
        self.assertEqual(set(summary), CONTRACT_KEYS)
        self.assertNotIn("is_ip6", summary)
        self.assertNotIn("errCode", summary)


class BatchResultPerItemTests(unittest.TestCase):
    """UT-BULK-06③：逐条结果可得时的计数与失败清单（形状对齐 config-batch）。"""

    def test_ut_bulk_06c_all_success(self):
        """③ 全部成功 -> 计数正确、``failed`` 为空、``per_item_result: True``。"""
        response = {"BatchResult": [{"msg": "success"}, {"msg": "success"}]}
        summary = summarize_batch_result(response, requested_count=2)
        self.assertTrue(summary["per_item_result"])
        self.assertEqual(summary["count"], 2)
        self.assertEqual(summary["success_count"], 2)
        self.assertEqual(summary["failed_count"], 0)
        self.assertEqual(summary["failed"], [])
        self.assertEqual(
            summary["count"], summary["success_count"] + summary["failed_count"]
        )  # 逐条对齐时计数闭合

    def test_ut_bulk_06c2_partial_failure_lists_failed_entries(self):
        """③ 部分失败 -> ``failed[]`` 可枚举（index / status / error_code / message）。"""
        response = {
            "BatchResult": [
                {"msg": "success"},
                {"msg": "delete failed", "errCode": "eNotFound"},
                {"msg": "success"},
                {"status": "failed"},
            ]
        }
        summary = summarize_batch_result(response, requested_count=4)
        self.assertTrue(summary["per_item_result"])
        self.assertEqual(summary["success_count"], 2)
        self.assertEqual(summary["failed_count"], 2)
        self.assertEqual(
            summary["failed"],
            [
                {"index": 2, "status": "failed", "error_code": "eNotFound", "message": "delete failed"},
                {"index": 4, "status": "failed", "error_code": None, "message": None},
            ],
        )
        for entry in summary["failed"]:
            self.assertEqual(set(entry), FAILED_ENTRY_KEYS)
            self.assertEqual(entry["status"], "failed")
        self.assertEqual(summary["count"], summary["success_count"] + summary["failed_count"])

    def test_ut_bulk_06c3_success_markers_are_normalized_but_message_is_verbatim(self):
        """③ 标记比对大小写/空白不敏感；设备消息**原文**保留（不改写证据）。"""
        response = {"BatchResult": [{"msg": " SUCCESS "}, {"status": "OK"}]}
        summary = summarize_batch_result(response, requested_count=2)
        self.assertTrue(summary["per_item_result"])
        self.assertEqual(summary["success_count"], 2)
        self.assertEqual(summary["failed"], [])

    def test_ut_bulk_06c4_failure_markers_and_message_sources(self):
        """③ 失败识别：``status`` 命中失败标记，或带非成功消息（errMsg 亦可）。"""
        response = {
            "BatchResult": [
                {"status": "Error"},
                {"errMsg": "entry not found"},
                {"status": "failure", "error_code": "eDuplicate", "message": "dup"},
            ]
        }
        summary = summarize_batch_result(response, requested_count=3)
        self.assertTrue(summary["per_item_result"])
        self.assertEqual(summary["failed_count"], 3)
        self.assertEqual(summary["success_count"], 0)
        self.assertEqual(summary["failed"][0]["error_code"], None)
        self.assertEqual(summary["failed"][0]["message"], None)
        self.assertEqual(summary["failed"][1]["message"], "entry not found")
        self.assertEqual(summary["failed"][2]["error_code"], "eDuplicate")
        self.assertEqual(summary["failed"][2]["message"], "dup")

    def test_ut_bulk_06c5_single_entry_request_can_be_per_item(self):
        """③ 单条目请求（N=1）+ 1 条结果 -> 逐条可采信（边界条件不是恒 False）。"""
        summary = summarize_batch_result(
            {"BatchResult": [{"msg": "success"}]}, requested_count=1
        )
        self.assertTrue(summary["per_item_result"])
        self.assertEqual(summary["success_count"], 1)
        self.assertEqual(summary["failed_count"], 0)


class BatchResultConsumerContractTests(unittest.TestCase):
    """UT-BULK-06②：反例 —— 边界摘要**不得**被读成「无失败」。"""

    def test_ut_bulk_06b_empty_failed_list_is_not_a_no_failure_claim(self):
        """② 能力边界下 ``failed == []`` 不构成「无失败」结论（须看 per_item_result）。"""
        summary = _boundary_summary({"BatchResult": [{"msg": "success"}]}, requested_count=2048)
        self.assertEqual(summary["failed"], [])  # 空列表是「不可得」的表达，不是「零失败」
        self.assertIsNone(summary["failed_count"])  # None != 0：没有「零失败」的主张
        self.assertIsNone(summary["success_count"])
        # 反例断言：消费侧**不得**由该摘要产出「无失败」结论。
        self.assertFalse(_consumer_may_conclude_no_failure(summary))

    def test_ut_bulk_06b2_direct_comparison_of_the_two_readings(self):
        """② 对照：同一 ``failed == []``，``per_item_result: True`` 时可判「无失败」。"""
        boundary = _boundary_summary({"msg": "success"}, requested_count=2)
        conclusive = summarize_batch_result(
            {"BatchResult": [{"msg": "success"}, {"msg": "success"}]}, requested_count=2
        )
        self.assertEqual(boundary["failed"], conclusive["failed"])  # 两者 failed 都是 []
        self.assertFalse(_consumer_may_conclude_no_failure(boundary))  # 边界：不可判
        self.assertTrue(_consumer_may_conclude_no_failure(conclusive))  # 逐条可得：可判

    def test_ut_bulk_06b3_boundary_flag_is_the_only_trigger(self):
        """② 只有 ``per_item_result is True`` 才允许采信计数（其余解读一律禁止）。"""
        responses = (
            None,
            {"msg": "success"},
            {"BatchResult": [{"msg": "success"}]},  # 1 vs 3：对不上
            {"BatchResult": [{"val": 3}, {"val": 3}, {"val": 3}]},  # 不可判定
        )
        for response in responses:
            with self.subTest(response=response):
                summary = summarize_batch_result(response, requested_count=3)
                self.assertFalse(_consumer_may_conclude_no_failure(summary))


class BatchResultAdditiveRegressionTests(unittest.TestCase):
    """UT-BULK-06④：追加式扩展 —— 既有键与输入对象零影响。"""

    def test_ut_bulk_06d_summary_is_appended_without_touching_existing_keys(self):
        """④ ``**summary`` 并入既有结果 dict：既有键逐键不变（不改名/不移动/不删除）。"""
        response = {"BatchResult": [{"msg": "success"}]}
        existing = {
            "op_id": "fw_delete_batch_interface",
            "status": "success",
            "status_code": 200,
            "request": {"method": "POST", "path": "/api/v1/batch"},
            "response": response,
        }
        summary = summarize_batch_result(response, requested_count=1)
        merged = {**existing, **summary}
        for key, value in existing.items():
            self.assertEqual(merged[key], value)  # 既有键语义不变
        self.assertEqual(set(merged) - set(existing), CONTRACT_KEYS)  # 只新增五键

    def test_ut_bulk_06d2_response_object_is_not_mutated(self):
        """④ 摘要只读：输入响应对象逐键零改动（含逐条结果列表本身）。"""
        response = {"BatchResult": [{"msg": "success"}, {"msg": "delete failed"}]}
        snapshot = {"BatchResult": [dict(item) for item in response["BatchResult"]]}
        summarize_batch_result(response, requested_count=2)
        self.assertEqual(response, snapshot)
        self.assertEqual(set(response), {"BatchResult"})

    def test_ut_bulk_06d3_contract_keys_are_exactly_five_everywhere(self):
        """④ 五种路径（边界 / 逐条 / 非 dict / 长度不符 / 不可判定）恒输出同五键。"""
        cases = (
            ({"msg": "success"}, 1),
            ({"BatchResult": [{"msg": "success"}]}, 1),
            (None, 1),
            ({"BatchResult": [{"msg": "success"}]}, 9),
            ({"BatchResult": [{"val": 1}]}, 1),
        )
        for response, requested_count in cases:
            with self.subTest(response=response, requested_count=requested_count):
                summary = summarize_batch_result(response, requested_count=requested_count)
                self.assertEqual(set(summary), CONTRACT_KEYS)
                self.assertIsInstance(summary["failed"], list)
                self.assertEqual(summary["count"], requested_count)


class BatchResultValidationTests(unittest.TestCase):
    """契约常量与调用侧校验（fail-loud，不静默）。"""

    def test_requested_count_must_be_a_positive_int(self):
        """``requested_count`` 非法 -> ``RUNNER_VALIDATION_FAILED``（exit 49，不静默）。"""
        for bad in (0, -1, "3", 3.0, True, None):
            with self.subTest(bad=bad):
                with self.assertRaises(RunnerError) as ctx:
                    summarize_batch_result({"msg": "success"}, requested_count=bad)
                self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")
                self.assertEqual(ctx.exception.details.get("field"), "count")

    def test_contract_constants_are_registered_and_conservative(self):
        """识别键与标记集合以常量登记；成功标记不含「非失败即成功」式放宽。"""
        self.assertEqual(BATCH_RESULT_KEYS, ("BatchResult",))
        self.assertIn("success", BATCH_ITEM_SUCCESS_MARKERS)
        self.assertIn("failed", BATCH_ITEM_FAILURE_MARKERS)
        self.assertNotIn("unknown", BATCH_ITEM_SUCCESS_MARKERS)
        self.assertNotIn("", BATCH_ITEM_SUCCESS_MARKERS)


if __name__ == "__main__":
    unittest.main()
