"""tg_start_capture / tg_stop_capture 载荷构造与校验单测（2026-09-12）。

背景：抓包能力此前只有 trex-api 服务端（`POST /api/v1/ops/tg_start_capture` /
`tg_stop_capture`），ptm-atomic `tg trex` 无对应 action、op_mapper 也无映射 ——
ARP 类用例（M6 免费ARP、DMAC 改写断言等）因此一条都写不了。

本测试固化 ptm-atomic 侧的载荷契约：
  - start/stop 共用定位参数（user_id/ports/rxport/txport/capture_port）
  - stop 的 check_* 传哪个带哪个（None 不进 payload = 服务端不参与判定）
  - 本地校验拦明显非法组合（空 ports / rxport 不在 ports / capture_port=tx 缺 txport / 非法 check 值）
  - check_arp_opcode 是 ARP 断言入口（1=request / 2=reply）
"""

from __future__ import annotations

import unittest

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.trex import (
    ERROR_TYPE_MAP,
    build_trex_payload,
    validate_trex_payload,
)


class StartCapturePayloadTests(unittest.TestCase):
    def test_minimal_payload(self):
        payload = build_trex_payload(
            "tg_start_capture",
            {"user_id": "default", "ports": ["2_3", "2_4"], "rxport": "2_4"},
        )
        self.assertEqual(payload["ports"], ["2_3", "2_4"])
        self.assertEqual(payload["rxport"], "2_4")
        # 未指定 capture_port / txport 时不进 payload（服务端按 rx 默认）
        self.assertNotIn("capture_port", payload)
        self.assertNotIn("txport", payload)

    def test_capture_tx_requires_txport(self):
        with self.assertRaises(RunnerError) as ctx:
            build_trex_payload(
                "tg_start_capture",
                {"ports": ["2_3", "2_4"], "rxport": "2_4", "capture_port": "tx"},
            )
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_capture_tx_payload(self):
        payload = build_trex_payload(
            "tg_start_capture",
            {"ports": ["2_3", "2_4"], "rxport": "2_4", "txport": "2_3", "capture_port": "tx"},
        )
        self.assertEqual(payload["capture_port"], "tx")
        self.assertEqual(payload["txport"], "2_3")

    def test_empty_ports_rejected(self):
        with self.assertRaises(RunnerError) as ctx:
            build_trex_payload("tg_start_capture", {"ports": [], "rxport": "2_4"})
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_rxport_must_be_in_ports(self):
        with self.assertRaises(RunnerError) as ctx:
            build_trex_payload(
                "tg_start_capture", {"ports": ["2_3"], "rxport": "2_4"}
            )
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")


class StopCapturePayloadTests(unittest.TestCase):
    def _build(self, **extra):
        params = {"user_id": "default", "ports": ["2_3", "2_4"], "rxport": "2_4"}
        params.update(extra)
        return build_trex_payload("tg_stop_capture", params)

    def test_observation_only_omits_checks(self):
        """不传任何 check_* = 纯观测，payload 里不得出现 check 字段。"""
        payload = self._build()
        self.assertFalse([k for k in payload if k.startswith("check_")])

    def test_checks_only_when_provided(self):
        """只带传了的 check 项（None 表示不验，不进 payload）。"""
        payload = self._build(check_arp_opcode=1, check_min_packets=3)
        self.assertEqual(payload["check_arp_opcode"], 1)
        self.assertEqual(payload["check_min_packets"], 3)
        self.assertNotIn("check_vlan", payload)
        self.assertNotIn("check_l4_protocol", payload)
        self.assertNotIn("check_fragment", payload)

    def test_check_fragment_false_is_kept(self):
        """check_fragment=False 是有效断言（必须无分片），不能被当成"未传"丢掉。"""
        payload = self._build(check_fragment=False)
        self.assertIn("check_fragment", payload)
        self.assertIs(payload["check_fragment"], False)

    def test_invalid_check_arp_opcode_rejected(self):
        with self.assertRaises(RunnerError) as ctx:
            self._build(check_arp_opcode=3)
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_invalid_check_l4_protocol_rejected(self):
        with self.assertRaises(RunnerError) as ctx:
            self._build(check_l4_protocol="icmp")
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_invalid_check_ip_version_rejected(self):
        with self.assertRaises(RunnerError) as ctx:
            self._build(check_ip_version=5)
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")

    def test_vlan_and_no_vlan_mutually_exclusive(self):
        with self.assertRaises(RunnerError) as ctx:
            self._build(check_vlan=2, check_no_vlan=True)
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")


class CaptureExitSemanticsTests(unittest.TestCase):
    def test_state_mismatch_maps_to_business_failure(self):
        """check 不通过时服务端返回 STATE_MISMATCH -> CLI 映射为业务失败。

        这是 ARP 断言能驱动用例 PASS/FAIL 的关键：trex-api 的 check 结果以
        error_type=STATE_MISMATCH 回来（HTTP 仍 200），CLI 层必须把它翻成
        非成功错误码，case_runner 才会判 FAIL/expected_failure。
        """
        code, retryable = ERROR_TYPE_MAP["STATE_MISMATCH"]
        self.assertEqual(code, "RUNNER_VALIDATION_FAILED")
        self.assertFalse(retryable)

    def test_validate_direct_call_accepts_valid_payload(self):
        payload = {"ports": ["2_4"], "rxport": "2_4", "check_arp_opcode": 2}
        self.assertEqual(validate_trex_payload("tg_stop_capture", payload), payload)


class CaptureCheckEchoGuardTests(unittest.TestCase):
    """防「静默空过」：请求了 check_* 但服务端没回显对应项 -> 报部署不匹配。

    真机实测（2026-09-12）：服务端 pydantic 静默忽略未知字段，把 check_arp_opcode 发给
    尚未部署该断言的旧版 trex-api 时会被悄悄丢弃 -> checks=[] -> passed=true -> 用例假绿。
    """

    def setUp(self):
        from atomic_ops.runner.trex import _verify_capture_checks_echoed

        self.guard = _verify_capture_checks_echoed

    def test_accepts_when_all_requested_checks_echoed(self):
        self.guard(
            "tg_stop_capture",
            {"check_arp_opcode": 1, "check_min_packets": 2},
            {"checks": [{"name": "arp_opcode"}, {"name": "min_packets"}]},
        )

    def test_raises_when_check_not_echoed(self):
        with self.assertRaises(RunnerError) as ctx:
            self.guard(
                "tg_stop_capture",
                {"check_arp_opcode": 1},
                {"checks": [], "passed": True, "mismatches": []},
            )
        self.assertEqual(ctx.exception.error_code, "RUNNER_RESPONSE_INVALID")
        self.assertEqual(ctx.exception.details["missing_checks"], ["arp_opcode"])

    def test_raises_when_only_some_echoed(self):
        with self.assertRaises(RunnerError) as ctx:
            self.guard(
                "tg_stop_capture",
                {"check_arp_opcode": 1, "check_min_packets": 2},
                {"checks": [{"name": "min_packets"}]},
            )
        self.assertEqual(ctx.exception.details["missing_checks"], ["arp_opcode"])

    def test_observation_only_skips_guard(self):
        """无 check_* = 纯观测，服务端 checks 为空是正常的，不得报错。"""
        self.guard("tg_stop_capture", {"ports": ["2_4"], "rxport": "2_4"}, {"checks": [], "packet_count": 0})

    def test_other_ops_skip_guard(self):
        self.guard("tg_verify_traffic_loss", {"max_loss": 0}, {})


if __name__ == "__main__":
    unittest.main()
