"""tg 分口观测契约（2026-09-22）：多流 + 多接收口 + 逐口比例。

固化两端契约（全部本地，不发真实 HTTP、不碰设备）：

  服务端 trex-api（ptm-team/scripts/trex-api）：
    - tg_apply_traffic_template.stream_count：l4_sport 为**起始**端口，
      展开成 N 条源端口连续的五元组；count 仍是**总包数**
    - tg_start_traffic_stream / tg_verify_traffic_loss.rxport：单值或列表
    - tg_verify_traffic_loss.expect_ports/tolerance：逐口比例判定

  客户端（本仓）：
    - CLI：--stream-count / --rxport 逗号串 / --expect-ports JSON 串 / --tolerance
    - 本地预校验与 trex-api schema 同口径，并额外拦住两种「给了却不生效」形态
      （ICMP 传 stream_count；stream_count>1 却缺 l4_sport -> 多流静默退化）

  跨仓契约（op_mapper 侧渲染，见 ptm-team tests/test_tg_op_mapping.py）：
    rxport list -> 逗号串（_parse_rxport 切分）；
    expect_ports 结构化列表 -> JSON 串（_parse_expect_ports json.loads）。
    两边任一改渲染形态都会让本文件的往返用例失败。
"""

from __future__ import annotations

import argparse
import json
import unittest

from atomic_ops.commands.run_trex import (
    _params_from_args,
    _parse_expect_ports,
    _parse_rxport,
)
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.trex import build_trex_payload, validate_trex_payload

PORTS = ["2_3", "2_4", "2_5"]
TX = "2_3"
RX1 = "2_4"
RX2 = "2_5"


def _apply_params(**overrides):
    """apply 的合法参数基线；stream_count 相关用例只覆盖自己关心的字段。"""
    base = {
        "user_id": "default",
        "template": "udp-demo",
        "tx_port": TX,
        "rx_port": RX1,
        "ip_version": "ipv4",
        "l4_protocol": "udp",
        "l4_sport": 1025,
        "l4_dport": 5678,
        "traffic_mode": "count",
        "rate": "100pps",
        "count": 500,
    }
    base.update(overrides)
    return base


def _stream_params(op_id, **overrides):
    base = {
        "user_id": "default",
        "ports": list(PORTS),
        "txport": TX,
        "rxport": RX1,
        "name": "stream-1",
    }
    if op_id == "tg_start_traffic_stream":
        base["template"] = "udp-demo"
    if op_id == "tg_verify_traffic_loss":
        base["max_loss"] = 0
    base.update(overrides)
    return base


def _stream_args(op_id, **overrides) -> argparse.Namespace:
    """CLI 侧 Namespace 基线（--rxport/--ports 为逗号串，--expect-ports 为 JSON 串）。"""
    base = {
        "user_id": "default",
        "ports": ",".join(PORTS),
        "txport": TX,
        "rxport": RX1,
        "name": "stream-1",
        "payload_file": None,
        "payload_json": None,
    }
    if op_id == "tg_start_traffic_stream":
        base["template"] = "udp-demo"
    if op_id == "tg_verify_traffic_loss":
        base.update({"max_loss": 0.0, "expect_ports": None, "tolerance": None})
    base.update(overrides)
    return argparse.Namespace(**base)


class ParseRxportTests(unittest.TestCase):
    """CLI --rxport：单值保持字符串（请求体形状不变）、逗号多值转列表。"""

    def test_single_value_stays_string(self) -> None:
        self.assertEqual(_parse_rxport("2_4"), "2_4")

    def test_comma_separated_becomes_list(self) -> None:
        self.assertEqual(_parse_rxport("2_4,2_5"), ["2_4", "2_5"])
        self.assertEqual(_parse_rxport("2_4, 2_5 ,2_6"), ["2_4", "2_5", "2_6"])

    def test_trailing_comma_ignored(self) -> None:
        self.assertEqual(_parse_rxport("2_4,"), "2_4")

    def test_empty_rejected(self) -> None:
        for value in (None, "", " ", ",,"):
            with self.subTest(value=value):
                with self.assertRaises(RunnerError) as ctx:
                    _parse_rxport(value)
                self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")
                self.assertEqual(ctx.exception.details["field"], "rxport")


class ParseExpectPortsTests(unittest.TestCase):
    """CLI --expect-ports：JSON 数组文本 -> list（跨仓契约：op_mapper 侧按 JSON 渲染）。"""

    def test_valid_array(self) -> None:
        expect = [{"port": RX1, "ratio": 100}, {"port": RX2, "ratio": 0}]
        self.assertEqual(_parse_expect_ports(json.dumps(expect)), expect)

    def test_invalid_json_rejected(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            _parse_expect_ports("{'port': '2_4'}")  # Python repr 正是逗号串渲染的产物
        self.assertEqual(ctx.exception.details["field"], "expect_ports")

    def test_non_array_rejected(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            _parse_expect_ports('{"port": "2_4", "ratio": 100}')
        self.assertEqual(ctx.exception.details["field"], "expect_ports")


class ParamsFromArgsTests(unittest.TestCase):
    """CLI args -> params：新字段透传，缺省不产生键（既有用例逐字不变）。"""

    def test_apply_forwards_stream_count(self) -> None:
        args = argparse.Namespace(
            user_id="default", template="udp-demo", tx_port=TX, rx_port=RX1,
            ip_version="ipv4", l4_protocol="udp", l4_sport=1025, l4_dport=5678,
            stream_count=4, traffic_mode="count", rate="100pps", count=500,
            frame_size=None, vlan=None, src_ip=None, dst_ip=None,
            src_mac=None, dst_mac=None, payload_file=None, payload_json=None,
        )
        params = _params_from_args(args, "tg_apply_traffic_template")
        self.assertEqual(params["stream_count"], 4)
        self.assertEqual(params["count"], 500)  # 总包数语义不变

    def test_verify_loss_multi_rxport_and_expectations(self) -> None:
        expect = [{"port": RX1, "ratio": 100}, {"port": RX2, "ratio": 0}]
        params = _params_from_args(
            _stream_args(
                "tg_verify_traffic_loss",
                rxport=f"{RX1},{RX2}",
                expect_ports=json.dumps(expect),
                tolerance=10.0,
            ),
            "tg_verify_traffic_loss",
        )
        self.assertEqual(params["rxport"], [RX1, RX2])
        self.assertEqual(params["expect_ports"], expect)
        self.assertEqual(params["tolerance"], 10.0)

    def test_verify_loss_omits_new_keys_when_absent(self) -> None:
        """不传新参数时 params 里没有这两个键 -> 请求体与改动前逐字相同。"""
        params = _params_from_args(
            _stream_args("tg_verify_traffic_loss"), "tg_verify_traffic_loss"
        )
        self.assertEqual(params["rxport"], RX1)
        self.assertNotIn("expect_ports", params)
        self.assertNotIn("tolerance", params)


class BuildApplyStreamCountTests(unittest.TestCase):
    """apply 的 stream_count：透传 + 本地预校验（与 trex-api schema 同口径）。"""

    def test_stream_count_forwarded(self) -> None:
        payload = build_trex_payload("tg_apply_traffic_template", _apply_params(stream_count=4))
        self.assertEqual(payload["stream_count"], 4)
        self.assertEqual(payload["count"], 500)

    def test_absent_stream_count_leaves_no_key(self) -> None:
        payload = build_trex_payload("tg_apply_traffic_template", _apply_params())
        self.assertNotIn("stream_count", payload)

    def test_icmp_rejected(self) -> None:
        """ICMP 无 L4 端口可变化 —— 服务端同口径拒绝（含 stream_count=1）。"""
        with self.assertRaises(RunnerError) as ctx:
            build_trex_payload(
                "tg_apply_traffic_template",
                _apply_params(l4_protocol="icmp", count=5, stream_count=4),
            )
        self.assertEqual(ctx.exception.details["field"], "stream_count")

    def test_missing_start_port_rejected_by_port_contract(self) -> None:
        """tcp/udp 缺 l4_sport 由既有端口契约直接拒绝（早于多流检查）。

        服务端 schema 允许 l4_sport 为 None，此时「stream_count 有值」不会报错但
        多流静默退化为单流；本地因端口强制必填而**不可达**该形态 —— 这里固化
        「本地更严」这一分叉，避免后人以为服务端那条静默路径在用例侧也走得通。
        """
        with self.assertRaises(RunnerError) as ctx:
            build_trex_payload(
                "tg_apply_traffic_template", _apply_params(stream_count=4, l4_sport=None)
            )
        self.assertEqual(ctx.exception.details["field"], "l4_sport")

    def test_single_flow_is_a_no_op(self) -> None:
        """stream_count=1 等价单流（起始端口齐全），不改变任何行为。"""
        payload = build_trex_payload(
            "tg_apply_traffic_template", _apply_params(stream_count=1)
        )
        self.assertEqual(payload["stream_count"], 1)

    def test_start_port_overflow_rejected(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_trex_payload(
                "tg_apply_traffic_template",
                _apply_params(l4_sport=65530, stream_count=10),
            )
        self.assertEqual(ctx.exception.details["field"], "stream_count")

    def test_boundary_values_pass(self) -> None:
        """上界恰好贴合：sport + stream_count - 1 == 65535 合法。"""
        payload = build_trex_payload(
            "tg_apply_traffic_template", _apply_params(l4_sport=65532, stream_count=4)
        )
        self.assertEqual(payload["stream_count"], 4)

    def test_stream_count_upper_bound_rejected(self) -> None:
        # 上限 10000（ff2fba1 放开）——测试原断言 1001 被拒，是**上限抬高后未同步**的
        # 过期基线失败（2026-09-24 修）：改为越界值 10001，并补边界值 10000 放行。
        with self.assertRaises(RunnerError):
            build_trex_payload("tg_apply_traffic_template", _apply_params(stream_count=10001))
        payload = build_trex_payload(
            "tg_apply_traffic_template", _apply_params(l4_sport=1, stream_count=10000)
        )
        self.assertEqual(payload["stream_count"], 10000)

    def test_non_positive_rejected(self) -> None:
        """0 / 负数 / 非数字一律拒绝。

        注：`True` 不在拒绝面内 —— `_validate_positive_int` 是既有共享 helper，
        对 bool 走 `int()` 转换得 1（既有语义，不在本轮改动范围）。
        """
        for value in (0, -1, "abc"):
            with self.subTest(value=value):
                with self.assertRaises(RunnerError):
                    build_trex_payload(
                        "tg_apply_traffic_template", _apply_params(stream_count=value)
                    )


class StreamRxportTests(unittest.TestCase):
    """start/stop/verify 的 rxport：单值回归不变 + 多口列表 + 成员检查。"""

    def test_single_rxport_unchanged(self) -> None:
        """既有单口请求逐字不变（rxport 仍是字符串）。"""
        for op_id in ("tg_start_traffic_stream", "tg_verify_traffic_loss"):
            with self.subTest(op_id=op_id):
                payload = build_trex_payload(op_id, _stream_params(op_id))
                self.assertEqual(payload["rxport"], RX1)
                self.assertIsInstance(payload["rxport"], str)

    def test_multi_rxport_accepted(self) -> None:
        payload = build_trex_payload(
            "tg_verify_traffic_loss",
            _stream_params("tg_verify_traffic_loss", rxport=[RX1, RX2]),
        )
        self.assertEqual(payload["rxport"], [RX1, RX2])

    def test_rxport_outside_ports_rejected(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_trex_payload(
                "tg_verify_traffic_loss",
                _stream_params("tg_verify_traffic_loss", rxport=[RX1, "2_9"]),
            )
        self.assertEqual(ctx.exception.details["field"], "rxport")
        self.assertEqual(ctx.exception.details["missing"], ["2_9"])

    def test_empty_rxport_rejected(self) -> None:
        for value in ("", [], ["2_4", " "]):
            with self.subTest(value=value):
                with self.assertRaises(RunnerError):
                    build_trex_payload(
                        "tg_verify_traffic_loss",
                        _stream_params("tg_verify_traffic_loss", rxport=value),
                    )


class VerifyExpectPortsTests(unittest.TestCase):
    """verify 的 expect_ports/tolerance：形状、归属、Σ 规则与容差边界。"""

    def _verify(self, **overrides):
        params = _stream_params("tg_verify_traffic_loss", rxport=[RX1, RX2])
        params.update(overrides)
        return build_trex_payload("tg_verify_traffic_loss", params)

    def test_ratio_split_accepted(self) -> None:
        payload = self._verify(
            expect_ports=[{"port": RX1, "ratio": 60}, {"port": RX2, "ratio": 40}],
            tolerance=10,
        )
        self.assertEqual(payload["tolerance"], 10.0)

    def test_all_zero_sum_accepted(self) -> None:
        """Σratio==0 = 要求各口都收不到包（流量不通场景）。"""
        payload = self._verify(
            expect_ports=[{"port": RX1, "ratio": 0}, {"port": RX2, "ratio": 0}]
        )
        self.assertEqual(len(payload["expect_ports"]), 2)

    def test_exact_split_accepted(self) -> None:
        payload = self._verify(
            expect_ports=[{"port": RX1, "ratio": 100}, {"port": RX2, "ratio": 0}]
        )
        self.assertEqual(payload["expect_ports"][1]["ratio"], 0)

    def test_sum_other_than_0_or_100_rejected(self) -> None:
        for total in (50, 99.9, 101):
            with self.subTest(total=total):
                with self.assertRaises(RunnerError) as ctx:
                    self._verify(
                        expect_ports=[
                            {"port": RX1, "ratio": total},
                            {"port": RX2, "ratio": 0},
                        ]
                    )
                self.assertEqual(ctx.exception.details["field"], "expect_ports")

    def test_ports_not_in_rxport_rejected(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            self._verify(expect_ports=[{"port": TX, "ratio": 100}])
        self.assertEqual(ctx.exception.details["field"], "expect_ports")

    def test_repeated_port_rejected(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            self._verify(
                expect_ports=[{"port": RX1, "ratio": 50}, {"port": RX1, "ratio": 50}]
            )
        self.assertEqual(ctx.exception.details["field"], "expect_ports")

    def test_shapes_rejected(self) -> None:
        for value in (
            [],
            [],
            [{"port": RX1}],
            [{"ratio": 100}],
            [RX1],
            ["not-a-dict"],
            [{"port": RX1, "ratio": -1}, {"port": RX2, "ratio": 101}],
            [{"port": RX1, "ratio": "60"}, {"port": RX2, "ratio": "40"}],
        ):
            with self.subTest(value=value):
                with self.assertRaises(RunnerError):
                    self._verify(expect_ports=value)

    def test_tolerance_bounds(self) -> None:
        for value in (-1, 101, "10"):
            with self.subTest(value=value):
                with self.assertRaises(RunnerError) as ctx:
                    self._verify(
                        expect_ports=[{"port": RX1, "ratio": 60}, {"port": RX2, "ratio": 40}],
                        tolerance=value,
                    )
                self.assertEqual(ctx.exception.details["field"], "tolerance")
        for value in (0, 100):
            with self.subTest(value=value):
                payload = self._verify(
                    expect_ports=[{"port": RX1, "ratio": 100}, {"port": RX2, "ratio": 0}],
                    tolerance=value,
                )
                self.assertEqual(payload["tolerance"], float(value))

    def test_absent_expectations_leave_payload_unchanged(self) -> None:
        payload = self._verify()
        self.assertNotIn("expect_ports", payload)
        self.assertNotIn("tolerance", payload)
        self.assertEqual(payload["max_loss"], 0.0)


class ValidateDirectPayloadTests(unittest.TestCase):
    """--payload-json 入口：validate_trex_payload 独立生效（不经 build）。"""

    def test_direct_verify_payload(self) -> None:
        payload = {
            "ports": PORTS, "txport": TX, "rxport": [RX1, RX2],
            "name": "stream-1", "max_loss": 0,
            "expect_ports": [{"port": RX1, "ratio": 100}, {"port": RX2, "ratio": 0}],
        }
        result = validate_trex_payload("tg_verify_traffic_loss", dict(payload))
        self.assertEqual(result["expect_ports"], payload["expect_ports"])

    def test_direct_apply_payload_stream_count(self) -> None:
        payload = {
            "template": "udp-demo", "tx_port": TX, "rx_port": RX1,
            "ip_version": "ipv4", "l4_protocol": "udp", "l4_sport": 1025,
            "l4_dport": 5678, "traffic_mode": "count", "rate": "100pps",
            "count": 500, "stream_count": 4,
        }
        result = validate_trex_payload("tg_apply_traffic_template", dict(payload))
        self.assertEqual(result["stream_count"], 4)


if __name__ == "__main__":
    unittest.main()
