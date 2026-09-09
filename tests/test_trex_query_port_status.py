"""tg_query_port_status 子命令委托测试（ISSUE-B 第二层，2026-09-09 现场诊断通道）。

固化契约（全部本地，不发真实 HTTP）：
  - run tg trex query-port-status 子命令在 build_subtree() 注册
  - runner TREX_OPS 映射 POST /api/v1/ops/tg_query_port_status
  - build_trex_payload：ports 可选（缺省=全部）、非 default user_id 转发
  - validate_trex_payload：空 ports 拒绝、非法 user_id 拒绝
  - CLI 参数 --ports/--user-id 解析（_params_from_args）
"""

from __future__ import annotations

import argparse
import unittest

from atomic_ops.commands import run_trex
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.trex import (
    TREX_OPS,
    build_trex_payload,
    validate_trex_payload,
)


def _args(**overrides) -> argparse.Namespace:
    base = {"user_id": "default", "ports": None, "payload_file": None, "payload_json": None}
    base.update(overrides)
    return argparse.Namespace(**base)


class QueryPortStatusSubtreeTests(unittest.TestCase):
    def test_subtree_registers_query_port_status(self) -> None:
        """tg trex 子树包含 query-port-status（handler 委托 tg_query_port_status）。"""
        (tg_group,) = run_trex.build_subtree()
        (trex_group,) = tg_group.children
        spec = next(s for s in trex_group.children if s.name == "query-port-status")
        args = _args()
        self.assertEqual(spec.handler.__name__, "_run_query_port_status")

    def test_trex_ops_mapping_is_post_dispatch(self) -> None:
        """runner 走 /api/v1/ops/{op_id} 调度（非 ownership 的独立 GET 端点）。"""
        method, path = TREX_OPS["tg_query_port_status"]
        self.assertEqual((method, path), ("POST", "/api/v1/ops/tg_query_port_status"))


class QueryPortStatusPayloadTests(unittest.TestCase):
    def test_build_payload_without_ports_defaults_to_all(self) -> None:
        payload = build_trex_payload("tg_query_port_status", run_trex._params_from_args(_args(), "tg_query_port_status"))
        self.assertEqual(payload, {})

    def test_build_payload_with_ports(self) -> None:
        args = _args(ports="2_1,2_2")
        payload = build_trex_payload("tg_query_port_status", run_trex._params_from_args(args, "tg_query_port_status"))
        self.assertEqual(payload, {"ports": ["2_1", "2_2"]})

    def test_build_payload_forwards_non_default_user_id(self) -> None:
        args = _args(user_id="dev171-1", ports="2_1")
        payload = build_trex_payload("tg_query_port_status", run_trex._params_from_args(args, "tg_query_port_status"))
        self.assertEqual(payload, {"ports": ["2_1"], "user_id": "dev171-1"})

    def test_build_payload_default_user_id_not_forwarded(self) -> None:
        payload = build_trex_payload("tg_query_port_status", {"user_id": "default"})
        self.assertNotIn("user_id", payload)

    def test_validate_rejects_empty_ports(self) -> None:
        with self.assertRaises(RunnerError):
            validate_trex_payload("tg_query_port_status", {"ports": []})

    def test_validate_accepts_ports_and_user_id(self) -> None:
        payload = validate_trex_payload(
            "tg_query_port_status", {"ports": ["2_3"], "user_id": "dev171-1"})
        self.assertEqual(payload["ports"], ["2_3"])

    def test_validate_rejects_bad_user_id(self) -> None:
        with self.assertRaises(RunnerError):
            validate_trex_payload("tg_query_port_status", {"user_id": "not a user"})

    def test_json_payload_passthrough(self) -> None:
        """--payload-json 完整载荷直接走 validate（与 build 路径等价）。"""
        raw = {"ports": ["2_1"], "user_id": "dev172-1"}
        payload = validate_trex_payload("tg_query_port_status", raw)
        self.assertEqual(payload, raw)


if __name__ == "__main__":
    unittest.main()
