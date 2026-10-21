"""tg_start_custom_l7_stream / tg_start_pcap_stream 组合 op 契约测试。

固化本仓（ptm-atomic）侧的契约，全部本地执行、不发真实 HTTP：
  - 子命令注册（start-custom-l7-stream / start-pcap-stream）
  - CLI 参数解析与 tunables JSON object 校验
  - build/validate：template 白名单、tunables 必须为对象、pcap 仅 basename、
    mult 正整数、duration -1 或正整数
  - 组合步骤：apply 先于 start；apply 失败不 start；user_id 同时下发
  - dry-run 展示两个请求；execute 合并 apply/start 结果
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import unittest
from unittest.mock import patch

from atomic_ops.cli import main as cli_main
from atomic_ops.commands import run_trex
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.trex import (
    COMPOSITE_STATEFUL_OPS,
    build_composite_stateful_payloads,
    build_trex_dry_run,
    build_trex_payload,
    execute_trex,
    validate_trex_payload,
)


def _args(**overrides) -> argparse.Namespace:
    base = {
        "user_id": "default",
        "template": "http-attack",
        "tunables": None,
        "mult": 1,
        "duration": 30,
        "pcap": None,
        "cps": 10,
        "payload_file": None,
        "payload_json": None,
    }
    base.update(overrides)
    return argparse.Namespace(**base)


def _l7_params(**overrides) -> dict:
    base = {
        "user_id": "default",
        "template": "http-attack",
        "tunables": {"method": "POST", "uri": "/login"},
        "mult": 1,
        "duration": 30,
    }
    base.update(overrides)
    return base


def _pcap_params(**overrides) -> dict:
    base = {
        "user_id": "default",
        "pcap": "threat_p2p_feiqiu.pcap",
        "cps": 10,
        "mult": 1,
        "duration": 30,
    }
    base.update(overrides)
    return base


class CompositeSubtreeTests(unittest.TestCase):
    def test_subtree_registers_both_composite_ops(self) -> None:
        (tg_group,) = run_trex.build_subtree()
        (trex_group,) = tg_group.children
        specs = {spec.name: spec for spec in trex_group.children}
        self.assertEqual(
            specs["start-custom-l7-stream"].handler.__name__,
            "_run_start_custom_l7_stream",
        )
        self.assertEqual(
            specs["start-pcap-stream"].handler.__name__,
            "_run_start_pcap_stream",
        )

    def test_composite_ops_are_not_direct_trex_api_dispatch(self) -> None:
        """组合 op 由 runner 拆成两次 trex-api 请求，不在 TREX_OPS 直连表中。"""
        from atomic_ops.runner.trex import TREX_OPS

        for op_id in COMPOSITE_STATEFUL_OPS:
            self.assertNotIn(op_id, TREX_OPS)


class CompositeParamsTests(unittest.TestCase):
    def test_params_parse_tunables_object(self) -> None:
        args = _args(tunables='{"method":"POST","body":"x"}')
        params = run_trex._params_from_args(args, "tg_start_custom_l7_stream")
        self.assertEqual(params["tunables"], {"method": "POST", "body": "x"})
        self.assertEqual(params["template"], "http-attack")

    def test_params_reject_tunables_non_object(self) -> None:
        for raw in ('["a"]', '"text"', "42"):
            with self.assertRaises(RunnerError) as ctx:
                run_trex._params_from_args(
                    _args(tunables=raw), "tg_start_custom_l7_stream"
                )
            self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")
            self.assertEqual(ctx.exception.details["field"], "tunables")

    def test_params_reject_invalid_tunables_json(self) -> None:
        with self.assertRaises(RunnerError):
            run_trex._params_from_args(
                _args(tunables="{not-json"), "tg_start_custom_l7_stream"
            )

    def test_params_pcap_defaults(self) -> None:
        params = run_trex._params_from_args(
            _args(pcap="sample.pcap"), "tg_start_pcap_stream"
        )
        self.assertEqual(params["pcap"], "sample.pcap")
        self.assertEqual(params["cps"], 10)
        self.assertEqual(params["mult"], 1)
        self.assertEqual(params["duration"], 30)


class CustomL7PayloadTests(unittest.TestCase):
    def test_defaults(self) -> None:
        payload = build_trex_payload(
            "tg_start_custom_l7_stream",
            run_trex._params_from_args(
                _args(template="http-attack"), "tg_start_custom_l7_stream"
            ),
        )
        self.assertEqual(payload["template"], "http-attack")
        self.assertEqual(payload["tunables"], {})
        self.assertEqual(payload["mult"], 1)
        self.assertEqual(payload["duration"], 30)
        self.assertNotIn("user_id", payload)

    def test_ftp_auth_allowed(self) -> None:
        payload = build_trex_payload(
            "tg_start_custom_l7_stream",
            _l7_params(template="ftp-auth", tunables={"attempts": 3}),
        )
        self.assertEqual(payload["template"], "ftp-auth")
        self.assertEqual(payload["tunables"], {"attempts": 3})

    def test_non_default_user_id_forwarded(self) -> None:
        payload = build_trex_payload(
            "tg_start_custom_l7_stream", _l7_params(user_id="dev163-1")
        )
        self.assertEqual(payload["user_id"], "dev163-1")

    def test_invalid_template_rejected(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_trex_payload(
                "tg_start_custom_l7_stream", _l7_params(template="http-simple")
            )
        self.assertEqual(ctx.exception.details["field"], "template")

    def test_tunables_must_be_object(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_trex_payload(
                "tg_start_custom_l7_stream", _l7_params(tunables=["x"])
            )
        self.assertEqual(ctx.exception.details["field"], "tunables")

    def test_mult_must_be_positive_integer(self) -> None:
        for bad in (0, -1, True, "2"):
            with self.assertRaises(RunnerError):
                build_trex_payload(
                    "tg_start_custom_l7_stream", _l7_params(mult=bad)
                )

    def test_duration_minus_one_and_positive_allowed(self) -> None:
        for value in (-1, 1, 30):
            payload = build_trex_payload(
                "tg_start_custom_l7_stream", _l7_params(duration=value)
            )
            self.assertEqual(payload["duration"], value)

    def test_duration_zero_and_negative_rejected(self) -> None:
        for bad in (0, -2, True, "30"):
            with self.assertRaises(RunnerError):
                build_trex_payload(
                    "tg_start_custom_l7_stream", _l7_params(duration=bad)
                )


class PcapPayloadTests(unittest.TestCase):
    def test_defaults(self) -> None:
        payload = build_trex_payload(
            "tg_start_pcap_stream", _pcap_params()
        )
        self.assertEqual(payload["pcap"], "threat_p2p_feiqiu.pcap")
        self.assertEqual(payload["cps"], 10)
        self.assertEqual(payload["mult"], 1)
        self.assertEqual(payload["duration"], 30)

    def test_pcap_required(self) -> None:
        with self.assertRaises(RunnerError) as ctx:
            build_trex_payload("tg_start_pcap_stream", _pcap_params(pcap=None))
        self.assertEqual(ctx.exception.details["field"], "pcap")

    def test_pcap_rejects_path_traversal(self) -> None:
        for bad in ("../x.pcap", "a/b.pcap", "..", "a\\b.pcap", "/abs.pcap"):
            with self.assertRaises(RunnerError) as ctx:
                build_trex_payload("tg_start_pcap_stream", _pcap_params(pcap=bad))
            self.assertEqual(ctx.exception.details["field"], "pcap")

    def test_cps_must_be_positive_number(self) -> None:
        for bad in (0, -1, True, "10"):
            with self.assertRaises(RunnerError):
                build_trex_payload("tg_start_pcap_stream", _pcap_params(cps=bad))

    def test_raw_payload_path_validates_same_rules(self) -> None:
        raw = {"pcap": "../x.pcap", "cps": 10, "mult": 1, "duration": 30}
        with self.assertRaises(RunnerError):
            validate_trex_payload("tg_start_pcap_stream", raw)


class CompositeStepPayloadTests(unittest.TestCase):
    def test_custom_l7_steps(self) -> None:
        apply_payload, start_payload = build_composite_stateful_payloads(
            "tg_start_custom_l7_stream", _l7_params(user_id="dev163-1")
        )
        self.assertEqual(
            apply_payload,
            {
                "template": "http-attack",
                "tunables": {"method": "POST", "uri": "/login"},
                "user_id": "dev163-1",
            },
        )
        self.assertEqual(
            start_payload, {"mult": 1, "duration": 30, "user_id": "dev163-1"}
        )

    def test_pcap_steps_map_to_p2p_replay(self) -> None:
        apply_payload, start_payload = build_composite_stateful_payloads(
            "tg_start_pcap_stream", _pcap_params(cps=20)
        )
        self.assertEqual(apply_payload["template"], "p2p-replay")
        self.assertEqual(
            apply_payload["tunables"],
            {"pcap": "threat_p2p_feiqiu.pcap", "cps": 20},
        )
        self.assertNotIn("user_id", apply_payload)
        self.assertEqual(start_payload, {"mult": 1, "duration": 30})


class CompositeDryRunTests(unittest.TestCase):
    def test_dry_run_shows_apply_then_start(self) -> None:
        result = build_trex_dry_run(
            op_id="tg_start_custom_l7_stream",
            base_url="http://<DUT_IP>:8000",
            payload=_l7_params(),
            verify_tls=False,
            timeout=5.0,
        )
        self.assertEqual(result["status"], "dry_run")
        self.assertTrue(result["composite"])
        self.assertEqual(len(result["steps"]), 2)
        first, second = result["steps"]
        self.assertEqual(first["op_id"], "tg_apply_stateful_template")
        self.assertEqual(second["op_id"], "tg_start_stateful_stream")
        self.assertTrue(
            first["request"]["url"].endswith("/api/v1/ops/tg_apply_stateful_template")
        )
        self.assertTrue(
            second["request"]["url"].endswith("/api/v1/ops/tg_start_stateful_stream")
        )
        self.assertEqual(first["request"]["payload"]["template"], "http-attack")
        self.assertEqual(second["request"]["payload"]["duration"], 30)

    def test_pcap_dry_run_tunables(self) -> None:
        result = build_trex_dry_run(
            op_id="tg_start_pcap_stream",
            base_url="http://<DUT_IP>:8000",
            payload=_pcap_params(),
            verify_tls=False,
            timeout=5.0,
        )
        apply_payload = result["steps"][0]["request"]["payload"]
        self.assertEqual(apply_payload["template"], "p2p-replay")
        self.assertEqual(apply_payload["tunables"]["pcap"], "threat_p2p_feiqiu.pcap")


class CompositeExecuteTests(unittest.TestCase):
    APPLY_OK = (
        200,
        {"status": "success", "data": {"template": "http-attack", "status": "applied"}},
        "",
    )
    START_OK = (
        200,
        {"status": "success", "data": {"state": "running"}},
        "",
    )

    def test_execute_apply_then_start_and_merge_result(self) -> None:
        with patch(
            "atomic_ops.runner.trex.request_json",
            side_effect=[self.APPLY_OK, self.START_OK],
        ) as mocked:
            result = execute_trex(
                op_id="tg_start_custom_l7_stream",
                base_url="http://<DUT_IP>:8000",
                payload=_l7_params(user_id="dev163-1"),
                verify_tls=False,
                timeout=5.0,
            )
        self.assertEqual(mocked.call_count, 2)
        first_url = mocked.call_args_list[0].args[1]
        second_url = mocked.call_args_list[1].args[1]
        self.assertTrue(first_url.endswith("/api/v1/ops/tg_apply_stateful_template"))
        self.assertTrue(second_url.endswith("/api/v1/ops/tg_start_stateful_stream"))
        self.assertEqual(
            mocked.call_args_list[0].kwargs["json_payload"]["user_id"], "dev163-1"
        )
        data = result["response"]
        self.assertEqual(data["user_id"], "dev163-1")
        self.assertEqual(data["template"], "http-attack")
        self.assertEqual(data["tunables"], {"method": "POST", "uri": "/login"})
        self.assertEqual(data["apply"]["status"], "success")
        self.assertEqual(data["start"]["status"], "success")
        self.assertEqual(data["start"]["status_code"], 200)

    def test_apply_failure_aborts_before_start(self) -> None:
        apply_error = (
            200,
            {"status": "error", "error_type": "RESOURCE_NOT_FOUND", "data": {}},
            "",
        )
        with patch(
            "atomic_ops.runner.trex.request_json", side_effect=[apply_error]
        ) as mocked:
            with self.assertRaises(RunnerError) as ctx:
                execute_trex(
                    op_id="tg_start_custom_l7_stream",
                    base_url="http://<DUT_IP>:8000",
                    payload=_l7_params(),
                    verify_tls=False,
                    timeout=5.0,
                )
        self.assertEqual(mocked.call_count, 1)
        self.assertEqual(ctx.exception.error_code, "RUNNER_VALIDATION_FAILED")
        self.assertEqual(ctx.exception.details["composite_step"], "apply")
        self.assertTrue(ctx.exception.details["start_skipped"])

    def test_start_failure_reports_successful_apply(self) -> None:
        start_error = (
            200,
            {"status": "error", "error_type": "STATE_MISMATCH", "data": {}},
            "",
        )
        with patch(
            "atomic_ops.runner.trex.request_json",
            side_effect=[self.APPLY_OK, start_error],
        ) as mocked:
            with self.assertRaises(RunnerError) as ctx:
                execute_trex(
                    op_id="tg_start_pcap_stream",
                    base_url="http://<DUT_IP>:8000",
                    payload=_pcap_params(),
                    verify_tls=False,
                    timeout=5.0,
                )
        self.assertEqual(mocked.call_count, 2)
        self.assertEqual(ctx.exception.details["composite_step"], "start")
        self.assertEqual(ctx.exception.details["apply"]["status"], "success")

    def test_pcap_execute_response_contains_pcap_and_cps(self) -> None:
        with patch(
            "atomic_ops.runner.trex.request_json",
            side_effect=[self.APPLY_OK, self.START_OK],
        ):
            result = execute_trex(
                op_id="tg_start_pcap_stream",
                base_url="http://<DUT_IP>:8000",
                payload=_pcap_params(cps=25),
                verify_tls=False,
                timeout=5.0,
            )
        data = result["response"]
        self.assertEqual(data["pcap"], "threat_p2p_feiqiu.pcap")
        self.assertEqual(data["cps"], 25)
        self.assertEqual(data["template"], "p2p-replay")


class CompositeCliTests(unittest.TestCase):
    def test_cli_dry_run_custom_l7(self) -> None:
        argv = [
            "run",
            "--base-url",
            "http://<DUT_IP>:8000",
            "--format",
            "json",
            "tg",
            "trex",
            "start-custom-l7-stream",
            "--user-id",
            "dev163-1",
            "--template",
            "http-attack",
            "--tunables",
            json.dumps({"method": "POST", "uri": "/login"}),
            "--mult",
            "1",
            "--duration",
            "30",
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(argv)
        self.assertEqual(exit_code, 0)
        envelope = json.loads(stdout.getvalue())
        self.assertEqual(envelope["op_id"], "tg_start_custom_l7_stream")
        self.assertEqual(envelope["status"], "dry_run")
        self.assertTrue(envelope["data"]["composite"])
        self.assertEqual(len(envelope["data"]["steps"]), 2)

    def test_cli_dry_run_pcap(self) -> None:
        argv = [
            "run",
            "--base-url",
            "http://<DUT_IP>:8000",
            "--format",
            "json",
            "tg",
            "trex",
            "start-pcap-stream",
            "--pcap",
            "threat_p2p_feiqiu.pcap",
            "--cps",
            "10",
            "--duration",
            "30",
        ]
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            exit_code = cli_main(argv)
        self.assertEqual(exit_code, 0)
        envelope = json.loads(stdout.getvalue())
        self.assertEqual(envelope["op_id"], "tg_start_pcap_stream")
        self.assertEqual(
            envelope["data"]["steps"][0]["request"]["payload"]["template"],
            "p2p-replay",
        )


if __name__ == "__main__":
    unittest.main()
