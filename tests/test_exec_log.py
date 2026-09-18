from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

from atomic_ops.commands.run import _to_run_envelope
from atomic_ops.errors import CliError, write_error
from atomic_ops.runner.errors import RunnerError


class ExecLogTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self._prev = os.environ.get("XDG_STATE_HOME")
        os.environ["XDG_STATE_HOME"] = self._tmp.name

    def tearDown(self):
        if self._prev is None:
            os.environ.pop("XDG_STATE_HOME", None)
        else:
            os.environ["XDG_STATE_HOME"] = self._prev
        self._tmp.cleanup()

    def _last_record(self, path: Path) -> dict:
        return json.loads(path.read_text(encoding="utf-8").strip().splitlines()[-1])

    def test_write_exec_log_writes_jsonl_record(self):
        from atomic_ops.runner.exec_log import run_log_path, write_exec_log

        path = write_exec_log(
            run_id="r1",
            op_id="fw_config_object",
            mode="execute",
            status="success",
            status_code=201,
        )
        self.assertTrue(path.exists())
        record = self._last_record(path)
        self.assertEqual(record["run_id"], "r1")
        self.assertEqual(record["op_id"], "fw_config_object")
        self.assertEqual(record["mode"], "execute")
        self.assertEqual(record["status"], "success")
        self.assertEqual(record["http_status"], 201)
        self.assertEqual(path, run_log_path("r1"))

    def test_to_run_envelope_records_exec_log_on_execute_success(self):
        from atomic_ops.runner.exec_log import bind_run_context, generate_run_id, reset_run_context

        token = bind_run_context(generate_run_id(), "execute")
        try:
            env = _to_run_envelope(
                {"op_id": "fw_config_object", "status": "success", "status_code": 201}
            )
        finally:
            reset_run_context(token)
        exec_log = env["metadata"]["exec_log"]
        self.assertIn("run_id", exec_log)
        self.assertTrue(Path(exec_log["path"]).exists())
        record = self._last_record(Path(exec_log["path"]))
        self.assertEqual(record["status"], "success")
        self.assertEqual(record["op_id"], "fw_config_object")
        self.assertEqual(record["http_status"], 201)

    def test_to_run_envelope_skips_dry_run(self):
        # contextvar 未设（不在 main execute 上下文）-> 不记 exec-log
        env = _to_run_envelope({"op_id": "fw_config_object", "status": "dry_run"})
        metadata = env.get("metadata") or {}
        self.assertNotIn("exec_log", metadata)

    def test_write_error_records_exec_log_on_execute_error(self):
        from atomic_ops.runner.exec_log import bind_run_context, generate_run_id, reset_run_context

        token = bind_run_context(generate_run_id(), "execute")
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                write_error(
                    CliError(
                        "RUNNER_CONFIG_REJECTED",
                        "rejected",
                        {"op_id": "fw_config_object", "err_code": "eDuplicate", "err_msg": "dup"},
                    ),
                    "json",
                )
        finally:
            reset_run_context(token)
        payload = json.loads(err.getvalue().strip())
        self.assertIn("run_id", payload)
        self.assertIn("exec_log_path", payload)
        log_path = Path(payload["exec_log_path"])
        self.assertTrue(log_path.exists())
        record = self._last_record(log_path)
        self.assertEqual(record["status"], "error")
        self.assertEqual(record["err_code"], "eDuplicate")
        self.assertEqual(record["err_msg"], "dup")
        self.assertEqual(record["error_type"], "RUNNER_CONFIG_REJECTED")

    def test_write_error_skips_when_not_run(self):
        # 非 run 命令（contextvar 未设）-> 不加 run_id，不写日志
        from atomic_ops.repository import ERROR_OP_NOT_FOUND

        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            write_error(CliError(ERROR_OP_NOT_FOUND, "x", {}), "json")
        payload = json.loads(err.getvalue().strip())
        self.assertNotIn("run_id", payload)


    # ── CT-REM-ATOM-AUDIT / 区域 #audit-error-type（UT-DIAG-08 / UT-DIAG-09）──────
    # FD-REM-DIAG §3/§4：审计行 error_type = 原始错误类型（不映射、不丢失），
    # runner_error_code = 映射后运行时代码，status_code = HTTP 状态码；
    # 不可得以 "-" 占位（不得省略键）；既有键语义与位置不变（append-only）。

    def _write_error_record(self, error: CliError) -> dict:
        """在 execute run 上下文内走 write_error，返回落盘的审计行。"""
        from atomic_ops.runner.exec_log import bind_run_context, generate_run_id, reset_run_context

        token = bind_run_context(generate_run_id(), "execute")
        err = io.StringIO()
        try:
            with contextlib.redirect_stderr(err):
                write_error(error, "json")
        finally:
            reset_run_context(token)
        payload = json.loads(err.getvalue().strip())
        return self._last_record(Path(payload["exec_log_path"]))

    def _tg_error(self, device_error_type: str, *, status_code: int | None = None) -> CliError:
        """构造 TG（trex）族失败：设备原始码位于 details["error_type"]，CLI 码为映射后码。"""
        details: dict = {
            "op_id": "tg_verify_traffic_loss",
            "envelope_status": "error",
            "error_type": device_error_type,
            "data": {"tx_packets": 100, "rx_packets": 0, "loss_ratio": 1.0},
            "diag_snapshot_ref": "",
        }
        if status_code is not None:
            details["status_code"] = status_code
        return CliError("RUNNER_VALIDATION_FAILED", "tg operation failed", details)

    def test_ut_diag_08_tg_audit_row_keeps_original_error_type_and_status_code(self):
        record = self._write_error_record(self._tg_error("STATE_MISMATCH", status_code=500))

        self.assertEqual(record["error_type"], "STATE_MISMATCH")  # 原始（设备返回）
        self.assertEqual(record["runner_error_code"], "RUNNER_VALIDATION_FAILED")  # 映射后
        self.assertEqual(record["error_type_source"], "original")
        self.assertEqual(record["status_code"], 500)  # FD §4 规范名
        self.assertEqual(record["http_status"], 500)  # 既有键语义不变（同值并存）
        self.assertEqual(record["op_id"], "tg_verify_traffic_loss")
        self.assertEqual(record["status"], "error")

    def test_ut_diag_09_three_semantics_distinguishable_in_audit_row(self):
        semantics = ["INVALID_PARAM", "RESOURCE_NOT_FOUND", "STATE_MISMATCH"]
        rows = [self._write_error_record(self._tg_error(name)) for name in semantics]

        # 三义在审计行上可区分（R-F-REM-018）……
        self.assertEqual([row["error_type"] for row in rows], semantics)
        # ……而映射后码对三者同值（改动前审计行只有该键 → 三义不可区分）
        self.assertEqual({row["runner_error_code"] for row in rows}, {"RUNNER_VALIDATION_FAILED"})
        # trex details 未提供 status_code（D2 未闭合）→ 显式占位，不省略键
        self.assertEqual([row["status_code"] for row in rows], ["-", "-", "-"])

    def test_audit_error_type_fallback_is_marked_mapped(self):
        record = self._write_error_record(
            CliError(
                "RUNNER_CONFIG_REJECTED",
                "rejected",
                {"op_id": "fw_config_object", "err_code": "eDuplicate", "err_msg": "dup"},
            )
        )

        # 原始码不可得 → 回退映射后码，并以 error_type_source 显式标注（不静默）
        self.assertEqual(record["error_type"], "RUNNER_CONFIG_REJECTED")
        self.assertEqual(record["error_type_source"], "mapped")
        self.assertEqual(record["runner_error_code"], "RUNNER_CONFIG_REJECTED")

    def test_audit_status_code_placeholder_when_unavailable(self):
        record = self._write_error_record(self._tg_error("RESOURCE_NOT_FOUND"))

        self.assertIn("status_code", record)  # 不得省略键
        self.assertEqual(record["status_code"], "-")
        self.assertNotIn("http_status", record)  # 既有键语义不变（不可得时不写）

    def test_error_row_audit_fields_never_omitted(self):
        from atomic_ops.runner.exec_log import write_exec_log

        path = write_exec_log(run_id="r-audit", op_id=None, mode="execute", status="error")
        record = self._last_record(path)

        for key in ("error_type", "runner_error_code", "status_code", "error_type_source"):
            self.assertIn(key, record)
            self.assertEqual(record[key], "-")

    def test_audit_row_is_append_only_for_existing_keys(self):
        record = self._write_error_record(
            CliError(
                "RUNNER_CONFIG_REJECTED",
                "rejected",
                {
                    "op_id": "fw_config_object",
                    "error_type": "RESOURCE_CONFLICT",
                    "status_code": 400,
                    "err_code": "eDuplicate",
                    "err_msg": "dup",
                },
            )
        )

        # 既有键相对顺序不变；新键追加在既有错误键之后；duration_ms 仍是末键
        self.assertEqual(
            list(record),
            [
                "run_id",
                "timestamp",
                "op_id",
                "mode",
                "status",
                "http_status",
                "err_code",
                "err_msg",
                "error_type",
                "runner_error_code",
                "status_code",
                "error_type_source",
                "duration_ms",
            ],
        )

    def test_success_row_not_extended_with_audit_error_keys(self):
        from atomic_ops.runner.exec_log import write_exec_log

        path = write_exec_log(
            run_id="r-success",
            op_id="fw_config_object",
            mode="execute",
            status="success",
            status_code=201,
        )
        record = self._last_record(path)

        self.assertEqual(record["http_status"], 201)
        for key in ("error_type", "runner_error_code", "status_code", "error_type_source"):
            self.assertNotIn(key, record)

    def _tg_runner_error(self, http_status: int, payload: dict) -> RunnerError:
        """走 trex 真实失败路径取 RunnerError（mock 设备响应，离线；不触设备）。"""
        from atomic_ops.runner import trex

        def _fake_request_json(method, url, **kwargs):
            return http_status, payload, ""

        original = trex.request_json
        trex.request_json = _fake_request_json
        try:
            with self.assertRaises(RunnerError) as raised:
                trex.execute_trex(
                    op_id="tg_verify_traffic_loss",
                    base_url="http://127.0.0.1:4500",
                    payload={},
                    verify_tls=False,
                    timeout=5.0,
                )
        finally:
            trex.request_json = original
        return raised.exception

    def test_tg_envelope_error_path_yields_original_error_type(self):
        """trex 信封级失败（HTTP 200 + status=error）→ 审计行保留设备原始码。

        该路径的 details 不含 status_code（trex 侧缺口 D2，落点在 03-06 区域）→
        审计行以 "-" 显式占位。
        """
        exc = self._tg_runner_error(
            200,
            {"status": "error", "error_type": "STATE_MISMATCH", "data": {"reason": "port down"}},
        )
        self.assertEqual(exc.error_code, "RUNNER_VALIDATION_FAILED")
        self.assertEqual(exc.details["error_type"], "STATE_MISMATCH")
        self.assertNotIn("status_code", exc.details)

        record = self._write_error_record(CliError(exc.error_code, exc.message, exc.details))
        self.assertEqual(record["error_type"], "STATE_MISMATCH")
        self.assertEqual(record["runner_error_code"], "RUNNER_VALIDATION_FAILED")
        self.assertEqual(record["status_code"], "-")

    def test_tg_http_error_path_yields_status_code(self):
        """trex HTTP 级失败（非 200）→ 审计行保留 HTTP 状态码。

        该路径的 details 不含 error_type（设备原始码未产生）→ error_type 回退映射后码
        并标注 error_type_source=mapped。
        """
        exc = self._tg_runner_error(500, {"message": "internal"})
        self.assertEqual(exc.error_code, "RUNNER_RESPONSE_INVALID")
        self.assertEqual(exc.details["status_code"], 500)

        record = self._write_error_record(CliError(exc.error_code, exc.message, exc.details))
        self.assertEqual(record["error_type"], "RUNNER_RESPONSE_INVALID")
        self.assertEqual(record["error_type_source"], "mapped")
        self.assertEqual(record["status_code"], 500)
        self.assertEqual(record["http_status"], 500)


if __name__ == "__main__":
    unittest.main()
