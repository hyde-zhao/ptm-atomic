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


if __name__ == "__main__":
    unittest.main()
