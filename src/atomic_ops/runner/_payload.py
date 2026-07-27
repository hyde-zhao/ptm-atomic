"""公共 payload 透传工具。

提供 ``--payload-file`` / ``--payload-json`` 双入口的统一加载逻辑，供多个
runner 模块复用。两个参数互斥，优先返回解析后的 dict；都不提供时返回 None。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import RunnerError


def load_json_payload(*, payload_file: str | None, payload_json: str | None) -> dict[str, Any] | None:
    """从 ``--payload-file`` 或 ``--payload-json`` 加载完整请求 payload。

    两者互斥；都不提供时返回 None。解析失败或根节点非对象时抛出
    ``RUNNER_VALIDATION_FAILED``。
    """
    if payload_file and payload_json:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "--payload-file and --payload-json cannot be used together.",
            {"fields": ["payload_file", "payload_json"]},
        )
    if not payload_file and not payload_json:
        return None
    try:
        raw = Path(payload_file).read_text(encoding="utf-8") if payload_file else str(payload_json)
        payload = json.loads(raw)
    except OSError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Payload file cannot be read.",
            {"path": payload_file, "reason": exc.__class__.__name__},
        ) from exc
    except json.JSONDecodeError as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Payload must be valid JSON.",
            {"reason": exc.msg},
        ) from exc
    if not isinstance(payload, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Payload JSON root must be an object.",
            {"type": type(payload).__name__},
        )
    return payload
