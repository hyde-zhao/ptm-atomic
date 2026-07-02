"""Polling helper for asynchronous NGFW task workflows.

Export/import operations are multi-step: a POST starts a background task and
returns a task id, then a GET must be polled until the task produces a result.
This module centralizes that loop so runners stay focused on request shape.
"""

from __future__ import annotations

import time
from typing import Any, Callable

from atomic_ops.runner.errors import RunnerError


def poll_until(
    call: Callable[[], Any],
    *,
    timeout_ms: int,
    interval_ms: int,
    is_done: Callable[[Any], bool],
) -> Any:
    """Call ``call`` repeatedly until ``is_done(result)`` is true or timeout.

    Returns the last result that satisfied ``is_done``. Raises
    ``RUNNER_VALIDATION_FAILED`` when the deadline elapses first, carrying
    ``elapsed_ms`` and ``timeout_ms`` for diagnosis. ``interval_ms`` is the
    sleep between attempts; the first attempt is immediate.
    """
    if interval_ms < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Poll interval must be non-negative.",
            {"field": "interval_ms", "value": interval_ms},
        )
    if timeout_ms <= 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Poll timeout must be positive.",
            {"field": "timeout_ms", "value": timeout_ms},
        )

    deadline = time.monotonic() + timeout_ms / 1000.0
    interval = interval_ms / 1000.0
    last_result: Any = None
    attempt = 0
    while True:
        attempt += 1
        last_result = call()
        if is_done(last_result):
            return last_result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Polling timed out before the task produced a result.",
                {
                    "attempts": attempt,
                    "elapsed_ms": round(timeout_ms - remaining * 1000),
                    "timeout_ms": timeout_ms,
                },
            )
        time.sleep(min(interval, remaining))
