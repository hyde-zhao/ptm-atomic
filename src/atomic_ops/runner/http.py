"""Small HTTP adapter used by runner commands."""

from __future__ import annotations

from typing import Any

import requests

from atomic_ops.runner.errors import RunnerError


def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_payload: dict[str, Any] | None = None,
    timeout: float = 10,
    verify_tls: bool = False,
) -> tuple[int, dict[str, Any], str]:
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            json=json_payload,
            timeout=timeout,
            verify=verify_tls,
        )
    except requests.RequestException as exc:
        raise RunnerError(
            "RUNNER_DEVICE_UNREACHABLE",
            "Device request failed before a response was received.",
            {"method": method, "url": _safe_url(url), "reason": exc.__class__.__name__},
            retryable=True,
        ) from exc

    text = response.text
    try:
        payload = response.json() if text else {}
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Device response is not valid JSON.",
            {"method": method, "url": _safe_url(url), "status_code": response.status_code},
        ) from exc
    if not isinstance(payload, dict):
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Device JSON response root must be an object.",
            {"method": method, "url": _safe_url(url), "status_code": response.status_code},
        )
    return response.status_code, payload, text


def request_text(
    url: str,
    *,
    timeout: float = 10,
    verify_tls: bool = False,
) -> str:
    try:
        response = requests.get(url, timeout=timeout, verify=verify_tls)
    except requests.RequestException as exc:
        raise RunnerError(
            "RUNNER_DEVICE_UNREACHABLE",
            "Device request failed before a response was received.",
            {"method": "GET", "url": _safe_url(url), "reason": exc.__class__.__name__},
            retryable=True,
        ) from exc
    if response.status_code != 200:
        raise RunnerError(
            "RUNNER_DEVICE_UNREACHABLE",
            "Device returned a non-success status while reading login assets.",
            {"method": "GET", "url": _safe_url(url), "status_code": response.status_code},
            retryable=True,
        )
    return response.text


def _safe_url(url: str) -> str:
    return url.split("?", 1)[0]

