"""Small HTTP adapter used by runner commands."""

from __future__ import annotations

import time
from typing import Any, Callable

import requests

from atomic_ops.runner.errors import RunnerError


def request_json_with_retries(
    send: Callable[[], tuple[int, dict[str, Any], str]],
    *,
    retries: int = 0,
    backoff_seconds: float = 1.0,
) -> tuple[int, dict[str, Any], str]:
    """带可选重试地执行一次 ``request_json`` 形状的请求（P2 delete 未就绪缺口）。

    背景（下游现场 2026-09-08~09-11）：DUT 未就绪时 delete 直接 exit 46（
    RUNNER_DEVICE_UNREACHABLE、retryable=true），重试语义只作为信号交给调用方，
    runner 内没有 backoff/重试循环，清理步会直接失败。本 helper 提供**默认关闭**
    的内部重试（retries=0 时行为与直接调用 send() 完全一致，向后兼容）：
    - 仅对 ``RUNNER_DEVICE_UNREACHABLE`` 且 ``retryable=True`` 的失败重试——46 精确
      对应「根本没拿到响应」；设备可达但拒绝（48 CONFIG_REJECTED）不重试。
    - 退避为固定间隔 ``backoff_seconds``（简单可预期；不做指数退避，避免测试与
      现场排障时的时长不确定性）。
    - ``send`` 由调用方以 lambda 闭包传入（内部引用调用方模块命名空间的
      ``request_json``），既有 ``patch("<module>.request_json")`` 测试注入不受影响。
    """
    if retries < 0:
        raise ValueError("retries must be >= 0")
    if backoff_seconds < 0:
        raise ValueError("backoff_seconds must be >= 0")
    attempt = 0
    while True:
        try:
            return send()
        except RunnerError as exc:
            if (
                attempt >= retries
                or exc.error_code != "RUNNER_DEVICE_UNREACHABLE"
                or not exc.retryable
            ):
                raise
            attempt += 1
            if backoff_seconds > 0:
                time.sleep(backoff_seconds)


def request_json(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_payload: dict[str, Any] | None = None,
    params: dict[str, Any] | None = None,
    timeout: float = 10,
    verify_tls: bool = False,
) -> tuple[int, dict[str, Any], str]:
    try:
        response = requests.request(
            method,
            url,
            headers=headers,
            json=json_payload,
            params=params,
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


def request_bytes(
    method: str,
    url: str,
    *,
    headers: dict[str, str] | None = None,
    json_payload: dict[str, Any] | None = None,
    timeout: float = 10,
    verify_tls: bool = False,
) -> tuple[int, bytes]:
    """Issue a request and return ``(status_code, response_content)`` for non-JSON bodies.

    Used by export-file workflows where the response body is a file stream rather
    than JSON. Network failures map to ``RUNNER_DEVICE_UNREACHABLE`` to stay
    consistent with ``request_json``.

    ``json_payload`` exists because some endpoints answer a JSON request with a
    plain-text body: the CRL download trigger (``PUT /api/v1/cert/download``)
    replies with a bare ``tmpcert/<file>`` path, so it cannot use
    ``request_json`` (which rejects a non-JSON root). Default ``None`` keeps the
    existing bodyless callers byte-for-byte unchanged.
    """
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
    return response.status_code, response.content


def request_multipart(
    url: str,
    *,
    fields: dict[str, str] | None = None,
    files: dict[str, tuple] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float = 30,
    verify_tls: bool = False,
) -> tuple[int, dict[str, Any], str]:
    """POST a multipart form-data request and return ``(status_code, json_payload, text)``.

    ``fields`` are plain form fields; ``files`` follows the ``requests`` tuple
    convention ``(filename, fileobj, content_type)``. The JSON response shape
    mirrors ``request_json`` so existing success/error handling can be reused.
    """
    try:
        response = requests.post(
            url,
            data=fields,
            files=files,
            headers=headers,
            timeout=timeout,
            verify=verify_tls,
        )
    except requests.RequestException as exc:
        raise RunnerError(
            "RUNNER_DEVICE_UNREACHABLE",
            "Device request failed before a response was received.",
            {"method": "POST", "url": _safe_url(url), "reason": exc.__class__.__name__},
            retryable=True,
        ) from exc
    text = response.text
    try:
        payload = response.json() if text else {}
    except ValueError as exc:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Device response is not valid JSON.",
            {"method": "POST", "url": _safe_url(url), "status_code": response.status_code},
        ) from exc
    if not isinstance(payload, dict):
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Device JSON response root must be an object.",
            {"method": "POST", "url": _safe_url(url), "status_code": response.status_code},
        )
    return response.status_code, payload, text


def _safe_url(url: str) -> str:
    return url.split("?", 1)[0]

