"""NGFW web-management login runner."""

from __future__ import annotations

import base64
import re
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding

from atomic_ops.runner.errors import CREDENTIAL_INJECTION_HINT, RunnerError
from atomic_ops.runner.http import request_json, request_text


PUBLIC_KEY_SCRIPT_RE = re.compile(r'src="(/js/ras_public_key\.\d+\.js)"')


def build_login_dry_run(
    *,
    base_url: str,
    username: str,
    session_file: str,
    change_default_password: bool,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    normalized = normalize_base_url(base_url)
    return {
        "op_id": "fw_login_web_management",
        "status": "dry_run",
        "execute_required": True,
        "request_plan": [
            {"method": "GET", "path": "/index.html"},
            {"method": "GET", "path": "/js/ras_public_key.<version>.js"},
            {"method": "PUT", "path": "/api/v1/auth"},
        ],
        "base_url": normalized,
        "username": username,
        "session_file": session_file,
        "change_default_password": change_default_password,
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def login(
    *,
    base_url: str,
    username: str,
    password_value: str,
    timeout: float,
    verify_tls: bool,
    change_default_password: bool,
    replacement_value: str | None,
) -> dict[str, Any]:
    normalized = normalize_base_url(base_url)
    result = _login_once(
        base_url=normalized,
        username=username,
        password_value=password_value,
        timeout=timeout,
        verify_tls=verify_tls,
    )

    if result.get("errCode") == "eChangDeafPwd":
        if not change_default_password:
            raise RunnerError(
                "RUNNER_LOGIN_FAILED",
                "Device requires default password change before login can complete.",
                {"err_code": "eChangDeafPwd"},
                suggestion="Pass --change-default-password and --new-password-env to allow this explicit high-risk action.",
            )
        if replacement_value is None or not replacement_value:
            # STORY-S6-02：凭据缺失（替换值环境变量未注入）与认证失败分层；文案用
            # 下划线形式变量名（new_password_env），避免独立词 password 触发输出层
            # 整行 REDACT
            raise RunnerError(
                "RUNNER_CREDENTIAL_MISSING",
                "Default credential change requires a non-empty value in the "
                "replacement environment variable (new_password_env).",
                {"missing": "new_password_env"},
                suggestion=CREDENTIAL_INJECTION_HINT,
            )
        change_result = _change_default_password(
            base_url=normalized,
            username=username,
            old_value=password_value,
            replacement_value=replacement_value,
            timeout=timeout,
            verify_tls=verify_tls,
        )
        if change_result.get("errCode"):
            raise RunnerError(
                "RUNNER_LOGIN_FAILED",
                "Default password change was rejected by the device.",
                {"err_code": change_result.get("errCode"), "err_msg": change_result.get("errMsg")},
            )
        result = _login_once(
            base_url=normalized,
            username=username,
            password_value=replacement_value,
            timeout=timeout,
            verify_tls=verify_tls,
        )

    session_value = result.get("token")
    if not isinstance(session_value, str) or not session_value.strip():
        err_code = result.get("errCode")
        if err_code:
            # STORY-S6-02：设备明确拒绝认证（口令错/凭据失效），与凭据缺失
            # （RUNNER_CREDENTIAL_MISSING，exit 43）分层；文案避开独立词
            # password/token（输出层整行 REDACT）
            raise RunnerError(
                "RUNNER_LOGIN_FAILED",
                "Authentication rejected by device (invalid credential or expired session).",
                {"err_code": err_code, "err_msg": result.get("errMsg")},
            )
        raise RunnerError(
            "RUNNER_LOGIN_FAILED",
            "Login response did not contain a session reference.",
            {"err_code": err_code, "err_msg": result.get("errMsg")},
        )
    return {
        "base_url": normalized,
        "username": username,
        "session_value": session_value,
        "raw_result": result,
    }


def normalize_base_url(base_url: str) -> str:
    if not base_url.startswith(("https://", "http://")):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Base URL must include http:// or https://.",
            {"base_url": base_url},
        )
    return base_url.rstrip("/")


def _login_once(
    *,
    base_url: str,
    username: str,
    password_value: str,
    timeout: float,
    verify_tls: bool,
) -> dict[str, Any]:
    encrypted_value = _encrypt_password(base_url, password_value, timeout=timeout, verify_tls=verify_tls)
    payload = {
        "id": username,
        "val": {
            "username": username,
            "passwd": encrypted_value,
            "action": "login",
            "autht": 0,
            "code": "",
        },
    }
    status_code, result, _text = request_json(
        "PUT",
        f"{base_url}/api/v1/auth",
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code < 200 or status_code >= 300:
        if status_code in (401, 403):
            # STORY-S6-02：HTTP 401/403 属认证被拒，与凭据缺失（exit 43）分层
            raise RunnerError(
                "RUNNER_LOGIN_FAILED",
                f"Authentication rejected by device (HTTP {status_code}).",
                {"status_code": status_code},
            )
        # 设备对「需要修改默认密码」用 **HTTP 400 + body errCode（eChangDeafPwd）** 表达
        # （DUT3 实测 2026-09-21：`{"errCode":"eChangDeafPwd","errMsg":"需要修改默认密码后才能登录"}`）。
        # 原实现在此一律抛错，令上层 `login()` 的 `errCode == "eChangDeafPwd"` 分支
        # **不可达**（`--change-default-password` 形同虚设）。故非 2xx 且 body 带 errCode 时
        # 原样上抛该 errCode 交由上层分流：eChangDeafPwd -> 走 changeDefPwd；其余 -> 由
        # `login()` 统一抛 RUNNER_LOGIN_FAILED（语义不变，错误码来源从 HTTP 状态变为设备 errCode）。
        err_code = result.get("errCode") if isinstance(result, dict) else None
        if err_code:
            return {
                "errCode": err_code,
                "errMsg": result.get("errMsg"),
                "status_code": status_code,
            }
        raise RunnerError(
            "RUNNER_LOGIN_FAILED",
            "Login request returned a non-success status.",
            {"status_code": status_code},
        )
    return result


def _change_default_password(
    *,
    base_url: str,
    username: str,
    old_value: str,
    replacement_value: str,
    timeout: float,
    verify_tls: bool,
) -> dict[str, Any]:
    encrypted_old = _encrypt_password(base_url, old_value, timeout=timeout, verify_tls=verify_tls)
    encrypted_new = _encrypt_password(base_url, replacement_value, timeout=timeout, verify_tls=verify_tls)
    payload = {
        "id": username,
        "val": {
            "username": username,
            "passwd": encrypted_new,
            "oldpasswd": encrypted_old,
        },
    }
    status_code, result, _text = request_json(
        "PUT",
        f"{base_url}/api/v1/changeDefPwd",
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code < 200 or status_code >= 300:
        raise RunnerError(
            "RUNNER_LOGIN_FAILED",
            "Default password change returned a non-success status.",
            {"status_code": status_code},
        )
    return result


def _encrypt_password(base_url: str, password_value: str, *, timeout: float, verify_tls: bool) -> str:
    public_key_pem = _get_public_key(base_url, timeout=timeout, verify_tls=verify_tls)
    public_key = serialization.load_pem_public_key(public_key_pem.encode("utf-8"))
    encrypted_bytes = public_key.encrypt(
        password_value.encode("utf-8"),
        padding.PKCS1v15(),
    )
    return base64.b64encode(encrypted_bytes).decode("utf-8")


def _get_public_key(base_url: str, *, timeout: float, verify_tls: bool) -> str:
    index_text = request_text(f"{base_url}/index.html", timeout=timeout, verify_tls=verify_tls)
    matches = PUBLIC_KEY_SCRIPT_RE.findall(index_text)
    if not matches:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Login page did not reference the RSA public key script.",
            {"path": "/index.html"},
        )
    script_text = request_text(f"{base_url}{matches[0]}", timeout=timeout, verify_tls=verify_tls)
    public_key_pem = (
        script_text.replace("\\n' +", "")
        .replace("var __PUBLIC_KEY__ =  ", "")
        .replace("'", "")
        .replace("  ", "")
        .strip()
    )
    if "BEGIN PUBLIC KEY" not in public_key_pem:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "RSA public key script did not contain a PEM public key.",
            {"path": matches[0]},
        )
    return public_key_pem


def build_logout_dry_run(
    *,
    base_url: str,
    session_file: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    normalized = normalize_base_url(base_url)
    return {
        "op_id": "fw_logout_web_management",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "path": "/api/v1/logout",
        },
        "base_url": normalized,
        "session_file": session_file,
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def logout(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    from atomic_ops.runner.session import read_session_file

    normalized = normalize_base_url(base_url)
    # CR-059：logout 也校验 session 文件与目标设备 base_url 绑定
    session_payload = read_session_file(session_file, expect_base_url=normalized)
    session_value = str(session_payload["session_value"])
    headers = {auth_header: f"Bearer {session_value}"}
    status_code, result, _text = request_json(
        "GET",
        f"{normalized}/api/v1/logout",
        headers=headers,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success = 200 <= status_code < 300
    return {
        "op_id": "fw_logout_web_management",
        "status": "success" if success else "failed",
        "status_code": status_code,
        "logout": success,
        "response": result,
    }

