"""NGFW PPPoE dial interface runner for PUT /api/v1/intf.

A PPPoE interface is configured through ``PUT /api/v1/intf`` with a fixed
interface shape and a pppoe block:

- The body is ``{"id": <intf id>, "val": {..., "pppoe": {"username":
  <user>, "password": <RSA ciphertext>}}}``.
- The PPPoE password is RSA-encrypted (PKCS1v15) with the same public key
  used by the web login flow. Plaintext only ever exists in the runner
  credential environment variable and is never written to output or repo.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import _encrypt_password, normalize_base_url
from atomic_ops.runner.session import read_session_file

SUCCESS_STATUS = {200, 201, 202}
PPPOE_PASSWORD_PLACEHOLDER = "<encrypted-at-execute>"
PPPOE_PATH = "/api/v1/intf"


def build_pppoe_payload(*, intf_id: str, username: str, dial_secret: str) -> dict[str, Any]:
    """Build the PUT body with the fixed PPPoE interface shape from the device capture."""
    return {
        "id": intf_id,
        "val": {
            "linkType": 0,
            "name": intf_id,
            "type": 3,
            "enabled": True,
            "vltype": "VPP",
            "mode": "Route",
            "service": {"https": False, "ssh": False, "ping": False},
            "sip": [],
            "smac": [],
            "ipv4_address_mode_config": {"address_mode": 2},
            "ipv6_address_mode_config": {
                "dhcp_client_setting": {},
                "address_mode": 0,
                "install_default_route": False,
            },
            "ip_addresses": [],
            "mtus": [1500, 0, 0, 0],
            "desc": "",
            "level": 100,
            "tag_rw_option": 0,
            "pppoe": {"username": username, "password": dial_secret},
        },
    }


def _validate_required(field: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Required PPPoE field is empty.",
            {"field": field},
        )


def build_pppoe_config_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    intf_id: str,
    username: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    _validate_required("id", intf_id)
    _validate_required("username", username)
    payload = build_pppoe_payload(intf_id=intf_id, username=username, dial_secret=PPPOE_PASSWORD_PLACEHOLDER)
    return {
        "op_id": "fw_config_pppoe",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "PUT",
            "url": f"{normalize_base_url(base_url)}{PPPOE_PATH}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "password_encryption": "RSA PKCS1v15 with the login public key at execute time",
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_pppoe_config(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    intf_id: str,
    username: str,
    password_env: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    _validate_required("id", intf_id)
    _validate_required("username", username)
    dial_secret = os.environ.get(password_env)
    if dial_secret is None or not dial_secret:
        raise RunnerError(
            "RUNNER_CREDENTIAL_MISSING",
            "PPPoE password environment variable is not set or is empty.",
            {"env": password_env},
        )
    encrypted_secret = _encrypt_password(base_url, dial_secret, timeout=timeout, verify_tls=verify_tls)
    payload = build_pppoe_payload(intf_id=intf_id, username=username, dial_secret=encrypted_secret)

    session_payload = read_session_file(session_file)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    status_code, response_payload, _text = request_json(
        "PUT",
        f"{normalize_base_url(base_url)}{PPPOE_PATH}",
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "PPPoE interface device request did not return a success status.",
            {
                "op_id": "fw_config_pppoe",
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    return {
        "op_id": "fw_config_pppoe",
        "status": "success",
        "status_code": status_code,
        "password_encrypted": True,
        "request": {
            "method": "PUT",
            "path": PPPOE_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }
