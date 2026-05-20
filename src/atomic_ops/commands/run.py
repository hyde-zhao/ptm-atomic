"""Implementation for the atomic-ops run command."""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

import yaml

from atomic_ops.errors import CliError, write_error, write_warning
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import DEFAULT_SESSION_FILE, resolve_session_file


SUPPORTED_OPS = ("fw_login_web_management", "fw_config_object", "fw_config_policy_route")


def add_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("op_id", help="Operation id to run.")
    parser.add_argument(
        "--format",
        choices=("json", "yaml"),
        default="yaml",
        help="Output format.",
    )
    parser.add_argument(
        "--execute",
        action="store_true",
        help="Perform live device requests. Omit for dry-run.",
    )
    parser.add_argument(
        "--base-url",
        required=True,
        help="Device management base URL, for example https://10.0.0.1.",
    )
    parser.add_argument(
        "--session-file",
        default=str(DEFAULT_SESSION_FILE),
        help="Session file path. Defaults to ~/.local/state/atomic-ops/ngfw/session.json.",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=10.0,
        help="HTTP timeout in seconds.",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify the device TLS certificate. Disabled by default for lab NGFW devices.",
    )

    parser.add_argument("--username", help="NGFW web-management username for fw_login_web_management.")
    parser.add_argument(
        "--password-env",
        help="Environment variable containing the NGFW web-management password.",
    )
    parser.add_argument(
        "--change-default-password",
        action="store_true",
        help="Allow fw_login_web_management to call /api/v1/changeDefPwd when the device requires it.",
    )
    parser.add_argument(
        "--new-password-env",
        help="Environment variable containing the replacement password for --change-default-password.",
    )

    parser.add_argument("--object-name", help="Address-object name for fw_config_object.")
    parser.add_argument("--ipaddr", help="IPv4 address or network address for fw_config_object.")
    parser.add_argument("--mask", help="IPv4 mask length for fw_config_object, for example 16 or 24.")
    parser.add_argument("--object-desc", help="Optional address-object description.")

    parser.add_argument("--source-network", help="Policy-route source address object or address-group name.")
    parser.add_argument(
        "--source-network-is-group",
        action="store_true",
        help="Treat --source-network as an address-group name.",
    )
    parser.add_argument("--dst-network", default="any", help="Policy-route destination address object or address-group name.")
    parser.add_argument(
        "--dst-network-is-group",
        action="store_true",
        help="Treat --dst-network as an address-group name.",
    )
    parser.add_argument("--next-hop-ip", help="Policy-route forwarding next-hop IPv4 address.")
    parser.add_argument("--in-interface", help="Policy-route incoming interface.")
    parser.add_argument("--outgoing-interface", default="", help="Policy-route outgoing interface.")
    parser.add_argument("--service", default="any", help="Policy-route service object/name.")
    parser.add_argument("--weight", type=int, default=1, help="Policy-route forwarding path weight.")
    parser.add_argument("--time-obj", default="", help="Policy-route time object.")
    parser.add_argument(
        "--auth-header",
        choices=("Authorization", "AuthorizationToken"),
        default="Authorization",
        help="Authentication header used for object and policy-route execution.",
    )


def run(args: argparse.Namespace) -> int:
    output_format = getattr(args, "format", "yaml")
    try:
        if not getattr(args, "verify_tls"):
            write_warning(
                {
                    "warning_code": "TLS_VERIFY_DISABLED",
                    "message": "Device TLS verification is disabled for this runner invocation.",
                },
                output_format,
            )

        op_id = getattr(args, "op_id")
        if op_id == "fw_login_web_management":
            payload = _run_login(args)
        elif op_id == "fw_config_object":
            payload = _run_object(args)
        elif op_id == "fw_config_policy_route":
            payload = _run_policy_route(args)
        else:
            raise RunnerError(
                "RUNNER_UNSUPPORTED_OP",
                "Runner does not support this operation.",
                {"op_id": op_id, "supported_ops": list(SUPPORTED_OPS)},
                suggestion="Use atomic-ops adapter for unsupported operations, or add a dedicated runner.",
            )
        _write_output(_to_run_envelope(payload), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(
                exc.error_code,
                exc.message,
                exc.details,
                retryable=exc.retryable,
                suggestion=exc.suggestion,
            ),
            output_format,
        )


def _run_login(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.ngfw_login import build_login_dry_run, login
    from atomic_ops.runner.session import session_summary, write_session_file

    session_file = resolve_session_file(getattr(args, "session_file", None))
    username = getattr(args, "username") or "admin"
    if not getattr(args, "execute"):
        return build_login_dry_run(
            base_url=getattr(args, "base_url"),
            username=username,
            session_file=str(session_file),
            change_default_password=bool(getattr(args, "change_default_password")),
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )

    password_value = _read_secret_env(getattr(args, "password_env", None), "password_env")
    replacement_value = None
    if getattr(args, "change_default_password"):
        replacement_value = _read_secret_env(getattr(args, "new_password_env", None), "new_password_env")

    result = login(
        base_url=getattr(args, "base_url"),
        username=username,
        password_value=password_value,
        timeout=float(getattr(args, "timeout")),
        verify_tls=bool(getattr(args, "verify_tls")),
        change_default_password=bool(getattr(args, "change_default_password")),
        replacement_value=replacement_value,
    )
    session_payload = write_session_file(
        session_file,
        base_url=result["base_url"],
        username=username,
        session_value=result["session_value"],
        source_op_id="fw_login_web_management",
    )
    return {
        "op_id": "fw_login_web_management",
        "status": "success",
        "session": session_summary(session_file, session_payload),
    }


def _run_object(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.object import (
        build_address_object_dry_run,
        build_address_object_payload,
        execute_address_object,
    )

    session_file = resolve_session_file(getattr(args, "session_file", None))
    _require_arg(args, "object_name")
    _require_arg(args, "ipaddr")
    _require_arg(args, "mask")
    payload = build_address_object_payload(
        object_name=getattr(args, "object_name"),
        ipaddr=getattr(args, "ipaddr"),
        mask=getattr(args, "mask"),
        object_desc=getattr(args, "object_desc"),
    )
    if not getattr(args, "execute"):
        return build_address_object_dry_run(
            base_url=getattr(args, "base_url"),
            session_file=session_file,
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )
    return execute_address_object(
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout")),
    )


def _run_policy_route(args: argparse.Namespace) -> dict[str, Any]:
    from atomic_ops.runner.policy_route import (
        build_policy_route_dry_run,
        build_policy_route_payload,
        execute_policy_route,
    )

    session_file = resolve_session_file(getattr(args, "session_file", None))
    _require_arg(args, "source_network")
    _require_arg(args, "next_hop_ip")
    _require_arg(args, "in_interface")
    payload = build_policy_route_payload(
        source_network=getattr(args, "source_network"),
        source_network_is_group=bool(getattr(args, "source_network_is_group")),
        dst_network=getattr(args, "dst_network"),
        dst_network_is_group=bool(getattr(args, "dst_network_is_group")),
        next_hop_ip=getattr(args, "next_hop_ip"),
        in_interface=getattr(args, "in_interface"),
        outgoing_interface=getattr(args, "outgoing_interface"),
        service=getattr(args, "service"),
        weight=int(getattr(args, "weight")),
        time_obj=getattr(args, "time_obj"),
    )
    if not getattr(args, "execute"):
        return build_policy_route_dry_run(
            base_url=getattr(args, "base_url"),
            session_file=session_file,
            auth_header=getattr(args, "auth_header"),
            payload=payload,
            verify_tls=bool(getattr(args, "verify_tls")),
            timeout=float(getattr(args, "timeout")),
        )
    return execute_policy_route(
        base_url=getattr(args, "base_url"),
        session_file=session_file,
        auth_header=getattr(args, "auth_header"),
        payload=payload,
        verify_tls=bool(getattr(args, "verify_tls")),
        timeout=float(getattr(args, "timeout")),
    )


def _require_arg(args: argparse.Namespace, name: str) -> None:
    value = getattr(args, name)
    if value is None or (isinstance(value, str) and not value.strip()):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Missing required runner argument.",
            {"argument": f"--{name.replace('_', '-')}"},
        )


def _read_secret_env(env_name: str | None, field_name: str) -> str:
    if not env_name:
        raise RunnerError(
            "RUNNER_CREDENTIAL_MISSING",
            "Runner credential environment variable name is required.",
            {"missing": field_name},
        )
    value = os.environ.get(env_name)
    if value is None or not value:
        raise RunnerError(
            "RUNNER_CREDENTIAL_MISSING",
            "Runner credential environment variable is not set or is empty.",
            {"env": env_name},
        )
    return value


def _write_output(payload: dict[str, Any], output_format: str) -> None:
    safe_payload = _redact_runner_output(payload)
    if output_format == "json":
        print(json.dumps(safe_payload, ensure_ascii=False, sort_keys=True))
        return
    print(yaml.safe_dump(safe_payload, allow_unicode=True, sort_keys=False), end="")


def _to_run_envelope(payload: dict[str, Any]) -> dict[str, Any]:
    """Wrap runner-specific payloads in the stable operation return envelope."""

    data = dict(payload)
    op_id = data.pop("op_id", None)
    status = data.pop("status", None)
    error_type = data.pop("error_type", "NONE")
    diag_snapshot_ref = data.pop("diag_snapshot_ref", "")

    envelope: dict[str, Any] = {
        "status": status or "success",
        "data": data,
        "error_type": error_type,
        "diag_snapshot_ref": diag_snapshot_ref,
    }
    if op_id is not None:
        envelope["op_id"] = op_id
    return envelope


def _redact_runner_output(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, inner in value.items():
            if key in {"session_value", "passwd", "oldpasswd"}:
                redacted[key] = "[REDACTED]"
            else:
                redacted[key] = _redact_runner_output(inner)
        return redacted
    if isinstance(value, list):
        return [_redact_runner_output(item) for item in value]
    return value
