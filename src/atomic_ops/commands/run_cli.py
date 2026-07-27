"""CLI (SSH/Telnet) runner commands for shell-based verification atoms.

Each subcommand accepts a ``--transport ssh|telnet`` parameter to select the
underlying transport at runtime, defaulting to ssh. The atom's ``transport``
field declares the default; the runtime parameter overrides it.
"""

from __future__ import annotations

import argparse

from atomic_ops.commands import CommandSpec
from atomic_ops.commands.run import (
    _to_run_envelope,
    _write_output,
    resolve_run_context,
)
from atomic_ops.errors import CliError, write_error
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file


SUPPORTED_TRANSPORTS = ("ssh", "telnet")
DEFAULT_TRANSPORT = "ssh"


def _add_transport_args(parser: argparse.ArgumentParser) -> None:
    """Register the shared --transport / --host / --port / --credential-env args."""
    parser.add_argument(
        "--transport",
        choices=SUPPORTED_TRANSPORTS,
        default=DEFAULT_TRANSPORT,
        help="Network transport used by the runner. Defaults to ssh.",
    )
    parser.add_argument(
        "--host",
        help="Target host; defaults to the host parsed from --base-url. Useful when the SSH/Telnet target differs from the management host.",
    )
    parser.add_argument(
        "--port",
        type=int,
        help="TCP port; defaults to 22 for ssh and 23 for telnet.",
    )
    parser.add_argument(
        "--credential-env",
        help="Name of the environment variable holding the password/credential. Required for --execute.",
    )


def build_subtree() -> tuple[CommandSpec, ...]:
    return (
        CommandSpec(
            name="verify-system-version",
            help="Verify NGFW system version over SSH/Telnet (cat /appdata/etc/version).",
            description="Read /appdata/etc/version over SSH or Telnet and optionally assert a version string.",
            handler=_run_verify_system_version,
            add_args=_add_verify_system_version_args,
        ),
        CommandSpec(
            name="check-bvi-interface-config",
            help="Query BVI interface config from etcd over SSH/Telnet (etcdctl get .../bvi<id>).",
            description="Read the BVI interface configuration from etcd over SSH or Telnet.",
            handler=_run_check_bvi_interface_config,
            add_args=_add_check_bvi_interface_config_args,
        ),
        CommandSpec(
            name="check-bridge-domain",
            help="Query VPP bridge-domain table over SSH/Telnet (vppctl show bridge-domain).",
            description="Read the VPP bridge-domain table over SSH or Telnet.",
            handler=_run_check_bridge_domain,
            add_args=_add_check_bridge_domain_args,
        ),
    )


def _add_verify_system_version_args(parser: argparse.ArgumentParser) -> None:
    _add_transport_args(parser)
    parser.add_argument(
        "--expected-version",
        help="Optional version string to assert against the device version file output.",
    )


def _run_verify_system_version(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ssh import (
        build_verify_system_version_dry_run,
        execute_verify_system_version,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        expected_version = getattr(args, "expected_version", None)
        if not ctx.get("execute"):
            result = build_verify_system_version_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                expected_version=expected_version,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            credential_env = getattr(args, "credential_env", None)
            if not credential_env:
                raise RunnerError(
                    "RUNNER_CREDENTIAL_MISSING",
                    "--credential-env is required when using --execute.",
                    {"missing": "credential_env"},
                )
            result = execute_verify_system_version(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                credential_env=credential_env,
                expected_version=expected_version,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _add_check_bvi_interface_config_args(parser: argparse.ArgumentParser) -> None:
    _add_transport_args(parser)
    parser.add_argument(
        "--bvi-id",
        required=True,
        help="BVI interface identifier substituted into the etcd key path.",
    )


def _run_check_bvi_interface_config(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ssh import (
        build_check_bvi_interface_config_dry_run,
        execute_check_bvi_interface_config,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        bvi_id = getattr(args, "bvi_id")
        if not ctx.get("execute"):
            result = build_check_bvi_interface_config_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                bvi_id=bvi_id,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            credential_env = getattr(args, "credential_env", None)
            if not credential_env:
                raise RunnerError(
                    "RUNNER_CREDENTIAL_MISSING",
                    "--credential-env is required when using --execute.",
                    {"missing": "credential_env"},
                )
            result = execute_check_bvi_interface_config(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                credential_env=credential_env,
                bvi_id=bvi_id,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _add_check_bridge_domain_args(parser: argparse.ArgumentParser) -> None:
    _add_transport_args(parser)


def _run_check_bridge_domain(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ssh import (
        build_check_bridge_domain_dry_run,
        execute_check_bridge_domain,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        if not ctx.get("execute"):
            result = build_check_bridge_domain_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            credential_env = getattr(args, "credential_env", None)
            if not credential_env:
                raise RunnerError(
                    "RUNNER_CREDENTIAL_MISSING",
                    "--credential-env is required when using --execute.",
                    {"missing": "credential_env"},
                )
            result = execute_check_bridge_domain(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                credential_env=credential_env,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
