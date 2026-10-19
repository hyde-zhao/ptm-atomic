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
    parser.add_argument(
        "--username",
        help="SSH/Telnet username; defaults to the session username (admin). Set to root for NGFW device SSH.",
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
        CommandSpec(
            name="verify-process-state",
            help="Check vpp/dnsmasq/agent process state over SSH (pgrep).",
            description="pgrep the process command line; a numeric pid means the process is running.",
            handler=_run_verify_process_state,
            add_args=_add_process_args,
        ),
        CommandSpec(
            name="kill-process",
            help="Kill vpp/dnsmasq/agent by pid over SSH (auto-restarts).",
            description="kill -9 <pid>; the device supervisor restarts the process automatically.",
            handler=_run_kill_process,
            add_args=_add_kill_args,
        ),
        CommandSpec(
            name="config-dns-diag",
            help="Run DNS resolution diagnostics over SSH (ping/traceroute).",
            description="ping or traceroute a domain from the firewall to verify local DNS resolution.",
            handler=_run_config_dns_diag,
            add_args=_add_dns_diag_args,
        ),
        CommandSpec(
            name="verify-iplink-etcd",
            help="Query iplink backend etcd config over SSH/Telnet (etcdctl get .../iplink/<name>).",
            description="Read an iplink entry's backend etcd config over SSH or Telnet.",
            handler=_run_verify_iplink_etcd,
            add_args=_add_verify_iplink_etcd_args,
        ),
        CommandSpec(
            name="verify-linkgroup-etcd",
            help="Query iplink-group backend etcd config over SSH/Telnet (etcdctl get .../linkgroup/<name>).",
            description="Read an iplink-group entry's backend etcd config over SSH or Telnet.",
            handler=_run_verify_iplink_group_etcd,
            add_args=_add_verify_iplink_group_etcd_args,
        ),
        CommandSpec(
            name="verify-iplink-status-etcd",
            help="Verify iplink status key (up/down) in etcd over SSH (etcdctl get .../status/iplink/<name>/<state>).",
            description="Verify an iplink entry's reachability status key in etcd over SSH or Telnet.",
            handler=_run_verify_iplink_status_etcd,
            add_args=_add_verify_iplink_status_etcd_args,
        ),
        CommandSpec(
            name="verify-linkgroup-status-etcd",
            help="Verify iplink-group status key (up/down) in etcd over SSH (etcdctl get .../status/iplink/<name>/<state>).",
            description="Verify an iplink-group entry's reachability status key in etcd over SSH or Telnet.",
            handler=_run_verify_iplink_group_status_etcd,
            add_args=_add_verify_iplink_group_status_etcd_args,
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


def _add_process_args(parser: argparse.ArgumentParser) -> None:
    _add_transport_args(parser)
    parser.add_argument(
        "--process",
        choices=("vpp", "dnsmasq", "agent"),
        required=True,
        help="Process to inspect: vpp, dnsmasq, or agent.",
    )


def _add_kill_args(parser: argparse.ArgumentParser) -> None:
    _add_transport_args(parser)
    parser.add_argument(
        "--process",
        choices=("vpp", "dnsmasq", "agent"),
        required=True,
        help="Process being killed (vpp, dnsmasq, or agent) for context.",
    )
    parser.add_argument(
        "--pid",
        required=True,
        help="Process id to kill; obtain it via verify-process-state.",
    )


def _add_dns_diag_args(parser: argparse.ArgumentParser) -> None:
    _add_transport_args(parser)
    parser.add_argument(
        "--domain",
        required=True,
        help="Domain name resolved by the firewall, e.g. www.baidu.com.",
    )
    parser.add_argument(
        "--mode",
        choices=("ping", "traceroute"),
        required=True,
        help="Diagnostic command: ping -c 3 <domain> or traceroute <domain>.",
    )


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


def _run_verify_process_state(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ssh import (
        build_verify_process_state_dry_run,
        execute_verify_process_state,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        process = getattr(args, "process")
        if not ctx.get("execute"):
            result = build_verify_process_state_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                process=process,
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
            result = execute_verify_process_state(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                credential_env=credential_env,
                process=process,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _run_kill_process(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ssh import (
        build_kill_process_dry_run,
        execute_kill_process,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        process = getattr(args, "process")
        pid = getattr(args, "pid")
        if not ctx.get("execute"):
            result = build_kill_process_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                process=process,
                pid=pid,
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
            result = execute_kill_process(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                credential_env=credential_env,
                process=process,
                pid=pid,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _run_config_dns_diag(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ssh import (
        build_dns_diag_dry_run,
        execute_dns_diag,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        domain = getattr(args, "domain")
        mode = getattr(args, "mode")
        if not ctx.get("execute"):
            result = build_dns_diag_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                domain=domain,
                mode=mode,
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
            result = execute_dns_diag(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                credential_env=credential_env,
                domain=domain,
                mode=mode,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _add_verify_iplink_etcd_args(parser: argparse.ArgumentParser) -> None:
    _add_transport_args(parser)
    parser.add_argument(
        "--name",
        required=True,
        help="Iplink name substituted into the etcd key path /vnf-agent/.../iplink/v1/iplink/<name>.",
    )


def _run_verify_iplink_etcd(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ssh import (
        build_verify_iplink_etcd_dry_run,
        execute_verify_iplink_etcd,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        username = getattr(args, "username", None)
        name = getattr(args, "name")
        if not ctx.get("execute"):
            result = build_verify_iplink_etcd_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                username=username,
                name=name,
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
            result = execute_verify_iplink_etcd(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                username=username,
                credential_env=credential_env,
                name=name,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _add_verify_iplink_group_etcd_args(parser: argparse.ArgumentParser) -> None:
    _add_transport_args(parser)
    parser.add_argument(
        "--name",
        required=True,
        help="Iplink-group name substituted into the etcd key path /vnf-agent/.../iplink/v1/linkgroup/<name>.",
    )


def _run_verify_iplink_group_etcd(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ssh import (
        build_verify_iplink_group_etcd_dry_run,
        execute_verify_iplink_group_etcd,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        username = getattr(args, "username", None)
        name = getattr(args, "name")
        if not ctx.get("execute"):
            result = build_verify_iplink_group_etcd_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                username=username,
                name=name,
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
            result = execute_verify_iplink_group_etcd(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                username=username,
                credential_env=credential_env,
                name=name,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _add_verify_iplink_status_etcd_args(parser: argparse.ArgumentParser) -> None:
    _add_transport_args(parser)
    parser.add_argument(
        "--name",
        required=True,
        help="Iplink name substituted into the etcd status key path.",
    )
    parser.add_argument(
        "--state",
        required=True,
        choices=("up", "down"),
        help="Expected state to verify: up (reachable) or down (unreachable).",
    )


def _run_verify_iplink_status_etcd(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ssh import (
        build_verify_iplink_status_etcd_dry_run,
        execute_verify_iplink_status_etcd,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        username = getattr(args, "username", None)
        name = getattr(args, "name")
        state = getattr(args, "state")
        if not ctx.get("execute"):
            result = build_verify_iplink_status_etcd_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                username=username,
                name=name,
                state=state,
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
            result = execute_verify_iplink_status_etcd(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                username=username,
                credential_env=credential_env,
                name=name,
                state=state,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _add_verify_iplink_group_status_etcd_args(parser: argparse.ArgumentParser) -> None:
    _add_transport_args(parser)
    parser.add_argument(
        "--name",
        required=True,
        help="Iplink-group name substituted into the etcd status key path.",
    )
    parser.add_argument(
        "--state",
        required=True,
        choices=("up", "down"),
        help="Expected state to verify: up (reachable) or down (unreachable).",
    )


def _run_verify_iplink_group_status_etcd(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ssh import (
        build_verify_iplink_group_status_etcd_dry_run,
        execute_verify_iplink_group_status_etcd,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        username = getattr(args, "username", None)
        name = getattr(args, "name")
        state = getattr(args, "state")
        if not ctx.get("execute"):
            result = build_verify_iplink_group_status_etcd_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                username=username,
                name=name,
                state=state,
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
            result = execute_verify_iplink_group_status_etcd(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                username=username,
                credential_env=credential_env,
                name=name,
                state=state,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
