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
# cli 族操作的凭据与 web 登录共用同一组 admin 凭据，默认键名取 FW_WEB_PASSWORD
DEFAULT_CREDENTIAL_ENV = "FW_WEB_PASSWORD"
# vppctl 相关操作需要 root 权限，root 凭据默认键名取 FW_SSH_PASSWORD（与 web 登录 admin 凭据不同）
MAC_AGE_CREDENTIAL_ENV = "FW_SSH_PASSWORD"


def _resolve_credential_env(credential_env: str | None, *, default: str = DEFAULT_CREDENTIAL_ENV) -> str:
    """Return the effective credential env var name; ``default`` names the fallback key."""
    return credential_env or default


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
        help="Name of the environment variable holding the password/credential. Loaded from .env; defaults to the operation's credential key (FW_WEB_PASSWORD for admin ops, FW_SSH_PASSWORD for root vppctl ops).",
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
            name="verify-l2fib",
            help="Query the L2FIB table via the tgfw-cli interactive shell over SSH/Telnet (show l2fib all).",
            description="Connect to the device, enter the tgfw-cli interactive shell, run 'show l2fib all', and parse the L2FIB table.",
            handler=_run_verify_l2fib,
            add_args=_add_verify_l2fib_args,
        ),
        CommandSpec(
            name="set-mac-age",
            help="Set VPP bridge-domain MAC ageing time over SSH/Telnet (vppctl set bridge-domain mac-age).",
            description="Run 'vppctl set bridge-domain mac-age <id> <mins>' as root and re-read the domain to confirm the Age(min) took effect.",
            handler=_run_set_mac_age,
            add_args=_add_set_mac_age_args,
        ),
        CommandSpec(
            name="verify-mac-age",
            help="Query VPP bridge-domain MAC ageing time over SSH/Telnet (vppctl show bridge-domain <id>).",
            description="Run 'vppctl show bridge-domain <id>' as root and parse the Age(min) column.",
            handler=_run_verify_mac_age,
            add_args=_add_verify_mac_age_args,
        ),
        CommandSpec(
            name="verify-neighbor-probe",
            help="Query VPP IP neighbor table to verify ARP phase/aging probes over SSH/Telnet.",
            description="Read the VPP IP neighbor table (vppctl show ip neighbor) and optionally assert an IP/interface/phase.",
            handler=_run_verify_neighbor_probe,
            add_args=_add_verify_neighbor_probe_args,
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
            credential_env = _resolve_credential_env(getattr(args, "credential_env", None))
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
            credential_env = _resolve_credential_env(getattr(args, "credential_env", None))
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


def _add_verify_l2fib_args(parser: argparse.ArgumentParser) -> None:
    _add_transport_args(parser)


def _run_verify_l2fib(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ssh import (
        build_verify_l2fib_dry_run,
        execute_verify_l2fib,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        if not ctx.get("execute"):
            result = build_verify_l2fib_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            credential_env = _resolve_credential_env(getattr(args, "credential_env", None))
            result = execute_verify_l2fib(
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
            credential_env = _resolve_credential_env(getattr(args, "credential_env", None))
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


def _add_mac_age_args(parser: argparse.ArgumentParser) -> None:
    """Register the shared mac-age args: transport + username + bridge-domain-id."""
    _add_transport_args(parser)
    parser.add_argument(
        "--username",
        default="root",
        help="SSH/Telnet username; defaults to root (vppctl requires root privileges).",
    )
    parser.add_argument(
        "--bridge-domain-id",
        type=int,
        required=True,
        help="VPP bridge-domain ID (1-4094).",
    )


def _add_set_mac_age_args(parser: argparse.ArgumentParser) -> None:
    _add_mac_age_args(parser)
    parser.add_argument(
        "--age-minutes",
        type=int,
        required=True,
        help="MAC ageing time in minutes (0 disables ageing).",
    )


def _add_verify_mac_age_args(parser: argparse.ArgumentParser) -> None:
    _add_mac_age_args(parser)


def _run_set_mac_age(args: argparse.Namespace) -> int:
    return _run_mac_age(args, "fw_config_bridge_domain_mac_age")


def _run_verify_mac_age(args: argparse.Namespace) -> int:
    return _run_mac_age(args, "fw_verify_bridge_domain_mac_age")


def _run_mac_age(args: argparse.Namespace, op_id: str) -> int:
    from atomic_ops.runner.ssh import (
        build_config_bridge_domain_mac_age_dry_run,
        build_verify_bridge_domain_mac_age_dry_run,
        execute_config_bridge_domain_mac_age,
        execute_verify_bridge_domain_mac_age,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        username = getattr(args, "username", "root")
        bridge_domain_id = int(getattr(args, "bridge_domain_id"))
        if not ctx.get("execute"):
            if op_id == "fw_config_bridge_domain_mac_age":
                result = build_config_bridge_domain_mac_age_dry_run(
                    base_url=ctx["base_url"],
                    session_file=session_file,
                    transport=transport,
                    host=host,
                    port=port,
                    username=username,
                    bridge_domain_id=bridge_domain_id,
                    age_minutes=int(getattr(args, "age_minutes")),
                    timeout=float(ctx.get("timeout", 10.0)),
                )
            else:
                result = build_verify_bridge_domain_mac_age_dry_run(
                    base_url=ctx["base_url"],
                    session_file=session_file,
                    transport=transport,
                    host=host,
                    port=port,
                    username=username,
                    bridge_domain_id=bridge_domain_id,
                    timeout=float(ctx.get("timeout", 10.0)),
                )
        else:
            credential_env = _resolve_credential_env(
                getattr(args, "credential_env", None), default=MAC_AGE_CREDENTIAL_ENV
            )
            if op_id == "fw_config_bridge_domain_mac_age":
                result = execute_config_bridge_domain_mac_age(
                    base_url=ctx["base_url"],
                    session_file=session_file,
                    transport=transport,
                    host=host,
                    port=port,
                    username=username,
                    credential_env=credential_env,
                    bridge_domain_id=bridge_domain_id,
                    age_minutes=int(getattr(args, "age_minutes")),
                    timeout=float(ctx.get("timeout", 10.0)),
                )
            else:
                result = execute_verify_bridge_domain_mac_age(
                    base_url=ctx["base_url"],
                    session_file=session_file,
                    transport=transport,
                    host=host,
                    port=port,
                    username=username,
                    credential_env=credential_env,
                    bridge_domain_id=bridge_domain_id,
                    timeout=float(ctx.get("timeout", 10.0)),
                )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )


def _add_verify_neighbor_probe_args(parser: argparse.ArgumentParser) -> None:
    _add_transport_args(parser)
    parser.add_argument(
        "--username",
        default=None,
        help="SSH login user; defaults to the web session username (admin). "
             "The FW CLI user is usually 'root'.",
    )
    parser.add_argument(
        "--expected-ip",
        help="Optional neighbor IP to assert present in the VPP neighbor table.",
    )
    parser.add_argument(
        "--expected-interface",
        help="Optional interface to filter the asserted neighbor rows.",
    )
    parser.add_argument(
        "--expected-phase",
        help="Optional phase value to assert on the matched rows (e.g. alive, probing, dead).",
    )


def _run_verify_neighbor_probe(args: argparse.Namespace) -> int:
    from atomic_ops.runner.ssh import (
        build_verify_neighbor_probe_dry_run,
        execute_verify_neighbor_probe,
    )

    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        transport = getattr(args, "transport", DEFAULT_TRANSPORT)
        host = getattr(args, "host", None)
        port = getattr(args, "port", None)
        expected_ip = getattr(args, "expected_ip", None)
        expected_interface = getattr(args, "expected_interface", None)
        expected_phase = getattr(args, "expected_phase", None)
        username = getattr(args, "username", None)
        if not ctx.get("execute"):
            result = build_verify_neighbor_probe_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                username=username,
                expected_ip=expected_ip,
                expected_interface=expected_interface,
                expected_phase=expected_phase,
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
            result = execute_verify_neighbor_probe(
                base_url=ctx["base_url"],
                session_file=session_file,
                transport=transport,
                host=host,
                port=port,
                username=username,
                credential_env=credential_env,
                expected_ip=expected_ip,
                expected_interface=expected_interface,
                expected_phase=expected_phase,
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
