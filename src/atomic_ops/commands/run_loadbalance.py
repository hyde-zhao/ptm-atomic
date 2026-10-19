"""CLI runner commands for link load-balance policy atoms (链路负载分担)."""

from __future__ import annotations

import argparse

from atomic_ops.commands import CommandGroup, CommandSpec
from atomic_ops.commands.run import (
    _to_run_envelope,
    _write_output,
    resolve_run_context,
)
from atomic_ops.errors import CliError, write_error
from atomic_ops.runner.errors import RunnerError
from atomic_ops.runner.session import resolve_session_file
from atomic_ops.runner.loadbalance import (
    _build_payload,
    build_link_loadbalance_dry_run,
    execute_link_loadbalance,
)


def build_subtree() -> tuple[CommandGroup, ...]:
    return (
        CommandGroup(
            name="loadbalance",
            help="Link load-balance policy operations.",
            description="Create/verify link load-balance policy (链路负载分担).",
            children=(
                CommandSpec(
                    name="config",
                    help="Create a link load-balance policy.",
                    description="Create a new link load-balance policy via /api/v1/loadbalancepolicy.",
                    handler=_run_config,
                    add_args=_add_config_args,
                ),
            ),
        ),
    )

def _add_config_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--name", required=True, help="Policy name.")
    parser.add_argument("--mode", type=int, required=True, choices=(1, 2, 4),
                        help="Load-balance mode: 1=链路带宽, 2=链路权重, 4=链路主备备份.")
    parser.add_argument("--enable", action="store_true", default=True, help="Enable policy (default).")
    parser.add_argument("--interface", action="append", required=True,
                        help="Egress interface name. May be repeated (need >=2).")
    parser.add_argument("--session-hold", action="store_true", help="Enable session hold.")
    parser.add_argument("--overload-protection", action="store_true", help="Enable overload protection.")
    parser.add_argument("--payload-file", help="Path to a complete JSON request payload.")
    parser.add_argument("--payload-json", help="Complete JSON request payload.")


def _run_config(args: argparse.Namespace) -> int:
    ctx = resolve_run_context(args)
    output_format = ctx.get("output_format", "yaml")
    try:
        session_file = resolve_session_file(ctx.get("session_file"))
        payload = _build_payload(
            name=getattr(args, "name"),
            enable=bool(getattr(args, "enable", True)),
            mode=int(getattr(args, "mode", 1)),
            interfaces=list(getattr(args, "interface") or []),
            session_hold=bool(getattr(args, "session_hold", False)),
            overload_protection=bool(getattr(args, "overload_protection", False)),
            payload_file=getattr(args, "payload_file", None),
            payload_json=getattr(args, "payload_json", None),
        )
        if not ctx.get("execute"):
            result = build_link_loadbalance_dry_run(
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        else:
            result = execute_link_loadbalance(
                base_url=ctx["base_url"],
                session_file=session_file,
                auth_header=ctx.get("auth_header", "Authorization"),
                payload=payload,
                verify_tls=bool(ctx.get("verify_tls")),
                timeout=float(ctx.get("timeout", 10.0)),
            )
        _write_output(_to_run_envelope(result), output_format)
        return 0
    except RunnerError as exc:
        return write_error(
            CliError(exc.error_code, exc.message, exc.details, retryable=exc.retryable, suggestion=exc.suggestion),
            output_format,
        )
