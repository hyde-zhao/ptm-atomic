"""Command-line entry point for atomic-ops."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from atomic_ops import __version__
from atomic_ops.commands import adapter as adapter_command
from atomic_ops.commands import list_ops as list_command
from atomic_ops.commands import packages as packages_command
from atomic_ops.commands import run as run_command
from atomic_ops.commands import show as show_command
from atomic_ops.commands import sync as sync_command
from atomic_ops.commands import validate as validate_command


EXIT_NOT_IMPLEMENTED = 2


@dataclass(frozen=True)
class CommandSpec:
    name: str
    help: str
    description: str


COMMANDS: tuple[CommandSpec, ...] = (
    CommandSpec(
        name="sync",
        help="Synchronize the local atomic operation repository cache.",
        description="Synchronize the local atomic operation repository cache.",
    ),
    CommandSpec(
        name="list",
        help="List available atomic operations.",
        description="List available atomic operations.",
    ),
    CommandSpec(
        name="show",
        help="Show one atomic operation by op_id.",
        description="Show one atomic operation by op_id.",
    ),
    CommandSpec(
        name="adapter",
        help="Show one adapter profile operation by op_id.",
        description="Show one adapter profile operation by op_id.",
    ),
    CommandSpec(
        name="run",
        help="Run a supported atomic operation against an NGFW device.",
        description="Run a supported atomic operation against an NGFW device.",
    ),
    CommandSpec(
        name="validate",
        help="Validate operation references or package manifests.",
        description="Validate operation references or package manifests.",
    ),
    CommandSpec(
        name="packages",
        help="List available package manifests.",
        description="List available package manifests.",
    ),
)


def _placeholder_handler(args: argparse.Namespace) -> int:
    command = getattr(args, "command", "<unknown>")
    print(
        f"error: command '{command}' is registered but not implemented in STORY-07",
        file=sys.stderr,
    )
    return EXIT_NOT_IMPLEMENTED


def _register_subcommand(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    spec: CommandSpec,
    handler: Callable[[argparse.Namespace], int],
) -> None:
    parser = subparsers.add_parser(
        spec.name,
        help=spec.help,
        description=spec.description,
    )
    parser.set_defaults(command=spec.name, handler=handler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="atomic-ops",
        description="Manage local atomic operation specifications.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    subparsers = parser.add_subparsers(
        title="commands",
        metavar="{sync,list,show,adapter,run,validate,packages}",
        dest="command",
    )
    subparsers.required = True

    for spec in COMMANDS:
        if spec.name == "sync":
            _register_subcommand(subparsers, spec, sync_command.run)
            sync_command.add_arguments(subparsers.choices[spec.name])
        elif spec.name == "list":
            _register_subcommand(subparsers, spec, list_command.run)
            list_command.add_arguments(subparsers.choices[spec.name])
        elif spec.name == "show":
            _register_subcommand(subparsers, spec, show_command.run)
            show_command.add_arguments(subparsers.choices[spec.name])
        elif spec.name == "adapter":
            _register_subcommand(subparsers, spec, adapter_command.run)
            adapter_command.add_arguments(subparsers.choices[spec.name])
        elif spec.name == "run":
            _register_subcommand(subparsers, spec, run_command.run)
            run_command.add_arguments(subparsers.choices[spec.name])
        elif spec.name == "packages":
            _register_subcommand(subparsers, spec, packages_command.run)
            packages_command.add_arguments(subparsers.choices[spec.name])
        elif spec.name == "validate":
            _register_subcommand(subparsers, spec, validate_command.run)
            validate_command.add_arguments(subparsers.choices[spec.name])
        else:
            _register_subcommand(subparsers, spec, _placeholder_handler)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args, _unknown = parser.parse_known_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
