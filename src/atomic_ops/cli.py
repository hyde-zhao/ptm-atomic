"""Command-line entry point for ptm-atomic."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable, Sequence

from atomic_ops import __version__
from atomic_ops.commands import adapter as adapter_command
from atomic_ops.commands import list_ops as list_command
from atomic_ops.commands import packages as packages_command
from atomic_ops.commands import run as run_command
from atomic_ops.commands import show as show_command
from atomic_ops.commands import sync as sync_command
from atomic_ops.commands import validate as validate_command
from atomic_ops.commands import CommandGroup, CommandSpec


EXIT_NOT_IMPLEMENTED = 2


# ── 根命令清单（扁平子命令层） ──────────────────────────


ROOT_COMMANDS: tuple[CommandSpec | CommandGroup, ...] = (
    CommandSpec(
        name="sync",
        help="Synchronize the local atomic operation repository cache.",
        description="Synchronize the local atomic operation repository cache.",
        handler=sync_command.run,
        add_args=sync_command.add_arguments,
    ),
    CommandSpec(
        name="list",
        help="List available atomic operations.",
        description="List available atomic operations.",
        handler=list_command.run,
        add_args=list_command.add_arguments,
    ),
    CommandSpec(
        name="show",
        help="Show one atomic operation by op_id.",
        description="Show one atomic operation by op_id.",
        handler=show_command.run,
        add_args=show_command.add_arguments,
    ),
    CommandSpec(
        name="adapter",
        help="Show one adapter profile operation by op_id.",
        description="Show one adapter profile operation by op_id.",
        handler=adapter_command.run,
        add_args=adapter_command.add_arguments,
    ),
    CommandSpec(
        name="validate",
        help="Validate operation references or package manifests.",
        description="Validate operation references or package manifests.",
        handler=validate_command.run,
        add_args=validate_command.add_arguments,
    ),
    CommandSpec(
        name="packages",
        help="List available package manifests.",
        description="List available package manifests.",
        handler=packages_command.run,
        add_args=packages_command.add_arguments,
    ),
    # run 是嵌套命令组，由 run_command 提供子结构
    CommandGroup(
        name="run",
        help="Run a supported atomic operation against an NGFW device.",
        description="Run a supported atomic operation against an NGFW device.",
        add_shared_args=run_command.add_shared_arguments,
        children=run_command.build_run_subtree(),
        legacy_handler=run_command.run_legacy,
    ),
)


# ── 注册函数 ──────────────────────────────────────────────


def _placeholder_handler(args: argparse.Namespace) -> int:
    command = getattr(args, "command", "<unknown>")
    print(
        f"error: command '{command}' is registered but not implemented",
        file=sys.stderr,
    )
    return EXIT_NOT_IMPLEMENTED


def _register_command_spec(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    spec: CommandSpec,
) -> None:
    """注册叶子命令。"""
    parser = subparsers.add_parser(
        spec.name,
        help=spec.help,
        description=spec.description,
    )
    parser.set_defaults(command=spec.name, handler=spec.handler)
    if spec.add_args is not None:
        spec.add_args(parser)


def _register_command_group(
    subparsers: argparse._SubParsersAction[argparse.ArgumentParser],
    group: CommandGroup,
) -> None:
    """递归注册嵌套命令组。"""
    parser = subparsers.add_parser(
        group.name,
        help=group.help,
        description=group.description,
    )
    # 注册 group 级别的共享参数
    if group.add_shared_args is not None:
        group.add_shared_args(parser)

    # 创建子命令层
    child_subparsers = parser.add_subparsers(
        title=f"{group.name} commands",
        dest=f"{group.name}_subcommand",
    )
    child_subparsers.required = True

    for child in group.children:
        if isinstance(child, CommandSpec):
            _register_command_spec(child_subparsers, child)
        elif isinstance(child, CommandGroup):
            _register_command_group(child_subparsers, child)
        else:
            raise TypeError(f"Unknown child type: {type(child)}")

    # 设置 group 级别的默认 handler（用于旧格式兼容或 fallback）
    if group.legacy_handler is not None:
        parser.set_defaults(handler=group.legacy_handler)
    else:
        parser.set_defaults(handler=_placeholder_handler)


# ── 构建解析器 ────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ptm-atomic",
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

    for item in ROOT_COMMANDS:
        if isinstance(item, CommandSpec):
            _register_command_spec(subparsers, item)
        elif isinstance(item, CommandGroup):
            _register_command_group(subparsers, item)
        else:
            raise TypeError(f"Unknown root item type: {type(item)}")

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args, _unknown = parser.parse_known_args(argv)
    handler: Callable[[argparse.Namespace], int] = args.handler
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
