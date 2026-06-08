"""Command module namespace for ptm-atomic subcommands.

提供 CommandSpec 和 CommandGroup 两个核心注册模型，被 cli.py 和各操作族模块
共享引用，避免循环导入。
"""

from __future__ import annotations

import argparse
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class CommandSpec:
    """叶子命令：无子命令，有 handler。"""

    name: str
    help: str
    description: str
    handler: Callable[[argparse.Namespace], int]
    add_args: Callable[[argparse.ArgumentParser], None] | None = None


@dataclass(frozen=True)
class CommandGroup:
    """嵌套命令组：包含子 CommandSpec 或子 CommandGroup。"""

    name: str
    help: str
    description: str
    children: tuple[CommandSpec | CommandGroup, ...] = ()
    add_shared_args: Callable[[argparse.ArgumentParser], None] | None = None
    legacy_handler: Callable[[argparse.Namespace], int] | None = None
