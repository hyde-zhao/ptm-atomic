# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

`atomic-ops` 是防火墙测试原子操作规范仓库与本地消费 CLI。CLI 通过 git 同步远端操作库到本地缓存，之后 `list`、`show`、`packages`、`validate` 均只读取本地缓存，不实时访问网络。

## 常用命令

### 安装与运行

```bash
# 安装到工具环境
uv tool install .

# 开发/临时验证（不安装）
uv run atomic-ops --help
```

### CLI 命令

```bash
atomic-ops sync                                    # 同步远端仓库到本地缓存
atomic-ops sync --repo git@host:path/repo.git      # 指定仓库地址
atomic-ops sync --latest                           # 跟踪默认分支
atomic-ops sync --ref <tag|sha>                    # 固定到特定 ref
atomic-ops list                                    # 列出所有 atom
atomic-ops list --device fw                        # 按设备类型过滤
atomic-ops list --package networking --format json  # 按 package 过滤
atomic-ops show fw_verify_acl_rule                 # 查看单个 atom
atomic-ops show fw_verify_acl_rule --format json   # JSON 格式输出
atomic-ops packages                                # 列出 package 清单
atomic-ops validate docs/test-case-template.yaml   # 校验测试用例引用
atomic-ops validate --package networking            # 校验 package 引用完整性
```

### 仓库维护脚本

```bash
# 布局检查
uv run python scripts/layout_check.py .

# 单个 atom schema 校验
uv run --with pyyaml --with jsonschema --python 3.11 python scripts/validate_schema.py atoms/fw/fw_verify_acl_rule.yaml
```

## 代码架构

### 源码结构 (`src/atomic_ops/`)

- `cli.py` — CLI 入口，argparse 子命令注册，`main()` 函数
- `commands/` — 每个子命令一个模块（`sync.py`、`list_ops.py`、`show.py`、`packages.py`、`validate.py`）
- `repository.py` — 本地缓存的只读访问层，`Repository` 类封装所有 atom/package 读取逻辑
- `git_ops.py` — 系统 git 适配器，`GitClient` 处理 clone、sparse checkout、fetch、pull
- `metadata.py` — 缓存元数据管理（`_metadata.json` 读写、缓存路径解析、敏感信息脱敏）
- `errors.py` — CLI 错误对象与输出辅助（`CliError`、`write_error`、`write_warning`、`redact`）
- `suggestions.py` — op_id 模糊匹配建议（Levenshtein 距离）

### 数据目录

- `atoms/<device_type>/<op_id>.yaml` — 原子操作定义（device_type: `fw`, `tg`, `mock`, `sw`）
- `packages/<package_id>.yaml` — package 过滤视图（仅引用 op_id 列表，不复制 atom）
- `schemas/atomic-op.schema.yaml` — atom YAML 的 JSON Schema 定义
- `docs/` — 字段参考、命名规范、错误码、工程师手册、测试用例模板

### 关键设计约束

- **双版本流**：`atoms-vX.Y.Z`（操作库）和 `cli-vX.Y.Z`（CLI 包）独立发布
- **op_id 命名规范**：`{device_prefix}_{verb}_{target}`，动词来自受控词汇表（`docs/naming-convention.md`）
- **缓存路径**：Linux/macOS `~/.cache/atomic-ops/repo/`，Windows `%LOCALAPPDATA%\atomic-ops\repo\`
- **stdout/stderr 分离**：成功结果写 stdout，warning/错误/建议写 stderr
- **敏感信息脱敏**：所有输出经过 `redact_sensitive()` 处理，URL 凭据、token、密码自动脱敏
- **错误码固定**：5 个 CLI 级错误码（21-25），9 个操作级错误类型（`docs/error-codes.md`）
- **sparse checkout**：git >= 2.25 使用 sparse checkout，旧版本回退到全量 checkout

## 依赖管理

使用 `uv` 管理 Python 环境和依赖，`pyproject.toml` 为唯一依赖声明，`uv.lock` 为锁定结果。运行时依赖仅 `pyyaml` 和 `jsonschema`。禁止裸 `pip install`。
