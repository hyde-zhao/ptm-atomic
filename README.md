# atomic-ops

防火墙测试原子操作规范仓库与本地消费 CLI。

`atomic-ops` 用于统一维护防火墙测试原子操作 YAML、package 过滤视图、测试用例引用模板和本地查询/校验命令。CLI 通过 git 同步远端操作库到本地缓存，之后 `list`、`show`、`packages`、`validate` 均只读取本地缓存，不实时访问网络。

## 快速开始

### 前置条件

- Python 3.11+
- uv
- git
- 可访问默认仓库的 git 原生认证环境，例如 SSH key 或系统 credential helper

默认仓库地址：

```text
git@<GITLAB_HOST>:<ORG/PROJECT>/ptm-atomic.git
```

### 安装 CLI

在仓库根目录执行：

```bash
uv tool install .
atomic-ops --version
```

开发或临时验证时，也可以不安装到工具环境，直接运行：

```bash
uv run atomic-ops --help
```

本项目使用 `pyproject.toml` 声明依赖，使用 `uv.lock` 锁定依赖。日常运行、验证和脚本入口统一使用 `uv run` 或 `uv tool`，不使用裸 `pip` 作为默认入口。

### 首次同步和查询

```bash
atomic-ops sync
atomic-ops packages
atomic-ops list
atomic-ops show fw_verify_acl_rule
```

如果需要显式指定仓库地址：

```bash
atomic-ops sync --repo git@<GITLAB_HOST>:<ORG/PROJECT>/ptm-atomic.git
```

## 核心命令

| 命令 | 用途 | 常用参数 |
|---|---|---|
| `atomic-ops sync` | 同步或刷新本地缓存 | `--repo`、`--latest`、`--ref`、`--format json/text` |
| `atomic-ops list` | 列出本地缓存中的 atom 摘要 | `--device`、`--package`、`--format json/table` |
| `atomic-ops show <op_id>` | 输出单个 atom 的 YAML 或 JSON | `--format yaml/json` |
| `atomic-ops packages` | 列出 package 清单 | `--format json/table` |
| `atomic-ops validate <test_case.yaml>` | 校验测试用例中的 `op_id` 引用 | `--format json/table` |
| `atomic-ops validate --package <name>` | 校验 package 清单引用完整性 | `--format json/table` |

常用示例：

```bash
atomic-ops list --device fw
atomic-ops list --package networking --format json
atomic-ops show fw_verify_acl_rule --format yaml
atomic-ops validate docs/test-case-template.yaml
atomic-ops validate --package security
```

## 仓库内容

| 路径 | 说明 |
|---|---|
| `src/atomic_ops/` | `atomic-ops` CLI 源码 |
| `schemas/atomic-op.schema.yaml` | atom YAML schema |
| `atoms/` | 原子操作定义，当前包含示例 `fw_verify_acl_rule` |
| `packages/` | package 过滤视图，当前包含 `networking` 与 `security` |
| `docs/` | 字段参考、命名规范、错误码、工程师手册和测试用例模板 |
| `scripts/layout_check.py` | 仓库布局检查脚本 |
| `scripts/validate_schema.py` | atom schema 校验脚本 |
| `delivery/` | 面向交付的 README 与用户手册 |
| `process/`、`checkpoints/` | 项目过程、设计、确认和验证追溯文档 |

## 本地缓存

`atomic-ops sync` 会把操作库同步到本地缓存，而不是修改 CLI 安装目录。

| 平台 | 默认缓存目录 |
|---|---|
| Linux/macOS | `~/.cache/atomic-ops/repo/` |
| Windows | `%LOCALAPPDATA%\\atomic-ops\\repo\\` |

缓存目录包含 sparse checkout 后的 `atoms/`、`schemas/`、`packages/`、`docs/` 和 `_metadata.json`。`_metadata.json` 只记录最近一次同步摘要，不是完整日志文件。

推荐同步频率：**每个工作日一次**。发布、联调、大批量引用 atom 或 CI 关键校验前，可以额外执行一次：

```bash
atomic-ops sync
```

## 校验与维护

布局检查：

```bash
uv run python scripts/layout_check.py .
```

单个 atom schema 校验：

```bash
uv run --with pyyaml --with jsonschema --python 3.11 python scripts/validate_schema.py atoms/fw/fw_verify_acl_rule.yaml
```

测试用例引用校验：

```bash
atomic-ops validate docs/test-case-template.yaml --format json
```

package 引用校验：

```bash
atomic-ops validate --package networking --format json
```

## 安全与诊断边界

- 认证完全委托 git 原生机制；CLI 不管理、不保存访问凭据。
- `sync` 是唯一需要访问远端 git 仓库的命令。
- `list`、`show`、`packages`、`validate` 是只读命令，不修改远端仓库。
- `validate` 只检查引用和结构，不连接设备，不执行 atom。
- 成功结果写入 stdout；warning、错误对象和修复建议写入 stderr。
- 当前不创建独立日志目录，也不默认写入滚动日志文件。
- package 是过滤视图，不复制、不安装 atom YAML。

## 更多文档

- [交付 README](delivery/README.md)
- [用户使用手册](delivery/doc/USER-MANUAL.md)
- [工程师手册](docs/engineer-handbook.md)
- [字段参考](docs/schema-field-reference.md)
- [命名规范](docs/naming-convention.md)
- [错误码规范](docs/error-codes.md)
- [测试用例模板](docs/test-case-template.yaml)

## 当前版本

| 项 | 值 |
|---|---|
| CLI 包名 | `atomic-ops` |
| 当前包版本 | `0.1.0` |
| Python 要求 | `>=3.11` |
| 默认分支 | `main` |
| 默认仓库 URL | `git@<GITLAB_HOST>:<ORG/PROJECT>/ptm-atomic.git` |
