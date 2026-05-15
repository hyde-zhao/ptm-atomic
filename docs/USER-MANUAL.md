# 用户使用手册

## 1. 开始之前

`atomic-ops` 用于同步、查询和校验防火墙测试原子操作。你需要准备 Python、uv、git，以及可访问默认 git 仓库的认证环境。

默认仓库地址：

```text
git@<GITLAB_HOST>:<ORG/PROJECT>/ptm-atomic.git
```

| 材料 | 格式 | 必填 | 说明 |
|---|---|---:|---|
| Python | `>=3.11` | 是 | CLI 运行环境。 |
| uv | 命令行工具 | 是 | 安装、升级和运行 Python CLI。 |
| git | 命令行工具 | 是 | 同步远端原子操作仓库。 |
| git 认证 | SSH key 或系统 credential helper | 是 | 由 git 自己处理，CLI 不保存凭据。 |
| 测试用例 | YAML | 按需 | 用于 `atomic-ops validate <test_case.yaml>`。 |
| package 名称 | 文本 | 按需 | 用于 `list --package` 或 `validate --package`。 |

### Python 环境（uv）

- Python 版本要求：`>=3.11`。
- 项目已交付 `pyproject.toml` 与 `uv.lock`。
- `pyproject.toml` 是 Python 依赖声明来源，`uv.lock` 是锁定结果。
- 日常运行优先使用 `uv tool install .` 安装 CLI，或在仓库根目录用 `uv run atomic-ops ...` 临时运行。
- 运行仓库脚本时使用 `uv run`，带临时依赖的脚本使用 `uv run --with <package>`。
- 一次性 Python 工具优先使用 `uvx`，但本项目当前核心入口是 `atomic-ops` CLI 和仓库内脚本。

## 2. 首次使用

### 步骤 1：安装或直接运行 CLI

从仓库根目录安装：

```bash
uv tool install .
atomic-ops --version
```

临时运行：

```bash
uv run atomic-ops --help
```

当前仓库没有独立安装脚本；不要把操作库同步和 CLI 本体安装混为一件事。CLI 本体由 `uv tool` 管理，操作库缓存由 `atomic-ops sync` 管理。

### 步骤 2：同步本地操作库

首次使用必须先同步：

```bash
atomic-ops sync
```

如果需要显式指定仓库地址：

```bash
atomic-ops sync --repo git@<GITLAB_HOST>:<ORG/PROJECT>/ptm-atomic.git
```

同步后，本地缓存会保存 sparse checkout 内容和 `_metadata.json`。

### 步骤 3：确认可查询

```bash
atomic-ops packages
atomic-ops list
atomic-ops show fw_verify_acl_rule
```

### 步骤 4：校验引用

```bash
atomic-ops validate docs/test-case-template.yaml
atomic-ops validate --package networking
```

## 3. 同步与本地缓存

### 同步命令

```bash
atomic-ops sync
atomic-ops sync --format json
atomic-ops sync --latest
atomic-ops sync --ref atoms-v0.1.0
```

`--latest` 表示跟踪默认分支最新状态；`--ref` 表示固定到指定分支、tag 或 commit。固定 ref 后，`_metadata.json.ref_mode` 会记录为 `pinned`。恢复默认分支跟踪时执行 `atomic-ops sync --latest`。

### 缓存路径

| 平台 | 路径 |
|---|---|
| Linux/macOS | `~/.cache/atomic-ops/repo/` |
| Windows | `%LOCALAPPDATA%\\atomic-ops\\repo\\` |

缓存目录包含：

| 内容 | 说明 |
|---|---|
| `atoms/` | 原子操作 YAML。 |
| `schemas/` | atom schema。 |
| `packages/` | package 清单。 |
| `docs/` | 可同步的用户参考文档。 |
| `_metadata.json` | 最近一次同步状态摘要。 |

`_metadata.json` 常见字段包括 `source_repo`、`default_branch`、`ref_mode`、`current_ref`、`commit_sha`、`synced_at`、`last_sync_status`、`cache_root`、`sparse_paths`。它不是完整日志文件。

### 同步频率

推荐频率为：**每个工作日一次**。

发布、联调、大批量引用 atom 或 CI 关键校验前，可额外执行一次：

```bash
atomic-ops sync
```

如果 `sync` 遇到网络错误但已有完整缓存，CLI 会把缓存标记为 `STALE`。此时 `list`、`show`、`packages`、`validate` 仍可继续读取本地缓存，但 stderr 会提醒结果基于过期缓存。

## 4. 查询原子操作

### 列出全部操作

```bash
atomic-ops list
```

默认输出表格，适合人工阅读。机器消费使用 JSON：

```bash
atomic-ops list --format json
```

### 按设备过滤

```bash
atomic-ops list --device fw
atomic-ops list --device tg
atomic-ops list --device mock
atomic-ops list --device sw
```

设备前缀必须与 `op_id`、`device_type` 和文件路径一致。例如 `fw_verify_acl_rule` 位于：

```text
atoms/fw/fw_verify_acl_rule.yaml
```

### 查看单个操作

```bash
atomic-ops show fw_verify_acl_rule
atomic-ops show fw_verify_acl_rule --format json
```

`show` 根据 `op_id` 前缀直接定位到 `atoms/<device>/<op_id>.yaml`。如果返回 `OP_NOT_FOUND`，先运行 `atomic-ops sync`，再检查前缀、拼写和相似建议。

## 5. Package 过滤

package 是一组 `op_id` 的过滤视图，用于快速聚合常用操作。它不会复制 atom 文件，也不会生成新的本地操作目录。

查看可用 package：

```bash
atomic-ops packages
atomic-ops packages --format json
```

当前基线 package：

| package | 说明 |
|---|---|
| `networking` | 网络连通性与防火墙策略验证操作。 |
| `security` | 安全策略与访问控制验证操作。 |

按 package 过滤操作：

```bash
atomic-ops list --package networking
atomic-ops list --package security
```

同时按 package 和设备过滤：

```bash
atomic-ops list --package networking --device fw
```

校验 package 引用完整性：

```bash
atomic-ops validate --package networking
atomic-ops validate --package security --format json
```

如果返回 `PACKAGE_NOT_FOUND`，先执行 `atomic-ops packages` 查看合法名称。如果 package 中的 `operations` 引用了不存在的 `op_id`，`validate --package` 会返回 `OP_NOT_FOUND`。

## 6. Validate 测试用例和 Package

`validate` 不执行真实设备操作，只检查测试用例或 package 中的 `op_id` 引用能否在本地缓存中解析，并报告基础结构问题。

### 校验测试用例

```bash
atomic-ops validate docs/test-case-template.yaml
atomic-ops validate docs/test-case-template.yaml --format json
```

测试用例模式会读取：

- `steps[].op_id`
- `tight_sequence.steps[].op_id`

常见输出字段：

| 字段 | 说明 |
|---|---|
| `status` | `passed` 或 `failed`。 |
| `mode` | `test_case` 或 `package`。 |
| `checked_count` | 已检查的引用数量。 |
| `missing_count` | 缺失的引用数量。 |
| `findings` | YAML 解析、结构或字段问题。 |
| `cache` | 本地缓存摘要。 |

### 校验 Package

```bash
atomic-ops validate --package networking
atomic-ops validate --package security
```

package 模式会读取 `packages/<name>.yaml` 的 `operations` 列表，并逐项确认 `op_id` 是否存在。

### 结果判断

- `status=passed`：当前输入中的引用均能在本地缓存中解析。
- `status=failed`：存在结构或引用问题，应按 `findings` 或错误对象修正。
- 顶层 `OP_NOT_FOUND`：某些引用缺失，CLI 可能给出相似 `op_id` 建议。
- `REPO_NOT_SYNCED`：本地缓存不可用，先执行 `atomic-ops sync`。

## 7. 测试用例模板

模板文件位于：

```text
docs/test-case-template.yaml
```

核心结构：

```yaml
test_case_id: tc_fw_acl_rule_tight_sequence
description: Template showing how a test case references atomic operations by op_id.
steps:
  - step: verify_acl_rule_baseline
    op_id: fw_verify_acl_rule
    device: fw_primary
    wait_ms: 0
    on_error: abort
tight_sequence:
  enabled: true
  steps:
    - step: verify_acl_rule_sequence_start
      op_id: fw_verify_acl_rule
      device: fw_primary
      wait_ms: 0
      on_error: abort
```

字段说明：

| 字段 | 说明 |
|---|---|
| `test_case_id` | 测试用例标识。 |
| `description` | 用例说明。 |
| `preconditions` | 执行前置条件。 |
| `steps[]` | 普通操作步骤。 |
| `steps[].step` | 步骤名。 |
| `steps[].op_id` | 引用的原子操作 ID。 |
| `steps[].device` | 消费方测试执行器中的设备实例名。 |
| `steps[].wait_ms` | 当前步骤执行前等待毫秒数，用于补偿前序步骤完成后的状态传播延迟。 |
| `steps[].on_error` | 错误处理建议，示例值为 `abort`、`retry_once`、`skip`。 |
| `tight_sequence.enabled` | 是否启用紧密时序段。 |
| `tight_sequence.steps[]` | 紧密时序步骤列表，字段形态与普通 `steps[]` 一致。 |
| `postconditions` | 执行后期望状态。 |

修改模板时，优先改 `op_id` 和设备实例名，不要把真实凭据、管理地址或设备回包写入模板。

## 8. 贡献原子操作流程

### 新增 Atom

1. 选择 `op_id`，必须符合：

```text
^(fw|tg|mock|sw)_[a-z]+_[a-z_]+$
```

2. 在对应设备目录创建 YAML：

```text
atoms/<device_type>/<op_id>.yaml
```

3. 填写 schema 必填字段：`schema_version`、`op_id`、`device_type`、`description`、`parameters`、`returns`、`idempotent`、`timeout_ms`、`error_types`。

4. 选择已登记的操作级错误类型：

```text
TIMEOUT
DEVICE_UNREACHABLE
INVALID_PARAM
RESOURCE_CONFLICT
RESOURCE_NOT_FOUND
PERMISSION_DENIED
STATE_MISMATCH
INTERNAL_ERROR
DRY_RUN
```

5. 如属于现有 package，更新 `packages/<package_id>.yaml` 的 `operations`。

6. 在 `CHANGELOG.md` 记录新增、修改、废弃或删除。

7. 本地校验：

```bash
uv run python scripts/layout_check.py .
uv run --with pyyaml --with jsonschema --python 3.11 python scripts/validate_schema.py atoms/fw/fw_verify_acl_rule.yaml
atomic-ops validate --package networking
```

### 修改或废弃 Atom

已被测试用例引用的 `op_id` 不应直接删除。推荐流程：

1. 创建替代 atom。
2. 将旧 atom 标记为 `deprecated: true`。
3. 填写 `deprecated_by` 和 `since_version`。
4. 更新 package 清单和 `CHANGELOG.md`。
5. 在明确版本窗口删除旧引用。

### 新增 Package

1. 创建 `packages/<package_id>.yaml`。
2. 保持文件名与 `package_id` 一致。
3. 填写 `display_name`、`description`、`version`。
4. 在 `operations` 中只写 `op_id`，不写文件路径，不嵌入 atom 内容。
5. 执行 `atomic-ops validate --package <package_id>`。

## 9. 日志与诊断边界

`atomic-ops` 当前没有独立日志文件，也不会默认创建 `logs/` 目录。

| 通道 | 内容 | 不包含 |
|---|---|---|
| stdout | 成功结果，如表格、JSON、YAML、同步摘要 | 调试日志、错误栈、warning |
| stderr | warning、错误对象、修复建议、stale cache 提醒 | 访问凭据、完整 traceback、设备回包 |
| `_metadata.json` | 最近一次同步摘要 | 操作明细日志、长期历史、设备诊断详情 |

机器消费建议：

- 成功路径读取 stdout。
- 失败路径读取 stderr 中的 `error_code`。
- CI 如需保留日志，应由 CI 自己重定向 stdout/stderr。
- `_metadata.json` 可用于确认 `commit_sha`、`synced_at` 和 `last_sync_status`，但不要把它当作审计日志。

## 10. 常见错误排查

| 问题现象 | 可能原因 | 解决方法 |
|---|---|---|
| `atomic-ops` 命令找不到 | `uv tool` 的可执行目录未加入 `PATH`，或尚未安装 CLI | 执行 `uv tool install .`，再检查 `uv tool dir` 对应目录是否在 `PATH`。 |
| `GIT_AUTH_FAILED` | git 原生认证未配置或无仓库权限 | 先用 `git ls-remote git@<GITLAB_HOST>:<ORG/PROJECT>/ptm-atomic.git` 做最小验证，修复后重跑 `atomic-ops sync`。 |
| `GIT_NETWORK_ERROR` | 网络不可达、DNS、TLS 或远端超时 | 网络恢复后重跑 `atomic-ops sync`；如已有完整缓存，可先继续只读查询。 |
| `REPO_NOT_SYNCED` | 首次未同步、缓存损坏、`_metadata.json` 缺失或不可读 | 执行 `atomic-ops sync`；确认缓存父目录可写且没有被普通文件占用。 |
| `OP_NOT_FOUND` | `op_id` 拼写错误、前缀错误、缓存过期或 atom 未发布 | 执行 `atomic-ops sync`，再用 `atomic-ops list --device <device>` 查找候选。 |
| `PACKAGE_NOT_FOUND` | package 名称不存在 | 执行 `atomic-ops packages` 查看可用名称。 |
| `validate` 返回 `YAML_PARSE_ERROR` | 测试用例 YAML 格式错误 | 用 YAML 解析器或编辑器检查缩进、冒号和列表结构。 |
| `validate` 返回 `INVALID_TEST_CASE` | `steps` 或 `tight_sequence.steps` 结构不符合约定 | 对照 `docs/test-case-template.yaml` 修正为对象列表，并确保 `op_id` 非空。 |
| package 校验失败 | package 清单引用了不存在或已重命名的 `op_id` | 维护者更新 package 的 `operations`，或补齐对应 atom。 |
| 缓存状态为 `STALE` | 最近一次同步网络失败，但本地缓存完整 | 只读命令可继续使用；发布或联调前需重新同步到 `SYNCED`。 |

## 11. 限制说明

- 当前只交付 CLI、schema、文档、示例 atom、package 清单和校验脚本，不交付真实设备执行器。
- `validate` 只校验引用和结构，不连接设备，不执行 atom。
- package 是过滤和校验视图，不复制、不安装 atom 文件。
- 不支持实时 Git API 拉取；数据更新通过 git 同步完成。
- 不支持多远端仓库联邦同步。
- 私有仓库证书、代理、系统 credential helper 等环境问题由 git 和本机环境处理。
- 当前示例 atom 只有 `fw_verify_acl_rule`，其他设备目录为后续扩展保留。
- 默认 sparse checkout 只同步 `atoms/`、`schemas/`、`packages/`、`docs/`；维护者开发 CLI 源码时应使用完整仓库。

## 12. 文档缺口清单

| 缺口类型 | 影响项 | 严重程度 | 修复建议 | 参考来源 |
|---|---|---|---|---|
| 无 BLOCKING 缺口 | 安装与首次使用 | BLOCKING | 已覆盖 `uv tool install`、`uv run`、首次 `sync`、默认仓库 URL 和本地缓存路径。 | README / 本手册 |
| 无 REQUIRED 缺口 | 核心命令与故障排查 | REQUIRED | 已覆盖 `sync/list/show/packages/validate`、五类 CLI 错误码、stdout/stderr/`_metadata.json` 边界。 | 已验证 CLI 合同 |
| 后续发布源说明 | 内部制品仓库或 tag 发布策略 | OPTIONAL | 若后续有正式包源或 release tag 规范，可补充“从制品源安装”的组织内示例。 | `pyproject.toml` / `CHANGELOG.md` |
| 更多业务样例 | 非 `fw_verify_acl_rule` 的真实 atom | OPTIONAL | 新增更多 atom 后，补充多设备、多 package、多步骤测试用例示例。 | `atoms/` / `packages/` |
