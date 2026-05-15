# 工程师手册

本文面向使用和维护 `atomic-ops` 的工程师，说明如何准备环境、安装 CLI、同步本地原子操作库、浏览和校验操作引用，以及如何贡献新的 atom 或 package 清单。当前现行命令只包括 `atomic-ops sync`、`atomic-ops list`、`atomic-ops show`、`atomic-ops packages` 和 `atomic-ops validate`。

## 环境准备

使用前确认本机具备三类基础能力：Python 3.11+、`uv` 和 `git`。`atomic-ops` 通过 Python CLI 分发，安装和升级 CLI 本体使用 `uv tool`；操作库数据通过 git 同步到本地缓存，后续查询与校验优先读取本地缓存。

默认原子操作仓库地址为：

```text
git@<GITLAB_HOST>:<ORG/PROJECT>/ptm-atomic.git
```

认证使用 git 原生机制。Linux/macOS 通常使用 SSH key 与 `~/.ssh/config`，Windows 通常使用 OpenSSH 配置或系统 Credential Manager。不要在命令行、配置文件、测试用例或文档示例中写入访问凭据；如果需要排查认证问题，应先用普通 `git ls-remote` 或 `git clone` 对同一仓库地址做最小验证。

本地缓存根路径由平台决定：

| 平台 | 缓存根路径 |
|---|---|
| Linux/macOS | `~/.cache/atomic-ops/repo/` |
| Windows | `%LOCALAPPDATA%\\atomic-ops\\repo\\` |

缓存目录中会保存 sparse checkout 后的 `atoms/`、`schemas/`、`packages/`、`docs/` 和 `_metadata.json`。`_metadata.json` 记录 `source_repo`、`ref_mode`、`current_ref`、`commit_sha`、`synced_at`、`last_sync_status`、`cache_root`、`sparse_paths` 等同步状态字段，不是诊断日志归档。

## 首次安装

首次使用先安装 CLI 本体。仓库根目录或发布包可被 `uv tool install` 安装为本机命令：

```bash
uv tool install .
atomic-ops --version
```

如果从远端包源或内部构建产物安装，仍保持同一原则：CLI 本体由 `uv tool install` 或 `uv tool upgrade atomic-ops` 管理，操作库数据由 `atomic-ops sync` 管理。两者是分离的生命周期，升级 CLI 不会自动更新本地 atom 数据，更新 atom 数据也不会改变 CLI 版本。

安装后建议先查看命令入口：

```bash
atomic-ops --help
atomic-ops sync --help
atomic-ops list --help
atomic-ops show --help
atomic-ops packages --help
atomic-ops validate --help
```

当前文档只记录现行五个子命令。使用手册中的示例时，优先复制完整命令并保留 `atomic-ops` 前缀；如果 shell 找不到命令，先检查 `uv tool dir` 对应的可执行目录是否已经加入 `PATH`。

## 同步操作库

`atomic-ops sync` 是建立或刷新本地缓存的唯一入口。首次安装后必须先执行一次同步，后续 `list`、`show`、`packages`、`validate` 才能读取本地操作库。

默认同步命令：

```bash
atomic-ops sync
```

指定仓库地址同步：

```bash
atomic-ops sync --repo git@<GITLAB_HOST>:<ORG/PROJECT>/ptm-atomic.git
```

跟踪默认分支最新状态：

```bash
atomic-ops sync --latest
```

固定到指定分支、标签或提交：

```bash
atomic-ops sync --ref atoms-v0.1.0
```

机器读取场景可以使用 JSON 输出：

```bash
atomic-ops sync --format json
```

推荐同步频率为每个工作日同步一次。发布/联调前可额外执行一次 `atomic-ops sync`，确保本地缓存包含最新的 atom、schema、package 清单和文档。大批量引用、CI 校验或跨团队交接前也应额外同步一次，避免用过期缓存做选择或校验。

同步成功后，命令会输出当前 `status`、`ref_mode`、`current_ref`、`commit_sha` 和 `cache_root`。如果网络失败但已有完整缓存，CLI 会把缓存标记为 `STALE`，只读命令仍可继续读取本地数据，并在 stderr 输出 stale warning。`STALE` 只表示缓存不是最新，不表示内容不可用。

## 浏览/查询原子操作

使用 `atomic-ops list` 查看本地缓存中的可用操作。默认表格输出适合人工阅读：

```bash
atomic-ops list
```

按设备类型过滤：

```bash
atomic-ops list --device fw
atomic-ops list --device tg
atomic-ops list --device mock
atomic-ops list --device sw
```

机器处理时使用 JSON：

```bash
atomic-ops list --format json
```

列表输出会包含 `op_id`、`device_type`、`idempotent`、`since_version` 和 `description`。`op_id` 是测试用例和自动化编排引用 atom 的稳定键，当前命名正则为：

```text
^(fw|tg|mock|sw)_[a-z]+_[a-z_]+$
```

查看单个操作完整 YAML：

```bash
atomic-ops show fw_verify_acl_rule
```

查看单个操作 JSON：

```bash
atomic-ops show fw_verify_acl_rule --format json
```

`show` 根据 `op_id` 前缀读取固定路径，例如 `fw_verify_acl_rule` 对应 `atoms/fw/fw_verify_acl_rule.yaml`。如果操作不存在，会返回 `OP_NOT_FOUND`，处理时先同步，再检查拼写和建议项。

查看可用 package 清单：

```bash
atomic-ops packages
atomic-ops packages --format json
```

package 输出包含 `package_id`、`display_name`、`version`、`operation_count` 和 `description`。package 是查询和校验视图，用来组织常用 op_id 集合。

## validate 校验

`atomic-ops validate` 用于校验测试用例中的 `op_id` 引用，或校验 package 清单引用是否都能在本地缓存中解析。它不执行真实设备操作，只检查引用完整性和基础结构问题。

校验测试用例 YAML：

```bash
atomic-ops validate test-case.yaml
```

校验 package 清单：

```bash
atomic-ops validate --package networking
atomic-ops validate --package security
```

输出 JSON：

```bash
atomic-ops validate test-case.yaml --format json
atomic-ops validate --package networking --format json
```

测试用例模式会读取 `steps[].op_id` 和 `tight_sequence.steps[].op_id`。缺失、空字符串、非对象 step、非列表 steps 或 YAML 解析失败会进入 validate findings；引用不存在的 op_id 会触发顶层 `OP_NOT_FOUND`，并在可用候选中给出相似建议。

package 模式会读取 `packages/<name>.yaml` 中的 `operations` 列表。未知 package 返回 `PACKAGE_NOT_FOUND`；已知 package 中存在无法解析的 op_id 时返回 `OP_NOT_FOUND`。在 `STALE` 缓存上执行 validate 时，CLI 会输出 stale warning，提醒结果基于过期本地缓存。

validate 报告的关键字段包括 `status`、`mode`、`checked_count`、`missing_count`、`findings` 和 `cache`。`status=passed` 表示当前输入中的引用在本地缓存中全部可解析；`status=failed` 表示存在结构或引用问题，需要按 findings 或错误对象修正后重跑。

## 套餐过滤

package 在当前设计中是过滤视图，不是复制、安装或分发 YAML 的机制。工程师通过 package 快速聚合一组相关操作，再在测试用例中直接引用这些操作的 `op_id`。

查看全部 package：

```bash
atomic-ops packages
```

按 package 过滤操作列表：

```bash
atomic-ops list --package networking
atomic-ops list --package security
```

结合设备类型继续收窄：

```bash
atomic-ops list --package networking --device fw
```

校验 package 内的全部引用：

```bash
atomic-ops validate --package networking
```

当前基线 package 包括 `networking` 和 `security`。两者都引用 `fw_verify_acl_rule`，用于演示 package 清单如何复用同一 atom。维护 package 时，`package_id` 应与文件名保持一致，例如 `packages/networking.yaml` 的 `package_id` 为 `networking`；`operations` 中只写 op_id，不写文件路径，也不嵌入 atom YAML 内容。

如果 `list --package <name>` 返回 `PACKAGE_NOT_FOUND`，先执行 `atomic-ops packages` 查看可用名称。如果 `list --package` 的 `missing_count` 大于 0，说明 package 清单中存在当前缓存无法解析的 op_id，应由维护者修正 package 清单或补齐对应 atom。

## 贡献流程

新增或修改 atom 时，先确定 `op_id`。命名必须符合 `^(fw|tg|mock|sw)_[a-z]+_[a-z_]+$`，语义形状为 `{device_prefix}_{verb}_{target}`。前缀必须与 `device_type` 和文件路径一致，例如：

```text
atoms/fw/fw_verify_acl_rule.yaml
```

受控动词包括 `create`、`delete`、`update`、`apply`、`rollback`、`verify`、`start`、`stop`、`reset`、`capture`。优先复用现有动词；确实需要新增动词或设备前缀时，按变更流程同步更新 schema、命名规范、layout 校验、CLI validate 逻辑和 CHANGELOG。

推荐贡献步骤：

1. 在 `atoms/<device_type>/<op_id>.yaml` 创建或修改 atom。
2. 确认顶层字段使用当前 schema 口径，例如 `op_id`、`device_type`、`parameters`、`returns`、`idempotent`、`timeout_ms`、`error_types`、`preconditions`、`postconditions`、`tags`、`deprecated`、`deprecated_by`、`since_version`。
3. 只使用已登记的操作级 `error_type`：`TIMEOUT`、`DEVICE_UNREACHABLE`、`INVALID_PARAM`、`RESOURCE_CONFLICT`、`RESOURCE_NOT_FOUND`、`PERMISSION_DENIED`、`STATE_MISMATCH`、`INTERNAL_ERROR`、`DRY_RUN`。
4. 如该操作属于现有 package，更新 `packages/<package_id>.yaml` 的 `operations` 列表；如新增 package，确保文件名、`package_id` 和用途说明一致。
5. 在 `CHANGELOG.md` 的下一条 `atoms-vX.Y.Z` 记录新增、修改、废弃、删除或安全相关变化。
6. 本地运行 schema、layout 和引用校验，再发起 review。

本地验证入口示例：

```bash
uv run python scripts/layout_check.py .
uv run --with pyyaml --with jsonschema --python 3.11 python scripts/validate_schema.py atoms/fw/fw_verify_acl_rule.yaml
atomic-ops sync --repo git@<GITLAB_HOST>:<ORG/PROJECT>/ptm-atomic.git
atomic-ops validate --package networking
```

修改已被测试用例引用的 `op_id` 时，不要直接删除旧操作。先创建新 atom，再将旧 atom 标记为 `deprecated: true`，填写 `deprecated_by` 和 `since_version`，同步更新 package 清单和 CHANGELOG，最后在下一个明确版本窗口删除旧引用。

## 故障诊断

CLI 顶层错误固定为五类。JSON 模式失败时，错误对象写入 stderr；成功结果写入 stdout。文本模式失败时，stderr 中会包含错误码、诊断和建议。

| 错误码 | 退出码 | 常见触发 | 处理建议 |
|---|---:|---|---|
| `GIT_AUTH_FAILED` | 21 | git 仓库认证失败，SSH key 或系统 credential helper 未配置 | 配置 git 原生认证后重跑 `atomic-ops sync` |
| `GIT_NETWORK_ERROR` | 22 | DNS、网络、远端不可达、TLS 或 git timeout | 网络恢复后重跑 `atomic-ops sync`；已有完整缓存时可继续只读工作 |
| `OP_NOT_FOUND` | 23 | `show` 或 `validate` 引用未知 op_id | 先 `atomic-ops sync`，再检查拼写、前缀和相似建议 |
| `REPO_NOT_SYNCED` | 24 | 首次运行、缓存缺失、`_metadata.json` 损坏或 clone 不完整 | 运行 `atomic-ops sync`；确认缓存父目录可写且没有普通文件占用路径 |
| `PACKAGE_NOT_FOUND` | 25 | `list --package` 或 `validate --package` 引用未知 package | 运行 `atomic-ops packages` 后选择存在的 package 名称 |

常见排查顺序：

1. 先看 stderr 中的 `error_code`，不要只看退出码。
2. 对同步失败，先确认默认仓库地址和 git 认证，再确认网络可达。
3. 对读取失败，确认是否已经执行过 `atomic-ops sync`，并检查缓存路径是否存在。
4. 对 `OP_NOT_FOUND`，用 `atomic-ops list --format json` 或 `atomic-ops list --device <device>` 查找候选。
5. 对 package 问题，先用 `atomic-ops packages` 列出合法 package，再用 `atomic-ops validate --package <name>` 检查引用完整性。

缓存损坏时可以清理平台缓存根目录后重新同步，但清理前应确认路径确实是 `~/.cache/atomic-ops/repo/` 或 `%LOCALAPPDATA%\\atomic-ops\\repo\\`，避免误删其他目录。清理动作不应在共享脚本中静默执行，应由工程师明确确认后手动完成。

## 发布与联调前检查

发布、联调或大批量引用前，按固定顺序做一次最小检查。第一步额外执行 `atomic-ops sync`，确保本地缓存不是过期数据；第二步浏览 package 和目标 op_id；第三步运行 validate，确认测试用例或 package 引用完整。

建议命令：

```bash
atomic-ops sync
atomic-ops packages
atomic-ops list --package networking
atomic-ops show fw_verify_acl_rule
atomic-ops validate --package networking
atomic-ops validate test-case.yaml
```

如果联调需要固定版本，先与项目负责人确认要使用的分支、tag 或 commit，再执行：

```bash
atomic-ops sync --ref <branch-or-tag-or-commit>
```

固定 ref 后，`_metadata.json` 中的 `ref_mode` 会记录为 `pinned`。恢复跟踪默认分支时执行 `atomic-ops sync --latest`。交接给其他团队时，应同时记录 `commit_sha` 和 `synced_at`，使问题复现时能确认操作库版本。

## 附录：CLI 合同速查

| 命令 | 用途 | 常用参数 | 成功输出 |
|---|---|---|---|
| `atomic-ops sync` | 同步本地操作库缓存 | `--repo`、`--latest`、`--ref`、`--format json/text` | 同步状态、ref、commit、cache root |
| `atomic-ops list` | 列出 atom 摘要 | `--device`、`--package`、`--format json/table` | 操作摘要列表、过滤条件、package missing count |
| `atomic-ops show` | 查看单个 atom | `<op_id>`、`--format json/yaml` | atom 原始 YAML 或 JSON 对象 |
| `atomic-ops packages` | 列出 package 清单 | `--format json/table` | package 摘要列表 |
| `atomic-ops validate` | 校验测试用例或 package 引用 | `<test_case>`、`--package`、`--format json/table` | validate 报告或结构化错误 |

stdout/stderr 约定保持一致：成功结果写 stdout；错误对象、warning、stale cache 提醒写 stderr。机器消费时优先使用 `--format json`，并按 `error_code`、`retryable`、`details`、`suggestion` 字段处理失败。
