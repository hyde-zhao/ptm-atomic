# 工程师手册

本文面向维护 `ptm-atomic` 的工程师，说明当前交付面、贡献流程、CLI 执行边界、静态检查和发布前验证。当前 CLI 子命令包括 `sync`、`list`、`show`、`adapter`、`run`、`packages`、`validate`；`run` 按操作族分为 `auth`、`object`、`policy-route`、`interface`、`ospf`、`ospfv3` 六个嵌套子命令族。除 `run` 白名单 op 外，其余命令只读。

## 1. 维护边界

`ptm-atomic` 仓库的用户可见交付面是：

```text
atoms/
adapters/
schemas/
packages/
docs/
src/atomic_ops/
scripts/
pyproject.toml
uv.lock
```

维护文档时不要把其他内部目录描述为用户安装或交付目录。CLI 本体由 `uv tool install .` 或 `uv run ptm-atomic ...` 使用；操作库数据由 `ptm-atomic sync` 写入本地缓存。

### 生成过程产物与源代码卫生

以下路径是本地过程、运行时或工具产物，不是用户可见交付面：

| 路径 / 模式 | 处理规则 |
|---|---|
| `.input/` | 本地输入和临时资料目录；不得把内容写入文档示例或发布包。 |
| `process/` | Meta Flow 工作流内部过程文档；不作为 `ptm-atomic` 交付文档发布。 |
| `checkpoints/` | Meta Flow 人工检查点草稿；不作为产品文档发布。 |
| `AGENTS.md` | 本地生成的 agent 规则文件；当前 `.gitignore` 忽略它。 |
| `.agents/`、`.codex/`、`.claude/` | 本地 agent 或 IDE runtime 配置；不得作为消费者安装步骤。 |
| `.cache/`、`logs/`、`*.log`、`__pycache__/` | 缓存、日志和解释器产物；不得提交或发布。 |

如需记录交付事实，写入 `README.md`、`docs/` 或 `CHANGELOG.md`。不要把 `.input/`、`process/`、`checkpoints/` 中的过程性材料复制成用户示例。

## 2. 环境准备

工程师本机需要 Python 3.11+、`uv` 和 `git`。Python 依赖以 `pyproject.toml` 为声明来源，以 `uv.lock` 为锁定结果。

```bash
uv run ptm-atomic --help
uv run --python 3.11 python scripts/layout_check.py
```

仓库脚本和示例命令统一使用 `uv run` 或 `uv tool`。不要把裸 `pip install` 写成默认安装路径。

## 3. CLI 生命周期

CLI 与操作库缓存是两条生命周期：

| 对象 | 管理命令 | 影响 |
|---|---|---|
| CLI 本体 | `uv tool install .`、`uv tool upgrade ptm-atomic` | 安装或升级 `ptm-atomic` 命令和 Python 依赖。 |
| 操作库缓存 | `ptm-atomic sync --repo <ptm-atomic-git-repository-url>` | 同步 `atoms/`、`schemas/`、`packages/`、`docs/`、`adapters/` 到本地缓存。 |

同步后只读命令从缓存读取：

```bash
ptm-atomic packages
ptm-atomic list --package ngfw_capacity_config
ptm-atomic show fw_config_interface
ptm-atomic adapter fw_config_object
ptm-atomic adapter fw_config_policy_route
ptm-atomic adapter fw_config_ospfv2_global
ptm-atomic adapter fw_config_ospfv3_global
ptm-atomic adapter fw_config_bfd_global
ptm-atomic run object config --base-url https://<device-management-ip> --object-name srcObj --ipaddr 192.168.0.0 --mask 16
ptm-atomic run policy-route config --base-url https://<device-management-ip> --source-network srcObj --dst-network dstObj --next-hop-ip 1.1.1.1 --in-interface GE0_12
ptm-atomic run policy-route config --base-url https://<device-management-ip> --source-network any --dst-network any --in-interface GE0_2.106 --outgoing-interface tunnel2 --weight 123
ptm-atomic run ospf verify neighbor --base-url https://<device-management-ip> --page 1 --size 40
ptm-atomic run ospfv3 bfd verify-session --base-url https://<device-management-ip> --page 1 --size 40
ptm-atomic validate --package ngfw_installation
```

`run` 命令按操作族分为嵌套子命令（`auth`、`object`、`policy-route`、`interface`、`ospf`、`ospfv3`），默认 dry-run。只有 Web 登录、地址对象、策略路由、OSPFv2、OSPFv3 和 BFD 白名单 op 在显式 `--execute` 后会连接设备。其他命令不连接设备、不执行 atom、不推送配置、不保存凭据、不执行自动回滚。

`list`、`show`、`adapter`、`packages` 和 `validate` 都读取 synced cache，不读取当前工作树中尚未同步的修改。若 `sync` 失败但缓存完整，命令可能带 `STALE` 警告继续使用旧缓存；此时缓存 smoke test 不能证明当前工作树 manifest 已发布或已同步。

## 4. Schema v1.1 维护要点

新增或修改 atom 时使用 `schema_version: "1.1"`。路径、`device_type` 和 `op_id` 前缀必须一致：

```text
atoms/fw/fw_verify_interface.yaml
```

维护时重点检查：

| 字段 | 要求 |
|---|---|
| `risk` | 对有状态或高风险操作写明风险等级和说明。 |
| `credential_ref` | 只能写引用名，不能写真实凭据值。 |
| `session_ref` | 只能写会话引用，不能写 cookie 或会话密钥。 |
| `state_ref` | 只能写状态引用，不能嵌入生产数据。 |
| `gate` | 高风险或批量操作应声明前置门禁。 |
| `verification` | 配置类 atom 应声明验证方式或验证引用。 |
| `batch` | 批量 atom 应声明并发、失败策略和结果摘要字段。 |
| `adapter_contract_ref` | 可选引用公开 adapter profile operation；profile 只描述 API shape，不保存运行时材料。 |
| `aliases` | 可选的同义搜索词列表。用于上游消费者（m-analyzer）将自然语言变体（subinterface、trunk）匹配到标准 op_id。例如 `fw_config_interface` 的 aliases 为 `[subinterface, trunk, lag, bond, bvi, vlan-interface]`。无变体名时为空列表。 |

字段细节见 `docs/schema-field-reference.md`。批量配置字段见 `docs/batch-configuration-contract.md`。
Adapter profile 维护规则见 `docs/API-ADAPTER-SPEC.md`。

## 5. 当前 Package 事实

| Package | 用途 | op_id 数 |
|---|---|---:|
| `networking` | 旧基线网络验证视图 | 1 |
| `security` | 旧基线安全验证视图 | 1 |
| `ngfw_installation` | NGFW 安装初始化合同 | 5 |
| `ngfw_capacity_config` | 十域容量配置合同 | 10 |
| `ngfw_verification` | 十域容量验证合同 | 10 |
| `ngfw_batch_config` | 十域多设备批量配置合同 | 10 |

`ngfw_installation` 当前包含：

- `fw_install_ngfw_image`
- `fw_init_ngfw_minimal`
- `fw_login_web_management`
- `fw_check_login_state`
- `fw_verify_ngfw_health`

容量配置域：

- `fw_config_interface`
- `fw_update_interface`
- `fw_delete_interface`
- `fw_delete_batch_interface`
- `fw_config_object`
- `fw_update_object`
- `fw_delete_object`
- `fw_delete_batch_object`
- `fw_config_acl_policy`
- `fw_config_policy_route`
- `fw_config_ospfv2_global`
- `fw_config_ospfv2_redistribution`
- `fw_config_ospfv2_network`
- `fw_config_ospfv2_network_update`
- `fw_delete_ospfv2_network`
- `fw_config_ospfv2_interface`
- `fw_config_ospfv2_interface_update`
- `fw_delete_ospfv2_interface`
- `fw_config_ospfv3_global`
- `fw_config_ospfv3_redistribution`
- `fw_config_ospfv3_network`
- `fw_config_ospfv3_network_update`
- `fw_delete_ospfv3_network`
- `fw_config_ospfv3_interface`
- `fw_config_ospfv3_interface_update`
- `fw_delete_ospfv3_interface`
- `fw_config_bfd_global`
- `fw_config_static_route`
- `fw_config_nat`
- `fw_config_bandwidth`
- `fw_config_black_white_list`
- `fw_config_ssl_vpn`
- `fw_config_dynamic_routing`

容量验证域：

- `fw_verify_interface`
- `fw_verify_object`
- `fw_verify_acl_policy`
- `fw_verify_policy_route`
- `fw_verify_ospfv2_global`
- `fw_verify_ospfv2_redistribution`
- `fw_verify_ospfv2_network`
- `fw_verify_ospfv2_interface`
- `fw_verify_ospfv2_neighbor`
- `fw_capture_ospfv2_log`
- `fw_verify_ospfv3_global`
- `fw_verify_ospfv3_redistribution`
- `fw_verify_ospfv3_network`
- `fw_verify_ospfv3_interface`
- `fw_verify_ospfv3_neighbor`
- `fw_capture_ospfv3_log`
- `fw_verify_bfd_global`
- `fw_verify_bfd_session`
- `fw_capture_bfd_log`
- `fw_verify_static_route`
- `fw_verify_nat`
- `fw_verify_bandwidth`
- `fw_verify_black_white_list`
- `fw_verify_ssl_vpn`
- `fw_verify_dynamic_routing`

批量配置域：

- `fw_config_batch_interface`
- `fw_config_batch_object`
- `fw_config_batch_policy_route`
- `fw_config_batch_static_route`
- `fw_config_batch_nat`
- `fw_config_batch_bandwidth`
- `fw_config_batch_black_white_list`
- `fw_config_batch_ssl_vpn`
- `fw_config_batch_dynamic_routing`

`ngfw_verification` 只覆盖十个容量域验证，不包含 `fw_verify_ngfw_health`。健康检查属于 `ngfw_installation`。

package manifest 仅是 `op_id` 过滤视图，供 `list --package` 和 `validate --package` 读取。它们不安装 atom、不复制 atom 文件、不执行 atom、不分发 atom，也不是编排计划。

当前完整性事实：

- `packages/` 下有 6 个 manifest。
- 6 个 manifest 合计 69 条 `operations` 条目。
- 合计 68 个唯一 `op_id`，其中 `fw_verify_acl_rule` 同时属于 `networking` 与 `security` 旧基线视图。
- 所有 package `op_id` 都解析到 `atoms/fw/*.yaml`。

## 6. 批量配置合同

批量配置 atom 使用 `batch` 字段描述多设备行为。当前合同要点：

| 项 | 要求 |
|---|---|
| 并发 | 默认 `max_concurrency: 1`；schema 上限为 5。 |
| 失败策略 | 支持记录 `partial_failed`、`per_device_results`、`failed_devices`、`verification_summary_ref`。 |
| 门禁 | 高风险批量配置必须声明 gate。 |
| 幂等 | 批量配置 atom 必须明确幂等语义。 |

详细规则见 `docs/batch-configuration-contract.md`。

## 7. 新增 Atom 流程

1. 选择符合 `^(fw|tg|mock|sw)_[a-z]+_[a-z0-9_]+$` 的 `op_id`。
2. 在 `atoms/<device_type>/<op_id>.yaml` 创建或修改 atom。
3. 填写 schema v1.1 必填字段和适用的 v1.1 扩展字段。
4. 如属于已有 package，更新 `packages/<package_id>.yaml` 的 `operations`。
5. 如新增 package，确保文件名、`package_id` 和用途一致。
6. 更新 `CHANGELOG.md` 的 Unreleased 条目。
7. 运行发布前自检。

示例路径：

```text
atoms/fw/fw_verify_nat.yaml
packages/ngfw_verification.yaml
```

不要直接删除已被用例引用的 `op_id`。需要替换时，先保留旧 atom 并标记 `deprecated: true`、填写 `deprecated_by` 和 `since_version`，再在明确发布窗口删除旧引用。

## 8. 测试用例引用

测试用例通过 `op_id` 引用 atom。当前 CLI validate 读取：

- `steps[].op_id`
- `tight_sequence.steps[].op_id`

推荐从 `docs/test-case-template.yaml` 开始。模板使用逻辑设备名，不写真实地址或凭据。

```bash
ptm-atomic validate docs/test-case-template.yaml
```

## 9. 发布前自检

每次修改 atom、package、schema、CLI 或文档后，先运行工作树检查：

```bash
uv run ptm-atomic --help
uv run --python 3.11 python scripts/validate_schema.py atoms
uv run --python 3.11 python scripts/validate_adapter_profiles.py
uv run --python 3.11 python scripts/layout_check.py
uv run --python 3.11 python scripts/security_gate_check.py
uv run --python 3.11 python scripts/check_aliases.py
uv run --python 3.11 python scripts/check_package_refs.py
```

如果修改了 `packages/*.yaml` 或 `atoms/**/*.yaml`，还要检查 package-reference invariant：每个 `packages/*.yaml` 的 `operations[]` 必须解析到对应 atom 文件，且 `package_id` 必须等于文件名。

缓存消费者 smoke test 单独运行：

```bash
ptm-atomic packages
ptm-atomic adapter fw_config_object
ptm-atomic adapter fw_config_policy_route
ptm-atomic validate --package ngfw_installation
ptm-atomic validate --package networking
```

`ptm-atomic packages`、`ptm-atomic adapter <op_id>` 与 `ptm-atomic validate --package ...` 是 synced-cache smoke tests。如果本地 CLI 缓存尚未同步到包含新 package 或 adapter profile 的提交，`validate --package` 可能返回 `PACKAGE_NOT_FOUND`，`adapter` 可能返回 `REPO_NOT_SYNCED`；如果缓存处于 `STALE`，它也可能落后于当前仓库。先运行 `ptm-atomic packages` 和代表性 `adapter` 查询查看当前缓存事实，再同步到目标提交。

## 10. 安全门禁

`scripts/security_gate_check.py` 默认扫描：

- `atoms/`
- `adapters/`
- `packages/`
- `docs/`
- `schemas/`
- `scripts/`
- `src/atomic_ops/`

默认排除 `.input/`、`.git/`、`.venv/`、`__pycache__/`、`.pytest_cache/`、`.mypy_cache/`、`.ruff_cache/`、`.tox/`、`.nox/`、`.cache/`、`build/`、`dist/`、`htmlcov/`、`site/` 和 `.eggs/`。安全门禁执行两类只读检查：

- 敏感赋值模式检测：扫描文本文件中的 `token`、`cookie`、`authorization`、`password`、`ftp_pass`、`secret` 等赋值，允许 `<placeholder>` 形式和已批准示例字面值。
- Adapter profile 敏感内容检测：对 `adapters/` YAML 执行结构化字段名和值扫描，拒绝运行时敏感材料、生产样本和 `.input/capacity` 依赖；默认模式下若 `adapters/` 尚不存在，不会因此阻断安全门。
- 高风险 atom gate 完整性：对 `risk.level=high` 或 `op_id` 匹配 `^fw_(install|init|login|config|config_batch)_` 的 YAML，要求 `gate.required: true`，且 `gate.reason`、`gate.approver_role`、`gate.evidence_required` 非空。
- Adapter profile 边界：`scripts/validate_adapter_profiles.py` 校验 `adapters/` 中的公开 profile，并拒绝 runtime-sensitive 字段或值、生产样本和 `.input/capacity` 依赖。

退出码固定为：`31` 表示敏感模式发现，`32` 表示高风险 gate 合同缺失，`33` 表示输入、路径、schema 或 YAML 读取解析错误。

当前唯一允许作为示例出现的密码策略字面值是 `Ngfw@123`。除此之外，不要在仓库中写真实地址、token、cookie、私钥、FTP 凭据、生产样本或设备登录材料。

## 11. 错误处理

CLI 顶层错误码见 `docs/error-codes.md`：

| 错误码 | 退出码 | 处理 |
|---|---:|---|
| `GIT_AUTH_FAILED` | 21 | 检查 git 原生认证。 |
| `GIT_NETWORK_ERROR` | 22 | 网络恢复后重跑 `ptm-atomic sync`。 |
| `OP_NOT_FOUND` | 23 | 同步缓存后检查 `op_id`。 |
| `REPO_NOT_SYNCED` | 24 | 执行 `ptm-atomic sync --repo <ptm-atomic-git-repository-url>`。 |
| `PACKAGE_NOT_FOUND` | 25 | 用 `ptm-atomic packages` 查看可用 package。 |

脚本错误码包括 schema 校验、布局检查和安全门禁错误码。发布报告应记录命令、退出码和关键输出。

## 12. 发布记录

`CHANGELOG.md` 使用两条版本流：

- `atoms-vX.Y.Z`：schema、atom、package、命名规则和文档。
- `cli-vX.Y.Z`：CLI 代码、命令行为和 Python 包发布。

文档更新应记录其依据的 atom、package、schema 和验证事实。不要在发布说明中承诺当前 CLI 未实现的设备执行、配置下发或自动回滚能力。
