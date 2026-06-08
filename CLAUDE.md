# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

`ptm-atomic` 是防火墙测试原子操作规范仓库与本地消费 CLI。CLI 通过 git 同步远端操作库到本地缓存，之后 `list`、`show`、`packages`、`validate` 均只读取本地缓存，不实时访问网络。

## 常用命令

### 安装与运行

```bash
# 安装到工具环境
uv tool install .

# 开发/临时验证（不安装）
uv run ptm-atomic --help
```

### CLI 命令

```bash
ptm-atomic sync                                    # 同步远端仓库到本地缓存
ptm-atomic sync --repo git@host:path/repo.git      # 指定仓库地址
ptm-atomic sync --latest                           # 跟踪默认分支
ptm-atomic sync --ref <tag|sha>                    # 固定到特定 ref
ptm-atomic list                                    # 列出所有 atom
ptm-atomic list --device fw                        # 按设备类型过滤
ptm-atomic list --package networking --format json  # 按 package 过滤
ptm-atomic show fw_verify_acl_rule                 # 查看单个 atom
ptm-atomic show fw_verify_acl_rule --format json   # JSON 格式输出
ptm-atomic packages                                # 列出 package 清单
ptm-atomic validate docs/test-case-template.yaml   # 校验测试用例引用
ptm-atomic validate --package networking            # 校验 package 引用完整性
```

### CLI Run 嵌套子命令

`run` 命令按操作族分组为嵌套子命令，每个叶子命令只暴露自己的参数：

```bash
# 认证
ptm-atomic run auth login --base-url https://10.0.0.1 --username admin [--execute]

# 地址对象
ptm-atomic run object config --base-url https://10.0.0.1 --object-name srcObj --ipaddr 192.168.0.0 --mask 16

# 策略路由（三级：族/动作）
ptm-atomic run policy-route config --base-url https://10.0.0.1 --source-network net1 --in-interface GE0_1
ptm-atomic run policy-route delete --base-url https://10.0.0.1 --id 1

# 接口（三级：族/动作）
ptm-atomic run interface create --base-url https://10.0.0.1 --kind physical --id 1
ptm-atomic run interface delete-batch --base-url https://10.0.0.1 --id GE0_1 --id GE0_2

# OSPFv2（四级：族/动作/目标）
ptm-atomic run ospf config global --base-url https://10.0.0.1 --enable --router-id 10.1.1.1
ptm-atomic run ospf verify neighbor --base-url https://10.0.0.1 --page 1 --size 40
ptm-atomic run ospf delete interface --base-url https://10.0.0.1 --id GE0_1

# OSPFv3 + BFD
ptm-atomic run ospfv3 config global --base-url https://10.0.0.1 --enable
ptm-atomic run ospfv3 bfd config --base-url https://10.0.0.1
ptm-atomic run ospfv3 bfd verify-session --base-url https://10.0.0.1

# 向后兼容：旧格式 ptm-atomic run <op_id> 仍可用（deprecation warning）
ptm-atomic run fw_config_ospfv2_global --base-url https://10.0.0.1 --enable --router-id 10.1.1.1
```

**共享参数**（在 `run` 层级定义，所有子命令继承）：
`--base-url`（必填）、`--session-file`、`--timeout`、`--verify-tls`、`--format`、`--execute`、`--auth-header`

### 仓库维护脚本

```bash
# 布局检查
uv run python scripts/layout_check.py .

# 单个 atom schema 校验
uv run --with pyyaml --with jsonschema --python 3.11 python scripts/validate_schema.py atoms/fw/fw_verify_acl_rule.yaml
```

## 代码架构

### 源码结构 (`src/atomic_ops/`)

- `cli.py` — CLI 入口，argparse 嵌套子命令注册（`CommandSpec` + `CommandGroup`），`main()` 函数
- `commands/__init__.py` — 命令注册模型定义（`CommandSpec`、`CommandGroup`）
- `commands/` — 每个子命令一个模块
  - `sync.py`、`list_ops.py`、`show.py`、`packages.py`、`validate.py`、`adapter.py` — 顶层子命令
  - `run.py` — run 入口：共享参数注册 + 子命令树构建 + 旧格式兼容
  - `run_auth.py`、`run_object.py` — 简单操作族（二级嵌套）
  - `run_policy_route.py`、`run_interface.py` — 中等复杂度操作族（三级嵌套）
  - `run_ospf.py`、`run_ospfv3.py` — 高复杂度操作族（四级嵌套）
- `repository.py` — 本地缓存的只读访问层，`Repository` 类封装所有 atom/package 读取逻辑
- `git_ops.py` — 系统 git 适配器，`GitClient` 处理 clone、sparse checkout、fetch、pull
- `metadata.py` — 缓存元数据管理（`_metadata.json` 读写、缓存路径解析、敏感信息脱敏）
- `errors.py` — CLI 错误对象与公共输出辅助（`CliError`、`write_error`、`write_warning`、`write_stale_warning`、`write_read_error`、`details_text`）
- `suggestions.py` — op_id 模糊匹配建议（Levenshtein 距离）
- `runner/` — 操作族 runner 实现（`ngfw_login.py`、`object.py`、`policy_route.py`、`interface.py`、`ospfv2.py`、`ospfv3_bfd.py`）

### 数据目录

- `atoms/<device_type>/<op_id>.yaml` — 原子操作定义（device_type: `fw`, `tg`, `mock`, `sw`）
- `packages/<package_id>.yaml` — package 过滤视图（仅引用 op_id 列表，不复制 atom）
- `schemas/atomic-op.schema.yaml` — atom YAML 的 JSON Schema 定义
- `docs/` — 字段参考、命名规范、错误码、工程师手册、测试用例模板

### 关键设计约束

- **双版本流**：`atoms-vX.Y.Z`（操作库）和 `cli-vX.Y.Z`（CLI 包）独立发布
- **op_id 命名规范**：`{device_prefix}_{verb}_{target}`，动词来自受控词汇表（`docs/naming-convention.md`）
- **缓存路径**：Linux/macOS `~/.cache/ptm-atomic/repo/`，Windows `%LOCALAPPDATA%\ptm-atomic\repo\`
- **stdout/stderr 分离**：成功结果写 stdout，warning/错误/建议写 stderr
- **敏感信息脱敏**：所有输出经过 `redact_sensitive()` 处理，URL 凭据、token、密码自动脱敏
- **错误码固定**：5 个 CLI 级错误码（21-25），9 个操作级错误类型（`docs/error-codes.md`）
- **sparse checkout**：git >= 2.25 使用 sparse checkout，旧版本回退到全量 checkout

## 依赖管理

使用 `uv` 管理 Python 环境和依赖，`pyproject.toml` 为唯一依赖声明，`uv.lock` 为锁定结果。运行时依赖仅 `pyyaml` 和 `jsonschema`。禁止裸 `pip install`。

<!-- myflow:managed:begin v=1 commit=77ccc4e generated=2026-06-08T07:35:33Z -->
<!-- myflow-managed: version=1.0.0 canonical-commit=77ccc4e generated=2026-06-08T07:35:33Z -->

# Meta Flow 元工作流 — Claude Code 全局指令

本会话运行 **Meta Flow** 通用 Agent/Skill 工作流产物工厂。

---

## 角色与编排

- **主编排器**：`meta-po`（元工作流产品负责人），负责状态管理、阶段推进、CP0-CP8 检查点控制；不自动常驻，只有显式 `@meta-po` 或触发词命中时启动
- **功能 Agent**（按需启用）：`meta-pm`、`meta-se`、`meta-dev`、`meta-qa`、`meta-doc`
- **所有任务均通过 meta-po 发起**；`meta-pm` / `meta-se` 在阶段委托期间可直接与用户多轮沟通，阶段交还后仍由 meta-po 发起 CP2 / CP3 正式人工确认
- **调度证据优先**：handoff 文件只表示交接，不表示功能 Agent 已执行。功能 Agent 完成必须有平台 Task/Subagent 证据，或用户明确批准的 `inline-fallback`。
- **显示区分**：Claude Code 文件型 subagent 不使用 nickname；安装器通过 `color` 字段区分角色：`meta-po=red`、`meta-pm=orange`、`meta-se=yellow`、`meta-dev=green`、`meta-qa=cyan`、`meta-doc=purple`。Codex 侧默认每个 canonical subagent 预留 5 个命令别名，其中 `meta-dev` 与 `meta-qa` 各预留 10 个；按百家姓顺序依次为 `po-zhao/po-qian/po-sun/po-li/po-zhou`、`pm-wu/pm-zheng/pm-wang/pm-feng/pm-chen`、`se-chu/se-wei/se-jiang/se-shen/se-han`、`dev-yang/dev-zhu/dev-qin/dev-you/dev-xu/dev-he/dev-lv/dev-shi/dev-zhang/dev-kong`、`qa-he/qa-lv/qa-shi/qa-zhang/qa-kong/qa-cao/qa-yan/qa-hua/qa-jin/qa-wei`、`doc-cao/doc-yan/doc-hua/doc-jin/doc-wei`。

## Skill 发现路径

Skill 定义文件统一位于：`.agents/skills/<skill-name>/SKILL.md`

可用 Skills 及其触发词：

| Skill | 触发词 |
|-------|--------|
| `state-router` | 推进、下一步、当前状态、回退、状态查询、继续 |
| `checkpoint-manager` | 检查点、checklist、自检结果、人工审查、CP0、CP1、CP2、CP3、CP4、CP5、CP6、CP7、CP8 |
| `use-case-discovery` | 场景发现、使用场景讨论、用户场景梳理、use-case workshop、use case discovery |
| `requirement-extraction` | 提取需求、整理需求、结构化需求、需求分析 |
| `requirement-clarifier` | 澄清需求、需求问题、未决问题、需求歧义 |
| `scenario-expansion` | 展开场景、生成场景、测试场景、场景扩展 |
| `story-planning` | Story Map、MVP 范围、发布切片、产品规划、范围确认 |
| `blueprint-design` | 蓝图设计、Feature 边界、能力地图、领域建模、依赖地图 |
| `implementation-design` | Feature 设计、实现设计、技术设计、TEST-PLAN、TASKS |
| `implementation-execution` | 实现执行、IMPLEMENTATION、实现对象清单、设计契约映射、Fixture、最小实现切片 |
| `verification-execution` | 验证执行、VERIFICATION、验证对象清单、验证追踪矩阵、设计契约验证、PASS_WITH_RISK、CP7 |
| `quality-review` | 质量评审、测试报告、代码评审、REVIEW、TEST-REPORT |
| `release-readiness` | 发布准备、上线检查、回滚方案、RELEASE-NOTES、DEPLOY-CHECKLIST |
| `scope-normalization` | 归一化需求、去重、合并需求、范围整理 |
| `hld-designer` | HLD、高层设计、架构评审、架构方案、方案设计、架构设计、复杂度判定、设计方案、simple/standard/complex 判断 |
| `lld-designer` | LLD、详细设计、实现设计、Story 设计 |
| `claude-agent-writer` | 写 Claude Agent、创建 Claude 子代理、Claude subagent |
| `phase-designer` | 阶段划分、设计阶段、Phase 设计、执行顺序 |
| `wave-planner` | 并行分组、Wave 划分、并行计划、任务编排 |
| `dependency-mapper` | 依赖关系、DAG、任务依赖、前置依赖 |
| `story-manager` | 拆分 Story、Story 状态、Story 卡片、Story 管理 |
| `dag-validator` | DAG 校验、依赖校验、循环依赖检查 |
| `coverage-checker` | 覆盖率检查、场景覆盖、未覆盖场景 |
| `dangerous-command-scan` | 危险命令、命令扫描、安全扫描、风险扫描 |
| `platform-validator` | 校验安装目标、平台验证、结构校验 |
| `package-builder` | 安装脚本、安装到项目、用户级安装、平台安装 |
| `workflow-renderer` | 渲染工作流、生成文档、交付文档、输出工作流 |
| `context-handoff` | 上下文交接、装配上下文、阶段切换、交接给 |
| `context-manifest-builder` | 上下文清单、执行上下文、CONTEXT-MANIFEST |
| `review-artifact-protocol` | review gate、评审协议、advisor、Review Findings、Review Summary |
| `change-impact-analysis` | 需求变更、修改需求、变更影响、发起变更、CR |
| `issue-drafter` | 起草问题、创建 ISSUE、问题工单、报告问题 |
| `issue-routing` | 路由问题、分配问题、ISSUE 路由、问题分流 |
| `run-feedback-parser` | 执行反馈、提交反馈、记录执行结果、执行记录 |
| `regression-subset-builder` | 回归测试、最小回归集、修复验证、回归范围 |
| `runtime-risk-review` | 运行时风险、DryRun、执行环境、隔离检查 |
| `permission-boundary-check` | 权限检查、权限边界、越权验证、安全边界 |

## 状态文件

以下路径是 Meta Flow 无目标项目约定时的默认路由，不是 production 项目的强制目录。production 项目必须先识别目标项目已有交付目录和 README / docs 约定；存在约定时按目标项目路径映射并写入 `STATE.md.delivery_routing`，不得按下列默认路径另建 `docs/*` 或 `delivery/*`。

- **运行时状态**：`process/STATE.md`
- **自动检查结果**：`process/checks/CP*.md`
- **阶段上下文胶囊**：`process/context/CP*-*-CONTEXT.yaml`
- **讨论日志**：`process/discussions/CP2-SCENARIO-DISCUSSION-LOG.md`、`process/discussions/CP3-HLD-DISCUSSION-LOG.md`
- **高层设计**：`docs/design/HLD.md`
- **工程验证场景**：`docs/product/SCENARIOS.yaml`
- **测试覆盖矩阵**：`docs/product/TEST-MATRIX.md`
- **产品规划**：`docs/product/STORY-MAP.md`、`docs/product/MVP-SCOPE.md`、`docs/product/RELEASE-SLICES.md`、`docs/product/BACKLOG.md`
- **蓝图产物**：`docs/design/BLUEPRINT.md`、`docs/design/DOMAIN-MAP.md`、`docs/design/DEPENDENCY-MAP.md`
- **Feature 设计矩阵**：`docs/design/FEATURE-DESIGN-MATRIX.md`
- **Feature 级设计**：`docs/features/<feature>/DESIGN.md`、`docs/features/<feature>/TEST-PLAN.md`、`docs/features/<feature>/TASKS.md`
- **质量与发布产物**：`docs/quality/TEST-REPORT.md`、`docs/quality/REVIEW.md`、`docs/quality/FIXES.md`、`process/release/RELEASE-CONTEXT.yaml`、`docs/release/RELEASE-NOTES.md`、`docs/release/DEPLOY-CHECKLIST.md`、`docs/release/ROLLBACK.md`、`docs/release/MIGRATION.md`、`docs/release/FEEDBACK.md`
- **验证执行报告**：`docs/quality/VERIFICATION-REPORT.md` 或 `docs/features/<feature>/VERIFICATION.md`
- **Skill 私有模板**：`skills/<skill-name>/templates/`
- **人工确认稿**：`process/checkpoints/CP*.md`
- **Story 卡片**：`process/stories/STORY-*.md`
- **Story 设计证据**：`process/stories/STORY-*.md` 的 `technical-note` / `waived` 证据，或 `process/stories/STORY-*-LLD.md`
- **Story 实现执行证据**：`process/stories/STORY-*-IMPLEMENTATION.md`、`docs/features/<feature>/IMPLEMENTATION.md`，或低风险 Story 卡片 `implementation_context` / DEV-LOG 摘要
- **变更单**：`process/changes/CR-*.md`

## Python 环境与依赖管理（uv）

若项目包含 Python 代码、脚本、验证工具或 MCP 服务，必须遵循以下约束：

1. 统一使用 `uv` 管理 Python 解释器、虚拟环境和依赖。
2. 存在项目级 Python 依赖时，以 `pyproject.toml` 为唯一依赖声明来源，以 `uv.lock` 为唯一锁定结果；禁止提交 `.venv/`。
3. 所有开发、测试、构建和脚本执行统一通过 `uv run` 触发；一次性工具统一优先使用 `uvx`。
4. 禁止将裸 `pip install`、系统 Python 或未入库依赖作为日常工作流默认入口。
5. 若项目尚未建立 `pyproject.toml` / `uv.lock`，仍必须使用 `uv` 管理解释器，并以 `uv run --python <version> python <script>` 作为 Python 命令入口。
6. README、USER-MANUAL 及平台规则文件中的 Python 示例必须与上述约束保持一致。

## 核心协议规则

1. **澄清锁**：CP2 需求 / 场景 / 范围基线门未通过前，不得输出正式设计对象；CP2 前必须形成 `SCENARIOS.yaml`、`TEST-MATRIX.md`、`STORY-MAP.md`、`MVP-SCOPE.md` 或明确 N/A / WAIVED 原因
2. **HLD 锁**：CP3 蓝图 / HLD 架构评审门未通过前，不得进入 Story 拆解；跨 Feature / Epic、数据归属或依赖方向问题必须先完成 `BLUEPRINT.md` / `DOMAIN-MAP.md` / `DEPENDENCY-MAP.md` 或写明 N/A / WAIVED 原因
3. **Feature 设计矩阵锁**：CP3 通过后、CP4 通过前必须生成 `docs/design/FEATURE-DESIGN-MATRIX.md`，并为每个 Story 写明 `feature_design_refs` 与 `lld_policy.required_level=full-lld|technical-note|waived`
4. **Story 设计证据锁**：CP4 Story 计划自动预检未通过前，不得开始全量设计证据写作；Story 未进入 `lld-ready` / `package-draft` 等待设计状态前，不得开始对应 Story 的完整 LLD、技术说明或 waived 证据
5. **Story 开发锁**：全部目标 Story 的 CP5 Story 设计证据可实现性门未通过、尚未进入 `story-execution`、当前 Wave 不可执行、`dev_gate` 未满足、或文件所有权冲突时，不得开始任何 Story 实现
5a. **实现执行证据锁**：Story 开发开始后，meta-dev 必须使用 `implementation-execution` 产出实现对象清单、设计契约映射、测试 / Fixture 计划、最小实现切片、平台差异检查、本地验证和交接摘要；复杂 / 高风险 / Prompt-Skill / Workflow / 安装器 / 护栏 / 平台适配 / 发布相关 Story 必须有完整 `IMPLEMENTATION.md`，低风险 N/A 必须写入 CP6 或 Story 卡片
6. **验证锁**：`validation_mode=runtime|mixed` 且需要真实运行时，没有 `process/VALIDATION-ENV.yaml` 或 `approval.confirmed != true`，不得开始运行验证；`static-only` / `dry-run-only` / `review-only` 可使用等价验证方式，但必须在 CP7 写明 N/A 理由、未覆盖风险和证据
7. **文档锁**：未完成验证和安装脚本生成，不得输出最终版 `README.md` 与 `USER-MANUAL.md`
8. **禁止越级改写**：`meta-dev` 不修改 REQUIREMENTS.md、MVP-SCOPE.md、BLUEPRINT.md、HLD.md；`meta-qa` 不改设计对象；`meta-doc` 不改实现对象
9. **调研前置**：meta-pm 在场景发现前执行阶段零快速调研，记录至 CLARIFICATION-LOG.md
10. **确定性语言**：meta-se / meta-dev 产出使用确定性动词（创建/修改/删除）和量化条件，禁止模糊表述
11. **就绪检查**：meta-dev 开始实现前必须通过 Story 卡片完整性检查，并确认 `feature_design_refs`、`lld_policy` 和 Story 设计证据已获批、依赖门控满足、文件所有权不冲突
12. **测试策略与质量评审前置**：meta-qa 验收前先输出 `docs/quality/TEST-STRATEGY.md` 并声明 `validation_mode=runtime|static-only|dry-run-only|review-only|mixed`；验证时先使用 `verification-execution` 消费 `SCENARIOS.yaml` / `TEST-MATRIX.md`、设计证据和 CP6 实现执行证据，输出 `docs/quality/VERIFICATION-REPORT.md`，确认验证对象、设计契约、测试 / Fixture、最小切片、平台差异、人工审查、问题和风险闭环；随后使用 `quality-review` 固化 TEST-REPORT / REVIEW，发布前使用 `release-readiness` 先生成 `process/release/RELEASE-CONTEXT.yaml`，再按 `release_artifact_profile=minimal|compact|full` 固化发布、部署、回滚、迁移和反馈回流
12a. **发布准备 capsule-first**：发布前必须判定 `release_decision=READY|READY_WITH_RISK|NOT_READY|RELEASED|FAILED`。CP8 默认只允许 `READY` / `READY_WITH_RISK` / `NOT_READY`；`RELEASED` / `FAILED` 必须有独立真实发布授权和执行证据。发布阶段不得默认读取完整 HLD、全部 LLD、完整 TEST-MATRIX、完整 TEST-REPORT、完整 REVIEW 或完整 diff；只消费摘要、计数、风险 ID、决策 ID 和证据路径。`CHANGELOG.md`、`INSTALL.md`、`TROUBLESHOOTING.md`、`POST-RELEASE-OBSERVATION.md` 不作为默认产物，仅 `full` profile 或用户明确要求时生成。
13. **输出路由**：长期产品 / 设计 / 质量 / 发布文档在无目标项目约定时默认写入 `docs/product/`、`docs/design/`、`docs/features/`、`docs/quality/`、`docs/release/`；运行态写入 `process/`，自动检查结果写入 `process/checks/`，确认稿写入 `process/checkpoints/`；旧 `process/*.md` 技术文档路径与根目录 `checkpoints/CP*.md` 仅作为 legacy fallback 读取；只有 meta-flow 自身改进才默认写当前仓库 `delivery/`。production 项目必须先扫描目标项目已有交付目录，以及 README/docs 中的交付、发布、构建或包结构约定；存在则按目标约定写入并记录 `STATE.md.delivery_routing`，不得按 Meta Flow 默认路径另建交付目录；缺失时先询问用户
14. **Agent/Skill 关系维护**：开发或修改 Agent、Skill 时，若影响调用、适用或归属关系，必须同步更新 `skills/README.md`
15. **交付脚本边界**：`delivery/scripts/` 只允许安装器入口；Skill 运行时脚本必须放到 `delivery/skills/<skill>/scripts/`
16. **Skill 资产同树安装**：active Skill 引用的 `templates/`、`scripts/`、`schemas/`、`examples/` 资产必须与 Skill 同树存放，并使用 Skill 相对路径或 `<skill-root>/...`
17. **脚本安装验证**：active Skill 一旦新增脚本资产，必须验证 Claude Code / Codex 在 project 与 user scope 下安装后可直接执行
18. **缓存文件禁入库**：`__pycache__/`、`*.pyc` 及其他解释器缓存不是交付物，不得提交
19. **护栏静态检查**：`scripts/check_delivery_guardrails.py` 是 meta-flow 自身仓库 guardrail；仅当当前仓库存在该文件时，提交前运行 `uv run --python 3.11 python scripts/check_delivery_guardrails.py`。外部 production 项目不得硬引用 `/home/hyde/projects/meta-flow/scripts/check_delivery_guardrails.py`，应改按目标 README/docs 的测试、构建、安装 dry-run 或用户确认的验证命令执行。
20. **模式默认值**：若用户未显式声明“meta 工作流优化 / 自我开发”，工作流默认 `engagement_mode=production`
21. **场景主体默认值**：若用户未显式声明 meta 优化，`USE-CASES.md` 默认 `scenario_subject_type=target-artifact`，不得把当前仓库 / 当前工作流当成默认场景主体
22. **平台契约优先**：涉及安装路径、schema 或发现机制时，`delivery/doc/PLATFORM-CONTRACTS.yaml` 是路径真相源；Codex Skill 禁止写入 `.codex/skills` 或 `~/.codex/skills`
23. **安装路径前置校验**：安装器写入前必须逐级检查目标父路径；任一级被普通文件占用时必须 fail fast，输出 `安装路径被非目录占用: <path>`，不得暴露 Python traceback
24. **需求 / 场景变更追溯**：修改 `USE-CASES.md` / `REQUIREMENTS.md` 前必须在 CR 中填写文档处理决策；默认增量更新、保留旧基线并追加 `## 修订记录`，不得用新草案整体替换旧文档
25. **安装命令与组件默认值**：安装 CLI 使用 `meta-flow install <platform>`，卸载使用 `meta-flow uninstall <platform>`；`--platform` 与 `install --uninstall` 仅作 legacy 兼容。组件使用 `--component rules|agent|full`；user scope 默认 `rules`，project scope 默认 `full`；legacy `--content all|agents|skills|rules` 仅作兼容入口
26. **Codex 生命周期**：Codex 下同一工作流只允许 1 个 `meta-po` 子 agent；同角色同任务优先复用已有子 agent，检查点或交接完成后及时关闭；发现两个活动 `meta-po` 时必须阻断推进并要求用户选择保留线程
26. **检查点文件优先**：推进阶段前必须读取对应 `process/checks/CP*.md` 与 `process/checkpoints/CP*.md`；不能只看产物 frontmatter 的 `confirmed=true`
27. **人工审查回填**：meta-po 发起人工检查时必须提示 checklist 文件路径；用户直接对话确认后，仍必须回填对应 `process/checkpoints/CP*.md` 的“人工审查结果”
28. **子 agent 调度硬门禁**：meta-po 唤醒功能 Agent 必须使用平台 Task/Subagent 能力；Codex 环境对应 `spawn_agent` / `resume_agent` / `send_input`。`process/handoffs/*.md` 必须记录 `dispatch.mode`、`agent_id` / `thread_id`、`tool_name`、`spawned_at` / `resumed_at`、`completed_at`。只有 handoff 没有调度证据时，不得把目标 Agent 标记为 completed。
29. **inline fallback 显式化**：平台无法拉起子 agent 时，默认 blocked；只有用户明确批准，meta-po 才能用 `dispatch.mode=inline-fallback` 代执行，并记录 `fallback_reason`、`approved_by`、`approved_at`。结果必须写成 meta-po 代执行，不得写成 meta-dev / meta-qa 独立完成。
29. **全阶段 Context Capsule**：CP2 / CP3 / CP5 / CP6 / CP7 / CP8 前后必须生成或检查 `process/context/*-CONTEXT.yaml`。子 agent、人工门禁、验证和发布准备默认先读取 capsule；只有 capsule 缺失、冲突、字段不足、人工审计、深度评审或用户明确要求时，才读取完整正式文档，并在 `STATE.md.context_budget.read_expansion_log[]` 或 capsule `read_expansion_log[]` 写明 `full_doc_read_reason`。
29. **上下文预算与健康阈值**：`context-handoff` 必须传 `context_policy`，包含 capsule 路径、`read_profile=minimal|compact|full`、`must_read`、`read_if_needed`、`do_not_read_by_default` 和全文档扩展理由；不得默认传完整 HLD、全部 LLD、完整 TEST-MATRIX、完整 TEST-REPORT、完整 REVIEW、完整 diff 或完整会话 transcript。`STATE.md.workflow_health` 计数器超过阈值时，meta-po 必须停止静默重试，生成决策项、回退、CR、Spike 或人工仲裁请求。
30. **关键决策门控**：CP2 / CP3 / CP5 / CP8 是人工决策点；CP4 只写自动预检并汇入 CP5 Decision Brief。
31. **Decision Brief**：关键人工确认前必须汇总推荐决策、备选方案、影响维度、优劣、风险与回退、用户需决策事项。
32. **待人工决策清单**：工作流程中所有需要人工确定的信息都必须形成决策项；每项必须包含决策 ID、决策类型、待确认问题、推荐方案、至少 1 个备选方案（优先 2 个）、推荐 / 备选优劣分析、影响 / 风险和回退 / 切换条件。决策类型只能使用 `scope`、`architecture`、`security`、`implementation`、`runtime_authorization`、`risk_acceptance`、`follow_up_tracking`。meta-po 发起人工确认时必须收集所有未决人工决策项，去重后打印给用户统一决策；用户回复 `approve` 表示接受清单内全部推荐方案。
33. **结构化人工决策队列**：`process/STATE.md.human_gate_decisions.pending_human_decisions[]` 是 CP2 / CP3 / CP5 / CP8 待人工决策清单的状态机对象。所有 `Q-*`、`OPEN`、`LCQ-*`、`O-*`、权限 / 安全边界、风险接受、运行授权、外部接口、数据写入、publish、live / 交易类问题必须先分类；`decision-item` 必须进入该队列。
34. **Human Gate Launch Protocol**：CP2 / CP3 / CP5 / CP8 发起前必须运行 `meta-flow check human-gate` 校验 Decision Brief；Decision Brief 必须包含 `Decision Collection Coverage`，列出已扫描来源、候选问题数、纳入待决策数和 N/A / 缺失原因。若已有待发送消息草稿，必须同时校验对话内容包含 checklist 路径、自动预检结论、决策收集覆盖摘要、待决策项数量、待决策表格和三个 exact 回复。待决策项数量大于 0 但对话未打印表格，视为门禁发起失败。
34. **Decision Brief 压缩**：checkpoint 文件中的 Decision Brief 必须完整；对话发起消息可按 `STATE.md.human_gate_decisions.decision_brief_profile=full|compact|summary` 压缩。无论如何，对话仍必须包含 checklist 路径、自动预检结论、Context Capsule 摘要、决策收集覆盖摘要、待决策项总数、blocking / high-risk 决策、不授权项和 `approve` / `修改: <具体修改点>` / `reject` 三个 exact 回复。
35. **用户视角复述与不授权项**：人工门禁消息必须说明 `approve` 接受哪些推荐方案，并明确不代表授权哪些禁止操作。真实运行、凭据、安全、外部接口、数据写入、publish、live / 交易类事项必须独立列出不授权项。
36. **决策修订再发布**：用户纠正范围、安全、运行授权或风险接受含义后，meta-po 必须更新相关 DQ、重新计算影响面、重新生成 Decision Brief 和待决策表，并重新发起确认。
37. **自动拉起子 agent**：用户启动正式工作流后，同工作流内默认允许 meta-po 自动拉起功能 Agent；该授权不包含 inline fallback。
38. **阶段委托交互**：`requirement-clarification` 默认委托 `meta-pm` 直接与用户完成场景、需求、工程验证场景和产品规划输入草案；`solution-design` 默认委托 `meta-se` 直接与用户完成蓝图适用性、架构灰区、advisor table 和 HLD 草案。委托状态写入 `STATE.md.delegated_interaction`；被委托 Agent 不得推进跨阶段状态，不得发起 CP2 / CP3 正式人工检查点；阶段收敛后写交还摘要，由 meta-po 回收并发起 Decision Brief。
39. **LLD Clarification Queue**：并行 LLD 阶段多个 `meta-dev` 不得并发直接询问用户；遇到实现灰区必须写入 `STATE.md.parallel_execution.lld_clarification_queue.items[]`，字段至少包含 `id/story_id/owner_agent/question/options/recommendation/impact_surface/blocks_lld/answer/status`。meta-po 是唯一 question broker，负责合并同类问题、批量询问、回填答案并分发给对应 meta-dev。存在未回答 `blocks_lld=true` 项时不得发起 CP5；转 OPEN / Spike 的项必须在 CP5 Decision Brief、完整 LLD 或 Story 技术说明、DEV-LOG 中暴露。
40. **子 agent 用户提问权限**：`ask_user` 是语义动作，不等于平台工具必然可用；必须由 `STATE.md.agent_lifecycle.platform_capabilities.user_question` 判定 direct / relay / queue / exact-text。`meta-po` 是 CP2 / CP3 / CP5 / CP8 正式人工门禁和运行授权问题的唯一发起者；`meta-pm` 只在 `requirement-clarification` 阶段委托内问场景 / 需求问题，`meta-se` 只在 `solution-design` 阶段委托内问架构 / HLD 问题；`meta-dev` 默认写 clarification queue，不直接问用户；`meta-qa` / `meta-doc` 默认写待人工决策项，由 meta-po 汇总。Claude Code direct ask 必须同时满足阶段授权和 subagent frontmatter `tools:` 包含 `AskUserQuestion`；Codex 只有在当前工具面明确提供 `request_user_input` 时才使用结构化选择，否则使用 exact-text 或经 meta-po relay。
40. **CP8 后续跟踪分流**：CP8 必须区分关闭范围、不授权范围、风险接受项、后续 CR 候选项、取消 / deferred 项。后续 CR 候选只进入 `process/changes/CR-*-FOLLOW-UP-TRACKING-YYYY-MM-DD.md` 台账，状态取值为 `candidate`、`active`、`blocked`、`spike_candidate`、`converted-to-spike`、`closed`、`cancelled`、`superseded`；只有用户决定推进某项时才创建正式 CR 文件。
41. **后续 CR 启动与冲突预检**：用户用 `@meta-po 启动后续 CR` 并提供台账路径、候选编号和目标摘要后，meta-po 才能把候选项转正式 CR。启动前必须读取 `STATE.md.active_change`、`STATE.md.cr_tracking`、`process/changes/CR-INDEX.yaml`、台账和未关闭 CR，比较正式文档、Story、文件 owner、外部接口、安全 / 运行授权和风险接受项；`candidate` / `spike_candidate` 不占执行锁，已 `active` 的未完成 CR 若与新 CR 影响面重叠，默认不得并行推进，必须让用户选择合并、等待、blocked、拆分或 superseded。
42. **CR 跟踪状态查询**：用户询问当前状态、还有哪些 CR 需要推进或推进建议时，meta-po 必须输出 `active formal CR`、`blocked formal CR`、`follow-up candidate`、`spike_candidate`、`stale_status_conflicts` 五类清单；不得只返回唯一 active CR。存在 `meta-flow check cr-tracking` 时必须运行或记录跳过原因；若 `STATE.md.active_change` 指向已关闭 CR、与正式 active CR 不一致、台账 candidate 已有正式 CR 文件或 active 台账缺正式 CR 路径，必须先列为状态冲突并继续展示候选 backlog。
43. **fast-lane**：仅低风险轻量实现可用；不得跳过 CP6 / CP7、调度证据或 CP8 终验摘要；命中架构、权限、安装、外部接口、文件所有权冲突或多 Story 依赖时必须升级 standard。
44. **CP2 Scenario Gray Areas**：标准模式下，场景发现必须先识别 3-4 个会影响交付的灰区，让用户选择 1-3 个重点讨论；未选项进入 Deferred Ideas。讨论日志写入 `process/discussions/CP2-SCENARIO-DISCUSSION-LOG.md`，恢复点写入 `process/checks/CP2-DISCUSSION-CHECKPOINT.json`，缺失时 CP2 自动检查必须说明 N/A 或阻断原因。
45. **CP3 Architecture Gray Areas**：HLD 正式生成前必须先识别关键架构灰区，advisor lane 使用 `Option | Pros | Cons | Impact Surface | Recommendation | Assumptions / When to switch` 表格优先输出。讨论日志写入 `process/discussions/CP3-HLD-DISCUSSION-LOG.md`，恢复点写入 `process/checks/CP3-DISCUSSION-CHECKPOINT.json`，缺失时 CP3 自动检查必须说明 N/A 或阻断原因。
46. **讨论日志消费边界**：Discussion Log 用于审计和恢复，不替代 `USE-CASES.md`、`REQUIREMENTS.md`、`SCENARIOS.yaml`、`TEST-MATRIX.md`、`STORY-MAP.md`、`MVP-SCOPE.md`、`RELEASE-SLICES.md`、`BACKLOG.md`、`BLUEPRINT.md`、`DOMAIN-MAP.md`、`DEPENDENCY-MAP.md`、`HLD.md`、`ARCHITECTURE-DECISION.md`、`FEATURE-DESIGN-MATRIX.md`、Decision Brief 或必要的 `HLD-CONTEXT.md`。

## CP0-CP8 检查点

| CP | 名称 | 类型 | 文件 |
|----|------|------|------|
| CP0 | 原始请求受理门 | 自动 | `process/checks/CP0-REQUEST-INTAKE.md` |
| CP1 | 用户场景完备门 | 自动 | `process/checks/CP1-USE-CASE-COMPLETENESS.md` |
| CP2 | 需求 / 场景 / 范围基线门 | 自动预检 + 人工 | `process/checks/CP2-REQUIREMENTS-BASELINE.md`；`process/checkpoints/CP2-REQUIREMENTS-BASELINE.md` |
| CP3 | 蓝图 / HLD 架构评审门 | 自动预检 + 人工 | `process/checks/CP3-HLD-CONSISTENCY.md`；`process/checkpoints/CP3-HLD-REVIEW.md` |
| CP4 | Story 拆解与并行安全门 | 自动预检（汇入 CP5） | `process/checks/CP4-STORY-DAG-PARALLEL-SAFETY.md` |
| CP5 | Story 设计证据可实现性门 | 全量自动预检 + 人工 | `process/checks/CP5-{story_id}-{story_slug}-LLD-IMPLEMENTABILITY.md`；`process/checkpoints/CP5-ALL-STORIES-LLD-BATCH.md` |
| CP6 | Story 编码完成门 | 滚动自动 | `process/checks/CP6-{story_id}-{story_slug}-CODING-DONE.md` |
| CP7 | Story 验证完成门 | 滚动自动 | `process/checks/CP7-{story_id}-{story_slug}-VERIFICATION-DONE.md` |
| CP8 | 交付就绪门 | 自动预检 + 人工 | `process/checks/CP8-DELIVERY-READINESS.md`；`process/checkpoints/CP8-DELIVERY-READINESS.md` |

每个 CP 都必须包含 Entry Criteria、Checklist、Exit Criteria、Deliverables。自动检查点必须给出逐项检查结果；CP2 / CP3 / CP5 / CP8 人工检查点必须给出 checklist 路径、自动预检结论、Decision Brief、待人工决策清单并回填人工审查结果。待人工决策清单逐项列出决策 ID、决策类型、待确认问题、推荐方案、至少 1 个备选方案（优先 2 个）、优劣分析、影响 / 风险和回退 / 切换条件。

CP2 Decision Brief 必须额外覆盖用户真实意图、场景覆盖、`SCENARIOS.yaml` / `TEST-MATRIX.md` 覆盖摘要、`STORY-MAP.md` / `MVP-SCOPE.md` / `RELEASE-SLICES.md` 范围取舍、认知盲区、Scenario Gray Areas、Deferred Ideas、用户选择影响和回退方式。CP3 Decision Brief 必须额外覆盖 `BLUEPRINT.md` / `DOMAIN-MAP.md` / `DEPENDENCY-MAP.md` 适用性或 N/A / WAIVED 原因、Feature / Epic 边界、数据归属、候选架构适用条件、优化项、牺牲项、影响面、切换条件、Use Case → Architecture Traceability、场景模拟结果和未决风险。

CP6 / CP7 还必须包含 `Agent Dispatch Evidence` 小节。CP6 必须额外记录实现执行证据路径、证据类型和 N/A 理由。CP7 必须额外记录验证对象清单、验证追踪矩阵、设计契约验证、分层验证计划、fixture / dry-run / 人工审查、问题和剩余风险、阶段决策。缺少 meta-dev / meta-qa 的真实子 agent 证据，且没有用户批准的 `inline-fallback` 时，结论只能是 `FAIL` 或 `BLOCKED`。

Claude Code 可继续使用结构化选择，但 direct ask agent 的 frontmatter `tools:` 必须显式包含 `AskUserQuestion`。Codex 只有在当前工具面明确提供可用的 `request_user_input` / 选择 UI 时才使用结构化选择；否则默认使用 exact 文本确认。对用户只展示三个推荐回复：`approve`、`修改: <具体修改点>`、`reject`；历史别名 `1/通过`、`2/修改: ...`、`3/不通过` 仅作为兼容解析，不作为主要提示文案。`approve` 表示接受待人工决策清单内全部推荐方案；需要调整单项时用 `修改: <决策 ID>=<具体修改点>`。

## 并行执行（Complex 模式）

Claude Code 全局规则不复制完整工作流状态机；完整状态机以 `AGENTS.md`、`meta-po` 和 `state-router` 为准。本文件只保留执行边界摘要：

- `story-planning`：CP4 自动预检通过后，完成全部目标 Story 的完整 LLD / 技术说明 / waived 证据、CP5 自动预检和 CP5 全量人工确认
- `story-execution`：进入时全量 CP5 必须已通过；本阶段只按 Wave 调度开发与验证，不再进行设计证据写作；每个 Story 在 CP6 前必须完成实现执行证据或写明低风险 N/A 理由

Complex 模式下，LLD 写作、开发和验证均按 Story DAG 队列并行调度，但同一 Story 必须严格按：

`全量 CP5 设计证据确认 → implementation-execution 实现证据 → CP6 开发实现完成 → verification-execution 验证证据 → CP7 结论分级`

顺序推进。

设计证据写作必须覆盖全部目标 Story，且可以按 Story 并行；高风险 Story 使用 `full-lld`，低风险 Story 使用 Story 内 `technical-note`，明确不需要设计的 Story 使用 `waived` 并写理由。人工确认必须等全部目标 Story 的设计证据与 CP5 自动预检完成后统一发起。标准开发默认以全部目标 Story 为设计证据批次；变更流程默认以 CR 影响范围为批次。全量 CP5 通过前，不得启动任何 Story 开发；通过后按 Wave、依赖类型和文件所有权调度开发。复杂 / 高风险 / Prompt-Skill / Workflow / 安装器 / 护栏 / 平台适配 / 发布相关 Story 必须生成 `process/stories/STORY-*-IMPLEMENTATION.md` 或 `docs/features/<feature>/IMPLEMENTATION.md`；低风险 Story 可写 Story 摘要或 DEV-LOG，但必须保留实现对象、契约映射、测试 / Fixture、切片验证和平台差异的最小证据。

并行 LLD 写作时，meta-dev 只能写 clarification item，不能多个线程同时直接问用户。meta-po 统一合并队列、形成 `active_question_batch`、批量问用户，并把答案回填到 queue、完整 LLD 或 Story 技术说明、DEV-LOG。队列存在未回答 `blocks_lld=true` item 时，CP5 不得发起。

CP7 结论只能使用 `PASS`、`PASS_WITH_RISK`、`BLOCKED`、`NEEDS_REWORK`、`NEEDS_DESIGN_CLARIFICATION`、`WAIVED`。`PASS` / `WAIVED` 进入 `verified`；`PASS_WITH_RISK` 可推进但风险必须进入 CP8 Decision Brief / risk acceptance；`NEEDS_REWORK` 路由回 meta-dev 修复并重跑 CP6 / CP7；`NEEDS_DESIGN_CLARIFICATION` 路由回 meta-se / meta-po，必要时重开 CP5 或 CR；`BLOCKED` 阻断推进。

默认并发上限：`max_parallel_lld=3`、`max_parallel_dev=2`、`max_parallel_qa=2`。开发并行必须同时满足依赖类型门控和文件所有权门控；`runtime` 依赖默认等待上游 `verified` 或 `verified-with-risk`，`file-conflict` 依赖默认串行。

## 方案评审规则（Design Review）

对 HLD / LLD / Story Plan / ADR 等设计产物评审时，必须逐条校验：

1. **内部一致性检查**：ADR、Risk、NFR、模块职责、流程图之间不得自相矛盾，发现矛盾必须在同一轮修订中解决。
2. **目标必须量化**：成功标准必须含可度量值（数量、百分比、字段集、覆盖率），禁止"不少于"、"尽可能"、"更完整"等无下限表述。
3. **集成契约显式化**：新 Agent / Skill / 模块必须定义与调用方和相邻对象的契约（调用方向、时机、触发方式、输入/输出、衔接、降级、调用方同步修改范围），禁止只声明"独立可调用"。
4. **相邻对象边界澄清**：非目标章节必须显式区分与相邻 Skill / Agent 的职责，避免"澄清 / 扩展 / 发现"等近义词默认重叠。
5. **前置校验与失败路径**：每个执行阶段必须定义前置校验和失败行为（终止 / 降级 / 回退），禁止"成功路径 only"。
6. **回退决策可操作化**：用户修改/回退必须映射为可枚举决策表（意图 → 目标 → 理由），禁止模糊"根据类型回退"。
7. **理论依据可追溯**：枚举型框架（维度、阶段、清单）必须说明来源方法论，或显式声明"可扩展"，避免被当作穷尽集合。
8. **遗留问题状态闭环**：待确认问题每次修订必须回写状态（OPEN / RESOLVED + 日期）；收敛后原行不删除以保留追溯。
9. **Gotchas 必有**：Skill 类产出（HLD / SKILL.md）必须含实质性 Gotchas 章节。
10. **修订记录完整**：每次迭代必须在产物头部追加修订记录（版本号 / 日期 / 修订人 / 变更要点精确到章节号）；该规则同样覆盖 `USE-CASES.md` 与 `REQUIREMENTS.md`。
11. **Story 拆解一致性**：§工作量章节的 Story 数、Wave 数必须与 §分阶段落地一一对应。
12. **决策与产物形态对齐**：ADR 结论必须回写到架构图、模块表、流程图、落地阶段；孤立 ADR 视为未落地。
13. **官方契约一致性**：平台路径、schema 或发现机制必须引用官方文档或 `delivery/doc/PLATFORM-CONTRACTS.yaml`；禁止按同平台目录类比推断。

## LLD 消费契约补充

- `lld_policy.required_level=full-lld` 时，`STORY-*-LLD.md` 必须保留 14 个可见章节；`technical-note` / `waived` Story 的正式设计证据写入 Story 卡片。
- `tier`、`shared_fragments`、`open_items` 为必读字段。
- meta-dev / meta-qa 必须把接口、异常、测试、回滚章节转成实施或验证输入，不能自行脑补缺失部分。
- meta-qa 必须消费 CP6 实现执行证据并输出验证对象清单、验证追踪矩阵、设计契约验证和阶段决策；缺少 `IMPLEMENTATION.md` 或低风险 N/A 理由时，应判定为 CP6 输入缺陷。

## Review Gate 分派与灰度

| Lane | Agent | 主要职责 |
|------|-------|----------|
| `lane-product` | `meta-pm` | 场景与范围一致性、原始需求 / 场景基线保留和修订记录 |
| `lane-architecture` | `meta-se` | 架构与依赖一致性 |
| `lane-implementation` | `meta-dev` | 可实现性、平台约束与实现对象 / 契约闭环 |
| `lane-quality` | `meta-qa` | 可验证性、验证对象、契约闭环、风险和阶段决策 |
| `lane-docs` | `meta-doc` | 交付文档可读性 |

CP3 蓝图 / HLD 讨论中，`lane-product`、`lane-architecture`、`lane-quality` 是默认 advisor lane；`lane-docs` 的可解释性 / 可维护性作为汇总检查项纳入，不默认新增一次 subagent 调度。方案形成输入和 HLD 后评审意见必须分开记录。

灰度顺序：先 `HLD.md` / `STORY-*-LLD.md`，后 `ARCHITECTURE-DECISION.md` / `STORY-BACKLOG.md`，最后 `README.md` / `USER-MANUAL.md`。
<!-- myflow:managed:end -->
