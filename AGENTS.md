## Agent Memory Policy

### Recall Before Work

- 开始非简单任务前，先调用 `memory_recall` 查询相关记忆。
- 项目相关查询使用 `scope="project"`；query 应包含任务关键词、错误信息、相关文件路径或模块名。
- 跨项目通用偏好使用 `scope="user"`，例如命令习惯、语言偏好、代码风格偏好。
- 架构设计、技术选型、重构、迁移、安装配置、发布、测试策略、MCP、同步、数据库、权限或安全边界相关任务必须优先召回。
- 用户提到“之前”“上次”“仍然”“按项目规则”“不要再”等历史上下文时必须召回。
- 召回失败时不要阻塞任务；说明 memory 不可用，并以仓库文件和当前对话为准继续。

### Store After Stable Learning

- 只有稳定、可复用、未来有召回价值的信息才调用 `memory_store`。
- `memory_store` 参数使用 `summary` 和可选 `body`；也兼容 `content`，但优先写清楚 `summary`。
- 保存项目专属信息使用 `scope="project"`；保存跨项目通用偏好使用 `scope="user"`。
- `category` 只能使用 `preference`、`decision`、`gotcha`、`convention`、`fact`；默认使用 `fact`。
- `preference` 保存用户或团队偏好；`decision` 保存已确认决策；`gotcha` 保存踩坑和限制；`convention` 保存稳定约定；`fact` 保存中性事实。
- 写入内容必须简短、事实化，优先保存摘要、结论、原因和必要文件路径，不保存完整长对话。
- 用户明确纠正你的行为、命令、风格或架构理解时，应保存为 `preference`、`convention` 或 `decision`。

### Do Not Store

- 不得保存 token、API key、密码、私钥、cookie、session 或任何访问凭据。
- 不得保存客户数据、个人隐私、未脱敏日志或生产数据样本。
- 不得保存原始长对话、临时推测、未确认方案或一次性任务细节。
- 不得把仓库文件内容大段复制进 memory。
- 不得保存与当前仓库事实冲突、但未被用户确认的新规则。

### Authority Order

- 冲突时按以下优先级判断：当前用户明确指令 > 仓库文件和当前代码 > `AGENTS.md` / `CLAUDE.md` > project memory > user memory。
- memory 只作为提示性上下文，不得覆盖仓库事实。
- 如果 memory 与仓库文件冲突，以仓库文件为准，并在必要时更新或忘记过期 memory。

<!-- myflow:managed:begin v=1 commit=425f023 generated=2026-06-25T02:24:15Z -->
<!-- myflow-managed: version=1.0.0 canonical-commit=425f023 generated=2026-06-25T02:24:15Z -->

# Meta Flow 元工作流 — Agent 声明

> 本项目运行 **Meta Flow** 通用 Agent/Skill 工作流产物工厂。
> 主编排由当前会话的 **Host Orchestrator（主进程编排器）** 承担；不再安装或启动 `host-orchestrator` / `meta-po` 编排子 agent。

---

## 主进程编排器

| 字段 | 值 |
|------|----|
| 角色名称 | Host Orchestrator（主进程编排器） |
| 提示词文件 | 无；协议写入 `AGENTS.md`、`delivery/rules/*`、`state-router` 和 `process/STATE.md` |
| 触发词 | 开始、新建工作流、需求变更、推进、当前状态、继续、回退 |
| 始终激活 | 是。由当前主进程在本会话内执行编排；不得再 spawn 编排子 agent |

Host Orchestrator 的职责：

- **项目初始化**：创建 `process/`、`process/checks/`、`process/checkpoints/`，并按交付路由决定是否写入 `delivery/` 或目标项目约定目录
- 初始化 `process/STATE.md` 并维护全程状态
- **先理解，后行动**：退出条件先验、上下文先行、追问优先于假设、状态一致性校验
- 维护 CP0-CP8 检查点：自动检查点写入 `process/checks/CP*.md`，人工检查点写入 `process/checkpoints/CP*.md` 并在发起确认时提示用户 checklist 路径，审查后回填人工结果
- 维护关键决策门控：CP2 / CP3 / CP5 / CP8 面向用户决策；CP4 作为自动预检汇入 CP5 Decision Brief
- 唤醒和收敛下游功能 Agent（机器可验证退出条件）；用户启动正式工作流后，同工作流内默认授权 Host Orchestrator 自动拉起所需功能 Agent；Codex 下主进程直接调用 `spawn_agent` / `resume_agent` / `send_input`，Claude Code/OpenClaw 使用对应 Task/Subagent 能力；同角色同任务优先复用已有功能子 agent，检查点或交接完成后及时关闭
- 记录子 agent 调度证据：handoff 文件只表示交接，不表示目标 agent 已执行；meta-dev / meta-qa 等下游完成必须有 `spawn_agent` / `resume_agent` / `send_input` 或平台 Task/Subagent 证据，或用户批准的 `inline-fallback`
- 维护阶段委托交互：`meta-pm` / `meta-se` 在各自阶段内可直接与用户多轮沟通，host-orchestrator 记录委托状态并在阶段交还后发起 CP2 / CP3
- 维护 LLD Clarification Queue：并行 LLD 阶段由 meta-dev 写入 clarification item，host-orchestrator 作为唯一 question broker 合并、批量询问用户、回填答案并分发
- 维护 Agent 命令、显示与 Codex 思考等级区分：Codex 功能 agent 使用 `nickname_candidates`（如 `dev-yang`）区分显示，并使用 `model_reasoning_effort` 配置角色级思考等级；Claude Code 功能 subagent 不使用 nickname，改用不同 `color` 区分；主编排器不安装平台子 agent
- 受理变更请求，创建 `process/changes/CR-*.md`，执行五维度影响分析
- 判定 `standard` / `fast-lane` 模式；fast-lane 仅用于低风险轻量实现，仍必须保留验证、终验摘要和追溯证据
- **失败模式识别**：识别需求循环、HLD 僵局、LLD 僵局、开发卡顿等常见失败信号

## 功能 Agent（按需唤醒，由 Host Orchestrator 调度）

| Agent | 提示词文件 | 职责 | 唤醒条件 |
|-------|-----------|------|---------|
| **meta-pm** | `agents/meta-pm.md` | 被委托期间直接与用户完成快速调研（阶段零）+ Scenario Gray Areas 场景发现（USE-CASES.md，含画像/指标/候选理解、认知盲区、Deferred Ideas 与 trade-off）+ 需求结构化（REQUIREMENTS.md，含风险/里程碑）+ 工程验证场景（SCENARIOS.yaml / TEST-MATRIX.md）+ 产品规划输入（STORY-MAP.md / MVP-SCOPE.md / RELEASE-SLICES.md / BACKLOG.md）+ “可提交给 host-orchestrator”确认 + CP2 Decision Brief 输入 | 新请求进入、需求模糊、需求变更后重整 |
| **meta-se** | `agents/meta-se.md` | 被委托期间直接与用户完成蓝图适用性判定、Architecture Gray Areas、advisor table-first 讨论和 HLD 草案确认 + 蓝图设计（BLUEPRINT.md / DOMAIN-MAP.md / DEPENDENCY-MAP.md）+ HLD 设计（含候选方案对比、适用性矩阵、Use Case → Architecture Traceability、场景模拟 + 技术选型理由）+ Story 拆解（含文件布局 + TASK-ID 任务清单）+ 必要的 Feature 级实现设计 + 开发计划（含完成准则） | CP2 需求 / 场景 / 范围基线已确认（solution-design 和 story-planning 两阶段均由 meta-se 执行） |
| **meta-dm（归档）** | `process/archive/meta-dm.md` | 历史 Story 拆解与并行计划角色，职责已合并至 meta-se | 不得唤醒 / 不安装 |
| **meta-dev** | `agents/meta-dev.md` | Story 设计证据输出与批量确认闭环（full-lld / technical-note / waived）+ LLD clarification item 写入 + 实现执行证据（对象清单 / 契约映射 / 测试 Fixture / 切片验证 / IMPLEMENTATION.md）+ Agent/Skill 文件实现 + TASK-ID 增量追踪 + CP7 `NEEDS_REWORK` 回修 | 存在 `lld-ready` Story，或存在已批准且可执行的 `dev-ready` Story |
| **meta-qa** | `agents/meta-qa.md` | TEST-STRATEGY.md 输出（ISTQB/ISO 25010 + validation_mode）+ verification-execution 验证执行证据（对象清单 / 追踪矩阵 / 设计契约 / 分层计划 / fixture / dry-run / 风险 / 阶段决策）+ 8 维度验收 + TEST-MATRIX 覆盖验证 + 独立质量评审（TEST-REPORT.md / REVIEW.md / FIXES.md）+ 发布就绪检查（RELEASE-NOTES.md / DEPLOY-CHECKLIST.md / ROLLBACK.md / MIGRATION.md / FEEDBACK.md）+ 平台安装脚本交付 + 缺陷回修 / 设计澄清建议 | Story 进入 ready-for-verification + 验证环境或等价验证方式已就绪 |
| **meta-doc** | `agents/meta-doc.md` | README（含架构概览 + 用户旅程 + 关键决策门控 / fast-lane / 自动调度说明）+ USER-MANUAL（含故障排除）+ 严重度分级文档缺口 | 核心产物已验证且安装脚本稳定 |

### Agent 命令与显示映射

canonical role 仅包含功能 Agent，用于状态机、handoff、检查点和审计。平台展示按下表安装；主编排器由主进程承担，不安装 Codex / Claude Code agent 文件：

| canonical role | Codex 命令 / nickname_candidates | Codex `model_reasoning_effort` | Claude Code color |
|---|---|---|---|
| `meta-pm` | `pm-wu`、`pm-zheng`、`pm-wang`、`pm-feng`、`pm-chen` | `medium` | `orange` |
| `meta-se` | `se-chu`、`se-wei`、`se-jiang`、`se-shen`、`se-han` | `high` | `yellow` |
| `meta-dev` | `dev-yang`、`dev-zhu`、`dev-qin`、`dev-you`、`dev-xu`、`dev-he`、`dev-lv`、`dev-shi`、`dev-zhang`、`dev-kong` | `medium` | `green` |
| `meta-qa` | `qa-he`、`qa-lv`、`qa-shi`、`qa-zhang`、`qa-kong`、`qa-cao`、`qa-yan`、`qa-hua`、`qa-jin`、`qa-wei` | `high` | `cyan` |
| `meta-doc` | `doc-cao`、`doc-yan`、`doc-hua`、`doc-jin`、`doc-wei` | `low` | `purple` |

主进程 Host Orchestrator 不安装为 Codex custom agent；标准 / 复杂工作流建议父会话使用 `model_reasoning_effort="high"`，fast-lane 或小范围机械修改可降为 `medium`。功能子 agent 的 Codex TOML 显式写入上表等级；若某个字段省略，则继承父会话配置。

Codex 动态思考 profile 只改变实际 custom agent 名称，不改变 canonical role：

| canonical role | 默认 Codex agent | 升级触发 | 升级 Codex agent | 升级 effort |
|---|---|---|---|---|
| `meta-dev` | `meta-dev` | 实现失败超过 2 轮、CP7 回修反复、跨模块 bug、状态机异常、PIT / 数据泄漏 / 数据一致性风险、复杂 flaky test | `meta-dev-debugger` | `high` |
| `meta-se` | `meta-se` | 架构冻结、公共 contract、跨模块边界、安全权限、外部接口、重大 ADR | `meta-se-critical` | `xhigh` |
| `meta-qa` | `meta-qa` | CP5 全量设计证据确认、CP7 最终验证、CP8 交付就绪、发布前、高风险验证 | `meta-qa-critical` | `xhigh` |

Codex 主进程必须在 `STATE.md.agent_lifecycle.platform_capabilities.subagent_dispatch` 记录工具面探测结果。若当前工具面暴露 `spawn_agent` / `resume_agent` / `send_input` 且 `orchestrator_session.subagent_auto_dispatch=enabled`，创建 `mode=subagent` handoff 后必须立即调用真实子 agent 工具，并在 `active_agents[]` 与 handoff `dispatch` 中记录 `canonical_role`、`codex_agent_name`、`reasoning_profile`、`dispatch_trigger`、`tool_name`、`agent_id/thread_id`；只写 handoff 不算拉起子 agent。

## 工作流阶段与 Agent 对应关系

```
init（host-orchestrator）                                                   [CP0 自动]
 └─► requirement-clarification（host-orchestrator 委托 meta-pm 直连用户：Scenario Gray Areas → 场景发现 → 需求结构化 → SCENARIOS / STORY-MAP / MVP-SCOPE → 交还） [CP1 自动 + CP2 人工]
      └─► solution-design（host-orchestrator 委托 meta-se 直连用户：蓝图适用性 → Architecture Gray Areas → advisor discussion → HLD 草案 → 交还） [CP3 人工]
           └─► story-planning（meta-se 生成 FEATURE-DESIGN-MATRIX / 必要 Feature 设计 / 拆解全部 Story → CP4 自动预检 → host-orchestrator 计算全量设计证据队列 → meta-dev 并行产出 full-lld / technical-note / waived 证据） [CP4 自动 + CP5 全量确认]
                │    设计证据写作并行：全部目标 Story 的设计证据可按并发上限分轮起草
                │    LLD 问题收敛：meta-dev 只写 clarification queue，host-orchestrator 合并后批量问用户并回填答案
                │    设计证据确认全量化：CP4 摘要、全部 Story 设计证据与 CP5 自动预检完成后，统一人工确认
                └─► story-execution（全量设计证据确认后进入 Wave 开发/验证循环）
                │    开发并行：全量 CP5 已通过后，按 Wave 调度依赖满足且文件无冲突的 dev-ready Story 并行实现
                │    同一 Story 内串行：implementation-execution 实现证据 → CP6 开发完成 → verification-execution 验证证据 → CP7 结论分级；NEEDS_REWORK 回修，NEEDS_DESIGN_CLARIFICATION 回设计澄清
                └─► documentation（meta-doc）                      [CP8 人工]
                     └─► delivered
```

## 工作目录约定

> 下表是 Meta Flow 无目标项目约定时的默认路由，不是 production 项目的强制目录。production 项目必须先识别目标项目已有交付目录和 README / docs 约定；存在约定时按目标项目路径映射并写入 `STATE.md.delivery_routing`，不得按下表另建 `docs/*` 或 `delivery/*`。

| 目录 / 文件 | 用途 |
|------------|------|
| `process/STATE.md` | 工作流运行时状态（host-orchestrator 维护） |
| `process/REQUEST.md` | 用户原始请求 |
| `docs/product/USE-CASES.md` | 场景文档（meta-pm 产出） |
| `docs/product/REQUIREMENTS.md` | 结构化需求（meta-pm 产出） |
| `docs/product/SCENARIOS.yaml` | 工程验证场景（scenario-expansion 产出，meta-pm 编排） |
| `docs/product/TEST-MATRIX.md` | 场景 / Story / 测试覆盖矩阵（scenario-expansion 与 meta-qa 消费） |
| `docs/product/STORY-MAP.md` | 用户活动、任务与 Story Map（story-planning 产出，meta-pm 编排） |
| `docs/product/MVP-SCOPE.md` | MVP 范围、Out of Scope、Deferred 与决策项（story-planning 产出） |
| `docs/product/RELEASE-SLICES.md` | 发布切片（story-planning 产出） |
| `docs/product/BACKLOG.md` | 后续候选项与延后项（story-planning 产出） |
| `docs/design/BLUEPRINT.md` | Feature / Epic 能力边界与数据归属（blueprint-design 产出） |
| `docs/design/DOMAIN-MAP.md` | 领域对象、状态、规则和术语（blueprint-design 产出） |
| `docs/design/DEPENDENCY-MAP.md` | Feature / 模块依赖方向与禁止依赖（blueprint-design 产出） |
| `docs/design/HLD.md` | 高层设计文档（meta-se 产出） |
| `docs/design/ARCHITECTURE-DECISION.md` | 架构决策（meta-se 产出） |
| `docs/design/FEATURE-DESIGN-MATRIX.md` | Feature 设计适用性矩阵、Story `feature_design_refs` 与 `lld_policy`（implementation-design / meta-se 产出） |
| `process/STORY-BACKLOG.md` | Story 列表（meta-se 产出） |
| `process/DEVELOPMENT-PLAN.yaml` | Wave 执行计划（meta-se 产出，含完成准则） |
| `docs/quality/TEST-STRATEGY.md` | 测试策略（meta-qa 产出，ISTQB/ISO 25010） |
| `docs/quality/VERIFICATION-REPORT.md` | 验证执行报告（verification-execution / meta-qa 产出） |
| `docs/quality/TEST-REPORT.md` | 测试报告（quality-review / meta-qa 产出） |
| `docs/quality/REVIEW.md` | 质量评审 / 代码评审报告（quality-review 产出） |
| `docs/quality/FIXES.md` | 回修输入与修复摘要（quality-review 产出） |
| `docs/release/RELEASE-NOTES.md` | 发布说明（release-readiness 产出） |
| `docs/release/DEPLOY-CHECKLIST.md` | 部署检查清单（release-readiness 产出） |
| `docs/release/ROLLBACK.md` | 回滚方案（release-readiness 产出） |
| `docs/release/MIGRATION.md` | 迁移说明（release-readiness 产出，若无迁移则写 N/A） |
| `docs/release/FEEDBACK.md` | 反馈回流入口（release-readiness 产出） |
| `process/release/RELEASE-CONTEXT.yaml` | 发布上下文胶囊（release-readiness 产出；只保存摘要、计数、风险 ID、决策 ID 和证据路径） |
| `docs/features/` | Feature 级 DESIGN.md / TEST-PLAN.md / TASKS.md（implementation-design 产出） |
| `process/discussions/` | CP2 / CP3 讨论日志（人类审计与恢复，不替代正式产物） |
| `process/checks/` | 自动检查点结果（CP0/CP1/CP2/CP3/CP4/CP5/CP6/CP7/CP8） |
| `process/context/` | 阶段上下文胶囊（CP2/CP3/CP5/CP6/CP7/CP8，作为子 agent、人工门禁、验证和发布准备的默认读取入口） |
| `skills/<skill-name>/templates/` | Skill 私有模板目录（仅单个 Skill 内部初始化 / 渲染使用） |
| `skills/<skill-name>/scripts/` | Skill 私有运行时脚本目录（需随 Skill 一起安装时使用） |
| `process/checkpoints/` | 人工检查点审查稿（CP2/CP3/CP5/CP8，含 Decision Brief、checklist 和人工审查结果；CP4 只写自动预检） |
| `process/stories/` | Story 卡片（STORY-*.md，含 technical-note / waived 证据）、full-lld Story 的 LLD（STORY-*-LLD.md）和 Story 级实现执行证据（STORY-*-IMPLEMENTATION.md） |
| `process/changes/` | 变更单（CR-*.md） |
| `delivery/agents/` | 交付 Agent 提示词文件（canonical 源，同时是 meta-dev 产出目录） |
| `delivery/skills/` | 交付 Skill 定义文件（canonical 源，同时是 meta-dev 产出目录） |
| `delivery/rules/` | 各平台规则文件（AGENTS.md / CLAUDE.md） |
| `delivery/scripts/` | 仅安装器入口（install.py / install.sh / install.ps1） |
| `scripts/` | 仓库级检查与构建脚本（不属于交付包） |
| `delivery/README.md` | 产物 README（meta-doc 产出） |
| `delivery/doc/USER-MANUAL.md` | 产物用户手册（meta-doc 产出） |
| `.agents/agents/` | 元工作流功能 Agent 提示词文件（pm/se/dev/qa/doc）；主编排由 Host Orchestrator 主进程承担，不安装编排 agent |
| `.agents/skills/` | 元工作流 Skill 定义文件（Meta Flow 内置） |

### 输出隔离原则

> **所有由元工作流产生的文件必须按层输出到 `docs/`（长期产品 / 设计 / 质量 / 发布文档）、`process/`（运行态）、`process/checks/`（自动检查结果）、`process/checkpoints/`（确认态）和经确认的交付出口。**
> `docs/product/` 承载 USE-CASES / REQUIREMENTS / SCENARIOS / TEST-MATRIX / STORY-MAP / MVP-SCOPE / RELEASE-SLICES / BACKLOG；`docs/design/` 承载 BLUEPRINT / DOMAIN-MAP / DEPENDENCY-MAP / HLD / ARCHITECTURE-DECISION / FEATURE-DESIGN-MATRIX；`docs/features/` 承载 Feature 级 DESIGN / TEST-PLAN / TASKS；`docs/quality/` 承载 TEST-STRATEGY / VERIFICATION-REPORT / TEST-REPORT / REVIEW / FIXES；`docs/release/` 承载 RELEASE-NOTES / DEPLOY-CHECKLIST / ROLLBACK / MIGRATION / FEEDBACK。
> `process/` 只承载运行状态、计划、Story 执行态、discussion、handoff、CR 和自动检查等过程文档；旧 `process/*.md` 技术文档路径与根目录 `checkpoints/CP*.md` 仅作为 legacy fallback 读取，不作为新生成默认路径。
> `process/` 是项目运行态入口，不要求真实存储在当前源码仓库内。外置模式下，初始化必须创建 `<artifact-root>/process/<project-name>/` 并将 `<project-root>/process` 软链接到该目录，同时写入 `process/.meta-flow-process.yaml` 和 `STATE.md.artifact_routing`。健康检查发现 `process` 缺失、断链、`process/STATE.md` 缺失、`project_name` 不匹配或路由元数据冲突时，必须强制中断当前工作流，由用户提供有效 `artifact_root` / `process_root` 后继续；不得静默重建新的 `STATE.md`。当前未迁移仓库可使用 `routing_mode=local-directory` 兼容模式，直到迁移 CR 切换为 `symlink`。
> 当前 meta-flow 源码仓库的 `docs/` 分为公开文档和内部归档文档：源码仓库跟踪 `docs/README.md`、`docs/release/RELEASE-NOTES.md` 和 `docs/USER-MANUAL.md` 等用户可见入口；`docs/design`、`docs/features`、`docs/quality`、内部 release 审查文档、修改记录和偏好类文档由 artifact repo 跟踪，并可在本机通过 ignored symlink 保持旧路径可读。production 项目仍按目标 README/docs 约定或用户确认路由，不得把 meta-flow 自身 docs 分层策略强加给目标项目。
> 只有 `engagement_mode=meta-self-dev` 或用户明确说明优化 meta-flow 本身时，才默认把交付物写入当前仓库 `delivery/`。
> production 项目必须先扫描目标项目已有交付目录，以及 `README.md` / `README.*` / `docs/` 中的交付物、发布、构建或包结构约定；存在则遵守并写入 `STATE.md.delivery_routing`，不得再按 Meta Flow 默认路径另建交付目录；不存在则先提出建议并等待用户确认。
> 当前仓库 `delivery/` 是 meta-flow 自身可独立推送到目标 Git 仓库的交付包，内含 `agents/`、`skills/`、`rules/`、`scripts/`。
> `.agents/` 保留元工作流引擎自身定义，不参与安装。

## Python 环境与依赖管理（uv）

若项目包含 Python 代码、脚本、验证工具或 MCP 服务，必须遵循以下约束：

1. 统一使用 `uv` 管理 Python 解释器、虚拟环境和依赖。
2. 存在项目级 Python 依赖时，以 `pyproject.toml` 为唯一依赖声明来源，以 `uv.lock` 为唯一锁定结果；禁止提交 `.venv/`。
3. 所有开发、测试、构建和脚本执行统一通过 `uv run` 触发；一次性工具统一优先使用 `uvx`。
4. 禁止将裸 `pip install`、系统 Python 或未入库依赖作为日常工作流默认入口。
5. 若项目尚未建立 `pyproject.toml` / `uv.lock`，仍必须使用 `uv` 管理解释器，并以 `uv run --python <version> python <script>` 作为 Python 命令入口。
6. README、USER-MANUAL 及平台规则文件中的 Python 示例必须与上述约束保持一致。

## 方案编写与修订规则

1. **先核对事实，再写方案**：平台路径、发现面、配置位置和行为约束，必须以当前仓库实现与官方文档为准；发现旧假设错误时，先修正事实判断，再扩展方案。涉及平台安装路径时，`delivery/doc/PLATFORM-CONTRACTS.yaml` 是单一真相源，README / USER-MANUAL / HLD / LLD 只能作为派生说明。
2. **优先最简方案**：默认选择能满足目标的最小设计，避免为“统一”额外引入新抽象层、共享运行时或重复形态；若必须保留备选方案，应说明何时切换。
3. **废弃内容要彻底删除**：已确认废弃的目录、路径变量、章节、实施步骤和验收项，不得只标注“废弃”而保留残余引用。
   - 本规则不得用于删除仍需追溯的旧需求或旧场景基线；需求 / 场景变更必须通过 CR 记录旧基线保留方式。
4. **问题必须状态化**：阻塞问题、遗留问题和开放问题必须逐项标注状态（如已解答、部分解答、待整改），并在方案修订时同步刷新。
5. **主选与备选并存**：已确认主选方案时，实施文档应同时记录主选值、备选方案和切换条件，避免后续重复讨论同一决策。
6. **问题描述必须完整**：方案中的问题条目不能只有标题，至少应说明背景、触发条件、影响范围、为何是问题以及需要谁决策。
7. **目录设计要分层**：过程文档、人工检查点文档、交付文档应分区描述，避免把运行态、检查态和交付态混写为同一输出面。
8. **稳定偏好才能升格为共享规则**：只有已经稳定、适合团队复用的偏好才能进入仓库共享规范；明显属于个人工作习惯的内容不应直接写入共享规则。

## 方案评审规则（Design Review）

> 本节规则适用于对 HLD / LLD / Story Plan / ADR 等设计产物的评审。评审方（无论是人还是 Agent）必须逐条校验下列维度，未通过项必须返工或在产物中显式留痕。

1. **内部一致性检查**：ADR、Risk Matrix、NFR、模块职责、流程图之间不得自相矛盾。典型反例：ADR-1 规定"HTML 注释隐藏" vs Risk 应对要求"可读附录"。发现矛盾必须在同一轮修订中解决，不得延迟。
2. **目标必须量化**：成功标准（Success Criteria）每一条必须含可度量值（数量、百分比、字段集、耗时、覆盖率等）；禁止"不少于 X"、"尽可能"、"更完整"这类无可检验下限的表述。
3. **集成契约显式化**：任何新 Agent / Skill / 模块必须显式定义与调用方和相邻对象的契约，至少覆盖：**调用方向、调用时机、触发方式、输入契约、输出契约、后续衔接、降级策略、调用方需要同步修改的范围**。不允许只声明"独立可调用"而不说明如何被真实集成。
4. **相邻对象边界澄清**：非目标（Out of Scope）章节必须显式指出与相邻 Skill / Agent 的职责差异；同名或近义职责（如"澄清"、"扩展"、"发现"）必须逐词界定归属，避免默认重叠。
5. **前置校验与失败路径**：每个执行阶段必须定义前置条件校验表与失败行为（终止 / 降级 / 回退），禁止"成功路径 only"的设计。
6. **回退决策可操作化**：用户的修改/回退动作必须映射为可枚举的决策表（意图关键词 → 回退目标 → 理由），避免"根据类型回退"这类需模型自由裁量的模糊规则。
7. **理论依据可追溯**：枚举型框架（维度表、阶段列表、检查清单）必须说明来源方法论（如 JTBD / FMEA / Journey Mapping / ISTQB / ISO 25010 等），或显式声明"领域经验 + 可扩展"以避免被当作穷尽集合使用。
8. **遗留问题状态闭环**：待确认问题在每次修订必须回写状态（OPEN / RESOLVED + 日期 + 决策引用）；收敛后原问题行不得删除，以保留决策追溯链。
9. **Gotchas 必有**：Skill 类产出的 HLD 或 SKILL.md 必须包含实质性 Gotchas 章节（至少列出常见误用与规避），形式性填充视为未完成。
10. **修订记录完整**：每次设计迭代必须在产物头部的 `修订记录` 表追加一行，包含版本号、日期、修订人、变更要点（精确到章节号），避免靠 Git 历史反推；该规则同样覆盖 `USE-CASES.md` 与 `REQUIREMENTS.md`。
11. **Story 拆解一致性**：§工作量章节中的 Story 数、Wave 数必须与 §分阶段落地章节一一对应；不一致视为设计缺陷。
12. **决策与产物形态对齐**：ADR 的结论必须反映在对应章节（架构图、模块表、流程图、落地阶段）中；孤立的 ADR 未回写到其他章节视为未落地。
13. **官方契约一致性**：涉及平台路径、schema 或发现机制的 HLD / LLD / Story Plan / ADR，必须引用官方文档或 `delivery/doc/PLATFORM-CONTRACTS.yaml` 中的已验证来源；禁止用同平台目录类比推断。Codex Agent 与 Skill 必须分开断言：Agent 在 `.codex/agents` / `~/.codex/agents`，Skill 在 `.agents/skills` / `~/.agents/skills`。

## 协议约定

- **文件系统协议**：Agent 间通过 Markdown/YAML 文件交换信息，不依赖隐式推理传递
- **单写规则**：同一核心对象同一时刻只允许一个主要写入方
- **回写规则**：每一阶段结束必须回写 `STATE.md`
- **变更规则**：需求或设计变动必须先创建 `CR-*.md` 再修改正式对象
- **需求 / 场景变更追溯**：修改 `USE-CASES.md` / `REQUIREMENTS.md` 前，必须在 CR 中填写文档处理决策（新增 / 原文档更新 / 归档 / 不变）；默认增量更新、保留旧基线并追加 `## 修订记录`，不得用新草案整体替换旧文档
- **检查点结构**：CP0-CP8 均必须包含 Entry Criteria、Checklist、Exit Criteria、Deliverables；自动检查点必须在 `process/checks/CP*.md` 写入逐项结果，人工检查点必须在 `process/checkpoints/CP*.md` 写入 checklist 和“人工审查结果”。
- **全阶段 Context Capsule**：CP2 / CP3 / CP5 / CP6 / CP7 / CP8 前后必须生成或检查 `process/context/*-CONTEXT.yaml`。子 agent、人工门禁、验证和发布准备默认先读取 capsule；只有 capsule 缺失、冲突、字段不足、人工审计、深度评审或用户明确要求时，才读取完整正式文档，并在 `STATE.md.context_budget.read_expansion_log[]` 或 capsule `read_expansion_log[]` 写明 `full_doc_read_reason`。
- **Story Return / Evidence / Design Delta**：CP6 / CP7 Story agent 完成后必须写入 `process/returns/STORY-*.return.json`，并用 `meta-flow story return-check` 校验 Story / stage 匹配、写入路径、禁止路径、unexpected imports、验证证据和设计 delta 引用。CP6 / CP7 检查默认消费 `process/evidence/STORY-*.index.json` 证据索引，不复制完整证据正文。Story 修改长期 Feature DESIGN / ADR / HLD 时必须写 `process/design-deltas/STORY-*.delta.json`；CP8 前对需要回写的 delta 运行 `meta-flow design delta-check --require-merged`。
- **CP Result / Event Ledger**：CP 自动检查应优先写入 `process/checks/CP*.result.json` 作为机器真相源，并用 `meta-flow cp result-check` 校验；`process/checks/CP*.summary.md` 或旧 Markdown 检查文件只作为人类摘要。每个 CP result 应通过 `meta-flow cp ledger-append` 追加 `process/state/CHECKPOINT-LEDGER.ndjson`；handoff、agent dispatch、run、gate 事件分别写入 `HANDOFF-LEDGER.ndjson`、`AGENT-DISPATCH-LEDGER.ndjson`、`RUN-LEDGER.ndjson`、`GATE-LEDGER.ndjson`，并用 `meta-flow event check` 校验。Markdown 摘要不得替代 result JSON、evidence index 或 event ledger。
- **上下文预算**：`STATE.md.context_budget.require_capsule_first=true` 时，`context-handoff` 必须传 `context_policy`，包含 capsule 路径、`read_profile=minimal|compact|full`、`must_read`、`read_if_needed`、`do_not_read_by_default` 和全文档扩展理由。不得默认把完整 HLD、全部 LLD、完整 TEST-MATRIX、完整 TEST-REPORT、完整 REVIEW、完整 diff 或完整会话 transcript 传给下游。
- **Agent / Skill Contract Slimming**：功能 Agent 与高频 Skill 必须遵守 `delivery/rules/AGENT-SKILL-CONTRACT.md`。默认机器状态入口是 `process/state/STATE.current.json`，默认上下文入口是阶段 context pack 或 Story packet，默认读取集合只能来自 `allowed_reads` / `must_read`；`process/STATE.md` 只作为人类摘要、迁移兼容或人工审计 fallback。Handoff 只传 `context_ref` / `story_packet_ref` / `evidence_ref` / `result_ref`，真实执行证据写入 handoff / dispatch / checkpoint / run ledgers。
- **Workflow Health 阈值**：`STATE.md.workflow_health` 必须维护重复问题、HLD 修订、LLD clarification、CP 重试、Story 回修、产物 hash 不变和阶段轮次计数。任一计数器超过阈值时，host-orchestrator 必须停止静默重试，生成决策项、回退、CR、Spike 或人工仲裁请求。
- **关键决策门控**：CP2 / CP3 / CP5 / CP8 是用户决策点；CP4 只生成自动预检 `process/checks/CP4-STORY-DAG-PARALLEL-SAFETY.md`，其摘要、风险和开放项必须汇入 CP5 Decision Brief。
- **Decision Brief**：CP2 / CP3 / CP5 / CP8 发起人工确认前，必须在对应 `process/checkpoints/CP*.md` 写入 Decision Brief，覆盖推荐决策、备选方案、影响维度、优劣、风险与回退、用户需决策事项，并必须包含 `### 审批者摘要` 和 `### 决策分层`。审批者摘要必须说明本次确认服务的整体目标、推荐动作、`approve` 后会发生什么、`approve` 不授权什么、不确认会阻塞什么；决策分层必须区分“必须用户决策”“高风险策略确认”“agent 默认处理”“仅审计记录”。
- **待人工决策清单**：工作流程中所有需要人工确定的信息都必须形成决策项；每项必须包含决策 ID、决策类型、待确认问题、推荐方案、至少 1 个备选方案（优先 2 个）、推荐 / 备选优劣分析、影响 / 风险和回退 / 切换条件。决策类型只能使用 `scope`、`architecture`、`security`、`implementation`、`runtime_authorization`、`risk_acceptance`、`follow_up_tracking`。host-orchestrator 发起人工确认时必须收集所有未决人工决策项，去重后打印给用户统一决策；用户回复 `approve` 表示接受清单内全部推荐方案。
- **结构化人工决策队列**：`process/STATE.md.human_gate_decisions.pending_human_decisions[]` 是 CP2 / CP3 / CP5 / CP8 待人工决策清单的状态机对象。meta-pm / meta-se / meta-dev / meta-qa 发现需要用户决定的问题时，必须写入该队列或交还给 host-orchestrator 写入；不得只留在对话、discussion log 或下游 Markdown 中。
- **灰区问题分类**：进入 CP2 / CP3 / CP5 / CP8 前，所有 `Q-*`、`OPEN`、`LCQ-*`、`O-*`、权限 / 安全边界、风险接受、运行授权、外部接口、数据写入、publish、live / 交易类问题必须分类为 `resolved-by-user`、`decision-item`、`non-blocking-open`、`converted-to-spike` 或 `n/a-with-reason`；其中 `decision-item` 必须进入待人工决策清单。
- **CP2 场景讨论追溯**：标准模式下，CP2 前必须处理 `Scenario Gray Areas`，并至少产生 1 条 `SGQ-*` 用户可见场景确认交互（问题、候选选项或 freeform、用户回答、复述确认、影响面）；将讨论日志写入 `process/discussions/CP2-SCENARIO-DISCUSSION-LOG.md`，将恢复点写入 `process/checks/CP2-DISCUSSION-CHECKPOINT.json`；缺少 SGQ 证据时 CP2 只能 `FAIL` / `BLOCKED`，fast-lane N/A 必须写明原因。
- **CP3 架构讨论追溯**：HLD 正式生成前必须处理 `Architecture Gray Areas`，advisor lane 使用 `Option | Pros | Cons | Impact Surface | Recommendation | Assumptions / When to switch` 表格优先输出；讨论日志写入 `process/discussions/CP3-HLD-DISCUSSION-LOG.md`，恢复点写入 `process/checks/CP3-DISCUSSION-CHECKPOINT.json`，缺失时必须在 CP3 自动检查中记录 `N/A` 或阻断原因。
- **讨论日志消费边界**：Discussion Log 用于人类审计和中断恢复，不作为下游唯一输入；下游正式消费仍以 `USE-CASES.md`、`REQUIREMENTS.md`、`SCENARIOS.yaml`、`TEST-MATRIX.md`、`STORY-MAP.md`、`MVP-SCOPE.md`、`RELEASE-SLICES.md`、`BACKLOG.md`、`BLUEPRINT.md`、`DOMAIN-MAP.md`、`DEPENDENCY-MAP.md`、`HLD.md`、`ARCHITECTURE-DECISION.md`、`FEATURE-DESIGN-MATRIX.md`、Decision Brief 或必要的 `HLD-CONTEXT.md` 为准。
- **异步讨论模式边界**：`process/discussions/CP2-QUESTIONS.json/html` 与 `CP3-QUESTIONS.json/html` 属于后续可选增强，不作为当前默认产物或检查点前置条件。
- **人工检查点**：关键人工确认统一由 host-orchestrator 发起；发起时必须提示用户 checklist 文件路径（如 `process/checkpoints/CP3-HLD-REVIEW.md`）、自动预检结论、审批者摘要、决策分层、待决策项数量，并打印本轮待人工决策清单（决策 ID、决策类型、问题、推荐方案、备选方案、优劣摘要、影响 / 风险）。低风险、可回退、实现细节类事项默认归入 `agent 默认处理` 或 `仅审计记录`，不得升级为用户必须确认的细粒度问题。Claude Code 可使用结构化选择，但 direct ask agent 的 frontmatter `tools:` 必须显式包含 `AskUserQuestion`；Codex 只有在当前工具面明确提供可用的 `request_user_input` / 选择 UI 时才使用结构化选择，否则默认使用 exact 文本确认。发起确认时只展示三个推荐回复：`approve`、`修改: <具体修改点>`、`reject`；内部可兼容历史别名 `1/通过`、`2/修改: ...`、`3/不通过`，但不得把多个别名混排成用户必须理解的选项。用户直接在对话中确认时，host-orchestrator 仍必须回填对应 `process/checkpoints/CP*.md`。
- **Human Gate Launch Protocol**：CP2 / CP3 / CP5 / CP8 发起前必须运行 `meta-flow check human-gate` 校验 Decision Brief；Decision Brief 必须包含 `Decision Collection Coverage`，列出已扫描来源、候选问题数、纳入待决策数和 N/A / 缺失原因，并包含审批者摘要与决策分层。若已有待发送消息草稿，必须同时校验对话内容包含 checklist 路径、自动预检结论、审批者摘要、决策分层、决策收集覆盖摘要、待决策项数量、待决策表格和三个 exact 回复。若待决策项数量大于 0 但对话未打印表格，视为门禁发起失败；若待决策项为 0，也必须打印原因。
- **阶段结束下一步提示词**：每个阶段任务、检查点、Story 实现 / 验证或 CR 收敛完成后，host-orchestrator 必须输出“下一步准确提示词”，且该提示词必须可直接复制执行或回复；不得只提示“同意”“继续”“可以”等模糊词。人工门禁只展示 `approve`、`修改: <具体修改点>`、`reject`；非门禁推进使用 `执行下一步: <具体动作>`、`推进阶段: <阶段名>`、`处理阻塞: <具体处理方式>` 等明确格式。`meta-flow next` 必须遵守同一格式。
- **Decision Brief 压缩**：checkpoint 文件中的 Decision Brief 必须完整；对话发起消息可按 `STATE.md.human_gate_decisions.decision_brief_profile=full|compact|summary` 压缩。无论如何，对话仍必须包含 checklist 路径、自动预检结论、Context Capsule 摘要、审批者摘要、决策分层、决策收集覆盖摘要、待决策项总数、blocking / high-risk 决策、不授权项和 `approve` / `修改: <具体修改点>` / `reject` 三个 exact 回复。
- **用户视角复述与不授权项**：人工门禁消息必须说明“如果你回复 approve，表示你接受以下 N 项推荐方案，不表示授权以下 M 项禁止操作”。对真实运行、凭据、安全、外部接口、数据写入、publish、live / 交易类事项，必须独立列出不授权项；设计通过不得被误读为运行授权。
- **决策修订再发布**：用户纠正范围、安全、运行授权或风险接受含义后，host-orchestrator 必须更新相关 DQ、重新计算影响面、重新生成 Decision Brief 和待决策表，并重新发起确认；不得只在后续 HLD / LLD / CP 文件中静默修正。
- **阶段委托交互**：`requirement-clarification` 默认委托 `meta-pm` 直接与用户完成场景和需求草案；`solution-design` 默认委托 `meta-se` 直接与用户完成架构灰区、advisor table 和 HLD 草案。委托状态写入 `STATE.md.delegated_interaction`；被委托 Agent 不得推进跨阶段状态，不得发起 CP2 / CP3 正式人工检查点；阶段收敛后写交还摘要，由 host-orchestrator 回收并发起 Decision Brief。
- **子 agent 调度证据**：host-orchestrator 调用功能 Agent 必须使用平台子 agent 调度能力。Codex 新任务使用 `spawn_agent`，复用任务使用 `resume_agent` 或 `send_input`；Claude Code/OpenClaw 使用对应 Task/Subagent 能力。`process/handoffs/*.md` 必须包含 `dispatch` 区，记录 `mode`、`canonical_role`、`codex_agent_name`、`reasoning_profile`、`dispatch_trigger`、`agent_id` / `thread_id`、`tool_name`、`spawned_at` / `resumed_at`、`completed_at`。缺少这些字段时，只能判定为 `handoff-created` 或 `spawn-requested`，不得写成目标 agent 已完成。
- **子 agent 自动调度**：用户启动正式工作流后，同工作流内默认授权 `host-orchestrator` 按阶段自动拉起 `meta-pm` / `meta-se` / `meta-dev` / `meta-qa` / `meta-doc`；自动授权只覆盖真实子 agent 调度，不覆盖 inline fallback。Codex 下若 `spawn_agent` / `resume_agent` / `send_input` 工具面可用，Host Orchestrator 必须真实调用工具；若不可用，必须标记 `subagent_dispatch.available=false` 并阻断，不得静默用 handoff 代执行。
- **inline fallback 门禁**：当前平台无法拉起子 agent 时，host-orchestrator 必须阻断并说明原因；只有用户明确批准后才能用 `dispatch.mode=inline-fallback` 代执行，并记录 `fallback_reason`、`approved_by`、`approved_at`。inline fallback 结果必须表述为 host-orchestrator 代执行，不得表述为 meta-dev / meta-qa 独立完成。
- **HLD 门控**：CP3 自动预检和人工确认未通过前，不得进入 Story 拆解。跨 Feature / Epic、数据归属或依赖方向问题必须先完成 `BLUEPRINT.md` / `DOMAIN-MAP.md` / `DEPENDENCY-MAP.md` 或写明 N/A / WAIVED 原因。
- **Feature 设计矩阵门控**：CP3 通过后、CP4 通过前必须生成 `docs/design/FEATURE-DESIGN-MATRIX.md`，判定 Feature / Epic 的 `required` / `waived` / `n/a`，并为每个 Story 写入 `feature_design_refs` 与 `lld_policy.required_level=full-lld|technical-note|waived`。required Feature 必须生成 `docs/features/<feature>/DESIGN.md` / `TEST-PLAN.md` / `TASKS.md`，或写明 waived 决策和重访条件。
- **Story 计划与 LLD 门控**：CP4 自动预检未通过前，不得开始全量设计证据写作；全部目标 Story 的 CP5 自动预检和全量人工确认未通过前，不得进入 Story 执行。设计证据必须覆盖全部目标 Story：高风险 Story 使用 `full-lld`，低风险 Story 使用 Story 内 `technical-note`，明确不需要设计的 Story 使用 `waived` 并写理由。标准开发默认以全部目标 Story为 `lld_design_batch`；变更流程默认以 CR 影响范围为批次。
- **LLD Clarification Queue**：并行 LLD 阶段多个 `meta-dev` 不得并发直接询问用户；遇到实现灰区必须写入 `STATE.md.parallel_execution.lld_clarification_queue.items[]`，字段至少包含 `id/story_id/owner_agent/question/options/recommendation/impact_surface/blocks_lld/answer/status`。host-orchestrator 是唯一 question broker，负责合并同类问题、批量询问、回填答案并分发给对应 meta-dev。存在未回答 `blocks_lld=true` 项时不得发起 CP5；转 OPEN / Spike 的项必须在 CP5 Decision Brief、完整 LLD 或 Story 技术说明、DEV-LOG 中暴露。
- **子 agent 用户提问权限**：`ask_user` 是语义动作，不等于平台工具必然可用；必须由 `STATE.md.agent_lifecycle.platform_capabilities.user_question` 判定 direct / relay / queue / exact-text。`host-orchestrator` 是 CP2 / CP3 / CP5 / CP8 正式人工门禁和运行授权问题的唯一发起者；`meta-pm` 只在 `requirement-clarification` 阶段委托内问场景 / 需求问题，`meta-se` 只在 `solution-design` 阶段委托内问架构 / HLD 问题；`meta-dev` 默认写 clarification queue，不直接问用户；`meta-qa` / `meta-doc` 默认写待人工决策项，由 host-orchestrator 汇总。Claude Code direct ask 必须同时满足阶段授权和 subagent frontmatter `tools:` 包含 `AskUserQuestion`；Codex 只有在当前工具面明确提供 `request_user_input` 时才使用结构化选择，否则使用 exact-text 或经 host-orchestrator relay；人工门禁可用 `meta-flow ask-user human-gate --checkpoint <process/checkpoints/CP*.md> --format codex-json` 生成 Codex `request_user_input` 负载或 exact-text fallback。
- **Story 执行门控**：进入 story-execution 时全部目标 Story 的设计证据必须已确认；开发按 Wave、Story DAG、依赖类型和文件所有权调度，不得在 CP5 前实现任何 Story。
- **实现执行门控**：Story 开发开始后，meta-dev 必须使用 `implementation-execution` 将已确认设计证据转为实现对象清单、设计契约映射、测试 / Fixture 计划、最小实现切片、平台差异检查、本地验证和 QA / Review / Doc 交接摘要。复杂 / 高风险 / Prompt-Skill / Workflow / 安装器 / 护栏 / 平台适配 / 发布相关 Story 必须输出 `process/stories/STORY-{id}-{story_slug}-IMPLEMENTATION.md` 或 `docs/features/<feature>/IMPLEMENTATION.md`；低风险 Story 可写 Story 摘要或 DEV-LOG，但 CP6 必须记录 N/A 理由。
- **编码与验证门控**：Story 实现完成后必须写入 CP6 编码完成检查结果；CP6 必须包含实现执行证据路径 / 证据类型 / N/A 理由。验证完成后必须写入 CP7 验证完成检查结果；CP7 必须包含验证对象清单、验证追踪矩阵、设计契约验证、分层验证计划、fixture / dry-run / 人工审查、问题和剩余风险、阶段决策。CP6/CP7 必须包含 `Agent Dispatch Evidence`；缺少真实子 agent 证据且没有用户批准的 `inline-fallback` 时不得推进 Story 状态。CP6/CP7 的机器真相源应优先使用 Story Return Packet、Evidence Index 和 CP result JSON；Markdown 摘要只引用这些结构化证据。
- **验证结论路由**：CP7 结论只能使用 `PASS`、`PASS_WITH_RISK`、`BLOCKED`、`NEEDS_REWORK`、`NEEDS_DESIGN_CLARIFICATION`、`WAIVED`。`PASS` / `WAIVED` 进入 `verified`；`PASS_WITH_RISK` 可推进但风险必须进入 CP8 Decision Brief / risk acceptance；`NEEDS_REWORK` 路由回 meta-dev 修复并重跑 CP6 / CP7；`NEEDS_DESIGN_CLARIFICATION` 路由回 meta-se / host-orchestrator，必要时重开 CP5 或 CR；`BLOCKED` 阻断推进。
- **CP8 后续跟踪分流**：CP8 必须区分关闭范围、不授权范围、风险接受项、后续 CR 候选项、取消 / deferred 项。后续 CR 候选只进入 `process/changes/CR-*-FOLLOW-UP-TRACKING-YYYY-MM-DD.md` 台账，状态取值为 `candidate`、`active`、`blocked`、`spike_candidate`、`converted-to-spike`、`closed`、`cancelled`、`superseded`；只有用户决定推进某项时才创建正式 CR 文件。
- **后续 CR 启动与冲突预检**：用户提出“启动后续 CR”并提供台账路径、候选编号和目标摘要后，Host Orchestrator 才能把候选项转正式 CR。启动前必须读取 `STATE.md.active_change`、`STATE.md.cr_tracking`、`process/changes/CR-INDEX.yaml`、台账和未关闭 CR，比较正式文档、Story、文件 owner、外部接口、安全 / 运行授权和风险接受项；`candidate` / `spike_candidate` 不占执行锁，已 `active` 的未完成 CR 若与新 CR 影响面重叠，默认不得并行推进，必须让用户选择合并、等待、blocked、拆分或 superseded。
- **CR 跟踪状态查询**：用户询问当前状态、还有哪些 CR 需要推进或推进建议时，host-orchestrator 必须输出 `active formal CR`、`blocked formal CR`、`follow-up candidate`、`spike_candidate`、`stale_status_conflicts` 五类清单；不得只返回唯一 active CR。存在 `meta-flow check cr-tracking` 时必须运行或记录跳过原因；若 `STATE.md.active_change` 指向已关闭 CR、与正式 active CR 不一致、台账 candidate 已有正式 CR 文件或 active 台账缺正式 CR 路径，必须先列为状态冲突并继续展示候选 backlog。
- **项目画像与验证目标**：`engagement_mode` 只区分 meta-flow 自改进与 production 交付路由；项目类型必须写入 `STATE.md.target_project_profile.project_kind=code-project|workflow-product|agentic-code-product|mixed|unknown`。Story / 交付对象必须用 `validation_target.sut_type=code-project|generated-workflow|prompt-skill-workflow|meta-flow-core-code|agentic-code-product|mixed` 判定 CP7 验证层。
- **Workflow Eval 与 Prompt Bundle 治理**：纯代码项目默认执行目标项目原生测试、构建、静态检查和 quality-review，workflow eval 可 N/A；generated workflow、prompt-skill、meta-flow-core-code、agentic-code-product 和 mixed 对象必须消费 `WORKFLOW-EVAL.yaml`、`PROMPT-BUNDLE.yaml`、`CASE-REGISTRY.yaml`、`process/evals/runs/<run-id>/run-summary.json` 或写明 WAIVED / BLOCKED。eval run evidence 必须保留结构化 grader evidence；需要真实运行可信度时使用通用 `runtime_artifact` grader 检查已有运行工作区，release-grade 样本优先通过 `RUNTIME-SAMPLE-REGISTRY.yaml` / `sample_ids` 声明，并覆盖 STATE、Skill 调用链、Gate、阶段顺序、内容密度、空文件 / 模板残留、delivery、trace chain、coverage 和表格；发布判定使用 `suite-health` + `release-check --profile release`，release-check 输出 `PASS|PASS_WITH_RISK|BLOCKED`，eval run PASS 只是 CP7 输入证据，不等于 CP7 PASS。
- **Feedback / GAP / install eval 闭环**：`runtime-run` 只生成 RUN-EXEC 和 runtime artifact manifest，不启动 Agent、不替代 grader 判分。field feedback 必须先 normalize 为结构化 RUN-EXEC，再 triage 为 `ISSUE_DRAFT` / `GAP` / `BACKLOG` / `ENVIRONMENT` / `USAGE` / `DUPLICATE` / `NO_ACTION`；不得把所有 feedback 自动升级为 ISSUE。`suite-health` 只做趋势报告，`release-check` 才阻断未闭环 P0 GAP、blocking/high ISSUE 缺 regression asset、required grader 不通过和 runtime sample 不足。`install_mapping` 可消费 `PLATFORM-CONTRACTS.yaml` 检查平台发现路径、stale / forbidden 项；`mutate` 生成带 `expected_failing_grader` 的负例来验证 grader 有效性。
- **外部 Eval Adapter 授权边界**：Promptfoo / DeepEval / Langfuse / Garak 默认 disabled，仅可作为 adapter policy、case/result 映射或 trace mapping。任何网络、凭据、trace 上传、外部模型调用、publish、live 或 production 写入必须单独形成 `runtime_authorization` 决策项。
- **Skill 模板关系维护**：创建或修改 Agent、Skill 或 Skill 私有模板时，若影响调用、适用、归属或模板交叉引用关系，必须同步更新 `skills/README.md`
- **交付脚本边界**：`delivery/scripts/` 只允许安装器入口；任何被 Skill 运行时引用的脚本必须放到 `delivery/skills/<skill>/scripts/`
- **Skill 资产同树安装**：active Skill 引用的 `templates/`、`scripts/`、`schemas/`、`examples/` 资产必须与 Skill 同树存放，并使用 Skill 相对路径或 `<skill-root>/...` 表达
- **脚本安装验证**：active Skill 一旦新增脚本资产，必须验证 Claude Code / Codex 在 project 与 user scope 下安装后可直接执行
- **缓存文件禁入库**：`__pycache__/`、`*.pyc` 及其他解释器生成缓存不是交付物，不得提交
- **护栏静态检查**：`scripts/check_delivery_guardrails.py` 是 meta-flow 自身仓库 guardrail；仅当当前仓库存在该文件时，提交前运行 `uv run --python 3.11 python scripts/check_delivery_guardrails.py`。外部 production 项目不得硬引用 `<project-root>/scripts/check_delivery_guardrails.py` 或任意设备绝对路径，应改按目标 README/docs 的测试、构建、安装 dry-run 或用户确认的验证命令执行。
- **调研前置**：meta-pm 在场景发现前执行阶段零快速调研，记录至 CLARIFICATION-LOG.md
- **模式默认值**：若用户未显式声明“meta 工作流优化 / 自我开发”，工作流默认 `engagement_mode=production`
- **工作流模式默认值**：默认 `workflow_mode=standard`；`fast-lane` 仅适用于低风险轻量实现，不能跳过 CP6 / CP7、Agent Dispatch Evidence 或 CP8 终验摘要；命中架构、权限、安全、平台安装、外部接口、文件所有权冲突或多 Story 依赖时必须升级 standard。
- **场景主体默认值**：若用户未显式声明 meta 优化，`USE-CASES.md` 默认 `scenario_subject_type=target-artifact`，不得把当前仓库 / 当前工作流当成默认场景主体
- **确定性语言**：meta-se 与 meta-dev 产出使用确定性动词（创建/修改/删除）和量化条件，禁止模糊表述
- **就绪检查**：meta-dev 开始实现前必须通过 Story 卡片完整性检查，并确认 `feature_design_refs`、`lld_policy` 和 Story 设计证据已获批
- **测试策略与质量评审前置**：meta-qa 验收前先输出 `docs/quality/TEST-STRATEGY.md`，声明 `validation_mode=runtime|static-only|dry-run-only|review-only|mixed`。验证时先使用 `verification-execution` 消费 `SCENARIOS.yaml` / `TEST-MATRIX.md`、设计证据和 CP6 实现执行证据，输出 `docs/quality/VERIFICATION-REPORT.md`，确认验证对象、设计契约、测试 / Fixture、最小切片、平台差异、人工审查、问题和风险闭环；随后使用 `quality-review` 固化 TEST-REPORT / REVIEW，发布前使用 `release-readiness` 固化发布、部署、回滚、迁移和反馈回流
- **发布准备 capsule-first**：发布前 `release-readiness` 必须先生成 `process/release/RELEASE-CONTEXT.yaml`，并判定 `release_artifact_profile=minimal|compact|full` 与 `release_decision=READY|READY_WITH_RISK|NOT_READY|RELEASED|FAILED`。CP8 默认只允许 `READY` / `READY_WITH_RISK` / `NOT_READY`；`RELEASED` / `FAILED` 必须有独立真实发布授权和执行证据。发布阶段不得默认读取完整 HLD、全部 LLD、完整 TEST-MATRIX、完整 TEST-REPORT、完整 REVIEW 或完整 diff；只消费摘要、计数、风险 ID、决策 ID 和证据路径。`CHANGELOG.md`、`INSTALL.md`、`TROUBLESHOOTING.md`、`POST-RELEASE-OBSERVATION.md` 不作为默认产物，仅 `full` profile 或用户明确要求时生成。
- **方案收敛优先**：涉及方案设计、整改规划或跨平台治理时，默认优先最简方案与内联策略；除非事实或验收要求证明不足，不新增共享模板体系或多余抽象层
- **精确匹配优先**：涉及对象定位、版本对齐、规则命中或平台路径判定时，默认采用 exact 语义，不使用模糊匹配作为默认行为
- **平台契约优先**：安装器、DryRun、guardrail 与交付文档必须共同引用 `delivery/doc/PLATFORM-CONTRACTS.yaml`；Codex Skill 禁止写入 `.codex/skills` 或 `~/.codex/skills`
- **安装路径前置校验**：安装器写入前必须逐级检查目标父路径；任一级被普通文件占用时必须 fail fast，输出 `安装路径被非目录占用: <path>`，不得暴露 Python traceback
- **安装命令与组件默认值**：安装 CLI 使用 `meta-flow install <platform>`，卸载使用 `meta-flow uninstall <platform>`；`--platform` 与 `install --uninstall` 仅作 legacy 兼容。组件使用 `--component rules|agent|full`；`rules` 只安装 AGENTS.md / CLAUDE.md 等规则，`agent` 安装 agents+skills，`full` 同时安装两类内容；user scope 默认 `rules`，project scope 默认 `full`；legacy `--content all|agents|skills|rules` 仅作兼容入口

## 防火墙测试工作流（现有，独立运行）

> 本项目同时保留原有防火墙测试元工作流说明，两套系统并行存在，互不干扰。
> 当前统一编排入口：Host Orchestrator 主进程。Codex/Claude Code/OpenClaw 只安装功能子 agent；不安装主编排子 agent。

## LLD 消费契约补充

- `lld_policy.required_level=full-lld` 时，`STORY-*-LLD.md` 必须保持 **14 个可见章节**；`Tier-S` 只允许简化内容深度，不允许压缩章节数量。`technical-note` / `waived` Story 的正式设计证据写入 Story 卡片。
- `tier`、`shared_fragments`、`open_items` 是强输入字段，meta-dev / meta-qa 不得跳过。
- meta-dev 至少消费：文件影响范围、接口设计、异常处理、测试设计、实施步骤、回滚策略，并在全部目标 Story 的完整 LLD / 技术说明 / waived 证据统一确认且当前 Wave 的 `dev_gate` 满足后优先复用同一子 agent 继续实现。
- meta-qa 至少消费：接口设计、核心流程、测试设计、回滚策略、OPEN/Spike 状态、CP6 实现执行证据，并输出验证对象清单、验证追踪矩阵、设计契约验证和阶段决策。

## 实现执行证据补充

- CP6 不只检查“代码已改完”，还必须检查实现执行证据是否闭环：实现对象清单、设计契约映射、测试 / Fixture 计划、最小实现切片、本地验证、平台差异和交接摘要。
- `IMPLEMENTATION.md` 是条件必需产物：复杂 / 高风险 / Prompt-Skill / Workflow / 安装器 / 护栏 / 平台适配 / 发布相关 Story 必须生成；低风险 Story 可使用 Story 卡片 `implementation_context` 或 DEV-LOG 摘要，但必须说明 N/A 理由。
- CP7 / verification-execution / quality-review 必须消费实现执行证据；缺少证据时应判定为 CP6 输入缺陷，而不是让 meta-qa 自行脑补实现意图。

## Review Gate 分派与灰度

| Lane | Agent | 主要职责 |
|------|-------|----------|
| `lane-product` | `meta-pm` | 场景、画像、指标与范围一致性、原始需求 / 场景基线保留和修订记录 |
| `lane-architecture` | `meta-se` | 设计边界、依赖、ADR 与阶段一致性 |
| `lane-implementation` | `meta-dev` | 可实现性、文件归属、平台约束 |
| `lane-quality` | `meta-qa` | 可验证性、风险、安全、安装约束 |
| `lane-docs` | `meta-doc` | 面向用户的可读性与交付完整性 |

灰度顺序：

1. 先覆盖 `HLD.md` 与 `STORY-*-LLD.md`
2. 再覆盖 `ARCHITECTURE-DECISION.md` 与 `STORY-BACKLOG.md`
3. 最后覆盖 `README.md`、`USER-MANUAL.md` 等交付文档
<!-- myflow:managed:end -->
