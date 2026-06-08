# ptm-atomic

防火墙测试原子操作规范仓库与本地 CLI。

## 目录

- [1. 项目定位](#1-项目定位)
- [2. 已交付能力](#2-已交付能力)
- [3. 目录结构](#3-目录结构)
- [4. 快速开始](#4-快速开始)
- [5. CLI 命令](#5-cli-命令)
- [6. 当前 Package 和 Op ID](#6-当前-package-和-op-id)
- [7. Schema v1.1 摘要](#7-schema-v11-摘要)
- [8. 安全边界](#8-安全边界)
- [9. 仓库检查](#9-仓库检查)
- [10. 文档入口](#10-文档入口)
- [11. 发布说明](#11-发布说明)

## 1. 项目定位

`ptm-atomic` 用于维护防火墙测试原子操作的 YAML 规范、package 过滤视图和本地查询校验 CLI。它解决三类问题：

- 原子操作字段和命名统一，测试用例以稳定的 `op_id` 引用操作。
- 操作库可通过 git 同步到本地缓存，离线执行查询和引用校验。
- 发布前可用仓库脚本检查 schema、目录布局和安全门禁。

本仓库的用户可见交付面是原生仓库结构：

| 路径 | 用途 |
|---|---|
| `atoms/` | 原子操作 YAML，当前包含基础验证、NGFW 安装初始化、容量配置、验证和批量配置操作。 |
| `schemas/` | `schemas/atomic-op.schema.yaml` 定义 schema v1.1 字段合同。 |
| `packages/` | package 清单，作为 `op_id` 过滤视图；不安装、复制、执行或分发 atom。 |
| `adapters/` | 公开、非敏感的 adapter profile，描述 CLI runner 和外部脚本生成器可消费的 API shape 映射。 |
| `docs/` | 用户手册、工程师手册、字段参考、错误码、命名规范和测试用例模板。 |
| `src/atomic_ops/` | `ptm-atomic` CLI 实现。 |
| `scripts/` | 仓库级校验脚本。 |
| `pyproject.toml` | Python 包和依赖声明。 |
| `uv.lock` | Python 依赖锁定结果。 |

## 2. 已交付能力

| 能力 | 已验证事实 |
|---|---|
| Schema v1.1 | 顶层 `schema_version: "1.1"`，新增或收口 `risk`、`credential_ref`、`session_ref`、`state_ref`、`gate`、`verification`、`batch` 等字段。 |
| NGFW 安装初始化 | `ngfw_installation` package 包含 5 个 op：镜像安装、最小初始化、Web 管理登录、登录状态检查和健康检查。 |
| 容量配置 | `ngfw_capacity_config` package 包含接口、对象、ACL 策略、策略路由、OSPFv2、OSPFv3、BFD、静态路由、NAT、带宽、黑白名单、SSL VPN、动态路由等配置 op。 |
| 容量验证 | `ngfw_verification` package 包含对应容量域验证 op 和 OSPFv2、OSPFv3、BFD 查询，不包含安装健康检查 `fw_verify_ngfw_health`。 |
| 多设备批量配置 | `ngfw_batch_config` package 包含 10 个批量配置 op；批量合同见 `docs/batch-configuration-contract.md`。 |
| Adapter profile | `adapters/ngfw/default.yaml` 为地址对象、策略路由、OSPFv2、OSPFv3 和 BFD runner 提供公开 API shape 映射；合同见 `docs/API-ADAPTER-SPEC.md`。 |
| CLI | 当前 CLI 提供 `sync`、`list`、`show`、`adapter`、`run`、`packages`、`validate`；除 `run` 白名单外，其余命令只读。 |
| 安全门禁 | `scripts/security_gate_check.py` 执行敏感赋值模式检测，并检查高风险 atom 的 gate 合同完整性。 |
| 静态检查 | `scripts/validate_schema.py`、`scripts/validate_adapter_profiles.py`、`scripts/layout_check.py`、`scripts/security_gate_check.py`、`scripts/check_aliases.py`、`scripts/check_package_refs.py` 均可通过 `uv run --python 3.11 python ...` 执行。 |

## 3. 目录结构

```text
.
├── atoms/
│   └── fw/
├── adapters/
│   └── ngfw/
├── docs/
│   ├── API-ADAPTER-SPEC.md
│   ├── USER-MANUAL.md
│   ├── batch-configuration-contract.md
│   ├── engineer-handbook.md
│   ├── error-codes.md
│   ├── naming-convention.md
│   ├── schema-field-reference.md
│   └── test-case-template.yaml
├── packages/
│   ├── networking.yaml
│   ├── ngfw_batch_config.yaml
│   ├── ngfw_capacity_config.yaml
│   ├── ngfw_installation.yaml
│   ├── ngfw_verification.yaml
│   └── security.yaml
├── schemas/
│   ├── adapter-profile.schema.yaml
│   └── atomic-op.schema.yaml
├── scripts/
│   ├── check_aliases.py
│   ├── check_package_refs.py
│   ├── layout_check.py
│   ├── security_gate_check.py
│   ├── validate_adapter_profiles.py
│   └── validate_schema.py
├── src/atomic_ops/
├── pyproject.toml
└── uv.lock
```

## 4. 快速开始

### 安装或临时运行 CLI

```bash
uv tool install .
ptm-atomic --version
```

开发和本地验证可直接使用：

```bash
uv run ptm-atomic --help
```

本项目使用 `uv` 管理 Python 运行、工具安装和依赖锁定。仓库文档中的 Python 命令统一使用 `uv run`、`uv run --python 3.11 python ...` 或 `uv tool`，不把裸 `pip install` 作为默认路径。

### 同步操作库缓存

```bash
ptm-atomic sync --repo <ptm-atomic-git-repository-url>
```

同步使用 git 访问远端仓库并写入本地缓存。同步后，`list`、`show`、`adapter`、`packages`、`validate` 只读取本地缓存，不读取当前未同步的工作树修改。若同步失败但已有完整缓存，缓存可能以 `STALE` 状态继续服务只读查询，并可能落后于仓库最新提交。

### 查看和校验

```bash
ptm-atomic packages
ptm-atomic list --package ngfw_installation
ptm-atomic show fw_verify_ngfw_health
ptm-atomic adapter fw_config_policy_route
ptm-atomic validate docs/test-case-template.yaml
ptm-atomic validate --package ngfw_installation
```

### 执行操作（新格式）

`run` 命令按操作族分为嵌套子命令。共享参数（`--base-url`、`--execute`、`--format` 等）在 `run` 层级定义：

```bash
# 认证
ptm-atomic run auth login --base-url https://<device-management-ip> --username admin

# 地址对象
ptm-atomic run object config --base-url https://<device-management-ip> --object-name srcObj --ipaddr 192.168.0.0 --mask 16

# 策略路由
ptm-atomic run policy-route config --base-url https://<device-management-ip> --source-network srcObj --dst-network dstObj --next-hop-ip 18.18.2.2 --in-interface GE0_12

# OSPFv2
ptm-atomic run ospf config global --base-url https://<device-management-ip> --enable --router-id <DUT_IP> --originate --always

# OSPFv3 + BFD
ptm-atomic run ospfv3 config global --base-url https://<device-management-ip> --enable --router-id <DUT_IP>
ptm-atomic run ospfv3 bfd verify-session --base-url https://<device-management-ip> --page 1 --size 40
```

旧格式 `ptm-atomic run <op_id>` 仍然兼容，但会显示 deprecation warning。迁移指引：`ptm-atomic run --help` 查看所有可用操作族。

## 5. CLI 命令

| 命令 | 用途 | 范围 |
|---|---|---|
| `ptm-atomic sync` | 同步本地操作库缓存 | 访问 git 仓库，写入本地缓存。 |
| `ptm-atomic list` | 列出本地缓存中的 atom 摘要 | 读取本地缓存。 |
| `ptm-atomic show <op_id>` | 输出单个 atom 的 YAML 或 JSON | 读取本地缓存。 |
| `ptm-atomic adapter <op_id>` | 输出单个 atom 引用的 adapter profile operation | 读取本地缓存中的 atom 与 `adapters/`。 |
| `ptm-atomic run <family> <action> [target]` | 按操作族执行 runner op，默认 dry-run | 共享参数在 `run` 层级；支持 `auth`、`object`、`policy-route`、`interface`、`ospf`、`ospfv3` 六个操作族。真实请求必须显式 `--execute`。旧格式 `run <op_id>` 仍兼容。 |
| `ptm-atomic packages` | 列出 package 清单 | 读取本地缓存。 |
| `ptm-atomic validate <test_case.yaml>` | 校验测试用例中的 `op_id` 引用 | 读取本地缓存和指定 YAML。 |
| `ptm-atomic validate --package <package_id>` | 校验 package 清单中的 `op_id` 引用 | 读取本地缓存。 |

除 `ptm-atomic run` 的白名单 runner 外，其他 CLI 命令仍是只读缓存查询或校验。`run` 默认 dry-run，不发设备请求；登录真实执行需要 `--execute --password-env <ENV>`，地址对象、策略路由、OSPFv2、OSPFv3 和 BFD 真实执行需要已有 session 文件和 `--execute`。CLI 不接受明文密码参数，不打印完整会话值，不把运行时材料写入仓库。

`ptm-atomic run` 成功输出使用固定 envelope。runner 细节统一放入 `data`，调用方不应从顶层读取 `request`、`session`、`response` 等旧字段：

```yaml
op_id: fw_config_object
status: dry_run
data:
  execute_required: true
  request:
    method: POST
    url: https://<device-management-ip>/api/v1/ippool
    auth:
      name: Authorization
      value: <session-ref>
    content_type: application/json
    payload:
      val:
        name: srcObj
        desc: srcObj
        type: 4
        ranges: []
        networks:
          - ipaddr: 192.168.0.0
            mask: "16"
  session_file: ~/.local/state/ptm-atomic/ngfw/session.json
  verify_tls: false
  timeout: 10.0
error_type: NONE
diag_snapshot_ref: ""
```

### Runner 示例

登录防火墙 Web 管理面，并把会话材料写入用户 state 目录：

```bash
NGFW_PASSWORD='<password>' ptm-atomic run auth login \
  --base-url https://<device-management-ip> \
  --username admin \
  --password-env NGFW_PASSWORD \
  --execute
```

先创建策略路由要引用的 IPv4 地址对象。`--object-name` 是设备对象名，策略路由的 `--source-network` / `--dst-network` 后续引用这个名称：

```bash
ptm-atomic run object config \
  --base-url https://<device-management-ip> \
  --object-name srcObj \
  --ipaddr 192.168.0.0 \
  --mask 16 \
  --execute
```

先 dry-run 查看策略路由请求体。`--source-network` 和 `--dst-network` 是地址对象名；如果传入的是地址组名，必须同时加 `--source-network-is-group` 或 `--dst-network-is-group`：

```bash
ptm-atomic run policy-route config \
  --base-url https://<device-management-ip> \
  --source-network srcObj \
  --dst-network dstObj \
  --next-hop-ip 18.18.2.2 \
  --in-interface GE0_12
```

策略路由也支持出接口转发模式。此模式不传 `--next-hop-ip`，但必须传 `--outgoing-interface`；IPv4 和 IPv6 策略路由都适用：

```bash
ptm-atomic run policy-route config \
  --base-url https://<device-management-ip> \
  --source-network any \
  --dst-network any \
  --in-interface GE0_2.106 \
  --outgoing-interface tunnel2 \
  --weight 123
```

确认无误后显式执行：

```bash
ptm-atomic run policy-route config \
  --base-url https://<device-management-ip> \
  --source-network srcObj \
  --dst-network dstObj \
  --next-hop-ip 18.18.2.2 \
  --in-interface GE0_12 \
  --execute
```

接口配置 runner 调用 `/api/v1/intf`，按方法拆为 `create`、`update`、`verify`、`delete`，批量删除使用独立的 `delete-batch` 调用 `/api/v1/batch`。BVI 和子接口只支持 `Route` 模式；物理口和聚合口支持 `Route`、`Switch`、`Pair`、`Monitor`；物理口只允许 `PUT/GET`。

创建 BVI 接口 dry-run：

```bash
ptm-atomic run interface create \
  --base-url https://<device-management-ip> \
  --interface-kind bvi \
  --id bvi109 \
  --ip-address 191.109.0.31/24 \
  --ip-address 2091:109::31/64
```

更新子接口或物理口使用 `update`；单个删除使用查询参数 `id` 且不发送请求体；查询接口返回全量接口：

```bash
ptm-atomic run interface update \
  --base-url https://<device-management-ip> \
  --interface-kind sub \
  --id GE0_2.106 \
  --ip-address 192.106.0.31/24 \
  --ip-address 2092:106::31/64

ptm-atomic run interface verify --base-url https://<device-management-ip>
ptm-atomic run interface delete --base-url https://<device-management-ip> --id GE0_2.106
```

批量删除是独立 batch 请求：

```bash
ptm-atomic run interface delete-batch \
  --base-url https://<device-management-ip> \
  --id bvi109 \
  --id GE0_2.106
```

OSPFv2 按 HTTP 方法拆分为独立原子操作。先 dry-run 查看全局配置请求体：

```bash
ptm-atomic run ospf config global \
  --base-url https://<device-management-ip> \
  --enable \
  --router-id <DUT_IP> \
  --originate \
  --always
```

配置 OSPFv2 路由引入：

```bash
ptm-atomic run ospf config redistribution \
  --base-url https://<device-management-ip> \
  --redistribute connected=333 \
  --redistribute static=666 \
  --redistribute rip=333
```

新增、更新和删除 OSPFv2 network 使用不同子命令；PUT 和 DELETE 必须显式传 `--id`：

```bash
ptm-atomic run ospf config network \
  --base-url https://<device-management-ip> \
  --network 191.0.0.0/24 \
  --area 0

ptm-atomic run ospf config network-update \
  --base-url https://<device-management-ip> \
  --id <ospfv2-network-id> \
  --network 191.0.0.0/24 \
  --area 0

ptm-atomic run ospf delete network \
  --base-url https://<device-management-ip> \
  --id <ospfv2-network-id>
```

接口配置同样按 POST、PUT、DELETE 拆分：

```bash
ptm-atomic run ospf config interface \
  --base-url https://<device-management-ip> \
  --interface bvi109 \
  --cost 1 \
  --priority 1 \
  --hello-interval 10 \
  --retransmit-interval 5 \
  --dead-interval 40 \
  --transmit-delay 1 \
  --type-network 0 \
  --int-auth-mode 0 \
  --bfd-enable \
  --detect-multiplier 3 \
  --min-rx-interval 300 \
  --min-tx-interval 300
```

OSPFv2 interface 删除使用接口名作为 `--id`：

```bash
ptm-atomic run ospf delete interface \
  --base-url https://<device-management-ip> \
  --id GE0_12 \
  --execute
```

查询邻居和日志时 `--page` 默认 `1`，`--size` 默认 `40`：

```bash
ptm-atomic run ospf verify neighbor --base-url https://<device-management-ip>
ptm-atomic run ospf verify neighbor --base-url https://<device-management-ip> --page 1 --size 40
```

OSPFv3 使用相同的按方法拆分模式，接口路径为 `ospf6*`：

```bash
ptm-atomic run ospfv3 config global \
  --base-url https://<device-management-ip> \
  --enable \
  --router-id <DUT_IP>

ptm-atomic run ospfv3 config redistribution \
  --base-url https://<device-management-ip> \
  --redistribute connected=333 \
  --redistribute static=333

ptm-atomic run ospfv3 config network \
  --base-url https://<device-management-ip> \
  --interface bvi109 \
  --area 0

ptm-atomic run ospfv3 verify neighbor --base-url https://<device-management-ip> --page 1 --size 40
```

BFD 支持全局启停、会话查询：

```bash
ptm-atomic run ospfv3 bfd config \
  --base-url https://<device-management-ip> \
  --enable

ptm-atomic run ospfv3 bfd verify-session --base-url https://<device-management-ip> --page 1 --size 40
```

> **兼容模式**：旧格式 `ptm-atomic run fw_config_ospfv2_global ...` 等仍可用，但会显示 deprecation warning 提示迁移到新格式。兼容模式将在 1-2 个版本后移除。

## 6. 当前 Package 和 Op ID

| Package | 当前 op_id 数 | 代表性 op_id |
|---|---:|---|
| `networking` | 1 | `fw_verify_acl_rule` |
| `security` | 1 | `fw_verify_acl_rule` |
| `ngfw_installation` | 5 | `fw_install_ngfw_image`、`fw_init_ngfw_minimal`、`fw_login_web_management`、`fw_check_login_state`、`fw_verify_ngfw_health` |
| `ngfw_capacity_config` | 33 | `fw_config_interface`、`fw_update_interface`、`fw_delete_interface`、`fw_config_policy_route`、`fw_config_ospfv2_global` |
| `ngfw_verification` | 25 | `fw_verify_interface`、`fw_verify_policy_route`、`fw_verify_ospfv2_neighbor`、`fw_verify_ospfv3_neighbor`、`fw_verify_bfd_session` |
| `ngfw_batch_config` | 10 | `fw_config_batch_interface`、`fw_config_batch_object`、`fw_config_batch_acl_policy`、`fw_config_batch_nat`、`fw_config_batch_dynamic_routing` |

`package_id` 必须与 `packages/<package_id>.yaml` 文件名一致。package 是 `list`、`validate --package` 等命令使用的过滤视图，不复制 atom 文件，不安装 atom，不执行 atom，不分发 atom，也不表示可执行计划。

当前 package 完整性事实：

- 共有 6 个 package manifest。
- 共有 69 条 package `operations` 条目。
- 共有 68 个唯一 `op_id`；`fw_verify_acl_rule` 同时出现在 `networking` 和 `security` 旧基线视图中。
- 所有 package `op_id` 均能解析到 `atoms/fw/*.yaml`。

## 7. Schema v1.1 摘要

单个 atom 位于：

```text
atoms/<device_type>/<op_id>.yaml
```

v1.1 atom 使用 `schema_version: "1.1"`。重要字段包括：

| 字段 | 说明 |
|---|---|
| `risk` | 记录操作风险等级和说明。 |
| `credential_ref` | 只保存凭据引用名，不保存真实密码、token 或密钥值。 |
| `session_ref` | 标识会话状态引用，不能写入会话密钥或 cookie。 |
| `state_ref` | 标识操作前后状态引用，不能嵌入生产数据。 |
| `gate` | 声明执行前置门禁，如人工确认或只读校验。 |
| `verification` | 描述验证方式和期望结果。 |
| `batch` | 描述批量配置的并发、失败策略和设备结果摘要字段。 |
| `adapter_contract_ref` | 可选 JSON Pointer，指向公开 adapter profile operation，如 `adapters/ngfw/default.yaml#/operations/fw_config_policy_route`。 |

字段完整说明见 `docs/schema-field-reference.md`。

## 8. 安全边界

`ptm-atomic` 当前主要是本地规范消费和校验工具；只有 `run` 白名单 op 具备受控设备执行能力。

| 边界 | 说明 |
|---|---|
| 设备连接 | 除 `ptm-atomic run` 的 Web 登录、地址对象、策略路由、OSPFv2、OSPFv3 和 BFD 白名单 op 外，CLI 不连接真实防火墙、流量发生器、交换机或管理面。 |
| 配置变更 | 除地址对象、策略路由、OSPFv2、OSPFv3 和 BFD runner 白名单外，CLI 不执行 atom，不下发配置，不触发安装、初始化或策略修改。 |
| 凭据处理 | CLI 不接受明文密码参数；登录 runner 只从环境变量读取口令，会话材料默认写入用户 state 目录，文档和 YAML 不写真实凭据值。 |
| 回滚 | CLI 不执行自动回滚；回滚只能作为 atom 合同或人工流程描述。 |
| 敏感输入 | 仓库文档不得包含 `.input` 数据、真实地址、token、cookie、私钥、FTP 凭据或生产环境样本。 |

当前唯一允许出现在仓库示例中的密码策略字面值是 `Ngfw@123`，用于 NGFW 初始化口令复杂度合同说明；它不是可直接使用的生产默认密码。

## 9. 仓库检查

发布或合并前先运行工作树检查：

```bash
uv run ptm-atomic --help
uv run --python 3.11 python scripts/validate_schema.py atoms
uv run --python 3.11 python scripts/validate_adapter_profiles.py
uv run --python 3.11 python scripts/layout_check.py
uv run --python 3.11 python scripts/security_gate_check.py
uv run --python 3.11 python scripts/check_aliases.py
uv run --python 3.11 python scripts/check_package_refs.py
```

如需证明 package manifest 与当前工作树 atom 文件一致，`check_package_refs.py` 已直接读取工作树交叉校验，无需依赖缓存。

再运行消费者缓存 smoke check：

```bash
uv run ptm-atomic packages
uv run ptm-atomic validate --package ngfw_installation
```

`ptm-atomic packages`、`ptm-atomic adapter <op_id>` 和 `ptm-atomic validate --package ...` 是缓存消费者检查，只反映本地 synced cache；如果缓存未同步到当前提交，它们不会看到未提交或未同步的本地 manifest 修改。要查询新增或修改后的 adapter profile，必须先同步到包含 `adapters/` 的目标提交。

静态检查脚本只读取仓库文件并输出检查结果：

| 脚本 | 检查内容 |
|---|---|
| `validate_schema.py` | atom YAML 是否符合 `atomic-op.schema.yaml` |
| `validate_adapter_profiles.py` | adapter profile 结构 + atom `adapter_contract_ref` 引用完整性 |
| `layout_check.py` | 仓库目录结构是否包含必需路径 |
| `security_gate_check.py` | 敏感信息零落盘 + 高风险 atom gate 合同完整性 |
| `check_aliases.py` | 别名格式（小写连字符）+ 别名与 op_id 冲突检测 |
| `check_package_refs.py` | package `operations[]` 是否全部解析到 atom 文件 |

`security_gate_check.py` 默认扫描 `atoms/`、`adapters/`、`packages/`、`docs/`、`schemas/`、`scripts/`、`src/atomic_ops/`，并排除 `.input/`、版本控制目录、虚拟环境和缓存目录；默认模式下若 `adapters/` 尚不存在，不会因此阻断安全门。它检测敏感赋值模式，对 adapter profile 执行结构化敏感字段和值扫描，并对 `risk.level=high` 或 `op_id` 匹配 `^fw_(install|init|login|config|config_batch)_` 的 atom 检查 `gate.required`、`gate.reason`、`gate.approver_role` 和 `gate.evidence_required`。

`.input/`、`process/`、`checkpoints/`、本地生成的 `AGENTS.md`、本地 agent 配置目录和缓存/日志目录是被 `.gitignore` 忽略的过程或运行时产物，不属于交付文档，也不应在发布包中承诺为用户可见内容。

## 10. 文档入口

| 文档 | 用途 |
|---|---|
| `docs/USER-MANUAL.md` | 面向使用者的安装、同步、查询、校验和故障排查。 |
| `docs/API-ADAPTER-SPEC.md` | 公开 adapter profile 合同、敏感边界和外部 runner 分工。 |
| `docs/engineer-handbook.md` | 面向维护者的贡献流程、发布检查和安全边界。 |
| `docs/schema-field-reference.md` | schema v1.1 字段参考和兼容性说明。 |
| `docs/batch-configuration-contract.md` | 多设备批量配置合同。 |
| `docs/test-case-template.yaml` | 可被 `ptm-atomic validate` 读取的测试用例模板。 |
| `docs/error-codes.md` | CLI、脚本和操作级错误码说明。 |
| `docs/naming-convention.md` | `op_id` 命名、动词和 CLI 命令边界。 |

## 11. 发布说明

版本记录见 `CHANGELOG.md`。仓库使用两条版本流：

- `atoms-vX.Y.Z`：schema、atom、package、命名规范和文档。
- `cli-vX.Y.Z`：CLI 代码、命令行为、错误处理和 Python 包发布。

两条版本流独立推进。更新 atom 数据不自动发布 CLI；更新 CLI 也不自动修改本地操作库缓存。
