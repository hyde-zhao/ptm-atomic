# 用户使用手册

`ptm-atomic` 用于同步、查询、校验和受控执行防火墙测试原子操作。当前 CLI 提供 `sync`、`list`、`show`、`adapter`、`run`、`packages` 和 `validate`；除 `run` 白名单 op 外，其余命令只读。

**`run` 命令已重构为嵌套子命令**（v0.1.0+），按操作族分组为 `auth`、`object`、`policy-route`、`interface`、`ospf`、`ospfv3`。共享参数（`--base-url`、`--execute` 等）在 `run` 层级定义，每个叶子命令只暴露自己的参数。旧格式 `ptm-atomic run <op_id>` 仍兼容，但输出 deprecation warning。详见下文第 5 节。

## 1. 使用前准备

| 材料 | 必填 | 说明 |
|---|---:|---|
| Python `>=3.11` | 是 | CLI 运行环境。 |
| `uv` | 是 | 安装、运行和锁定 Python 环境。 |
| `git` | 是 | `ptm-atomic sync` 使用 git 同步远端操作库。 |
| git 认证 | 按需 | 由 git 原生机制处理，CLI 不保存凭据。 |
| 测试用例 YAML | 按需 | 用于 `ptm-atomic validate <test_case.yaml>`。 |
| package 名称 | 按需 | 用于 `list --package` 或 `validate --package`。 |

本项目已交付 `pyproject.toml` 与 `uv.lock`。安装 CLI 使用 `uv tool`，仓库内脚本使用 `uv run --python 3.11 python ...`。

## 2. 安装和首次同步

### 安装 CLI

在仓库根目录执行：

```bash
uv tool install .
ptm-atomic --version
```

开发或临时验证时可以不安装到工具环境：

```bash
uv run ptm-atomic --help
```

### 同步本地缓存

首次使用前同步操作库：

```bash
ptm-atomic sync --repo <ptm-atomic-git-repository-url>
```

同步只访问 git 仓库并写入本地缓存。同步成功后，`list`、`show`、`adapter`、`packages`、`validate` 都读取本地缓存，不访问设备。

这些只读命令读取 synced cache，不读取当前工作树中尚未同步的本地修改。若同步失败但已有完整缓存，命令可能继续使用标记为 `STALE` 的旧缓存；此时结果可能落后于仓库最新提交。

### 确认可查询

```bash
ptm-atomic packages
ptm-atomic list --package ngfw_installation
ptm-atomic show fw_verify_ngfw_health
```

## 3. 本地缓存

| 平台 | 默认缓存目录 |
|---|---|
| Linux/macOS | `~/.cache/ptm-atomic/repo/` |
| Windows | `%LOCALAPPDATA%\\ptm-atomic\\repo\\` |

缓存内容包括 `atoms/`、`schemas/`、`packages/`、`docs/`、`adapters/` 和 `_metadata.json`。`_metadata.json` 记录 `source_repo`、`ref_mode`、`current_ref`、`commit_sha`、`synced_at`、`last_sync_status`、`cache_root`、`sparse_paths` 等同步状态字段。

常用同步命令：

```bash
ptm-atomic sync --repo <ptm-atomic-git-repository-url>
ptm-atomic sync --format json
ptm-atomic sync --latest
ptm-atomic sync --ref atoms-v1.1.0
```

`--latest` 跟踪默认分支最新状态；`--ref` 固定到指定分支、tag 或 commit。网络失败但本地缓存完整时，CLI 可标记为 `STALE`，只读命令仍可基于缓存继续工作。

## 4. 查询原子操作

列出全部本地 atom：

```bash
ptm-atomic list
ptm-atomic list --format json
```

`list` 表格输出包含 `op_id`、`device_type`、`idempotent`、`since_version`、`tags`（逗号连接）、`aliases`（逗号连接，同义搜索词）和 `description` 七列。JSON 输出额外包含 `parameters_summary` 字段（参数名、类型、是否必填），示例如下：

```json
{
  "op_id": "fw_config_interface",
  "description": "Create an NGFW interface entry through /api/v1/intf.",
  "idempotent": true,
  "device_type": "fw",
  "since_version": "1.3.0",
  "tags": ["firewall", "capacity", "interface", "configuration"],
  "aliases": ["subinterface", "trunk", "lag", "bond", "bvi", "vlan-interface"],
  "parameters_summary": [
    {"name": "state_ref", "type": "string", "required": false},
    {"name": "config_domain", "type": "string", "required": true},
    {"name": "params", "type": "json", "required": true}
  ]
}
```

`aliases` 为上游语义匹配消费者（如 m-analyzer）提供自然语言同义搜索词。例如用户描述 "创建子接口" 时，m-analyzer 可通过 `aliases` 中的 `subinterface` 匹配到 `fw_config_interface`。没有变体名的 op 此字段为空列表。

按设备和 package 过滤：

```bash
ptm-atomic list --device fw
ptm-atomic list --package ngfw_capacity_config
ptm-atomic list --package ngfw_verification --device fw
```

查看单个 atom：

```bash
ptm-atomic show fw_verify_interface
ptm-atomic show fw_verify_interface --format json
```

`show` 根据 `op_id` 前缀定位到 `atoms/<device_type>/<op_id>.yaml`。如果返回 `OP_NOT_FOUND`，先执行 `ptm-atomic sync`，再检查拼写、前缀和相似建议。

查看单个 atom 引用的 adapter profile operation：

```bash
ptm-atomic adapter fw_config_policy_route
ptm-atomic adapter fw_config_policy_route --format json
```

`adapter` 先读取缓存中的 atom，再通过 `adapter_contract_ref` 解析 `adapters/<profile>.yaml#/operations/<op_id>`。如果 atom 没有声明 adapter 引用，命令返回 `OP_NOT_FOUND`；如果缓存缺少 `adapters/` 或 profile 文件，命令返回 `REPO_NOT_SYNCED`，需要同步到包含 adapter profile 的提交。

## 5. Runner 执行

`ptm-atomic run` 支持六个操作族，默认 dry-run，必须显式 `--execute` 才发真实请求。

### 执行审计日志（exec-log）

仅 `--execute` 调用（含成功与错误）写本地执行审计日志，dry-run 不记。每次 execute 调用生成一个 `run_id`，日志按 `run_id` 分目录隔离，避免单文件 append 累积。日志路径与 atom 缓存分开（日志是运行历史，不应被缓存清理误删）：

| 平台 | 路径 |
|------|------|
| Linux/macOS | `~/.local/state/ptm-atomic/runs/<run_id>/exec-log.jsonl` |
| Windows | `%LOCALAPPDATA%\ptm-atomic\runs\<run_id>\exec-log.jsonl` |

调用方定位日志：

- 成功：返回 envelope 的 `metadata.exec_log`，含 `run_id` 与 `path`。
- 错误：stderr 错误对象含 `run_id` 与 `exec_log_path`，透传的 `err_code` / `err_msg` 同步写入日志。

日志记录字段（按需出现）：

| 字段 | 含义 |
|------|------|
| `run_id` | 本次 execute 调用唯一标识 |
| `timestamp` | 写入时刻（ISO-8601 毫秒） |
| `op_id` | 原子操作 id |
| `mode` | 固定 `execute` |
| `status` | `success` 或 `error` |
| `http_status` | 设备 HTTP 状态码 |
| `err_code` / `err_msg` | 设备透传错误码与信息（错误时） |
| `error_type` | CLI 错误类型（错误时，如 `RUNNER_CONFIG_REJECTED`） |
| `duration_ms` | 调用耗时（毫秒） |

### 操作族与新命令格式

| 旧 op_id | 新命令 |
|------|------|
| `fw_login_web_management` | `ptm-atomic run auth login` |
| `fw_config_object` | `ptm-atomic run object config` |
| `fw_config_policy_route` | `ptm-atomic run policy-route config` |
| `fw_update_policy_route` | `ptm-atomic run policy-route update` |
| `fw_delete_policy_route` | `ptm-atomic run policy-route delete` |
| `fw_verify_policy_route` | `ptm-atomic run policy-route verify` |
| `fw_update_policy_route_priority` | `ptm-atomic run policy-route priority` |
| `fw_config_interface` | `ptm-atomic run interface create` |
| `fw_update_interface` | `ptm-atomic run interface update` |
| `fw_verify_interface` | `ptm-atomic run interface verify` |
| `fw_delete_interface` | `ptm-atomic run interface delete` |
| `fw_delete_batch_interface` | `ptm-atomic run interface delete-batch` |
| `fw_config_ospfv2_global` | `ptm-atomic run ospf config global` |
| `fw_delete_ospfv2_network` | `ptm-atomic run ospf delete network` |
| `fw_verify_ospfv2_neighbor` | `ptm-atomic run ospf verify neighbor` |
| `fw_config_ospfv3_global` | `ptm-atomic run ospfv3 config global` |
| `fw_config_bfd_global` | `ptm-atomic run ospfv3 bfd config` |
| `fw_verify_bfd_session` | `ptm-atomic run ospfv3 bfd verify-session` |

旧格式 `ptm-atomic run <op_id>` 仍兼容（1-2 版本后移除），使用时会输出 deprecation warning。以下示例沿用旧格式以保证脚本兼容，同时标注新格式等效写法。

成功输出使用固定 envelope。`op_id`、`status`、`data`、`error_type` 和 `diag_snapshot_ref` 是稳定顶层字段；请求计划、真实执行响应、session 摘要等 runner 专属内容放在 `data` 下：

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

登录 Web 管理面：

```bash
NGFW_PASSWORD='<password>' ptm-atomic run fw_login_web_management \
  --base-url https://<device-management-ip> \
  --username admin \
  --password-env NGFW_PASSWORD \
  --execute
```

登录 runner 会读取防火墙登录页 RSA 公钥、加密密码、调用 `PUT /api/v1/auth`，并把返回的会话材料写入 `~/.local/state/ptm-atomic/ngfw/session.json`。CLI 不接受 `--password <明文>`，也不会打印完整会话值。

地址对象 dry-run：

```bash
ptm-atomic run fw_config_object \
  --base-url https://<device-management-ip> \
  --object-name srcObj \
  --ipaddr 192.168.0.0 \
  --mask 16
```

地址对象真实执行：

```bash
ptm-atomic run fw_config_object \
  --base-url https://<device-management-ip> \
  --object-name srcObj \
  --ipaddr 192.168.0.0 \
  --mask 16 \
  --execute
```

地址对象 runner 调用 `POST /api/v1/ippool`。设备对象名规则：1-31 个字符，由大小写字母、数字、中文、连接符(-)、点(.)构成；名称不能是 `.` 或 `..` 单独出现；不能以 `IDMC-` 开头；不接受下划线，也不要用 CIDR 字符串作为对象名。

地址对象更新 dry-run 与真实执行（`PUT /api/v1/ippool`，body 含顶层 `id` 与 `val`，`id` 与 `val.name` 指向同一对象）：

```bash
ptm-atomic run object update \
  --base-url https://<device-management-ip> \
  --object-name srcObj \
  --ipaddr 192.168.0.0 \
  --mask 16
ptm-atomic run object update \
  --base-url https://<device-management-ip> \
  --object-name srcObj \
  --ipaddr 192.168.0.0 \
  --mask 16 \
  --execute
```

地址对象删除 dry-run 与真实执行（`DELETE /api/v1/ippool?id=<object-name>`，按对象名删除，不发 JSON body）：

```bash
ptm-atomic run object delete \
  --base-url https://<device-management-ip> \
  --object-name srcObj
ptm-atomic run object delete \
  --base-url https://<device-management-ip> \
  --object-name srcObj \
  --execute
```

地址对象查询 dry-run 与真实执行（`GET /api/v1/ippool?page=&size=`，返回 `count` 与 `vals` 列表，每个 `vals` 项含 `name`、`type`、`networks`、`desc`、`refcnt`）：

```bash
ptm-atomic run object verify \
  --base-url https://<device-management-ip> \
  --page 1 --size 40
ptm-atomic run object verify \
  --base-url https://<device-management-ip> \
  --page 1 --size 40 \
  --execute
```

地址对象批量删除 dry-run 与真实执行（`POST /api/v1/batch`，body 为 `batch` 数组，每项是 `DELETE /api/v1/ippool` 且 `body.id` 为对象名列表）：

```bash
ptm-atomic run object delete-batch \
  --base-url https://<device-management-ip> \
  --object-name srcObj --object-name dstObj
ptm-atomic run object delete-batch \
  --base-url https://<device-management-ip> \
  --object-name srcObj --object-name dstObj \
  --execute
```

策略路由 dry-run：

```bash
ptm-atomic run fw_config_policy_route \
  --base-url https://<device-management-ip> \
  --source-network srcObj \
  --dst-network dstObj \
  --next-hop-ip 18.18.2.2 \
  --in-interface GE0_12
```

策略路由也支持出接口转发模式。此模式不传 `--next-hop-ip`，但必须传 `--outgoing-interface`；IPv4 和 IPv6 策略路由都适用：

```bash
ptm-atomic run fw_config_policy_route \
  --base-url https://<device-management-ip> \
  --source-network any \
  --dst-network any \
  --in-interface GE0_2.106 \
  --outgoing-interface tunnel2 \
  --weight 123
```

策略路由真实执行：

```bash
ptm-atomic run fw_config_policy_route \
  --base-url https://<device-management-ip> \
  --source-network srcObj \
  --dst-network dstObj \
  --next-hop-ip 18.18.2.2 \
  --in-interface GE0_12 \
  --execute
```

策略路由 runner 调用 `POST /api/v1/policyroute`，默认使用登录会话和 `Authorization` 头。`--source-network` 和 `--dst-network` 是地址对象名；如果传入的是地址组名，必须同时加 `--source-network-is-group` 或 `--dst-network-is-group`。转发路径要求 `--next-hop-ip` 或 `--outgoing-interface` 至少提供一个；提供 `--next-hop-ip` 时地址族必须匹配 `--policy-route-type`。若目标版本要求 capacity 风格头名，可传 `--auth-header AuthorizationToken`。

接口配置 runner 调用 `/api/v1/intf`。`fw_config_interface` 使用 `POST` 创建 BVI、子接口或聚合口；`fw_update_interface` 使用 `PUT` 更新 BVI、子接口、物理口或聚合口；`fw_verify_interface` 使用 `GET` 查询全量接口且不发送请求体；`fw_delete_interface` 使用 `DELETE /api/v1/intf?id=<id>` 单删且不发送请求体。`fw_delete_batch_interface` 是独立的 `/api/v1/batch` 批量删除命令。

BVI 和子接口只支持 `Route` 模式；物理口和聚合口支持 `Route`、`Switch`、`Pair`、`Monitor`。物理口只支持 `PUT/GET`，不支持创建或删除。

创建 BVI 接口 dry-run：

```bash
ptm-atomic run fw_config_interface \
  --base-url https://<device-management-ip> \
  --interface-kind bvi \
  --id bvi109 \
  --ip-address 191.109.0.31/24 \
  --ip-address 2091:109::31/64
```

更新子接口、查询全量接口、删除单个接口：

```bash
ptm-atomic run fw_update_interface \
  --base-url https://<device-management-ip> \
  --interface-kind sub \
  --id GE0_2.106 \
  --ip-address 192.106.0.31/24 \
  --ip-address 2092:106::31/64

ptm-atomic run fw_verify_interface --base-url https://<device-management-ip>
ptm-atomic run fw_delete_interface --base-url https://<device-management-ip> --id GE0_2.106
```

批量删除接口：

```bash
ptm-atomic run fw_delete_batch_interface \
  --base-url https://<device-management-ip> \
  --id bvi109 \
  --id GE0_2.106
```

接口对使用独立的 `/api/v1/intf/pair` 端点，必须先用 `interface update` 把两个物理口准备为 `--mode Pair`，再创建接口对；L2 转发场景先完成 Switch 成员口和 BVI 配置，再创建接口对。接口对名称只允许中文/字母/数字/`-`/`.`，长度 1-31，不允许下划线；创建或更新时名称不合法会在本地直接报 `RUNNER_VALIDATION_FAILED`。重复创建会返回 `400 eObjCreateExist`（配置拒绝），重复删除会返回 `400 eObjGetNoExist`（错误详情为 `RESOURCE_NOT_FOUND`，但该 op 声明 `idempotent: false`，重复删除不算成功）。查询只支持 `--page/--size`，`--name/--receive-interface/--transmit-interface` 由 runner 在客户端过滤：

```bash
ptm-atomic run --base-url https://<device-management-ip> interface update --interface-kind physical --id GE0_1 --mode Pair --pvid 10
ptm-atomic run --base-url https://<device-management-ip> interface update --interface-kind physical --id GE0_2 --mode Pair --pvid 10
ptm-atomic run --base-url https://<device-management-ip> interface pair-config --name pair1 --receive-interface GE0_1 --transmit-interface GE0_2 --allowed-vlan 0
ptm-atomic run --base-url https://<device-management-ip> interface pair-verify --name pair1 --page 1 --size 20
ptm-atomic run --base-url https://<device-management-ip> interface pair-update --id pair1 --receive-interface GE0_1 --transmit-interface GE0_2 --status-sync
ptm-atomic run --base-url https://<device-management-ip> interface pair-delete --id pair1
```

系统时间查询只读，不提供修改系统时间的 op。`--expected-date`（`YYYY-MM-DD`）和 `--expected-time`（`HH:MM:SS`）用于精确断言，不匹配时只把 `matches_expected*` 置为 false，不修改设备时钟：

```bash
ptm-atomic run --base-url https://<device-management-ip> system time-verify
ptm-atomic run --base-url https://<device-management-ip> system time-verify --expected-date 2026-10-21 --expected-time 12:00:00
```

OSPFv2、OSPFv3 和 BFD runner 按 HTTP 方法拆分 op。GET 查询发送空请求体；POST 创建；PUT 更新；network DELETE 使用 `{"id": "<id>"}`；OSPFv2/OSPFv3 interface DELETE 使用 `?id=<interface>`。所有真实请求都需要已有登录 session 和 `--execute`。

启停 OSPFv2 全局配置 dry-run：

```bash
ptm-atomic run fw_config_ospfv2_global \
  --base-url https://<device-management-ip> \
  --enable \
  --router-id <DUT_IP> \
  --originate \
  --always
```

配置路由引入：

```bash
ptm-atomic run fw_config_ospfv2_redistribution \
  --base-url https://<device-management-ip> \
  --redistribute connected=333 \
  --redistribute static=666 \
  --redistribute rip=333
```

新增、更新、删除 OSPFv2 network：

```bash
ptm-atomic run fw_config_ospfv2_network \
  --base-url https://<device-management-ip> \
  --network 191.0.0.0/24 \
  --area 0

ptm-atomic run fw_config_ospfv2_network_update \
  --base-url https://<device-management-ip> \
  --id <ospfv2-network-id> \
  --network 191.0.0.0/24 \
  --area 0

ptm-atomic run fw_delete_ospfv2_network \
  --base-url https://<device-management-ip> \
  --id <ospfv2-network-id>
```

新增 OSPFv2 interface：

```bash
ptm-atomic run fw_config_ospfv2_interface \
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

更新和删除 OSPFv2 interface 使用 `fw_config_ospfv2_interface_update` 和 `fw_delete_ospfv2_interface`，并且必须传 `--id`。邻居和日志查询支持分页：

```bash
ptm-atomic run fw_verify_ospfv2_neighbor --base-url https://<device-management-ip> --page 1 --size 40
ptm-atomic run fw_capture_ospfv2_log --base-url https://<device-management-ip> --page 1 --size 40
```

OSPFv3 使用 `ospf6*` API 路径：

```bash
ptm-atomic run fw_config_ospfv3_global \
  --base-url https://<device-management-ip> \
  --enable \
  --router-id <DUT_IP>

ptm-atomic run fw_config_ospfv3_redistribution \
  --base-url https://<device-management-ip> \
  --redistribute connected=333 \
  --redistribute static=333

ptm-atomic run fw_config_ospfv3_network \
  --base-url https://<device-management-ip> \
  --interface bvi109 \
  --area 0

ptm-atomic run fw_config_ospfv3_interface \
  --base-url https://<device-management-ip> \
  --interface bvi109 \
  --cost 1 \
  --priority 1 \
  --hello-interval 10 \
  --retransmit-interval 5 \
  --dead-interval 40 \
  --transmit-delay 1 \
  --type-network 0
```

OSPFv3 network/interface 的 update 和 delete op 同样必须传 `--id`。OSPFv3 邻居和日志查询支持分页：

```bash
ptm-atomic run fw_verify_ospfv3_neighbor --base-url https://<device-management-ip> --page 1 --size 40
ptm-atomic run fw_capture_ospfv3_log --base-url https://<device-management-ip> --page 1 --size 40
```

BFD 全局启停、会话查询和日志查询：

```bash
ptm-atomic run fw_config_bfd_global \
  --base-url https://<device-management-ip> \
  --enable

ptm-atomic run fw_verify_bfd_global --base-url https://<device-management-ip>
ptm-atomic run fw_verify_bfd_session --base-url https://<device-management-ip> --page 1 --size 40
ptm-atomic run fw_capture_bfd_log --base-url https://<device-management-ip> --page 1 --size 40
```

## 6. Package 过滤

package 是一组 `op_id` 的过滤视图。它不复制 atom 文件，不代表可执行计划，也不会触发设备动作。

查看 package：

```bash
ptm-atomic packages
ptm-atomic packages --format json
```

当前 package：

| Package | 用途 | op_id 数 |
|---|---|---:|
| `networking` | 网络连通性与防火墙策略验证示例 | 1 |
| `security` | 安全策略与访问控制验证示例 | 1 |
| `ngfw_installation` | NGFW 安装、初始化、登录和健康检查合同 | 5 |
| `ngfw_capacity_config` | 容量域、OSPFv2、OSPFv3 和 BFD 的单设备配置合同 | 33 |
| `ngfw_verification` | 容量域、OSPFv2、OSPFv3 和 BFD 的只读验证合同 | 25 |
| `ngfw_batch_config` | 十个容量域的多设备批量配置合同 | 10 |

当前完整性事实：6 个 package manifest 合计 69 条 `operations`，对应 68 个唯一 `op_id`；所有 package `op_id` 都能解析到 `atoms/fw/*.yaml`。`fw_verify_acl_rule` 同时属于 `networking` 和 `security` 两个旧基线过滤视图。

代表性 op：

| Package | 示例 op_id |
|---|---|
| `ngfw_installation` | `fw_install_ngfw_image`、`fw_init_ngfw_minimal`、`fw_login_web_management`、`fw_check_login_state`、`fw_verify_ngfw_health` |
| `ngfw_capacity_config` | `fw_config_interface`、`fw_update_interface`、`fw_delete_interface`、`fw_config_policy_route`、`fw_config_ospfv2_global` |
| `ngfw_verification` | `fw_verify_interface`、`fw_verify_policy_route`、`fw_verify_ospfv2_neighbor`、`fw_verify_ospfv3_neighbor`、`fw_verify_bfd_session` |
| `ngfw_batch_config` | `fw_config_batch_interface`、`fw_config_batch_object`、`fw_config_batch_static_route`、`fw_config_batch_nat`、`fw_config_batch_dynamic_routing` |

校验 package 引用完整性：

```bash
ptm-atomic validate --package ngfw_installation
ptm-atomic validate --package networking
```

如果返回 `PACKAGE_NOT_FOUND`，先用 `ptm-atomic packages` 查看本地缓存中已有的名称。缓存必须同步到包含目标 package 的提交后，package 校验才会解析到最新清单。`validate --package` 是 synced-cache 引用 smoke test，不会检查当前未提交或未同步的本地 manifest 编辑；维护者要验证工作树时应使用仓库级 schema、layout、安全门禁和 package-reference invariant 检查。

## 7. Validate 测试用例

`validate` 只检查引用，不执行 atom。

```bash
ptm-atomic validate docs/test-case-template.yaml
ptm-atomic validate docs/test-case-template.yaml --format json
```

测试用例模式读取：

- `steps[].op_id`
- `tight_sequence.steps[].op_id`

常见结果字段：

| 字段 | 说明 |
|---|---|
| `status` | `passed` 或 `failed`。 |
| `mode` | `test_case` 或 `package`。 |
| `checked_count` | 已检查的引用数量。 |
| `missing_count` | 缺失引用数量。 |
| `findings` | YAML 解析、结构或字段问题。 |
| `cache` | 本地缓存摘要。 |

## 8. 测试用例模板

模板位于 `docs/test-case-template.yaml`。下面是模板摘录，展示 `validate` 会读取的 `steps[].op_id` 引用；完整模板以文件本身为准：

```yaml
test_case_id: tc_ngfw_read_only_reference_check
steps:
  - step: verify_ngfw_health_reference
    op_id: fw_verify_ngfw_health
    device: fw_lab_primary
  - step: verify_interface_reference
    op_id: fw_verify_interface
    device: fw_lab_primary
```

`device` 是消费方测试框架中的逻辑名称，不应写真实地址、账号、token、cookie 或设备口令。

## 9. Schema v1.1 使用边界

atom 顶层使用 `schema_version: "1.1"`。字段参考见 `docs/schema-field-reference.md`。

| 字段 | 用户侧含义 |
|---|---|
| `risk` | 操作风险和人工确认要求。 |
| `credential_ref` | 凭据引用名，不保存凭据值。 |
| `session_ref` | 会话状态引用，不保存 cookie 或会话密钥。 |
| `state_ref` | 状态引用，不嵌入生产数据。 |
| `gate` | 执行前置门禁说明。 |
| `verification` | 验证方式和期望结果。 |
| `batch` | 批量配置的并发、失败策略和设备结果摘要。 |

当前唯一允许在示例中出现的密码策略字面值是 `Ngfw@123`。它用于描述初始化口令复杂度要求，不是生产默认密码。

## 10. CLI 不做什么

除 `ptm-atomic run` 白名单 op 外，当前 CLI 不具备以下能力：

| 边界 | 说明 |
|---|---|
| 非白名单设备连接 | 不连接真实防火墙或管理面。 |
| 通用 atom 执行 | 不执行 `fw_install_ngfw_image` 等未接入 runner 的 atom。 |
| 通用配置下发 | 不推送白名单以外的配置，不修改白名单以外的设备状态。 |
| 凭据保存 | 不保存账号、密码、cookie、私钥；会话材料只写入用户指定 session 文件，且不允许写入仓库目录。 |
| 自动回滚 | 不在失败后自动回滚设备配置。 |
| `.input` 数据 | 不在运行时读取或发布 `.input` 目录数据；实现只迁移了公开 API 形态。 |

新增 runner 必须单独设计白名单入口、dry-run、凭据边界、审计输出和测试覆盖。

## 11. 常见故障

| 错误码 | 退出码 | 常见触发 | 处理 |
|---|---:|---|---|
| `GIT_AUTH_FAILED` | 21 | git 认证失败 | 配置 git 原生认证后重跑 `ptm-atomic sync`。 |
| `GIT_NETWORK_ERROR` | 22 | 网络、DNS、远端或 TLS 失败 | 网络恢复后重跑同步；已有完整缓存时可继续只读查询。 |
| `OP_NOT_FOUND` | 23 | `show` / `validate` 引用未知 `op_id`，或 `adapter` 查询的 atom 没有 adapter 引用 | 先同步，再检查拼写、候选建议和 `adapter_contract_ref`。 |
| `REPO_NOT_SYNCED` | 24 | 缓存缺失、损坏，或 adapter 引用的 profile 未同步 | 执行 `ptm-atomic sync --repo <ptm-atomic-git-repository-url>`。 |
| `PACKAGE_NOT_FOUND` | 25 | 引用未知 package | 运行 `ptm-atomic packages` 后选择已有名称。 |
| `RUNNER_UNSUPPORTED_OP` | 41 | `run` 请求未接入 runner 的 op | 使用 `adapter` 查询契约，或新增专用 runner。 |
| `RUNNER_CREDENTIAL_MISSING` | 43 | 登录执行缺少 `--password-env` 或环境变量为空 | 设置环境变量后重跑。 |
| `RUNNER_SESSION_INVALID` | 45 | session 文件不存在、权限过宽或格式无效 | 先执行登录，或修正 session 文件权限为 `0600`。 |
| `RUNNER_CONFIG_REJECTED` | 48 | 设备拒绝地址对象或策略路由配置 | 检查对象名、参数、会话和设备侧错误。 |

仓库脚本错误码见 `docs/error-codes.md`。

## 12. 发布前自检

```bash
uv run ptm-atomic --help
uv run ptm-atomic packages
uv run ptm-atomic adapter fw_config_policy_route
uv run --python 3.11 python scripts/validate_schema.py atoms
uv run --python 3.11 python scripts/layout_check.py
uv run --python 3.11 python scripts/security_gate_check.py
uv run --python 3.11 python scripts/check_aliases.py
uv run --python 3.11 python scripts/check_package_refs.py
```

这些命令不连接设备，不读取 `.input`，不保存凭据。
