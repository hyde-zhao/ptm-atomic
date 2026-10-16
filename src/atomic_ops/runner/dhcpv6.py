"""NGFW IPv6 DHCP (DHCPv6) runner for ``/api/v1/dhcpv6`` and ``/api/v1/dhcpstaticip``.

本模块覆盖两个资源：

- **DHCPv6 服务**（``/api/v1/dhcpv6``）—— 新建（POST）、编辑（PUT）、禁用（PUT，
  读改写）、删除（DELETE ``?id=<网卡名>``）、查询（GET）。条目身份就是 ``ifname``，
  与 v4 族同构。
- **DHCPv6 静态地址分配**（``/api/v1/dhcpstaticip``）—— **与 v4 族共用的单条删除
  端点**，见下方「共用端点」段。

字段真相全部来自 2026-10-16 在 <DUT_IP> 的实机探测（Q1~Q15 与后续补测），
规格文档 ``dhcp6API规范文档.txt`` 在其中数处与设备实际行为不符，逐条见下。

**错误信封是嵌套的（本仓首例）**
    ``/api/v1/dhcpv6`` 失败时答 ``{"error": {"code", "message", "target", "details",
    "innererror"}}`` —— 与本仓此前所有端点（``/dhcp``／``/ippool``／``/batch`` …）
    的**扁平** ``{"errCode", "errMsg", ...}`` 都不同。共享助手
    :mod:`atomic_ops.runner.errors` 只认扁平键，故本模块在进入任何判定之前先把嵌套
    信封摊平（:func:`_flatten_device_error`），否则会话失效识别与幂等归一都会
    静默落空。

**``lease`` 是崩溃护栏，本族沿用 v4 的判定（非 v6 本地实证）**
    规格把 ``val.server.lease`` 标为可选，与 v4 那句已被证伪的话一字不差；同一设备、
    同一族字段，故沿用 v4 的单变量隔离结论（缺 ``lease`` 崩溃，nginx 502、约 90 秒
    自愈、既有会话失效）而**不重复**那次破坏性实验（用户 2026-10-16 拍板）。本族另有
    **本地实证的第二条崩溃路径**：省略 ``server.subnet`` 同样 502（约 3 分钟不可用，
    会话未失效、无残留配置）。故 :func:`validate_dhcpv6_payload` 对**任何来源**（含
    ``--payload-json``）的最终载荷强制这两个键存在，缺则本地 fail-loud，请求根本不发出。

**``enable`` 有两层，且必须显式发出**
    ``val.enable`` 与 ``val.server.enable`` 都参与「是否服务」。实测：显式发
    ``val.enable: true`` 后做静态删除，两层 ``enable`` 都不再翻转；此前观察到的
    ``enable: false`` 是设备为**从未发出的键**物化出的默认值 —— 即 v4 族的载荷构造器
    漏发 ``val.enable`` 是**缺陷**（任何静态删除后回读变 ``false``），已在同批修复。
    本族一律显式发出两层 ``enable``。

**禁用 = 读改写（PUT 是全量替换）**
    实测：最小 body（只给 ``enable``）被拒（v6 ``eRequestParam``／
    ``eDhcpdNoPrefixOrNetworkWithDetail``「地址池缺失」，v4 ``eDhcpdConfigBuildFail``）；
    PUT 是**全量替换**而非字段合并。故 ``fw_disable_dhcpv6_server`` 实现为
    **读回现有条目 → 翻转两层 enable → 原样回写**（两族同构）。往返保真已实测
    （两族各自）：忽略 ``enable`` 前后逐键 diff 为空，且可逆（再启用同样干净）。

**共用端点 ``/api/v1/dhcpstaticip``（更正 v4 交付的过窄断言）**
    该端点接受**直接单条删除** ``DELETE ?id=<地址>``，且 v4/v6 共用：实测删
    ``8.1.1.20``（v4 绑定）与删 ``1111::100``（v6 绑定）走同一路径。v4 交付文档里
    「只能经批量删除」的断言（``adapters/ngfw/default.yaml`` 与
    ``docs/API-ADAPTER-SPEC.md``）**过窄**，本批一并更正；v4 的 batch op 保留不动。
    该端点**极端宽松**：重复删 200、删不存在的地址 200、**完全不带 id 也 200** ——
    设备级幂等，但也因此**永远无法报告是否真的删掉了什么**。故本族的静态删除只承诺
    「请求被接受」，不承诺「确有绑定被移除」，这一区分写进 atom 的 postconditions。
    地址里的 ``:`` 经 ``urlencode`` 编码为 ``%3A`` 后设备**能正确解码**（实测差分：
    编码形态精确删掉 ``1111::100`` 而未动 ``1111::101``），故 URL 不做特判。

**``fw_delete_dhcpv6_server`` 的「不存在」判据（op 专属）**
    实测五例对照：①重复删已删过的网卡 ②删从不存在的名字（NO_SUCH_INTF）③``id=`` 空串
    → 三者同为 400 ``eRequestParam``「http请求参数错误」；④**不带 id** →
    200 ``{"data":"success"}`` 但**条目原封不动**（本仓最危险的一类假成功：漏传 id 会
    拿到 success 而什么都没删）；⑤方法错误 → 405。故 :func:`_request_url` 对空 id
    **本地 fail-loud**（请求根本不发出，④这条路径从调用面消失），此后「非空 id +
    400 eRequestParam + 该文案」**唯一**对应「该网卡没有可删的 DHCPv6 配置」。该组合经
    ``errors.py#RESOURCE_NOT_FOUND_OP_CODE_MARKERS`` 登记为**仅本 op 生效**的判据 ——
    全局 marker 列表对 ``eRequestParam`` 太宽（真·畸形请求会被误判成「已达成」→ 漏报
    真残留），故作用域严格限定到本 op。

**查询无过滤能力**：沿用 v4 的七个候选参数判别法（``key``／``keywords``／``name``／
    ``ifname``／``page``／``size``／``search``），实测全部静默忽略，故本族 verify
    **不带任何查询参数** —— 不提供 ``--key``／``--page``／``--size``。

**读回键是 ``data`` 而非 ``vals``**：v4 的 ``/api/v1/dhcp`` 回 ``vals``，v6 的
    ``/api/v1/dhcpv6`` 回 ``data``，这是两族**唯一**的响应形状差异。

**静态绑定用 ``duid`` 而非 ``mac``**，且地址必须落在 ``server.subnet`` 内（实测
    ``eDhcpdConfigHostIpWithinSubnetWithDetail``「保留IPv6地址错误,未在子网范围内」）。

**``prefix`` 不得等于 ``subnet``**（实测 ``eDhcpdNetworkDuplicateWithDetail``「网络
    地址存在冲突」），但**可以**等于网卡自身的网络；``subnet`` 也**不必**落在网卡自身
    的子网内（实测 ``9999::/96`` 在 GE0_13 上被接受）—— 与 v4 的
    ``eDhcpdConfigIpPoolLimit`` 规则不同，故本族 preconditions 不写那条。
    ``prefix_len`` 必须落在 ``[prefix 前缀长度, +16]`` 内（实测
    ``eDhcpdPrefixRangeErrorWithDetail``）；沿用 v4 口径，格式与范围由 DUT 判定，
    runner 不做 CIDR 解析。

**可选键一律显式补齐**：``dns1``／``dns2``／``sip``／``sntp``／``domain`` 送空串被
    接受，且回读**十二个键全在**（实测）。显式补齐使回读形状可预期，避免「键缺失」与
    「键为空」在 post_verify 比较时产生歧义。

**本族不碰 ``runner/batch.py``**：静态删是单条 DELETE，无批量载荷，故无
    ``tests/test_batch.py`` 的 AST 扫描面，也无需 ``carrier=`` 覆盖。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.errors import (
    RunnerError,
    raise_if_device_session_rejected,
    raise_if_resource_not_found,
    resource_not_found_error,
)
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

DHCPV6_RESOURCE = "/api/v1/dhcpv6"
# 与 v4 族**共用**的单条删除端点（见模块 docstring「共用端点」段）。
DHCP_STATIC_IP_RESOURCE = "/api/v1/dhcpstaticip"

DHCPV6_ENDPOINTS = {
    "fw_config_dhcpv6_server": ("POST", DHCPV6_RESOURCE),
    "fw_update_dhcpv6_server": ("PUT", DHCPV6_RESOURCE),
    # 禁用走 PUT，但 body 在**执行期**由读回的现有条目生成（见
    # :func:`_execute_disable`），不在 CLI 侧构造。
    "fw_disable_dhcpv6_server": ("PUT", DHCPV6_RESOURCE),
    "fw_verify_dhcpv6_server": ("GET", DHCPV6_RESOURCE),
    "fw_delete_dhcpv6_server": ("DELETE", DHCPV6_RESOURCE),
    # 投影视图：同 URL，不同输出形状（见模块 docstring）。
    "fw_verify_dhcpv6_static_ip": ("GET", DHCPV6_RESOURCE),
    "fw_delete_dhcpv6_static_ip": ("DELETE", DHCP_STATIC_IP_RESOURCE),
}
GET_OPS = {"fw_verify_dhcpv6_server", "fw_verify_dhcpv6_static_ip"}
# 载荷即查询串、永不进 body 的 op。与 NO_BODY_OPS 恰好同集，但**语义不同**
# （前者管「URL 里拼 id」，后者管「不发 body」），故刻意不合并 —— 与 v4 族同款约定。
QUERY_ID_OPS = {"fw_delete_dhcpv6_server", "fw_delete_dhcpv6_static_ip"}
NO_BODY_OPS = GET_OPS | QUERY_ID_OPS
CONFIG_OPS = {"fw_config_dhcpv6_server", "fw_update_dhcpv6_server"}
# 读改写：先 GET 读回现有条目，再 PUT 原样回写（两层 enable 已翻转）。
READ_MODIFY_WRITE_OPS = {"fw_disable_dhcpv6_server"}
# 需要校验「最终载荷含 lease 与 server.subnet」的 op（双崩溃护栏）。
LEASE_GUARDED_OPS = CONFIG_OPS | READ_MODIFY_WRITE_OPS
# dry-run 里 ``request.payload`` 显示 ``null`` 的 op：GET／DELETE 本就不发 body，
# 禁用则在执行期才生成 body，三者都不该让审阅者看到一个「其实不发」的载荷。
PAYLOADLESS_DRY_RUN_OPS = NO_BODY_OPS | READ_MODIFY_WRITE_OPS

DEFAULT_IFMODE = "SERVER"
DEFAULT_LEASE_LIMITED = True
DEFAULT_LEASE_DEFAULT_SECONDS = 86400

# ``ifmode`` 只锁实测接受的 ``SERVER``：``CLIENT``／``RELAY``／``OFF``／乱串一律
# 400 ``eRequestParam``（2026-10-16 在 <DUT_IP> 逐一实测）。这是一个**只作用于
# flag 路径**的防笔误白名单（在 :func:`build_dhcpv6_server_val` 内）：走
# ``--payload-json`` 时不经此检查，值原样透传给设备判定。与作用于**所有**来源的
# ``lease``／``subnet`` 崩溃护栏是两种不同强度的手段，刻意不混为一谈。
IFMODES = ("SERVER",)


def build_dhcpv6_binding(*, name: str, addr: str, duid: str) -> dict[str, Any]:
    """构造一条静态绑定 ``{name, addr, duid}``（规格的 ``server.hosts[]``）。

    ``duid`` 取代 v4 的 ``mac``。``addr`` 就是静态删除时查询串 ``id`` 取的值
    （实测：删 ``1111::100`` 后该条从 ``server.hosts`` 消失）。
    """
    _validate_non_empty("binding_name", name)
    _validate_non_empty("binding_addr", addr)
    _validate_non_empty("binding_duid", duid)
    return {"name": name, "addr": addr, "duid": duid}


def build_dhcpv6_server_val(
    *,
    ifname: str,
    subnet: str,
    prefix: str,
    prefix_len: Any,
    ifmode: str = DEFAULT_IFMODE,
    enable: bool = True,
    server_name: str | None = None,
    lease_limited: bool = DEFAULT_LEASE_LIMITED,
    lease_default_seconds: int = DEFAULT_LEASE_DEFAULT_SECONDS,
    dns1: str = "",
    dns2: str = "",
    sip: str = "",
    sntp: str = "",
    domain: str = "",
    bindings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """构造 ``val``（规格 1.1 的结构）。

    与 v4 的**结构差异**：子网是**单个字符串** ``server.subnet``（v4 是 ``subnets``
    数组，每条带 ``range`` 与 ``gateway``，v6 两者皆无）；另有 ``prefix`` 与
    ``prefix_len`` 两个必填字段。

    ``server_name`` 缺省取 ``ifname`` —— 实测 ``server.name`` 必填（省略答 400
    ``eRequestParam``），而规格示例里两者本就一致，故不做成必填 flag。
    """
    _validate_non_empty("ifname", ifname)
    _validate_non_empty("subnet", subnet)
    _validate_non_empty("prefix", prefix)
    _validate_choice("ifmode", ifmode, IFMODES)
    _validate_prefix_len(prefix_len)
    _validate_lease(lease_limited, lease_default_seconds)
    rows = _validate_bindings(bindings)
    return {
        "ifname": ifname,
        "ifmode": ifmode,
        # 顶层 enable 必须显式发出：省略会让设备物化出 false，且任何静态删除后
        # 回读翻转（见模块 docstring）。v4 族同款缺陷已在同批修复。
        "enable": bool(enable),
        "server": {
            "enable": bool(enable),
            "name": server_name if server_name is not None else ifname,
            "subnet": subnet,
            "prefix": prefix,
            "prefix_len": int(prefix_len),
            # 双崩溃护栏之一：此键永不省略（见模块 docstring）。
            "lease": {
                "limited": bool(lease_limited),
                "default_seconds": int(lease_default_seconds),
            },
            "dns1": "" if dns1 is None else str(dns1),
            "dns2": "" if dns2 is None else str(dns2),
            "hosts": rows,
            "sip": "" if sip is None else str(sip),
            "sntp": "" if sntp is None else str(sntp),
            "domain": "" if domain is None else str(domain),
        },
    }


def build_dhcpv6_payload(**kwargs: Any) -> dict[str, Any]:
    """构造新建载荷 ``{"val": {...}}``（规格 1.1）。"""
    return {"val": build_dhcpv6_server_val(**kwargs)}


def build_dhcpv6_update_payload(*, entry_id: str, **kwargs: Any) -> dict[str, Any]:
    """构造编辑载荷 ``{"id": <网卡名>, "val": {...}}``。

    ``entry_id`` 是目标网卡名，不是数字 id —— 与 v4 族同构。
    """
    _validate_non_empty("id", entry_id)
    return {"id": entry_id, "val": build_dhcpv6_server_val(**kwargs)}


def build_dhcpv6_delete_query(*, entry_id: str) -> dict[str, str]:
    """构造删除的**查询串**载荷 ``{"id": <网卡名或地址>}``。

    返回值只用于拼 URL，**永不进 body**。与 v4 族同款有意分歧：``payload`` 全程为
    ``None``，dry-run 的 ``request.payload`` 自然显示 ``null``，不会出现「有个
    payload 但其实不发」的错觉。
    """
    _validate_non_empty("id", entry_id)
    return {"id": entry_id}


def build_disabled_dhcpv6_val(entry: dict[str, Any]) -> dict[str, Any]:
    """把读回的现有条目改造成「两层 ``enable`` 均为 false」的 ``val``。

    只动 ``enable`` 两个键，**其余逐键原样保留** —— 实测 PUT 是全量替换，故任何省略
    都会丢配置（最小 body 被设备直接拒绝）。读回的 ``prefix`` 已被设备归一化
    （``8888::1111/96`` → ``8888::/96``），回写归一化后的值同样被接受，往返无漂移。
    """
    val = dict(entry)
    val["enable"] = False
    server = val.get("server")
    if isinstance(server, dict):
        val["server"] = {**server, "enable": False}
    return val


def flatten_dhcpv6_static_bindings(entries: Any) -> list[dict[str, str]]:
    """把 ``GET /api/v1/dhcpv6`` 的原始 ``data`` 展平成静态绑定行。

    每个条目 ``server.hosts`` 里的每条绑定展开为 ``{ifname, name, addr, duid}``
    （``ifname`` 来自宿主条目，用于区分不同网卡上的同名绑定）。这是
    ``fw_verify_dhcpv6_static_ip`` 的输出形状，也是
    ``fw_delete_dhcpv6_static_ip`` 唯一能观察前后状态的视角 —— 删除端点自身恒答
    200，无从判断是否真的删掉了什么。
    """
    rows: list[dict[str, str]] = []
    if not isinstance(entries, list):
        return rows
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ifname = str(entry.get("ifname") or "")
        server = entry.get("server")
        hosts = server.get("hosts") if isinstance(server, dict) else None
        if not isinstance(hosts, list):
            continue
        for host in hosts:
            if not isinstance(host, dict):
                continue
            rows.append(
                {
                    "ifname": ifname,
                    "name": str(host.get("name") or ""),
                    "addr": str(host.get("addr") or ""),
                    "duid": str(host.get("duid") or ""),
                }
            )
    return rows


def validate_dhcpv6_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    """对**最终载荷**做 op 相关校验（含 ``--payload-json`` 来源）。

    对配置与编辑（以及读改写的回写）强制 ``val.server.lease`` 与
    ``val.server.subnet`` 存在 —— 这是**两条崩溃护栏**的最后一道闸：载荷可能来自扁平
    flag，也可能来自 ``--payload-json`` 逃生舱，两条路径都必须过这里。
    """
    if op_id in LEASE_GUARDED_OPS:
        _validate_crash_guards(payload)
    return payload


def build_dhcpv6_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    entry_id: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    """构造 dry-run 信封。

    ``fw_verify_dhcpv6_static_ip`` 额外声明其投影关系；``fw_disable_dhcpv6_server``
    声明读改写两步（两个请求都不发出，第二步的 body 要执行期才由读回结果生成）。
    """
    method, _path = _method_path(op_id)
    result: dict[str, Any] = {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": _request_url(base_url, op_id, entry_id=entry_id),
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None if op_id in PAYLOADLESS_DRY_RUN_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }
    if op_id == "fw_verify_dhcpv6_static_ip":
        result["projection"] = {
            "source_op": "fw_verify_dhcpv6_server",
            "note": (
                "The device exposes no GET on /api/v1/dhcpstaticip; static bindings are a "
                "projection of each DHCPv6 entry's server.hosts and have no separate storage. "
                "This op reads /api/v1/dhcpv6 and emits only the flattened "
                "ifname/name/addr/duid rows."
            ),
        }
    if op_id in READ_MODIFY_WRITE_OPS:
        result["disable_steps"] = [
            {
                "method": "GET",
                "path": DHCPV6_RESOURCE,
                "note": f"read the live entry whose ifname is {entry_id or '<id>'}",
            },
            {
                "method": "PUT",
                "path": DHCPV6_RESOURCE,
                "note": (
                    "replay that entry verbatim as val with enable=false at both the val "
                    "and server levels; PUT replaces the whole configuration, so no field "
                    "may be restated or omitted by the caller"
                ),
            },
        ]
    return result


def execute_dhcpv6(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    entry_id: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    headers = _session_headers(session_file, base_url, auth_header)
    if op_id in READ_MODIFY_WRITE_OPS:
        return _execute_disable(
            op_id=op_id,
            base_url=base_url,
            headers=headers,
            auth_header=auth_header,
            entry_id=entry_id,
            verify_tls=verify_tls,
            timeout=timeout,
        )
    method, path = _method_path(op_id)
    status_code, response_payload, _text = request_json(
        method,
        _request_url(base_url, op_id, entry_id=entry_id),
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in (GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS):
        _raise_request_failure(op_id, method, status_code, response_payload)
    result: dict[str, Any] = {
        "op_id": op_id,
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": method,
            "path": path,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
    }
    if op_id == "fw_verify_dhcpv6_static_ip":
        # 投影：把原始 DHCPv6 条目换成展平的绑定行，原始响应仍保留在 response 里。
        result["bindings"] = flatten_dhcpv6_static_bindings(response_payload.get("data"))
        result["binding_count"] = len(result["bindings"])
    return result


def _execute_disable(
    *,
    op_id: str,
    base_url: str,
    headers: dict[str, str],
    auth_header: str,
    entry_id: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    """读改写：GET 读回条目 → 翻转两层 enable → PUT 原样回写（见模块 docstring）。

    条目不存在时按「目标状态已达成」处理（该网卡本就没有在服务的 DHCPv6 配置），
    经 :func:`resource_not_found_error` 抛带幂等键的结构化错误 —— 注意此处**没有**
    设备错误可引用（读回是成功的空列表），故 ``err_code``／``err_msg`` 为 ``None``，
    判据来源写进 ``extra_details``。
    """
    _validate_non_empty("id", entry_id)
    get_status, get_payload, _text = request_json(
        "GET",
        _request_url(base_url, "fw_verify_dhcpv6_server", entry_id=""),
        headers=headers,
        json_payload=None,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if get_status not in GET_SUCCESS_STATUS:
        _raise_request_failure("fw_verify_dhcpv6_server", "GET", get_status, get_payload)
    entry = _find_entry(get_payload.get("data"), entry_id)
    if entry is None:
        raise resource_not_found_error(
            get_status,
            get_payload,
            op_id=op_id,
            extra_details={
                "id": entry_id,
                "judgement": (
                    "no DHCPv6 entry is bound to this interface name, so it is not serving; "
                    "the goal state of a disable is already reached"
                ),
            },
        )
    val = build_disabled_dhcpv6_val(entry)
    # 回写的 body 也过崩溃护栏：读回若缺 lease/subnet，本地 fail-loud 而不是把
    # 设备打挂（读回正常时此检查恒过）。
    validate_dhcpv6_payload({"val": val}, op_id="fw_update_dhcpv6_server")
    if val.get("ifname") and str(val["ifname"]) != entry_id:
        # 条目身份就是 ifname，回写时以调用方给的 id 为准会把配置挪到别的网卡上。
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "The live entry's ifname does not match the requested id.",
            {"field": "id", "requested": entry_id, "live_ifname": val.get("ifname")},
        )
    put_status, put_payload, _text = request_json(
        "PUT",
        _request_url(base_url, op_id, entry_id=""),
        headers=headers,
        json_payload={"id": entry_id, "val": val},
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if put_status not in SUCCESS_STATUS:
        _raise_request_failure(op_id, "PUT", put_status, put_payload)
    return {
        "op_id": op_id,
        "status": "success",
        "status_code": put_status,
        "request": {
            "method": "PUT",
            "path": DHCPV6_RESOURCE,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "disable_steps": [
            {"step": "read", "method": "GET", "status_code": get_status, "count": _count_of(get_payload)},
            {"step": "write", "method": "PUT", "status_code": put_status},
        ],
        "readback": entry,
        "response": put_payload,
    }


def _request_url(base_url: str, op_id: str, *, entry_id: str) -> str:
    """按 **op_id** 分派 URL，绝不按 method 或族（``ipsec.py`` 的同款显式约定）。

    只有两个删除 op 往 URL 里拼查询串，且**不带任何其它查询参数** —— 实测设备对该
    端点族的七种过滤／分页参数一律静默忽略。空 id 在此 fail-loud：实测「不带 id」
    的删除答 200 却什么都不删，是最危险的一类假成功，必须在调用面就消灭。
    """
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in QUERY_ID_OPS:
        _validate_non_empty("id", entry_id)
        # IPv6 地址里的 ':' 会编码成 %3A；实测设备能正确解码，故不做特判。
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return DHCPV6_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this DHCPv6 operation.",
            {"op_id": op_id},
        ) from exc


def _session_headers(session_file: Path, base_url: str, auth_header: str) -> dict[str, str]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    return {"Content-Type": "application/json", auth_header: header_value}


def _raise_request_failure(
    op_id: str, method: str, status_code: int, response_payload: Any
) -> None:
    """统一的失败分支：先摊平嵌套信封，再做会话失效与幂等归一判定。

    摊平是**前提**：本族设备答 ``{"error": {...}}``，共享助手只认扁平键，不摊平则
    两个判定都会静默落空（见模块 docstring）。
    """
    flat = _flatten_device_error(response_payload)
    raise_if_device_session_rejected(status_code, flat)
    # 目标资源不存在 == 目标状态已达成（幂等删除契约，权威门见 errors.py 登记表）
    raise_if_resource_not_found(status_code, flat, op_id=op_id)
    raise RunnerError(
        "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
        "DHCPv6 device request did not return a success status.",
        {
            "op_id": op_id,
            "status_code": status_code,
            "err_code": flat.get("errCode") if isinstance(flat, dict) else None,
            "err_msg": (flat.get("errMsg") or flat.get("message")) if isinstance(flat, dict) else None,
            "response_keys": sorted(response_payload.keys()) if isinstance(response_payload, dict) else [],
            # 原始嵌套信封原样保留，便于诊断（幂等判定只认摊平后的键）。
            "device_error": response_payload.get("error") if isinstance(response_payload, dict) else None,
        },
    )


def _flatten_device_error(response_payload: Any) -> Any:
    """把 DHCPv6 的嵌套错误信封摊平成共享助手认识的扁平键（见模块 docstring）。

    只做**加法**：非字典或没有 ``error`` 对象时原样返回；已有 ``errCode``／``errMsg``
    时不覆盖。返回浅拷贝，原始载荷不被修改，以便调用方保留原文诊断。
    """
    if not isinstance(response_payload, dict):
        return response_payload
    error = response_payload.get("error")
    if not isinstance(error, dict):
        return response_payload
    flat = dict(response_payload)
    code = error.get("code")
    message = error.get("message")
    if isinstance(code, str):
        flat.setdefault("errCode", code)
    if isinstance(message, str):
        flat.setdefault("errMsg", message)
    return flat


def _find_entry(entries: Any, entry_id: str) -> dict[str, Any] | None:
    """按 ``ifname`` 定位单个条目（条目身份就是网卡名，没有单独的数字 id）。"""
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if isinstance(entry, dict) and str(entry.get("ifname") or "") == entry_id:
            return entry
    return None


def _count_of(payload: Any) -> int:
    entries = payload.get("data") if isinstance(payload, dict) else None
    return len(entries) if isinstance(entries, list) else 0


def _validate_crash_guards(payload: dict[str, Any]) -> None:
    """双崩溃护栏：最终载荷必须带 ``server.lease`` 与 ``server.subnet``。

    两条都是**本地实证**会让设备管理服务崩溃（nginx 502）的省略：``lease`` 沿用 v4
    的单变量隔离结论，``subnet`` 是本族本地实测（约 3 分钟不可用）。只检查「键存在且
    是对象／非空字符串」—— 取值本身由设备判定，设备崩的是**缺键**，不是取值。
    """
    val = payload.get("val")
    server = val.get("server") if isinstance(val, dict) else None
    if not isinstance(server, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            (
                "val.server is required and must be an object: a POST or PUT to "
                "/api/v1/dhcpv6 without it cannot carry subnet or lease, whose omission "
                "crashes the device's management service (nginx 502)."
            ),
            {"field": "val.server", "crash_guard": True},
        )
    if not isinstance(server.get("lease"), dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            (
                "val.server.lease is required and must be an object: the device's management "
                "service crashes (nginx 502, ~90s outage) when a POST or PUT omits it. The "
                "interface specification marks it optional, but live isolation on the IPv4 "
                "sibling family proved the omission is what crashes the device."
            ),
            {"field": "val.server.lease", "crash_guard": True},
        )
    if not str(server.get("subnet") or "").strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            (
                "val.server.subnet is required and must be non-empty: live probing on "
                "2026-10-16 proved that omitting it crashes the device's management service "
                "(nginx 502, roughly 3 minutes of outage)."
            ),
            {"field": "val.server.subnet", "crash_guard": True},
        )


def _validate_prefix_len(prefix_len: Any) -> None:
    """``prefix_len`` 必须是正整数。

    不做「落在 [prefix 前缀长度, +16] 内」的本地判定 —— 那是设备规则（实测答
    ``eDhcpdPrefixRangeErrorWithDetail``），沿用 v4 口径由 DUT 回答，本地不复制一份
    可能与设备不一致的 CIDR 解析。
    """
    if isinstance(prefix_len, bool) or not isinstance(prefix_len, int):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "server.prefix_len must be an integer.",
            {"field": "prefix_len", "value": prefix_len},
        )
    if prefix_len < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "server.prefix_len must not be negative.",
            {"field": "prefix_len", "value": prefix_len},
        )


def _validate_lease(lease_limited: Any, lease_default_seconds: Any) -> None:
    if not isinstance(lease_limited, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "lease limited must be a boolean.",
            {"field": "lease_limited", "value": lease_limited},
        )
    try:
        parsed = int(lease_default_seconds)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "lease default_seconds must be an integer.",
            {"field": "lease_default_seconds", "value": lease_default_seconds},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "lease default_seconds must not be negative.",
            {"field": "lease_default_seconds", "value": lease_default_seconds},
        )


def _validate_bindings(bindings: Any) -> list[dict[str, Any]]:
    """``bindings=None`` 与 ``[]`` 同义（都产出 ``hosts: []``）。"""
    if bindings is None:
        return []
    if not isinstance(bindings, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "hosts bindings must be a list.",
            {"field": "hosts"},
        )
    rows: list[dict[str, Any]] = []
    for item in bindings:
        if not isinstance(item, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each hosts binding must be an object with name, addr and duid.",
                {"field": "hosts"},
            )
        for key in ("name", "addr", "duid"):
            _validate_non_empty(f"binding_{key}", item.get(key))
        rows.append({"name": item["name"], "addr": item["addr"], "duid": item["duid"]})
    return rows


def _validate_choice(field: str, value: str, allowed: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"DHCPv6 {field} must be one of: {', '.join(allowed)}.",
            {"field": field, "value": value, "allowed": list(allowed)},
        )
    return value


def _validate_non_empty(field: str, value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "DHCPv6 field is required and must be non-empty.",
            {"field": field},
        )
