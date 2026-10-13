"""NGFW IPv4 DHCP runner for ``/api/v1/dhcp`` and ``/api/v1/dhcpstaticip``.

本模块覆盖两个资源：

- **IPv4 DHCP 服务**（``/api/v1/dhcp``）—— 新建（POST）、编辑（PUT）、删除
  （DELETE ``?id=<网卡名>``）、查询（GET）。条目身份就是 ``ifname``：设备回读的
  ``val`` 与写入的 body **逐字节一致**，没有单独的 id 字段，也没有额外的包装层。
- **IPv4 静态地址分配**（``/api/v1/dhcpstaticip``）—— **纯删除资源**，只能经
  ``POST /api/v1/batchv2`` 操作。

字段真相全部来自 2026-10-13 在 <DUT_IP> 的实机探测（P1~P8），规格文档
``dhcp,API规范文档.txt`` 在其中数处与设备实际行为不符，逐条见下。

**``lease`` 是崩溃护栏，不是普通默认值（本模块最重要的约束）**
    规格 1.1 把 ``val.server.lease`` 标为「否（可选）」，实机却是**必填**：
    POST 或 PUT 的 body 缺少 ``lease`` 会让设备的管理服务进程崩溃（nginx 返回
    502 Bad Gateway），约 90 秒后自愈、并使既有会话失效（重登后恢复）。
    单变量隔离实验已坐实因果：对照组（带 lease）200 success，实验组（唯一差异
    是不带 lease）502。故本模块不把它当作「缺省填一个值」，而是作为**最终载荷的
    不变量**校验 —— 由 :func:`validate_dhcp_payload` 对**包括 ``--payload-json``
    在内的**任何来源的载荷强制，缺则本地 fail-loud，请求根本不发出。
    同类省略的对照结果：``ifmode``／``server.name``／``server.subnets`` 省略均被
    设备的 schema 校验干净拒绝（400 ``eRequestParam``，带「is required」文案），
    只有 ``lease`` 走的是「通过校验后在业务代码里崩」的路径。

**其余可选字段（实测可省，省略则回读里该键缺失）**：``server.enable`` 省略也
    照样 200（规格标它必填，实际可省）；``dns1``／``dns2``／``hosts`` 省略或留空
    串均接受。本模块一律**显式补齐**这些键（``hosts: []``、``dns1: ""``），使回读
    形状可预期，避免「键缺失」与「键为空」在 post_verify 比较时产生歧义。

**静态绑定没有独立存储**：删掉 DHCP 服务即级联清空其 ``server.hosts``，同网卡
    重建后 ``hosts`` 为空 —— 所以 ``/api/v1/dhcpstaticip`` 只是 ``server.hosts[]``
    的一个**投影**，批量删除的 ``body.id`` 取的就是 ``hosts[].addr``。

**``/api/v1/dhcpstaticip`` 没有 GET**（GET 与 POST 均答 405 MethodNotAllowd，
    设备前端 bundle 里该路径只作为 ``staticdel`` 出现）。因此
    :func:`fw_verify_dhcp_static_ip` 不可能是「访问该资源自己的端点」，本模块把它
    实现为**对 ``GET /api/v1/dhcp`` 的客户端投影**：同样的 URL，但只输出展平后的
    绑定行 ``[{ifname, name, addr, mac}]``。这与本仓「URL 按 op_id 分派、不按族」
    的既有约定一致，也是批量删除唯一能观察前后状态的视角。

**查询无过滤能力**：``key``／``keywords``／``name``／``ifname``／``page``／
    ``size``／``search`` 七个候选参数实测**全部被静默忽略**（count 恒为全量），
    故本族 verify **不带任何查询参数** —— 不提供 ``--key``／``--page``／``--size``，
    不引入 ``SEARCH_QUERY_KEY`` 常量（对比 keyword/crl 两族各持一个）。

**批量删除必须一条 id 一个 item**（``carrier="per_id_item"``，见
    :func:`build_dhcp_static_ip_batch_delete_payload`）：2026-10-13 在
    <DUT_IP> 实测，``body.id`` 给两个地址时设备**只删第一个**，响应也**只回
    一条**，第二个被静默丢弃且无任何报错 —— 是本族唯一的「静默部分成功」面。
    共享构建器的默认形态 ``single_item`` 在本设备上是错的。

**批量删除响应形状**：``{"BatchResult": [{"id": ..., "data": "success"}]}``。
    ``data`` 不是 ``runner/batch.py#_item_text`` 认识的四个键
    （``status``／``msg``／``message``／``errMsg``）之一，接线 ``summarize_batch_result``
    会得到「每条都不可判定 ⇒ 整批降级 ⇒ success_count/failed_count 恒为 None」的
    永不采信结果，故本族**不接线**（与 keyword/crl 两族一致）。

**静态绑定的地址必须落在子网的 ``range`` 池内**，只同网段不够：设备回
    ``eDhcpdConfigHostIpInNet``「DHCP服务器保留IP应在地址池范围内」（实测
    2026-10-13）。这是设备侧规则，runner 不做 CIDR 解析、由 DUT 校验。

**批量删除必须经** :func:`atomic_ops.runner.batch.build_batch_delete_payload`
    构造载荷：``tests/test_batch.py`` 以 ``ast.walk`` 扫描 ``runner/*.py``，任何字面
    ``{"id": [...]}`` 形态都会被记为命中，模块名不在 ``UNINCLUDED_FAMILIES`` 即失败。
"""

from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import urlencode

from atomic_ops.runner.batch import build_batch_delete_payload
from atomic_ops.runner.errors import (
    RunnerError,
    raise_if_device_session_rejected,
    raise_if_resource_not_found,
)
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

DHCP_RESOURCE = "/api/v1/dhcp"
DHCP_STATIC_IP_RESOURCE = "/api/v1/dhcpstaticip"
# 本仓首个非 ``/api/v1/batch`` 的批量端点。族内持有，**绝不下沉到 batch.py**
# （那是 ADR-REM-06 的禁改区，且其 resource 本就是入参，无需知道路径）。
BATCH_V2_PATH = "/api/v1/batchv2"

DHCP_ENDPOINTS = {
    "fw_config_dhcp_server": ("POST", DHCP_RESOURCE),
    "fw_update_dhcp_server": ("PUT", DHCP_RESOURCE),
    "fw_verify_dhcp_server": ("GET", DHCP_RESOURCE),
    "fw_delete_dhcp_server": ("DELETE", DHCP_RESOURCE),
    # 投影视图：同 URL，不同输出形状（见模块 docstring）。
    "fw_verify_dhcp_static_ip": ("GET", DHCP_RESOURCE),
    "fw_delete_batch_dhcp_static_ip": ("POST", BATCH_V2_PATH),
}
GET_OPS = {"fw_verify_dhcp_server", "fw_verify_dhcp_static_ip"}
# 载荷即查询串、永不进 body 的 op。与 NO_BODY_OPS 恰好同集，但**语义不同**
# （前者管「URL 里拼 id」，后者管「不发 body」），故刻意不合并 —— 将来新增
# 「不发 body 但也不拼 id」或「拼 id 但发 body」的 op 时二者会分叉。
QUERY_ID_OPS = {"fw_delete_dhcp_server"}
NO_BODY_OPS = GET_OPS | QUERY_ID_OPS
BATCH_OPS = {"fw_delete_batch_dhcp_static_ip"}
CONFIG_OPS = {"fw_config_dhcp_server", "fw_update_dhcp_server"}
# 需要校验「最终载荷含 lease」的 op（崩溃护栏）。
LEASE_GUARDED_OPS = CONFIG_OPS

DEFAULT_IFMODE = "SERVER"
DEFAULT_LEASE_LIMITED = True
DEFAULT_LEASE_DEFAULT_SECONDS = 86400

# ``ifmode`` 只锁规格明确写出的 ``SERVER``（「接口模式，DHCP 服务端通常填 SERVER」）。
# 探测只拿到「缺省 → 400 ifmode is required」，未逐一枚举设备接受的其它模式串，
# 故这是一个**只作用于 flag 路径**的防笔误白名单（在 build_dhcp_server_val 内）：
# 走 ``--payload-json`` 时不经此检查，值原样透传给设备判定。与下面作用于**所有**
# 来源的 ``lease`` 崩溃护栏是两种不同强度的手段，刻意不混为一谈。
IFMODES = ("SERVER",)


def build_dhcp_subnet(
    *,
    subnet: str,
    range_start: str,
    range_end: str,
    gateway: str,
) -> dict[str, Any]:
    """构造一个子网条目 ``{subnet, range: [{start, end}], gateway}``（规格 1.1）。

    四个字段只做非空校验，**不做 CIDR／IP 格式校验** —— 与
    ``runner/interface.py`` 对接口 id 的处理同口径：格式合法性由 DUT 回答，
    本地不复制一份可能与设备不一致的规则。实测设备对池与网卡不同网段会答
    ``eDhcpdConfigIpPoolLimit``（网卡无 IPv4 地址时同样如此），该判断留给设备。
    """
    _validate_non_empty("subnet", subnet)
    _validate_non_empty("range_start", range_start)
    _validate_non_empty("range_end", range_end)
    _validate_non_empty("gateway", gateway)
    return {
        "subnet": subnet,
        "range": [{"start": range_start, "end": range_end}],
        "gateway": gateway,
    }


def build_dhcp_binding(*, name: str, addr: str, mac: str) -> dict[str, Any]:
    """构造一条静态绑定 ``{name, addr, mac}``（规格 1.1 的 ``server.hosts[]``）。

    ``addr`` 就是批量删除时 ``body.id`` 取的值（实测：删 ``8.1.1.2`` 后该条
    从 ``server.hosts`` 消失）。
    """
    _validate_non_empty("binding_name", name)
    _validate_non_empty("binding_addr", addr)
    _validate_non_empty("binding_mac", mac)
    return {"name": name, "addr": addr, "mac": mac}


def build_dhcp_server_val(
    *,
    ifname: str,
    subnets: list[dict[str, Any]],
    ifmode: str = DEFAULT_IFMODE,
    enable: bool = True,
    server_name: str | None = None,
    lease_limited: bool = DEFAULT_LEASE_LIMITED,
    lease_default_seconds: int = DEFAULT_LEASE_DEFAULT_SECONDS,
    dns1: str = "",
    dns2: str = "",
    bindings: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """构造 ``val``（规格 1.1／1.2 的结构）。

    ``server_name`` 缺省取 ``ifname`` —— 设备要求 ``server.name`` 必填
    （省略答 400 ``eRequestParam``「server: name is required」），而规格示例里
    两者本就一致，故不做成必填 flag。
    """
    _validate_non_empty("ifname", ifname)
    _validate_choice("ifmode", ifmode, IFMODES)
    _validate_subnets(subnets)
    _validate_lease(lease_limited, lease_default_seconds)
    rows = _validate_bindings(bindings)
    return {
        "ifname": ifname,
        "ifmode": ifmode,
        "server": {
            "enable": bool(enable),
            "name": server_name if server_name is not None else ifname,
            "subnets": subnets,
            # 崩溃护栏的实际承载点：此键永不省略（见模块 docstring）。
            "lease": {
                "limited": bool(lease_limited),
                "default_seconds": int(lease_default_seconds),
            },
            "dns1": "" if dns1 is None else str(dns1),
            "dns2": "" if dns2 is None else str(dns2),
            "hosts": rows,
        },
    }


def build_dhcp_payload(**kwargs: Any) -> dict[str, Any]:
    """构造新建载荷 ``{"val": {...}}``（规格 1.1）。"""
    return {"val": build_dhcp_server_val(**kwargs)}


def build_dhcp_update_payload(*, entry_id: str, **kwargs: Any) -> dict[str, Any]:
    """构造编辑载荷 ``{"id": <网卡名>, "val": {...}}``（规格 1.2）。

    ``entry_id`` 是目标网卡名（规格原文「要修改的目标网卡名称或唯一标识」），
    不是数字 id —— 与 keyword 族同构。
    """
    _validate_non_empty("id", entry_id)
    return {"id": entry_id, "val": build_dhcp_server_val(**kwargs)}


def build_dhcp_delete_query(*, entry_id: str) -> dict[str, str]:
    """构造删除的**查询串**载荷 ``{"id": <网卡名>}``（规格 1.3）。

    返回值只用于拼 URL，**永不进 body**（DELETE 请求的 body 为空）。与
    ``runner/interface.py`` 把 id 藏在 ``payload`` 里再从 payload 取的做法有意
    不同：这里 ``payload`` 全程为 ``None``，dry-run 的 ``request.payload`` 自然
    显示 ``null``，不会出现「有个 payload 但其实不发」的错觉。
    """
    _validate_non_empty("id", entry_id)
    return {"id": entry_id}


def build_dhcp_static_ip_batch_delete_payload(*, entry_ids: list[str]) -> dict[str, Any]:
    """构造静态地址批量删除载荷（规格 2.1，resource = ``/api/v1/dhcpstaticip``）。

    ``entry_ids`` 是 ``hosts[].addr``（IP 字符串），不是 name。端点走
    ``/api/v1/batchv2``（见 :data:`BATCH_V2_PATH`）。

    承载形态**必须**是 ``per_id_item``（每条 id 一个 batch item），不能沿用共享
    构建器默认的 ``single_item``。2026-10-13 在 <DUT_IP> 实测：``body.id``
    给 ``["8.1.1.101", "8.1.1.102"]`` 时**只删掉了第一个**，响应 ``BatchResult``
    也**只回一条**，第二个 id 被静默丢弃 —— 没有报错，调用方会以为两条都删了。
    这是本族唯一会「静默部分成功」的地方，故在此显式覆盖 carrier 而不是靠默认值。
    规格 2.1 的示例 body 恰好就是单元素 ``id``，与该行为一致。
    """
    return build_batch_delete_payload(
        entry_ids=entry_ids,
        resource=DHCP_STATIC_IP_RESOURCE,
        carrier="per_id_item",
    )


def flatten_static_bindings(vals: Any) -> list[dict[str, str]]:
    """把 ``GET /api/v1/dhcp`` 的原始 ``vals`` 展平成静态绑定行。

    每个条目 ``server.hosts`` 里的每条绑定展开为
    ``{ifname, name, addr, mac}``（``ifname`` 来自宿主条目，用于区分不同网卡上的
    同名绑定）。这是 ``fw_verify_dhcp_static_ip`` 的输出形状，也是
    ``fw_delete_batch_dhcp_static_ip`` 唯一能观察前后状态的视角。
    """
    rows: list[dict[str, str]] = []
    if not isinstance(vals, list):
        return rows
    for entry in vals:
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
                    "mac": str(host.get("mac") or ""),
                }
            )
    return rows


def validate_dhcp_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    """对**最终载荷**做 op 相关校验（含 ``--payload-json`` 来源）。

    对 ``fw_config_dhcp_server``／``fw_update_dhcp_server`` 强制 ``lease`` 存在
    —— 这是崩溃护栏的最后一道闸：载荷可能来自扁平 flag，也可能来自
    ``--payload-json`` 逃生舱，两条路径都必须过这里。
    """
    if op_id in BATCH_OPS:
        return _validate_batch_payload(payload)
    if op_id in LEASE_GUARDED_OPS:
        _validate_lease_present(payload)
    return payload


def build_dhcp_dry_run(
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
    """构造 dry-run 信封。``fw_verify_dhcp_static_ip`` 额外声明其投影关系。"""
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
            "payload": None if op_id in NO_BODY_OPS else payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }
    if op_id == "fw_verify_dhcp_static_ip":
        result["projection"] = {
            "source_op": "fw_verify_dhcp_server",
            "note": (
                "The device exposes no GET on /api/v1/dhcpstaticip (405); static bindings "
                "are a projection of each DHCP entry's server.hosts and have no separate "
                "storage. This op reads /api/v1/dhcp and emits only the flattened "
                "ifname/name/addr/mac rows."
            ),
        }
    return result


def execute_dhcp(
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
    method, path = _method_path(op_id)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    status_code, response_payload, _text = request_json(
        method,
        _request_url(base_url, op_id, entry_id=entry_id),
        headers=headers,
        json_payload=None if op_id in NO_BODY_OPS else payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise_if_device_session_rejected(status_code, response_payload)
        # 目标资源不存在 == 目标状态已达成（幂等删除契约，权威门见 errors.py 登记表）
        raise_if_resource_not_found(status_code, response_payload, op_id=op_id)
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "DHCP device request did not return a success status.",
            {
                "op_id": op_id,
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
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
    if op_id == "fw_verify_dhcp_static_ip":
        # 投影：把原始 DHCP 条目换成展平的绑定行，原始响应仍保留在 response 里。
        result["bindings"] = flatten_static_bindings(response_payload.get("vals"))
        result["binding_count"] = len(result["bindings"])
    return result


def _request_url(base_url: str, op_id: str, *, entry_id: str) -> str:
    """按 **op_id** 分派 URL，绝不按 method 或族（``ipsec.py`` 的同款显式约定）。

    本族只有 ``fw_delete_dhcp_server`` 往 URL 里拼查询串，且**不带任何其它
    查询参数** —— 实测设备对该端点的七种过滤／分页参数一律静默忽略。
    """
    _method, path = _method_path(op_id)
    url = f"{normalize_base_url(base_url)}{path}"
    if op_id in QUERY_ID_OPS:
        _validate_non_empty("id", entry_id)
        url = f"{url}?{urlencode({'id': entry_id})}"
    return url


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return DHCP_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this DHCP operation.",
            {"op_id": op_id},
        ) from exc


def _validate_lease_present(payload: dict[str, Any]) -> None:
    """崩溃护栏：最终载荷必须带 ``server.lease``（见模块 docstring）。

    只检查「键存在且是对象」—— ``lease`` 的值本身可以是 ``{"limited": false,
    "default_seconds": 0}``（实测接受），设备崩的是**缺键**，不是取值。
    """
    val = payload.get("val")
    server = val.get("server") if isinstance(val, dict) else None
    lease = server.get("lease") if isinstance(server, dict) else None
    if not isinstance(lease, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            (
                "val.server.lease is required and must be an object: the device's management "
                "service crashes (nginx 502, ~90s outage) when a POST or PUT to /api/v1/dhcp "
                "omits it. The interface specification marks it optional, but live isolation "
                "proved the omission is what crashes the device."
            ),
            {"field": "val.server.lease", "crash_guard": True},
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


def _validate_subnets(subnets: Any) -> None:
    """规格 1.1 把 subnets 标为必填；设备同判（400「server: subnets is required」）。

    多条子网在协议上允许（``subnets`` 是数组），但 CLI 的扁平 flag 只覆盖单子网，
    多子网请走 ``--payload-json``（见 ``run_dhcp.py``）。
    """
    if not isinstance(subnets, list) or not subnets:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "server.subnets must be a non-empty list.",
            {"field": "subnets"},
        )
    for item in subnets:
        if not isinstance(item, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each subnet entry must be an object.",
                {"field": "subnets"},
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
                "Each hosts binding must be an object with name, addr and mac.",
                {"field": "hosts"},
            )
        for key in ("name", "addr", "mac"):
            _validate_non_empty(f"binding_{key}", item.get(key))
        rows.append({"name": item["name"], "addr": item["addr"], "mac": item["mac"]})
    return rows


def _validate_batch_payload(payload: dict[str, Any]) -> dict[str, Any]:
    batch = payload.get("batch")
    if not isinstance(batch, list) or not batch:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Batch delete payload must contain a non-empty batch list.",
            {"field": "batch"},
        )
    for item in batch:
        if not isinstance(item, dict):
            raise RunnerError("RUNNER_VALIDATION_FAILED", "Batch item must be an object.", {"field": "batch"})
        if item.get("method") != "DELETE" or item.get("resource") != DHCP_STATIC_IP_RESOURCE:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                f"Batch delete only supports DELETE {DHCP_STATIC_IP_RESOURCE} items.",
                {"method": item.get("method"), "resource": item.get("resource")},
            )
        body = item.get("body")
        ids = body.get("id") if isinstance(body, dict) else None
        if not isinstance(ids, list) or not ids:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch delete item body.id must be a non-empty list.",
                {"field": "batch"},
            )
    return payload


def _validate_choice(field: str, value: str, allowed: tuple[str, ...]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"DHCP {field} must be one of: {', '.join(allowed)}.",
            {"field": field, "value": value, "allowed": list(allowed)},
        )
    return value


def _validate_non_empty(field: str, value: Any) -> None:
    if not isinstance(value, str) or not value.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "DHCP field is required and must be non-empty.",
            {"field": field},
        )
