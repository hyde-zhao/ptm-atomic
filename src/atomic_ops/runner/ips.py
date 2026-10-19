"""NGFW IPS rule/profile runner for /api/v1/appsec/ips/{rules,profiles}.

IPS 族由两个资源组成：

- 规则（rules）：自定义/预定义入侵防御规则，支持列表、关键字与属性筛选、
  勾选规则详情、增删改与批量删除；
- 防护模板（profiles）：引用规则集合的防护模板，支持列表、增删改与批量删除。

抓包（ips-api.md）显示这两个资源的 GET 与 DELETE 都把 JSON 载荷放在请求
body 中，而不是 query string。runner 因此对 GET/DELETE 同样发送 JSON body，
这与仓库内多数“GET 无 body、DELETE 用 ?id=”的族不同。

批量删除沿用 ``runner/batch.py#build_batch_delete_payload``，并显式选择
``carrier="per_id_item"``：抓包中的 Web UI 对每条规则/模板各发一个 batch
item，每个 item 的 ``body.id`` 是单元素列表。该 helper 同时保证
``tests/test_batch.py`` 的静态扫描不会把本模块视为重复实现。
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from atomic_ops.runner.batch import build_batch_delete_payload, summarize_batch_result
from atomic_ops.runner.errors import (
    RunnerError,
    raise_if_device_session_rejected,
    raise_if_resource_not_found,
)
from atomic_ops.runner.http import request_bytes, request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

RULES_RESOURCE = "/api/v1/appsec/ips/rules"
PROFILES_RESOURCE = "/api/v1/appsec/ips/profiles"
BATCH_PATH = "/api/v1/batch"
SECLOG_PATH = "/api/v1/monitor/seclog"
SECLOG_EVIDENCE_PATH = "/api/v1/seclog/evidence"
DOWNLOAD_FILE_PATH = "/api/v1/downloadfile"
LOG_CACHE_PATH = "/api/v1/logsetting/logcacheset"

# security-log 模块 id：用户最终确认本次只实现 gid=1（入侵防御）。
# 其他日志类型（防病毒/内容过滤/...）不建参数枚举，后续特性再扩展。
SECLOG_GIDS: dict[int, str] = {
    1: "ips",
}
SECLOG_TIMETYPES = ("24h", "all", "1h", "7d", "1m", "custom")

IPS_ENDPOINTS: dict[str, tuple[str, str]] = {
    "fw_config_ips_rule": ("POST", RULES_RESOURCE),
    "fw_update_ips_rule": ("PUT", RULES_RESOURCE),
    "fw_verify_ips_rule": ("GET", RULES_RESOURCE),
    "fw_delete_ips_rule": ("DELETE", RULES_RESOURCE),
    "fw_delete_batch_ips_rule": ("POST", BATCH_PATH),
    "fw_config_ips_profile": ("POST", PROFILES_RESOURCE),
    "fw_update_ips_profile": ("PUT", PROFILES_RESOURCE),
    "fw_verify_ips_profile": ("GET", PROFILES_RESOURCE),
    "fw_delete_ips_profile": ("DELETE", PROFILES_RESOURCE),
    "fw_delete_batch_ips_profile": ("POST", BATCH_PATH),
}
GET_OPS = {"fw_verify_ips_rule", "fw_verify_ips_profile"}
BATCH_OPS = {"fw_delete_batch_ips_rule", "fw_delete_batch_ips_profile"}


# ── 规则载荷构造 ──────────────────────────────────────────


def build_ips_rule_payload(
    *,
    name: str,
    desc: str,
    is_profenal: bool = False,
) -> dict[str, Any]:
    """构造规则新建载荷 ``{"val": {name, desc, isProfenal}}``。"""
    return {"val": _ips_rule_val(name=name, desc=desc, is_profenal=is_profenal)}


def build_ips_rule_update_payload(
    *,
    entry_id: int | str,
    name: str,
    desc: str,
    is_profenal: bool = False,
) -> dict[str, Any]:
    """构造规则编辑载荷 ``{"id": <数字字符串>, "val": {...}}``。"""
    return {
        "id": _normalize_numeric_id("id", entry_id),
        "val": _ips_rule_val(name=name, desc=desc, is_profenal=is_profenal),
    }


def build_ips_rule_delete_payload(*, entry_id: int | str) -> dict[str, str]:
    """构造单条规则删除载荷；抓包显示 id 放在 JSON body 中。"""
    return {"id": _normalize_numeric_id("id", entry_id)}


def build_ips_rule_batch_delete_payload(*, entry_ids: list[int | str]) -> dict[str, Any]:
    """构造规则批量删除载荷；每条规则一个 item，与抓包形态一致。"""
    return _build_batch_delete_payload(
        entry_ids=entry_ids,
        resource=RULES_RESOURCE,
        field="ids",
    )


def build_ips_rule_query_payload(
    *,
    ids: list[int | str] | None = None,
    page: int | str = 1,
    size: int | str = 10,
    key: str = "",
    config_source: str | int | None = None,
    level: Any = None,
    direct: Any = None,
    os: Any = None,
    classtype: Any = None,
) -> dict[str, Any]:
    """构造规则查询载荷（GET 的 JSON body）。

    ids 非空时进入“勾选规则详情”模式，只发送 ``{"id": [...]}``；
    否则进入列表/筛选模式，发送 key、page、size 以及可选 config_source
    和属性过滤。抓包中单值过滤发标量字符串，多值过滤发字符串列表。
    """
    if ids:
        normalized = [_normalize_numeric_id("ids", entry_id) for entry_id in ids]
        return {"id": normalized}

    payload: dict[str, Any] = {
        "key": "" if key is None else str(key),
        "page": _normalize_positive_int("page", page),
        "size": _normalize_positive_int("size", size),
    }
    if config_source is not None:
        payload["config_source"] = str(config_source)
    for filter_name, value in (
        ("level", level),
        ("direct", direct),
        ("os", os),
        ("classtype", classtype),
    ):
        normalized_filter = _normalize_filter_value(filter_name, value)
        if normalized_filter is not None:
            payload[filter_name] = normalized_filter
    return payload


# ── 防护模板载荷构造 ──────────────────────────────────────


def build_ips_profile_payload(
    *,
    name: str,
    action_wrapper: list[Any] | None = None,
    filters: list[Any] | None = None,
    white_list: list[Any] | None = None,
    custom_add_rule_list: list[Any] | None = None,
    desc: str = "",
) -> dict[str, Any]:
    """构造防护模板新建载荷 ``{"val": {...}}``。"""
    return {
        "val": _ips_profile_val(
            name=name,
            action_wrapper=action_wrapper,
            filters=filters,
            white_list=white_list,
            custom_add_rule_list=custom_add_rule_list,
            desc=desc,
        )
    }


def build_ips_profile_update_payload(
    *,
    entry_id: int | str,
    name: str,
    action_wrapper: list[Any] | None = None,
    filters: list[Any] | None = None,
    white_list: list[Any] | None = None,
    custom_add_rule_list: list[Any] | None = None,
    desc: str = "",
) -> dict[str, Any]:
    """构造防护模板编辑载荷 ``{"id": <数字字符串>, "val": {...}}``。"""
    return {
        "id": _normalize_numeric_id("id", entry_id),
        "val": _ips_profile_val(
            name=name,
            action_wrapper=action_wrapper,
            filters=filters,
            white_list=white_list,
            custom_add_rule_list=custom_add_rule_list,
            desc=desc,
        ),
    }


def build_ips_profile_delete_payload(*, entry_id: int | str) -> dict[str, str]:
    """构造单个防护模板删除载荷；id 放在 JSON body 中。"""
    return {"id": _normalize_numeric_id("id", entry_id)}


def build_ips_profile_batch_delete_payload(*, entry_ids: list[int | str]) -> dict[str, Any]:
    """构造防护模板批量删除载荷；每个模板一个 item。"""
    return _build_batch_delete_payload(
        entry_ids=entry_ids,
        resource=PROFILES_RESOURCE,
        field="ids",
    )


def build_ips_profile_query_payload(
    *,
    page: int | str = 1,
    size: int | str = 10,
    key: str = "",
    config_source: str | int | None = None,
) -> dict[str, Any]:
    """构造防护模板列表查询载荷（GET 的 JSON body）。"""
    payload: dict[str, Any] = {
        "key": "" if key is None else str(key),
        "page": _normalize_positive_int("page", page),
        "size": _normalize_positive_int("size", size),
    }
    if config_source is not None:
        payload["config_source"] = str(config_source)
    return payload


def validate_ips_payload(payload: dict[str, Any], *, op_id: str) -> dict[str, Any]:
    """对批量删除载荷做结构校验（其余载荷由构造器校验）。"""
    if op_id not in BATCH_OPS:
        return payload
    resource = RULES_RESOURCE if op_id == "fw_delete_batch_ips_rule" else PROFILES_RESOURCE
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
        if item.get("method") != "DELETE" or item.get("resource") != resource:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Batch IPS delete only supports DELETE items for the family resource.",
                {"method": item.get("method"), "resource": item.get("resource"), "expected": resource},
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


# ── 执行与 dry-run ────────────────────────────────────────


def build_ips_dry_run(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    return {
        "op_id": op_id,
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": method,
            "url": f"{normalize_base_url(base_url)}{path}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_ips(
    *,
    op_id: str,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any] | None,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    method, path = _method_path(op_id)
    if payload is None:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS operation requires a request payload.",
            {"op_id": op_id},
        )
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    headers = {"Content-Type": "application/json", auth_header: header_value}
    status_code, response_payload, _text = request_json(
        method,
        f"{normalize_base_url(base_url)}{path}",
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    success_status = GET_SUCCESS_STATUS if method == "GET" else SUCCESS_STATUS
    if status_code not in success_status:
        raise_if_device_session_rejected(status_code, response_payload, op_id=op_id)
        # 重复删除（eConfigWrite + 专属文案）按「目标状态已达成」归一，
        # 权威门是 errors.py 的 IDEMPOTENT_ERROR_TYPES 登记表。
        raise_if_resource_not_found(status_code, response_payload, op_id=op_id)
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID" if method == "GET" else "RUNNER_CONFIG_REJECTED",
            "IPS device request did not return a success status.",
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
    result.update(_extract_ips_summary(op_id, payload, response_payload))
    if op_id in BATCH_OPS:
        batch_summary = summarize_batch_result(
            response_payload,
            requested_count=_batch_delete_requested_count(payload),
        )
        result.update(batch_summary)
        result["batch_result"] = {
            "status": _batch_status(batch_summary),
            **batch_summary,
        }
    return result


# ── 内部 helper ───────────────────────────────────────────


def _ips_rule_val(*, name: str, desc: str, is_profenal: bool) -> dict[str, Any]:
    if not isinstance(desc, str) or not desc.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS rule desc must contain a non-empty Snort-style rule body.",
            {"field": "desc"},
        )
    if not isinstance(name, str):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS rule name must be a string.",
            {"field": "name"},
        )
    if not is_profenal and not name.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS rule name is required when isProfenal is false.",
            {"field": "name"},
        )
    return {
        "name": name,
        "desc": desc,
        "isProfenal": bool(is_profenal),
    }


def _ips_profile_val(
    *,
    name: str,
    action_wrapper: list[Any] | None,
    filters: list[Any] | None,
    white_list: list[Any] | None,
    custom_add_rule_list: list[Any] | None,
    desc: str,
) -> dict[str, Any]:
    if not isinstance(name, str) or not name.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS profile name is required.",
            {"field": "name"},
        )
    val = {
        "name": name,
        "actionWrapper": _ensure_list("actionWrapper", action_wrapper),
        "filters": _ensure_list("filters", filters),
        "whiteList": _ensure_list("whiteList", white_list),
        "customAddRuleList": _ensure_list("customAddRuleList", custom_add_rule_list),
        "desc": "" if desc is None else str(desc),
    }
    return validate_ips_profile_val(val)


def validate_ips_profile_val(val: dict[str, Any]) -> dict[str, Any]:
    """校验 IPS 防护模板 val 的已知嵌套字段（未知字段原样保留）。

    覆盖抓包中的结构：
    - actionWrapper: priority 1..5、action 0/1/2，同一 priority 不重复；
    - filters: protocols/classtype/prioritys/Directs/OsTypes/builtintype 等
      过滤条件，可选 action 0/1/2 与 capture_pkt 布尔值；
    - whiteList: 例外规则列表，每条必须带 ruleId；
    - customAddRuleList: 规则条目必须带 id，可选 action 0/1/2 与
      capture_pkt 布尔值。
    """
    if not isinstance(val, dict):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS profile val must be an object.",
            {"field": "val", "received_type": type(val).__name__},
        )
    name = val.get("name")
    if not isinstance(name, str) or not name.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS profile val.name is required.",
            {"field": "val.name"},
        )
    _validate_action_wrapper(val.get("actionWrapper"))
    _validate_profile_filters(val.get("filters"))
    _validate_white_list(val.get("whiteList"))
    _validate_custom_add_rule_list(val.get("customAddRuleList"))
    return val


def _validate_action_wrapper(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "actionWrapper must be a list.",
            {"field": "actionWrapper", "received_type": type(value).__name__},
        )
    seen_priorities: set[int] = set()
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each actionWrapper entry must be an object.",
                {"field": "actionWrapper", "index": index},
            )
        priority = _optional_int_field("actionWrapper.priority", entry.get("priority"))
        if priority is None or priority not in {1, 2, 3, 4, 5}:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "actionWrapper.priority must be an integer from 1 to 5.",
                {"field": "actionWrapper.priority", "index": index, "value": entry.get("priority")},
            )
        if priority in seen_priorities:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "actionWrapper priorities must be unique.",
                {"field": "actionWrapper.priority", "index": index, "value": priority},
            )
        seen_priorities.add(priority)
        action = _optional_int_field("actionWrapper.action", entry.get("action"))
        if action is None or action not in {0, 1, 2}:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "actionWrapper.action must be 0, 1 or 2.",
                {"field": "actionWrapper.action", "index": index, "value": entry.get("action")},
            )


def _validate_profile_filters(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "filters must be a list.",
            {"field": "filters", "received_type": type(value).__name__},
        )
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each filters entry must be an object.",
                {"field": "filters", "index": index},
            )
        _validate_optional_action("filters.action", entry.get("action"), index)
        _validate_optional_bool("filters.capture_pkt", entry.get("capture_pkt"), index)
        for key in ("prioritys", "Directs", "OsTypes", "classtype", "protocols"):
            if key in entry and not isinstance(entry[key], list):
                raise RunnerError(
                    "RUNNER_VALIDATION_FAILED",
                    f"filters.{key} must be a list.",
                    {"field": f"filters.{key}", "index": index},
                )
        if "builtintype" in entry and not isinstance(entry["builtintype"], str):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "filters.builtintype must be a string.",
                {"field": "filters.builtintype", "index": index},
            )


def _validate_white_list(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "whiteList must be a list.",
            {"field": "whiteList", "received_type": type(value).__name__},
        )
    for index, entry in enumerate(value):
        if not isinstance(entry, dict) or entry.get("ruleId") is None:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each whiteList entry must be an object carrying ruleId.",
                {"field": "whiteList", "index": index},
            )


def _validate_custom_add_rule_list(value: Any) -> None:
    if value is None:
        return
    if not isinstance(value, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "customAddRuleList must be a list.",
            {"field": "customAddRuleList", "received_type": type(value).__name__},
        )
    for index, entry in enumerate(value):
        if not isinstance(entry, dict):
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each customAddRuleList entry must be an object.",
                {"field": "customAddRuleList", "index": index},
            )
        rule_id = _optional_int_field("customAddRuleList.id", entry.get("id"))
        if rule_id is None:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Each customAddRuleList entry requires a numeric id.",
                {"field": "customAddRuleList.id", "index": index, "value": entry.get("id")},
            )
        _validate_optional_action("customAddRuleList.action", entry.get("action"), index)
        _validate_optional_bool("customAddRuleList.capture_pkt", entry.get("capture_pkt"), index)


def _validate_optional_action(field: str, value: Any, index: int) -> None:
    if value is None:
        return
    action = _optional_int_field(field, value)
    if action not in {0, 1, 2}:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must be 0, 1 or 2.",
            {"field": field, "index": index, "value": value},
        )


def _validate_optional_bool(field: str, value: Any, index: int) -> None:
    if value is None:
        return
    if not isinstance(value, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must be a boolean.",
            {"field": field, "index": index, "value": value},
        )


def _optional_int_field(field: str, value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _ensure_list(field: str, value: list[Any] | None) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            f"{field} must be a list.",
            {"field": field, "received_type": type(value).__name__},
        )
    return value


def _build_batch_delete_payload(
    *,
    entry_ids: list[int | str],
    resource: str,
    field: str,
) -> dict[str, Any]:
    if not isinstance(entry_ids, list) or not entry_ids:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "At least one id is required for batch delete.",
            {"field": field},
        )
    normalized = [_normalize_numeric_id(field, entry_id) for entry_id in entry_ids]
    return build_batch_delete_payload(
        entry_ids=normalized,
        resource=resource,
        carrier="per_id_item",
    )


def _normalize_numeric_id(field: str, value: int | str) -> str:
    if isinstance(value, bool) or value is None:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS id must be a positive integer or a numeric string.",
            {"field": field, "value": value},
        )
    text = str(value).strip()
    if not text or not text.isdigit():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS id must be a positive integer or a numeric string.",
            {"field": field, "value": value},
        )
    if int(text) < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS id must be positive.",
            {"field": field, "value": value},
        )
    return text


def _normalize_positive_int(field: str, value: int | str) -> str:
    if isinstance(value, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS pagination field must be a positive integer.",
            {"field": field, "value": value},
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS pagination field must be a positive integer.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS pagination field must be positive.",
            {"field": field, "value": value},
        )
    return str(parsed)


def _normalize_filter_value(field: str, value: Any) -> str | list[str] | None:
    if value is None:
        return None
    if isinstance(value, (list, tuple)):
        items = [_scalar_filter_text(field, item) for item in value]
        items = [item for item in items if item]
        if not items:
            return None
        return items[0] if len(items) == 1 else items
    text = _scalar_filter_text(field, value)
    return text or None


def _scalar_filter_text(field: str, value: Any) -> str:
    if isinstance(value, bool) or isinstance(value, (dict, list, tuple)):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "IPS rule filter value must be a scalar or a list of scalars.",
            {"field": field, "value": value},
        )
    return str(value).strip()


def _extract_ips_summary(
    op_id: str,
    payload: dict[str, Any],
    response_payload: dict[str, Any],
) -> dict[str, Any]:
    if op_id == "fw_verify_ips_rule":
        vals = response_payload.get("vals")
        rule_ids = (
            [item.get("id") for item in vals if isinstance(item, dict) and item.get("id") is not None]
            if isinstance(vals, list)
            else []
        )
        return {
            "rule_ids": rule_ids,
            "count": response_payload.get("count"),
            "page": response_payload.get("page"),
            "size": response_payload.get("size"),
            "account": response_payload.get("account"),
        }
    if op_id == "fw_verify_ips_profile":
        vals = response_payload.get("vals")
        profile_ids: list[Any] = []
        profile_sources: list[dict[str, Any]] = []
        predefined_profile_ids: list[Any] = []
        custom_profile_ids: list[Any] = []
        if isinstance(vals, list):
            for item in vals:
                if not isinstance(item, dict):
                    continue
                profile_id = item.get("id")
                if profile_id is not None:
                    profile_ids.append(profile_id)
                source = _classify_profile_source(item)
                profile_sources.append(
                    {
                        "id": profile_id,
                        "name": item.get("name"),
                        "source": source,
                    }
                )
                if source == "predefined":
                    predefined_profile_ids.append(profile_id)
                elif source == "custom":
                    custom_profile_ids.append(profile_id)
        return {
            "profile_ids": profile_ids,
            "profile_sources": profile_sources,
            "predefined_profile_ids": predefined_profile_ids,
            "custom_profile_ids": custom_profile_ids,
            "count": response_payload.get("count"),
            "page": response_payload.get("page"),
            "size": response_payload.get("size"),
        }
    if op_id == "fw_config_ips_profile":
        id_key = "ips_profile_id"
        name_key = "ips_profile_name"
        vals = response_payload.get("vals")
        first = vals[0] if isinstance(vals, list) and vals and isinstance(vals[0], dict) else {}
        return {
            id_key: first.get("Id"),
            name_key: first.get("Name"),
            "created": True,
            **_requested_profile_summary(payload),
        }
    if op_id == "fw_config_ips_rule":
        id_key = "ips_rule_id"
        name_key = "ips_rule_name"
        vals = response_payload.get("vals")
        first = vals[0] if isinstance(vals, list) and vals and isinstance(vals[0], dict) else {}
        return {
            id_key: first.get("Id"),
            name_key: first.get("Name"),
            "created": True,
        }
    if op_id in {"fw_update_ips_rule", "fw_delete_ips_rule"}:
        return {"ips_rule_id": payload.get("id")}
    if op_id == "fw_update_ips_profile":
        return {
            "ips_profile_id": payload.get("id"),
            **_requested_profile_summary(payload),
        }
    if op_id == "fw_delete_ips_profile":
        return {"ips_profile_id": payload.get("id")}
    return {}


def _classify_profile_source(item: dict[str, Any]) -> str:
    """按用户确认的规则判别预定义/自定义来源。

    - config_source=18 为预定义（兼容部分版本的字段语义）；
    - 其余情况按 id：id<1000 预定义，id>=1000 自定义
      （抓包中用户新建模板得到 id=1000，故 1000 归入自定义）；
    - id 缺失或非数字时返回 unknown，不猜测。
    """
    if item.get("config_source") in (18, "18"):
        return "predefined"
    profile_id = item.get("id")
    if isinstance(profile_id, bool):
        return "unknown"
    try:
        numeric_id = int(profile_id)
    except (TypeError, ValueError):
        return "unknown"
    return "predefined" if numeric_id < 1000 else "custom"


def _requested_profile_summary(payload: dict[str, Any]) -> dict[str, Any]:
    """从请求 val 中提取 capture_pkt/actionWrapper/filters 摘要。

    这些值来自请求侧，供调用方确认 capture_pkt 开关与模板结构；设备
    回读仍以 fw_verify_ips_profile 为准。
    """
    val = payload.get("val") if isinstance(payload, dict) else None
    if not isinstance(val, dict):
        return {}
    custom_rules = val.get("customAddRuleList")
    enabled_ids: list[Any] = []
    disabled_ids: list[Any] = []
    if isinstance(custom_rules, list):
        for entry in custom_rules:
            if not isinstance(entry, dict):
                continue
            if entry.get("capture_pkt") is True:
                enabled_ids.append(entry.get("id"))
            elif entry.get("capture_pkt") is False:
                disabled_ids.append(entry.get("id"))
    action_wrapper = val.get("actionWrapper")
    filters = val.get("filters")
    return {
        "requested_action_wrapper": action_wrapper if isinstance(action_wrapper, list) else [],
        "requested_filter_count": len(filters) if isinstance(filters, list) else 0,
        "capture_pkt_enabled_rule_ids": enabled_ids,
        "capture_pkt_disabled_rule_ids": disabled_ids,
    }


def _batch_delete_requested_count(payload: dict[str, Any] | None) -> int:
    batch = payload.get("batch") if isinstance(payload, dict) else None
    if not isinstance(batch, list):
        return 0
    total = 0
    for item in batch:
        body = item.get("body") if isinstance(item, dict) else None
        ids = body.get("id") if isinstance(body, dict) else None
        if isinstance(ids, list):
            total += len(ids)
    return total


def _batch_status(summary: dict[str, Any]) -> str:
    if not summary.get("per_item_result"):
        return "indeterminate"
    failed_count = summary.get("failed_count")
    success_count = summary.get("success_count")
    if failed_count == 0:
        return "succeeded"
    if success_count == 0:
        return "failed"
    return "partial_failed"


def _method_path(op_id: str) -> tuple[str, str]:
    try:
        return IPS_ENDPOINTS[op_id]
    except KeyError as exc:
        raise RunnerError(
            "RUNNER_UNSUPPORTED_OP",
            "Runner does not support this IPS operation.",
            {"op_id": op_id},
        ) from exc


# ── IPS 日志 / 取证 / pcap 下载 ───────────────────────────


def build_ips_log_query(
    *,
    gid: int | str = 1,
    page: int | str = 1,
    size: int | str = 10,
    timetype: str = "24h",
    starttime: int | str | None = None,
    endtime: int | str | None = None,
) -> dict[str, Any]:
    """构造 /api/v1/monitor/seclog 的查询参数。

    用户最终确认：本次只支持 gid=1（入侵防御），其他日志类型不建枚举、
    后续特性再扩展。timetype=custom 时必须同时给出 starttime/endtime
    （epoch 秒）。非 custom 窗口忽略时间戳。
    """
    normalized_gid = _validate_seclog_gid(gid)
    normalized_page = int(_normalize_positive_int("page", page))
    normalized_size = int(_normalize_positive_int("size", size))
    if timetype not in SECLOG_TIMETYPES:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Security-log timetype is unsupported.",
            {"field": "timetype", "value": timetype, "allowed": list(SECLOG_TIMETYPES)},
        )
    query: dict[str, Any] = {
        "gid": normalized_gid,
        "page": normalized_page,
        "size": normalized_size,
        "timetype": timetype,
    }
    if timetype == "custom":
        if starttime is None or endtime is None:
            raise RunnerError(
                "RUNNER_VALIDATION_FAILED",
                "Custom timetype requires both starttime and endtime.",
                {"fields": ["starttime", "endtime"]},
            )
        query["starttime"] = _validate_non_negative_epoch("starttime", starttime)
        query["endtime"] = _validate_non_negative_epoch("endtime", endtime)
    return query


def build_ips_log_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    query: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_capture_ips_log",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": f"{normalize_base_url(base_url)}{SECLOG_PATH}?{urlencode(query)}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_ips_log(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    query: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    headers = _session_headers(session_payload, auth_header)
    status_code, response_payload, _text = request_json(
        "GET",
        f"{normalize_base_url(base_url)}{SECLOG_PATH}?{urlencode(query)}",
        headers=headers,
        json_payload=None,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in GET_SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response_payload, op_id="fw_capture_ips_log")
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Security-log device request did not return a success status.",
            {
                "op_id": "fw_capture_ips_log",
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    size = int(query.get("size", 10))
    count = response_payload.get("count")
    response_size = response_payload.get("size", size)
    try:
        page_size = int(response_size)
    except (TypeError, ValueError):
        page_size = size
    return {
        "op_id": "fw_capture_ips_log",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "GET",
            "path": SECLOG_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "query": dict(query),
        },
        "response": response_payload,
        "count": count,
        "page": response_payload.get("page", query.get("page")),
        "size": response_size,
        "page_count": _page_count(count, page_size),
    }


def build_ips_evidence_query(*, meta_file: str) -> dict[str, str]:
    if not isinstance(meta_file, str) or not meta_file.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "meta_file is required for security-log evidence.",
            {"field": "meta_file"},
        )
    return {"meta_file": meta_file.strip()}


def build_ips_evidence_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    query: dict[str, str],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_verify_seclog_evidence",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": f"{normalize_base_url(base_url)}{SECLOG_EVIDENCE_PATH}?{urlencode(query)}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_ips_evidence(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    query: dict[str, str],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    headers = _session_headers(session_payload, auth_header)
    status_code, response_payload, _text = request_json(
        "GET",
        f"{normalize_base_url(base_url)}{SECLOG_EVIDENCE_PATH}?{urlencode(query)}",
        headers=headers,
        json_payload=None,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in GET_SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response_payload, op_id="fw_verify_seclog_evidence")
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Security-log evidence device request did not return a success status.",
            {
                "op_id": "fw_verify_seclog_evidence",
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    vals = response_payload.get("vals")
    meta = vals.get("meta") if isinstance(vals, dict) else None
    packet_data = vals.get("packet_data") if isinstance(vals, dict) else None
    meta_file = vals.get("meta_file") if isinstance(vals, dict) else None
    pcap_filename = meta.get("pcap_filename") if isinstance(meta, dict) else None
    return {
        "op_id": "fw_verify_seclog_evidence",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "GET",
            "path": SECLOG_EVIDENCE_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "query": dict(query),
        },
        "response": response_payload,
        "meta_file": meta_file or query.get("meta_file"),
        "meta": meta if isinstance(meta, dict) else {},
        "pcap_filename": pcap_filename,
        "packet_data_present": isinstance(packet_data, str) and bool(packet_data),
        "packet_data_size": len(packet_data) if isinstance(packet_data, str) else 0,
    }


def build_ips_pcap_download_id(*, pcap_filename: str) -> str:
    """由文件名构造 downloadfile 的 id：裸文件名补 logpcap/ 前缀。"""
    if not isinstance(pcap_filename, str) or not pcap_filename.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "pcap_filename is required for security-log pcap download.",
            {"field": "pcap_filename"},
        )
    text = pcap_filename.strip()
    if text.startswith("logpcap/"):
        return text
    return f"logpcap/{text}"


def build_ips_pcap_download_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    pcap_filename: str,
    output_path: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    pcap_id = build_ips_pcap_download_id(pcap_filename=pcap_filename)
    return {
        "op_id": "fw_download_seclog_pcap",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "GET",
            "url": f"{normalize_base_url(base_url)}{DOWNLOAD_FILE_PATH}?id={quote(pcap_id, safe='')}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": None,
        },
        "download": {
            "pcap_id": pcap_id,
            "pcap_filename": pcap_filename,
            "output_path": output_path,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_ips_pcap_download(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    pcap_filename: str,
    output_path: str,
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    if not isinstance(output_path, str) or not output_path.strip():
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "output_path is required for security-log pcap download.",
            {"field": "output_path"},
        )
    pcap_id = build_ips_pcap_download_id(pcap_filename=pcap_filename)
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    headers = _session_headers(session_payload, auth_header)
    url = f"{normalize_base_url(base_url)}{DOWNLOAD_FILE_PATH}?id={quote(pcap_id, safe='')}"
    status_code, content = request_bytes(
        "GET", url, headers=headers, timeout=timeout, verify_tls=verify_tls,
    )
    if status_code != 200:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Security-log pcap download did not return a success status.",
            {"op_id": "fw_download_seclog_pcap", "status_code": status_code},
        )
    if not content:
        raise RunnerError(
            "RUNNER_RESPONSE_INVALID",
            "Security-log pcap download returned an empty body.",
            {"op_id": "fw_download_seclog_pcap", "pcap_id": pcap_id},
        )
    target = Path(output_path)
    target.write_bytes(content)
    return {
        "op_id": "fw_download_seclog_pcap",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "GET",
            "path": DOWNLOAD_FILE_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "pcap_id": pcap_id,
        },
        "download": {
            "pcap_id": pcap_id,
            "pcap_filename": pcap_filename,
            "output_path": str(target),
            "file_size": len(content),
            "sha256": hashlib.sha256(content).hexdigest(),
        },
    }


def _session_headers(session_payload: dict[str, Any], auth_header: str) -> dict[str, str]:
    session_value = str(session_payload["session_value"])
    header_value = f"Bearer {session_value}" if auth_header == "Authorization" else session_value
    return {"Content-Type": "application/json", auth_header: header_value}


def _validate_seclog_gid(gid: int | str) -> int:
    if isinstance(gid, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Security-log gid must be 1 (IPS) for this operation.",
            {"field": "gid", "value": gid, "allowed": [1]},
        )
    try:
        parsed = int(gid)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Security-log gid must be an integer.",
            {"field": "gid", "value": gid},
        ) from exc
    if parsed not in SECLOG_GIDS:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Only gid=1 (IPS) is implemented; other security-log types are out of scope for now.",
            {"field": "gid", "value": gid, "allowed": sorted(SECLOG_GIDS)},
        )
    return parsed


def _validate_non_negative_epoch(field: str, value: int | str) -> int:
    if isinstance(value, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Security-log timestamp must be a non-negative integer.",
            {"field": field, "value": value},
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Security-log timestamp must be a non-negative integer.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Security-log timestamp must be non-negative.",
            {"field": field, "value": value},
        )
    return parsed


def _page_count(count: Any, size: int) -> int | None:
    if isinstance(count, bool) or not isinstance(count, int) or count < 0 or size < 1:
        return None
    return (count + size - 1) // size


# ── 全局日志归并设置（IPS 日志场景）──────────────────────


def build_log_cache_payload(
    *,
    id: int | str = 1,
    enable: bool = True,
    time_set: int | str = 60,
) -> dict[str, Any]:
    """构造 PUT /api/v1/logsetting/logcacheset 的请求体。

    用户最终确认：id 只支持 1，且 id 不是 gid；该配置对所有类型日志的
    归并生效。timeSet 为归并窗口，单位以设备为准（样例 60），此处只做
    整数/布尔形状校验。
    """
    if not isinstance(enable, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Log-cache enable must be a boolean.",
            {"field": "enable", "value": enable},
        )
    return {
        "id": _validate_log_cache_id(id),
        "val": {
            "enable": enable,
            "timeSet": _normalize_non_negative_config_int("timeSet", time_set),
        },
    }


def build_log_cache_dry_run(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    return {
        "op_id": "fw_config_log_cache_set",
        "status": "dry_run",
        "execute_required": True,
        "request": {
            "method": "PUT",
            "url": f"{normalize_base_url(base_url)}{LOG_CACHE_PATH}",
            "auth": {"name": auth_header, "value": "<session-ref>"},
            "content_type": "application/json",
            "payload": payload,
        },
        "session_file": str(session_file),
        "verify_tls": verify_tls,
        "timeout": timeout,
    }


def execute_log_cache(
    *,
    base_url: str,
    session_file: Path,
    auth_header: str,
    payload: dict[str, Any],
    verify_tls: bool,
    timeout: float,
) -> dict[str, Any]:
    session_payload = read_session_file(session_file, expect_base_url=base_url)
    headers = _session_headers(session_payload, auth_header)
    status_code, response_payload, _text = request_json(
        "PUT",
        f"{normalize_base_url(base_url)}{LOG_CACHE_PATH}",
        headers=headers,
        json_payload=payload,
        timeout=timeout,
        verify_tls=verify_tls,
    )
    if status_code not in SUCCESS_STATUS:
        raise_if_device_session_rejected(status_code, response_payload, op_id="fw_config_log_cache_set")
        raise RunnerError(
            "RUNNER_CONFIG_REJECTED",
            "Log-cache setting request did not return a success status.",
            {
                "op_id": "fw_config_log_cache_set",
                "status_code": status_code,
                "err_code": response_payload.get("errCode"),
                "err_msg": response_payload.get("errMsg") or response_payload.get("message"),
                "response_keys": sorted(response_payload.keys()),
            },
        )
    val = payload.get("val") if isinstance(payload.get("val"), dict) else {}
    return {
        "op_id": "fw_config_log_cache_set",
        "status": "success",
        "status_code": status_code,
        "request": {
            "method": "PUT",
            "path": LOG_CACHE_PATH,
            "auth": {"name": auth_header, "value": "<session-ref>"},
        },
        "response": response_payload,
        "log_cache_id": payload.get("id"),
        "requested_enable": val.get("enable"),
        "requested_time_set": val.get("timeSet"),
    }


def _validate_log_cache_id(value: int | str) -> int:
    if isinstance(value, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Log-cache id must be 1; id is not gid.",
            {"field": "id", "value": value, "allowed": [1]},
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Log-cache id must be an integer.",
            {"field": "id", "value": value},
        ) from exc
    if parsed != 1:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Only id=1 is supported for the global log-cache setting; id is not gid.",
            {"field": "id", "value": value, "allowed": [1]},
        )
    return 1


def _normalize_non_negative_config_int(field: str, value: int | str) -> int:
    if isinstance(value, bool):
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Log-cache timeSet must be a non-negative integer.",
            {"field": field, "value": value},
        )
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Log-cache timeSet must be a non-negative integer.",
            {"field": field, "value": value},
        ) from exc
    if parsed < 0:
        raise RunnerError(
            "RUNNER_VALIDATION_FAILED",
            "Log-cache timeSet must be non-negative.",
            {"field": field, "value": value},
        )
    return parsed
