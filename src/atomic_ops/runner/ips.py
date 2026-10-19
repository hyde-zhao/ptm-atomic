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

from pathlib import Path
from typing import Any

from atomic_ops.runner.batch import build_batch_delete_payload, summarize_batch_result
from atomic_ops.runner.errors import RunnerError, raise_if_device_session_rejected
from atomic_ops.runner.http import request_json
from atomic_ops.runner.ngfw_login import normalize_base_url
from atomic_ops.runner.session import read_session_file


SUCCESS_STATUS = {200, 201, 202}
GET_SUCCESS_STATUS = {200}

RULES_RESOURCE = "/api/v1/appsec/ips/rules"
PROFILES_RESOURCE = "/api/v1/appsec/ips/profiles"
BATCH_PATH = "/api/v1/batch"

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
    return {
        "name": name,
        "actionWrapper": _ensure_list("actionWrapper", action_wrapper),
        "filters": _ensure_list("filters", filters),
        "whiteList": _ensure_list("whiteList", white_list),
        "customAddRuleList": _ensure_list("customAddRuleList", custom_add_rule_list),
        "desc": "" if desc is None else str(desc),
    }


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
        profile_ids = (
            [item.get("id") for item in vals if isinstance(item, dict) and item.get("id") is not None]
            if isinstance(vals, list)
            else []
        )
        return {
            "profile_ids": profile_ids,
            "count": response_payload.get("count"),
            "page": response_payload.get("page"),
            "size": response_payload.get("size"),
        }
    if op_id in {"fw_config_ips_rule", "fw_config_ips_profile"}:
        id_key = "ips_rule_id" if op_id == "fw_config_ips_rule" else "ips_profile_id"
        name_key = "ips_rule_name" if op_id == "fw_config_ips_rule" else "ips_profile_name"
        vals = response_payload.get("vals")
        first = vals[0] if isinstance(vals, list) and vals and isinstance(vals[0], dict) else {}
        return {
            id_key: first.get("Id"),
            name_key: first.get("Name"),
            "created": True,
        }
    if op_id in {"fw_update_ips_rule", "fw_delete_ips_rule"}:
        return {"ips_rule_id": payload.get("id")}
    if op_id in {"fw_update_ips_profile", "fw_delete_ips_profile"}:
        return {"ips_profile_id": payload.get("id")}
    return {}


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
