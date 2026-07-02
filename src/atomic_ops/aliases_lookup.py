"""Reverse lookup from a business keyword to operation ids.

The CLI's ``OP_NOT_FOUND`` path historically only offered Levenshtein-based
op_id suggestions. A user who writes ``fw_config_pppoe`` in a test case gets
no useful suggestion, because the real operation is ``fw_config_interface``
whose alias list carries ``pppoe``. This module maps business keywords back to
operations via aliases, tags, op_id, and description so the validate command
can explain the substitution.
"""

from __future__ import annotations

from typing import Any


# 防火墙 v1.1 的两段式逻辑动词；提取关键词时需整体跳过。
_TWO_WORD_VERBS = {"config_batch", "delete_batch"}


def find_ops_by_alias(keyword: str, operations: list[Any], *, limit: int = 5) -> list[dict[str, Any]]:
    """Return operations whose aliases/tags/op_id/description contain keyword.

    Each result carries the matched op_id, the first matched field, and the
    aliases that triggered the match so callers can explain the mapping.
    """
    if not keyword or not operations:
        return []
    needle = keyword.lower()
    matches: list[dict[str, Any]] = []
    for operation in operations:
        op_id = str(getattr(operation, "op_id", "") or "")
        aliases = list(getattr(operation, "aliases", None) or [])
        tags = list(getattr(operation, "tags", None) or [])
        description = str(getattr(operation, "description", "") or "")
        matched_field: str | None = None
        matched_aliases: list[str] = []
        if needle in op_id.lower():
            matched_field = "op_id"
        else:
            matched_aliases = [alias for alias in aliases if needle in str(alias).lower()]
            if matched_aliases:
                matched_field = "aliases"
            elif any(needle in str(tag).lower() for tag in tags):
                matched_field = "tags"
            elif needle in description.lower():
                matched_field = "description"
        if matched_field:
            matches.append(
                {
                    "op_id": op_id,
                    "matched_field": matched_field,
                    "matched_aliases": matched_aliases,
                }
            )
        if len(matches) >= limit:
            break
    return matches


def extract_alias_keywords(op_id: str) -> list[str]:
    """Extract business keyword candidates from a missing op_id.

    Examples:
        fw_config_pppoe -> ["pppoe"]
        fw_config_security_policy -> ["security-policy"]
        fw_config_southbound_interface -> ["southbound-interface"]
        fw_config_batch_acl_policy -> ["acl-policy"]
    """
    if not op_id:
        return []
    parts = op_id.split("_")
    if len(parts) < 2:
        return [op_id]
    parts = parts[1:]  # 去掉 device 前缀
    if len(parts) >= 2 and f"{parts[0]}_{parts[1]}" in _TWO_WORD_VERBS:
        parts = parts[2:]
    else:
        parts = parts[1:]
    target = "-".join(parts)
    return [target] if target else []
