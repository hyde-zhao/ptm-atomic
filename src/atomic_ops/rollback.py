"""Rollback contract helpers shared by read, validate, and run commands."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any


SIDE_EFFECTS = {
    "none",
    "observation",
    "traffic_runtime",
    "state_mutation",
    "destructive",
    "irreversible",
}
STATE_CHANGING_SIDE_EFFECTS = {
    "traffic_runtime",
    "state_mutation",
    "destructive",
    "irreversible",
}
ROLLBACK_STRATEGIES = {
    "inverse_op",
    "restore_snapshot",
    "compensating_op",
    "manual_required",
    "irreversible",
}


@dataclass(frozen=True)
class RollbackFinding:
    finding_type: str
    location: str
    message: str
    severity: str = "error"

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_type": self.finding_type,
            "location": self.location,
            "message": self.message,
            "severity": self.severity,
        }


def rollback_summary(data: dict[str, Any]) -> dict[str, Any]:
    """Return stable rollback metadata for list/show consumers."""

    rollback_strategy = data.get("rollback_strategy")
    pre_snapshot = data.get("pre_snapshot")
    post_verify = data.get("post_verify")
    risk = data.get("risk")
    return {
        "side_effect": data.get("side_effect"),
        "idempotent": data.get("idempotent"),
        "rollback_strategy": rollback_strategy if isinstance(rollback_strategy, dict) else None,
        "pre_snapshot": pre_snapshot if isinstance(pre_snapshot, dict) else None,
        "post_verify": post_verify if isinstance(post_verify, dict) else None,
        "dry_run_supported": data.get("dry_run_supported"),
        "risk_level": risk.get("level") if isinstance(risk, dict) else data.get("risk_level"),
    }


def run_rollback_context(op_id: str, data: dict[str, Any], result_data: dict[str, Any]) -> dict[str, Any] | None:
    """Build a lightweight runtime rollback context from an operation contract."""

    side_effect = data.get("side_effect")
    if side_effect not in STATE_CHANGING_SIDE_EFFECTS:
        return None

    strategy = data.get("rollback_strategy")
    if not isinstance(strategy, dict):
        return {
            "strategy": "missing",
            "op_id": None,
            "inputs": {},
            "notes": "operation declares state-changing side_effect but has no rollback_strategy",
        }

    required_inputs = _string_list(strategy.get("required_inputs"))
    available = _flatten_leaf_values(result_data)
    inputs = {
        name: available.get(name, f"<{name}-from-result-or-snapshot>")
        for name in required_inputs
    }
    context: dict[str, Any] = {
        "strategy": strategy.get("type"),
        "op_id": strategy.get("op_id"),
        "inputs": inputs,
        "snapshot_required": bool(strategy.get("snapshot_required", False)),
    }
    if strategy.get("notes"):
        context["notes"] = strategy.get("notes")
    if isinstance(data.get("pre_snapshot"), dict):
        context["pre_snapshot"] = data["pre_snapshot"]
    if isinstance(data.get("rollback_apply"), dict):
        context["rollback_apply"] = data["rollback_apply"]
    if isinstance(data.get("post_verify"), dict):
        context["post_verify"] = data["post_verify"]
    return context


def validate_rollback_contract(
    op_id: str,
    data: dict[str, Any],
    op_exists: Callable[[str], bool],
) -> list[RollbackFinding]:
    """Validate static rollback metadata for one atom."""

    findings: list[RollbackFinding] = []
    side_effect = data.get("side_effect")
    if not isinstance(side_effect, str):
        return [
            RollbackFinding(
                "ROLLBACK_SIDE_EFFECT_MISSING",
                f"{op_id}.side_effect",
                "operation must declare side_effect",
            )
        ]
    if side_effect not in SIDE_EFFECTS:
        findings.append(
            RollbackFinding(
                "ROLLBACK_SIDE_EFFECT_INVALID",
                f"{op_id}.side_effect",
                f"side_effect must be one of {sorted(SIDE_EFFECTS)}",
            )
        )
        return findings

    strategy = data.get("rollback_strategy")
    if side_effect not in STATE_CHANGING_SIDE_EFFECTS:
        return findings

    if not isinstance(strategy, dict):
        findings.append(
            RollbackFinding(
                "ROLLBACK_STRATEGY_MISSING",
                f"{op_id}.rollback_strategy",
                "state-changing operation must declare rollback_strategy",
            )
        )
        return findings

    strategy_type = strategy.get("type")
    if strategy_type not in ROLLBACK_STRATEGIES:
        findings.append(
            RollbackFinding(
                "ROLLBACK_STRATEGY_INVALID",
                f"{op_id}.rollback_strategy.type",
                f"rollback_strategy.type must be one of {sorted(ROLLBACK_STRATEGIES)}",
            )
        )
        return findings

    if strategy_type in {"inverse_op", "compensating_op"}:
        _validate_referenced_op(op_id, strategy, "rollback_strategy.op_id", op_exists, findings)

    if strategy_type == "restore_snapshot":
        if strategy.get("snapshot_required") is not True:
            findings.append(
                RollbackFinding(
                    "ROLLBACK_SNAPSHOT_REQUIRED_FALSE",
                    f"{op_id}.rollback_strategy.snapshot_required",
                    "restore_snapshot rollback must set snapshot_required: true",
                )
            )
        pre_snapshot = data.get("pre_snapshot")
        if not isinstance(pre_snapshot, dict):
            findings.append(
                RollbackFinding(
                    "ROLLBACK_PRE_SNAPSHOT_MISSING",
                    f"{op_id}.pre_snapshot",
                    "restore_snapshot rollback must declare pre_snapshot",
                )
            )
        else:
            _validate_referenced_op(op_id, pre_snapshot, "pre_snapshot.op_id", op_exists, findings)
            if not _string_list(pre_snapshot.get("capture_fields")):
                findings.append(
                    RollbackFinding(
                        "ROLLBACK_CAPTURE_FIELDS_MISSING",
                        f"{op_id}.pre_snapshot.capture_fields",
                        "pre_snapshot must capture fields sufficient for restore",
                    )
                )
        rollback_apply = data.get("rollback_apply")
        if not isinstance(rollback_apply, dict):
            findings.append(
                RollbackFinding(
                    "ROLLBACK_APPLY_MISSING",
                    f"{op_id}.rollback_apply",
                    "restore_snapshot rollback must declare rollback_apply",
                )
            )
        else:
            _validate_referenced_op(op_id, rollback_apply, "rollback_apply.op_id", op_exists, findings)
            if not isinstance(rollback_apply.get("input_from"), str) or not rollback_apply["input_from"].strip():
                findings.append(
                    RollbackFinding(
                        "ROLLBACK_APPLY_INPUT_MISSING",
                        f"{op_id}.rollback_apply.input_from",
                        "rollback_apply must declare input_from",
                    )
                )

    if strategy_type == "irreversible" or side_effect == "irreversible":
        if not isinstance(strategy.get("notes"), str) or not strategy["notes"].strip():
            findings.append(
                RollbackFinding(
                    "ROLLBACK_IRREVERSIBLE_NOTES_MISSING",
                    f"{op_id}.rollback_strategy.notes",
                    "irreversible rollback strategy must explain why automatic restore is impossible",
                )
            )

    missing_inputs = _missing_required_inputs(data, strategy)
    for input_name in missing_inputs:
        findings.append(
            RollbackFinding(
                "ROLLBACK_REQUIRED_INPUT_UNAVAILABLE",
                f"{op_id}.rollback_strategy.required_inputs",
                f"required input is not available from parameters, returns.data, or pre_snapshot: {input_name}",
            )
        )

    if "post_verify" not in data:
        findings.append(
            RollbackFinding(
                "ROLLBACK_POST_VERIFY_MISSING",
                f"{op_id}.post_verify",
                "post_verify is recommended for state-changing operations",
                severity="warning",
            )
        )
    return findings


def readiness_report(
    op_id: str,
    data: dict[str, Any],
    op_exists: Callable[[str], bool],
) -> dict[str, Any]:
    """Return ptm-te oriented rollback readiness for one op."""

    findings = validate_rollback_contract(op_id, data, op_exists)
    errors = [finding for finding in findings if finding.severity == "error"]
    warnings = [finding.message for finding in findings if finding.severity != "error"]
    strategy = data.get("rollback_strategy")
    strategy_type = strategy.get("type") if isinstance(strategy, dict) else None
    if strategy_type == "manual_required":
        warnings.append("operation requires manual confirmation before live execution")
    if strategy_type == "irreversible":
        warnings.append("operation is irreversible and requires manual risk acceptance")

    status = "pass"
    if errors or strategy_type in {"manual_required", "irreversible"}:
        status = "blocked"

    missing = [
        finding.location
        for finding in errors
        if finding.finding_type
        in {
            "ROLLBACK_SIDE_EFFECT_MISSING",
            "ROLLBACK_STRATEGY_MISSING",
            "ROLLBACK_PRE_SNAPSHOT_MISSING",
            "ROLLBACK_APPLY_MISSING",
            "ROLLBACK_REQUIRED_INPUT_UNAVAILABLE",
        }
    ]
    return {
        "status": status,
        "op_id": op_id,
        "side_effect": data.get("side_effect"),
        "rollback_strategy": strategy_type,
        "rollback_op_id": strategy.get("op_id") if isinstance(strategy, dict) else None,
        "missing": missing,
        "warnings": warnings,
        "findings": [finding.to_dict() for finding in findings],
    }


def _validate_referenced_op(
    op_id: str,
    container: dict[str, Any],
    field: str,
    op_exists: Callable[[str], bool],
    findings: list[RollbackFinding],
) -> None:
    value = container.get("op_id")
    if not isinstance(value, str) or not value.strip():
        findings.append(
            RollbackFinding(
                "ROLLBACK_REFERENCED_OP_MISSING",
                f"{op_id}.{field}",
                f"{field} must reference an existing op_id",
            )
        )
        return
    if not op_exists(value):
        findings.append(
            RollbackFinding(
                "ROLLBACK_REFERENCED_OP_NOT_FOUND",
                f"{op_id}.{field}",
                f"referenced rollback operation does not exist: {value}",
            )
        )


def _missing_required_inputs(data: dict[str, Any], strategy: dict[str, Any]) -> list[str]:
    required_inputs = _string_list(strategy.get("required_inputs"))
    if not required_inputs:
        return []
    available = set()
    parameters = data.get("parameters")
    if isinstance(parameters, dict):
        available.update(str(key) for key in parameters)
    returns = data.get("returns")
    if isinstance(returns, dict):
        result_data = returns.get("data")
        if isinstance(result_data, dict):
            available.update(_flatten_leaf_values(result_data))
    pre_snapshot = data.get("pre_snapshot")
    if isinstance(pre_snapshot, dict):
        available.update(_string_list(pre_snapshot.get("capture_fields")))
    inputs = data.get("inputs")
    if isinstance(inputs, dict):
        available.update(str(key) for key in inputs)
        params = inputs.get("params")
        if isinstance(params, dict):
            available.update(_flatten_leaf_values(params))
    return [name for name in required_inputs if name not in available]


def _flatten_leaf_values(data: dict[str, Any]) -> dict[str, Any]:
    values: dict[str, Any] = {}

    def visit(value: Any) -> None:
        if isinstance(value, dict):
            for key, child in value.items():
                if isinstance(key, str):
                    if not isinstance(child, (dict, list)):
                        values[key] = child
                    visit(child)
        elif isinstance(value, list):
            for child in value:
                visit(child)

    visit(data)
    return values


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, str) and item.strip()]
