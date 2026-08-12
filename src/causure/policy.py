"""Configurable evidence-gate policy."""

from __future__ import annotations

import dataclasses
import math
from dataclasses import dataclass
from typing import Any

from causure.constants import DEFAULT_POLICY_NAME
from causure.errors import DocumentValidationError, ValidationIssue


@dataclass(frozen=True, slots=True)
class GatePolicy:
    """Thresholds used to turn evidence into a gate decision."""

    name: str = DEFAULT_POLICY_NAME
    min_reproduction_trials: int = 3
    min_reproduction_rate: float = 0.67
    require_independent_oracle: bool = True
    min_attribution_confidence: float = 0.70
    min_attribution_margin: float = 0.15
    min_intervention_trials: int = 3
    min_intervention_success_rate: float = 0.67
    require_isolated_intervention: bool = True
    max_changed_surfaces: int = 1
    min_positive_controls: int = 1
    min_positive_pass_rate: float = 1.0
    min_negative_controls: int = 1
    min_negative_pass_rate: float = 1.0
    min_regression_controls: int = 3
    min_regression_pass_rate: float = 0.98
    allow_critical_regressions: bool = False
    require_metrics_for_approval: bool = True
    max_cost_increase_ratio: float = 0.10
    max_latency_increase_ratio: float = 0.15
    block_on_metric_regression: bool = False


_INTEGER_FIELDS = {
    "min_reproduction_trials",
    "min_intervention_trials",
    "max_changed_surfaces",
    "min_positive_controls",
    "min_negative_controls",
    "min_regression_controls",
}
_RATE_FIELDS = {
    "min_reproduction_rate",
    "min_attribution_confidence",
    "min_attribution_margin",
    "min_intervention_success_rate",
    "min_positive_pass_rate",
    "min_negative_pass_rate",
    "min_regression_pass_rate",
}
_NONNEGATIVE_NUMBER_FIELDS = {
    "max_cost_increase_ratio",
    "max_latency_increase_ratio",
}
_BOOLEAN_FIELDS = {
    "require_independent_oracle",
    "require_isolated_intervention",
    "allow_critical_regressions",
    "require_metrics_for_approval",
    "block_on_metric_regression",
}


def _finite_float(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        converted = float(value)
    except OverflowError:
        return None
    return converted if math.isfinite(converted) else None


def parse_policy(document: Any | None) -> GatePolicy:
    """Parse a sparse policy override on top of the versioned defaults."""

    if document is None:
        return GatePolicy()
    issues: list[ValidationIssue] = []
    if not isinstance(document, dict):
        raise DocumentValidationError(
            "gate policy",
            [ValidationIssue("$", "must be an object")],
        )

    allowed = {field.name for field in dataclasses.fields(GatePolicy)}
    for key in sorted(document.keys() - allowed):
        issues.append(ValidationIssue(f"$.{key}", "is not allowed"))

    values: dict[str, Any] = {}
    for key, value in document.items():
        if key not in allowed:
            continue
        path = f"$.{key}"
        if key == "name":
            if not isinstance(value, str) or not value.strip():
                issues.append(ValidationIssue(path, "must be a non-empty string"))
            else:
                values[key] = value.strip()
        elif key in _INTEGER_FIELDS:
            if type(value) is not int or value < 1:
                issues.append(ValidationIssue(path, "must be an integer of at least 1"))
            else:
                values[key] = value
        elif key in _RATE_FIELDS:
            converted = _finite_float(value)
            if converted is None or not 0 <= converted <= 1:
                issues.append(ValidationIssue(path, "must be a number between 0 and 1"))
            else:
                values[key] = converted
        elif key in _NONNEGATIVE_NUMBER_FIELDS:
            converted = _finite_float(value)
            if converted is None or converted < 0:
                issues.append(ValidationIssue(path, "must be a non-negative number"))
            else:
                values[key] = converted
        elif key in _BOOLEAN_FIELDS:
            if type(value) is not bool:
                issues.append(ValidationIssue(path, "must be a boolean"))
            else:
                values[key] = value

    if issues:
        raise DocumentValidationError("gate policy", issues)
    return dataclasses.replace(GatePolicy(), **values)


def policy_to_dict(policy: GatePolicy) -> dict[str, Any]:
    """Serialize a policy for audit output."""

    return dataclasses.asdict(policy)
