"""Typed evidence-case and review-result models."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, TypeVar

from causure.constants import (
    CASE_SCHEMA_VERSION,
    CheckStatus,
    Component,
    Consequence,
    Decision,
    IncidentSeverity,
    OracleKind,
    RecommendedAction,
    RequirementStatus,
    ValidationKind,
)
from causure.errors import DocumentValidationError, ValidationIssue

_CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_EnumT = TypeVar("_EnumT", bound=Enum)


@dataclass(frozen=True, slots=True)
class Incident:
    claimed_failure: str
    expected_behavior: str
    observed_behavior: str
    severity: IncidentSeverity
    requirement_status: RequirementStatus
    source_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class Oracle:
    kind: OracleKind
    description: str
    independent: bool
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ReproductionTrial:
    trial_id: str = field(metadata={"wire_name": "id"})
    reproduced: bool
    evidence_ref: str


@dataclass(frozen=True, slots=True)
class Verification:
    oracle: Oracle
    reproduction_trials: tuple[ReproductionTrial, ...]


@dataclass(frozen=True, slots=True)
class InterventionTrial:
    trial_id: str = field(metadata={"wire_name": "id"})
    failure_resolved: bool
    evidence_ref: str


@dataclass(frozen=True, slots=True)
class Intervention:
    description: str
    isolated: bool
    held_constant: tuple[str, ...]
    trials: tuple[InterventionTrial, ...]


@dataclass(frozen=True, slots=True)
class Hypothesis:
    component: Component
    confidence: float
    evidence_refs: tuple[str, ...]
    intervention: Intervention | None = field(metadata={"omit_none": True})


@dataclass(frozen=True, slots=True)
class Attribution:
    hypotheses: tuple[Hypothesis, ...]


@dataclass(frozen=True, slots=True)
class ProposedChange:
    component: Component
    summary: str
    prediction: str
    expected_unaffected_behaviors: tuple[str, ...]
    known_risks: tuple[str, ...]
    changed_surface_count: int
    change_ref: str


@dataclass(frozen=True, slots=True)
class NullHypothesis:
    statement: str
    evidence_against: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValidationCase:
    case_id: str = field(metadata={"wire_name": "id"})
    kind: ValidationKind
    critical: bool
    baseline_passed: bool
    candidate_passed: bool
    evidence_ref: str


@dataclass(frozen=True, slots=True)
class MetricSnapshot:
    p95_latency_ms: float | None = field(metadata={"omit_none": True})
    mean_cost_usd: float | None = field(metadata={"omit_none": True})
    mean_tokens: float | None = field(metadata={"omit_none": True})


@dataclass(frozen=True, slots=True)
class MetricComparison:
    baseline: MetricSnapshot
    candidate: MetricSnapshot


@dataclass(frozen=True, slots=True)
class Validation:
    cases: tuple[ValidationCase, ...]
    metrics: MetricComparison | None


@dataclass(frozen=True, slots=True)
class ChangeCase:
    schema_version: str
    case_id: str
    title: str
    created_at: str
    incident: Incident
    verification: Verification
    attribution: Attribution
    proposed_change: ProposedChange
    null_hypothesis: NullHypothesis
    validation: Validation


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    status: CheckStatus
    consequence: Consequence
    message: str
    details: dict[str, Any]


@dataclass(frozen=True, slots=True)
class ReviewResult:
    schema_version: str
    engine_version: str
    policy_name: str
    case_id: str
    case_title: str
    component: Component
    input_sha256: str
    reviewed_at: str
    decision: Decision
    recommended_action: RecommendedAction
    summary: str
    metrics: dict[str, int | float | None]
    findings: tuple[Finding, ...]


def _object(
    value: Any,
    path: str,
    *,
    required: set[str],
    optional: set[str] | None,
    issues: list[ValidationIssue],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        issues.append(ValidationIssue(path, "must be an object"))
        return {}

    optional = optional or set()
    for key in sorted(required - value.keys()):
        issues.append(ValidationIssue(f"{path}.{key}", "is required"))
    for key in sorted(value.keys() - required - optional):
        issues.append(ValidationIssue(f"{path}.{key}", "is not allowed"))
    return value


def _string(
    value: Any,
    path: str,
    issues: list[ValidationIssue],
    *,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        issues.append(ValidationIssue(path, "must be a string"))
        return ""
    normalized = value.strip()
    if not allow_empty and not normalized:
        issues.append(ValidationIssue(path, "must not be empty"))
    try:
        normalized.encode("utf-8")
    except UnicodeEncodeError:
        issues.append(ValidationIssue(path, "must contain valid Unicode scalar values"))
    return normalized


def _boolean(value: Any, path: str, issues: list[ValidationIssue]) -> bool:
    if type(value) is not bool:
        issues.append(ValidationIssue(path, "must be a boolean"))
        return False
    return value


def _integer(
    value: Any,
    path: str,
    issues: list[ValidationIssue],
    *,
    minimum: int = 0,
) -> int:
    if type(value) is not int:
        issues.append(ValidationIssue(path, "must be an integer"))
        return minimum
    if value < minimum:
        issues.append(ValidationIssue(path, f"must be at least {minimum}"))
    return value


def _number(
    value: Any,
    path: str,
    issues: list[ValidationIssue],
    *,
    minimum: float = 0.0,
    maximum: float | None = None,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        issues.append(ValidationIssue(path, "must be a number"))
        return minimum
    try:
        converted = float(value)
    except OverflowError:
        issues.append(ValidationIssue(path, "must be a finite number"))
        return minimum
    if not math.isfinite(converted):
        issues.append(ValidationIssue(path, "must be a finite number"))
        return minimum
    if converted < minimum:
        issues.append(ValidationIssue(path, f"must be at least {minimum:g}"))
    if maximum is not None and converted > maximum:
        issues.append(ValidationIssue(path, f"must be at most {maximum:g}"))
    return converted


def _enum(
    value: Any,
    path: str,
    enum_type: type[_EnumT],
    issues: list[ValidationIssue],
) -> _EnumT:
    try:
        return enum_type(value)
    except (TypeError, ValueError):
        allowed = ", ".join(member.value for member in enum_type)
        issues.append(ValidationIssue(path, f"must be one of: {allowed}"))
        return next(iter(enum_type))


def _string_list(
    value: Any,
    path: str,
    issues: list[ValidationIssue],
    *,
    minimum_items: int = 0,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        issues.append(ValidationIssue(path, "must be an array"))
        return ()
    if len(value) < minimum_items:
        issues.append(ValidationIssue(path, f"must contain at least {minimum_items} item(s)"))
    items = tuple(_string(item, f"{path}[{index}]", issues) for index, item in enumerate(value))
    if len(set(items)) != len(items):
        issues.append(ValidationIssue(path, "must not contain duplicate values"))
    return items


def _timestamp(value: Any, path: str, issues: list[ValidationIssue]) -> str:
    result = _string(value, path, issues)
    if not result:
        return result
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
    except ValueError:
        issues.append(ValidationIssue(path, "must be an ISO 8601 timestamp with a timezone"))
    return result


def _parse_incident(value: Any, issues: list[ValidationIssue]) -> Incident:
    path = "$.incident"
    obj = _object(
        value,
        path,
        required={
            "claimed_failure",
            "expected_behavior",
            "observed_behavior",
            "severity",
            "requirement_status",
            "source_refs",
        },
        optional=None,
        issues=issues,
    )
    return Incident(
        claimed_failure=_string(obj.get("claimed_failure"), f"{path}.claimed_failure", issues),
        expected_behavior=_string(
            obj.get("expected_behavior"),
            f"{path}.expected_behavior",
            issues,
        ),
        observed_behavior=_string(
            obj.get("observed_behavior"),
            f"{path}.observed_behavior",
            issues,
        ),
        severity=_enum(obj.get("severity"), f"{path}.severity", IncidentSeverity, issues),
        requirement_status=_enum(
            obj.get("requirement_status"),
            f"{path}.requirement_status",
            RequirementStatus,
            issues,
        ),
        source_refs=_string_list(
            obj.get("source_refs"),
            f"{path}.source_refs",
            issues,
            minimum_items=1,
        ),
    )


def _parse_oracle(value: Any, issues: list[ValidationIssue]) -> Oracle:
    path = "$.verification.oracle"
    obj = _object(
        value,
        path,
        required={"kind", "description", "independent", "evidence_refs"},
        optional=None,
        issues=issues,
    )
    return Oracle(
        kind=_enum(obj.get("kind"), f"{path}.kind", OracleKind, issues),
        description=_string(obj.get("description"), f"{path}.description", issues),
        independent=_boolean(obj.get("independent"), f"{path}.independent", issues),
        evidence_refs=_string_list(
            obj.get("evidence_refs"),
            f"{path}.evidence_refs",
            issues,
            minimum_items=1,
        ),
    )


def _parse_reproduction_trial(
    value: Any,
    index: int,
    issues: list[ValidationIssue],
) -> ReproductionTrial:
    path = f"$.verification.reproduction_trials[{index}]"
    obj = _object(
        value,
        path,
        required={"id", "reproduced", "evidence_ref"},
        optional=None,
        issues=issues,
    )
    return ReproductionTrial(
        trial_id=_string(obj.get("id"), f"{path}.id", issues),
        reproduced=_boolean(obj.get("reproduced"), f"{path}.reproduced", issues),
        evidence_ref=_string(obj.get("evidence_ref"), f"{path}.evidence_ref", issues),
    )


def _parse_verification(value: Any, issues: list[ValidationIssue]) -> Verification:
    path = "$.verification"
    obj = _object(
        value,
        path,
        required={"oracle", "reproduction_trials"},
        optional=None,
        issues=issues,
    )
    trials_value = obj.get("reproduction_trials")
    if not isinstance(trials_value, list):
        issues.append(ValidationIssue(f"{path}.reproduction_trials", "must be an array"))
        trials_value = []
    trials = tuple(
        _parse_reproduction_trial(trial, index, issues) for index, trial in enumerate(trials_value)
    )
    trial_ids = [trial.trial_id for trial in trials]
    if len(trial_ids) != len(set(trial_ids)):
        issues.append(ValidationIssue(f"{path}.reproduction_trials", "trial ids must be unique"))
    return Verification(oracle=_parse_oracle(obj.get("oracle"), issues), reproduction_trials=trials)


def _parse_intervention(
    value: Any,
    hypothesis_index: int,
    issues: list[ValidationIssue],
) -> Intervention:
    path = f"$.attribution.hypotheses[{hypothesis_index}].intervention"
    obj = _object(
        value,
        path,
        required={"description", "isolated", "held_constant", "trials"},
        optional=None,
        issues=issues,
    )
    trials_value = obj.get("trials")
    if not isinstance(trials_value, list):
        issues.append(ValidationIssue(f"{path}.trials", "must be an array"))
        trials_value = []
    trials: list[InterventionTrial] = []
    for index, trial_value in enumerate(trials_value):
        trial_path = f"{path}.trials[{index}]"
        trial_obj = _object(
            trial_value,
            trial_path,
            required={"id", "failure_resolved", "evidence_ref"},
            optional=None,
            issues=issues,
        )
        trials.append(
            InterventionTrial(
                trial_id=_string(trial_obj.get("id"), f"{trial_path}.id", issues),
                failure_resolved=_boolean(
                    trial_obj.get("failure_resolved"),
                    f"{trial_path}.failure_resolved",
                    issues,
                ),
                evidence_ref=_string(
                    trial_obj.get("evidence_ref"),
                    f"{trial_path}.evidence_ref",
                    issues,
                ),
            )
        )
    trial_ids = [trial.trial_id for trial in trials]
    if len(trial_ids) != len(set(trial_ids)):
        issues.append(ValidationIssue(f"{path}.trials", "trial ids must be unique"))
    return Intervention(
        description=_string(obj.get("description"), f"{path}.description", issues),
        isolated=_boolean(obj.get("isolated"), f"{path}.isolated", issues),
        held_constant=_string_list(
            obj.get("held_constant"),
            f"{path}.held_constant",
            issues,
            minimum_items=1,
        ),
        trials=tuple(trials),
    )


def _parse_attribution(value: Any, issues: list[ValidationIssue]) -> Attribution:
    path = "$.attribution"
    obj = _object(
        value,
        path,
        required={"hypotheses"},
        optional=None,
        issues=issues,
    )
    hypotheses_value = obj.get("hypotheses")
    if not isinstance(hypotheses_value, list):
        issues.append(ValidationIssue(f"{path}.hypotheses", "must be an array"))
        hypotheses_value = []
    hypotheses: list[Hypothesis] = []
    for index, hypothesis_value in enumerate(hypotheses_value):
        hypothesis_path = f"{path}.hypotheses[{index}]"
        hypothesis_obj = _object(
            hypothesis_value,
            hypothesis_path,
            required={"component", "confidence", "evidence_refs"},
            optional={"intervention"},
            issues=issues,
        )
        intervention_value = hypothesis_obj.get("intervention")
        hypotheses.append(
            Hypothesis(
                component=_enum(
                    hypothesis_obj.get("component"),
                    f"{hypothesis_path}.component",
                    Component,
                    issues,
                ),
                confidence=_number(
                    hypothesis_obj.get("confidence"),
                    f"{hypothesis_path}.confidence",
                    issues,
                    maximum=1.0,
                ),
                evidence_refs=_string_list(
                    hypothesis_obj.get("evidence_refs"),
                    f"{hypothesis_path}.evidence_refs",
                    issues,
                    minimum_items=1,
                ),
                intervention=(
                    _parse_intervention(intervention_value, index, issues)
                    if intervention_value is not None
                    else None
                ),
            )
        )
    components = [hypothesis.component for hypothesis in hypotheses]
    if len(components) != len(set(components)):
        issues.append(ValidationIssue(f"{path}.hypotheses", "components must be unique"))
    return Attribution(hypotheses=tuple(hypotheses))


def _parse_proposed_change(value: Any, issues: list[ValidationIssue]) -> ProposedChange:
    path = "$.proposed_change"
    obj = _object(
        value,
        path,
        required={
            "component",
            "summary",
            "prediction",
            "expected_unaffected_behaviors",
            "known_risks",
            "changed_surface_count",
            "change_ref",
        },
        optional=None,
        issues=issues,
    )
    return ProposedChange(
        component=_enum(obj.get("component"), f"{path}.component", Component, issues),
        summary=_string(obj.get("summary"), f"{path}.summary", issues),
        prediction=_string(obj.get("prediction"), f"{path}.prediction", issues),
        expected_unaffected_behaviors=_string_list(
            obj.get("expected_unaffected_behaviors"),
            f"{path}.expected_unaffected_behaviors",
            issues,
            minimum_items=1,
        ),
        known_risks=_string_list(obj.get("known_risks"), f"{path}.known_risks", issues),
        changed_surface_count=_integer(
            obj.get("changed_surface_count"),
            f"{path}.changed_surface_count",
            issues,
            minimum=1,
        ),
        change_ref=_string(obj.get("change_ref"), f"{path}.change_ref", issues),
    )


def _parse_null_hypothesis(value: Any, issues: list[ValidationIssue]) -> NullHypothesis:
    path = "$.null_hypothesis"
    obj = _object(
        value,
        path,
        required={"statement", "evidence_against"},
        optional=None,
        issues=issues,
    )
    return NullHypothesis(
        statement=_string(obj.get("statement"), f"{path}.statement", issues),
        evidence_against=_string_list(
            obj.get("evidence_against"),
            f"{path}.evidence_against",
            issues,
        ),
    )


def _parse_metric_snapshot(
    value: Any,
    path: str,
    issues: list[ValidationIssue],
) -> MetricSnapshot:
    obj = _object(
        value,
        path,
        required=set(),
        optional={"p95_latency_ms", "mean_cost_usd", "mean_tokens"},
        issues=issues,
    )

    def optional_number(field: str) -> float | None:
        if field not in obj:
            return None
        return _number(obj[field], f"{path}.{field}", issues)

    return MetricSnapshot(
        p95_latency_ms=optional_number("p95_latency_ms"),
        mean_cost_usd=optional_number("mean_cost_usd"),
        mean_tokens=optional_number("mean_tokens"),
    )


def _parse_validation(value: Any, issues: list[ValidationIssue]) -> Validation:
    path = "$.validation"
    obj = _object(
        value,
        path,
        required={"cases"},
        optional={"metrics"},
        issues=issues,
    )
    cases_value = obj.get("cases")
    if not isinstance(cases_value, list):
        issues.append(ValidationIssue(f"{path}.cases", "must be an array"))
        cases_value = []
    cases: list[ValidationCase] = []
    for index, case_value in enumerate(cases_value):
        case_path = f"{path}.cases[{index}]"
        case_obj = _object(
            case_value,
            case_path,
            required={
                "id",
                "kind",
                "critical",
                "baseline_passed",
                "candidate_passed",
                "evidence_ref",
            },
            optional=None,
            issues=issues,
        )
        cases.append(
            ValidationCase(
                case_id=_string(case_obj.get("id"), f"{case_path}.id", issues),
                kind=_enum(
                    case_obj.get("kind"),
                    f"{case_path}.kind",
                    ValidationKind,
                    issues,
                ),
                critical=_boolean(case_obj.get("critical"), f"{case_path}.critical", issues),
                baseline_passed=_boolean(
                    case_obj.get("baseline_passed"),
                    f"{case_path}.baseline_passed",
                    issues,
                ),
                candidate_passed=_boolean(
                    case_obj.get("candidate_passed"),
                    f"{case_path}.candidate_passed",
                    issues,
                ),
                evidence_ref=_string(
                    case_obj.get("evidence_ref"),
                    f"{case_path}.evidence_ref",
                    issues,
                ),
            )
        )
    case_ids = [case.case_id for case in cases]
    if len(case_ids) != len(set(case_ids)):
        issues.append(ValidationIssue(f"{path}.cases", "case ids must be unique"))

    metrics_value = obj.get("metrics")
    metrics: MetricComparison | None = None
    if metrics_value is not None:
        metrics_obj = _object(
            metrics_value,
            f"{path}.metrics",
            required={"baseline", "candidate"},
            optional=None,
            issues=issues,
        )
        metrics = MetricComparison(
            baseline=_parse_metric_snapshot(
                metrics_obj.get("baseline"),
                f"{path}.metrics.baseline",
                issues,
            ),
            candidate=_parse_metric_snapshot(
                metrics_obj.get("candidate"),
                f"{path}.metrics.candidate",
                issues,
            ),
        )
    return Validation(cases=tuple(cases), metrics=metrics)


def parse_change_case(document: Any) -> ChangeCase:
    """Validate and parse an untrusted JSON-compatible evidence document."""

    issues: list[ValidationIssue] = []
    obj = _object(
        document,
        "$",
        required={
            "schema_version",
            "case_id",
            "title",
            "created_at",
            "incident",
            "verification",
            "attribution",
            "proposed_change",
            "null_hypothesis",
            "validation",
        },
        optional=None,
        issues=issues,
    )

    schema_version = _string(obj.get("schema_version"), "$.schema_version", issues)
    if schema_version and schema_version != CASE_SCHEMA_VERSION:
        issues.append(
            ValidationIssue(
                "$.schema_version",
                f"unsupported version {schema_version!r}; expected {CASE_SCHEMA_VERSION!r}",
            )
        )

    case_id = _string(obj.get("case_id"), "$.case_id", issues)
    if case_id and not _CASE_ID_PATTERN.fullmatch(case_id):
        issues.append(
            ValidationIssue(
                "$.case_id",
                "must be 3-128 characters using letters, digits, dot, underscore, or hyphen",
            )
        )

    case = ChangeCase(
        schema_version=schema_version,
        case_id=case_id,
        title=_string(obj.get("title"), "$.title", issues),
        created_at=_timestamp(obj.get("created_at"), "$.created_at", issues),
        incident=_parse_incident(obj.get("incident"), issues),
        verification=_parse_verification(obj.get("verification"), issues),
        attribution=_parse_attribution(obj.get("attribution"), issues),
        proposed_change=_parse_proposed_change(obj.get("proposed_change"), issues),
        null_hypothesis=_parse_null_hypothesis(obj.get("null_hypothesis"), issues),
        validation=_parse_validation(obj.get("validation"), issues),
    )
    if issues:
        raise DocumentValidationError("change case", issues)
    return case


def to_jsonable(value: Any) -> Any:
    """Convert immutable domain models into JSON-compatible primitives."""

    if dataclasses.is_dataclass(value):
        result: dict[str, Any] = {}
        for model_field in dataclasses.fields(value):
            field_value = getattr(value, model_field.name)
            if field_value is None and model_field.metadata.get("omit_none"):
                continue
            wire_name = model_field.metadata.get("wire_name", model_field.name)
            result[wire_name] = to_jsonable(field_value)
        return result
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, tuple):
        return [to_jsonable(item) for item in value]
    if isinstance(value, list):
        return [to_jsonable(item) for item in value]
    if isinstance(value, dict):
        return {key: to_jsonable(item) for key, item in value.items()}
    return value


def document_sha256(value: Any) -> str:
    """Hash a document using canonical JSON encoding."""

    payload = json.dumps(
        to_jsonable(value),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()
