"""Evidence-bound post-deployment canary outcome comparison."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from statistics import NormalDist
from typing import Any

from causure.attestations import utc_timestamp
from causure.azure_devops import parse_review_result_bytes
from causure.constants import (
    CANARY_OBSERVATION_SCHEMA_VERSION,
    CANARY_POLICY_SCHEMA_VERSION,
    CANARY_RESULT_SCHEMA_VERSION,
    ENGINE_VERSION,
    CanaryAssignmentMethod,
    CanaryAssignmentUnit,
    CanaryDecision,
    CanaryMetricDirection,
    CanaryMetricStatus,
    CheckStatus,
    Decision,
    RecommendedAction,
)
from causure.io import InputDocumentError, parse_json_text
from causure.models import (
    ChangeCase,
    document_sha256,
    parse_change_case,
    to_jsonable,
)

MAX_CANARY_POLICY_BYTES = 256 * 1024
MAX_CANARY_OBSERVATION_BYTES = 2 * 1024 * 1024
MAX_CANARY_RESULT_BYTES = 2 * 1024 * 1024
MAX_CANARY_CHANGE_CASE_BYTES = 5 * 1024 * 1024
MAX_CANARY_REVIEW_RESULT_BYTES = 5 * 1024 * 1024
MAX_CANARY_METRICS = 50
MAX_CANARY_SAMPLE_COUNT = 1_000_000_000

_IDENTIFIER_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_REFERENCE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@#$%?=&-]{0,511}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_UTC_TIMESTAMP_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_BOUNDED_TEXT_PATTERN = re.compile(r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+$")


class CanaryValidationError(ValueError):
    """Raised when a canary boundary document or artifact binding is invalid."""

    def __init__(self, document_name: str, path: str, message: str) -> None:
        self.document_name = document_name
        self.path = path
        self.message = message
        super().__init__(f"Invalid {document_name} at {path}: {message}")


@dataclass(frozen=True, slots=True)
class CanaryMetricPolicy:
    metric_id: str
    direction: CanaryMetricDirection
    maximum_degradation: float


@dataclass(frozen=True, slots=True)
class CanaryPolicy:
    schema_version: str
    policy_id: str
    declared_at: str
    confidence_level: float
    maximum_looks: int
    minimum_observation_seconds: int
    minimum_sample_size_per_cohort: int
    evaluator_ref: str
    assignment_unit: CanaryAssignmentUnit
    assignment_method: CanaryAssignmentMethod
    require_sticky_assignment: bool
    metrics: tuple[CanaryMetricPolicy, ...]


@dataclass(frozen=True, slots=True)
class CanaryChangeBinding:
    case_id: str
    change_ref: str
    change_case_sha256: str
    review_result_sha256: str


@dataclass(frozen=True, slots=True)
class CanaryPolicyBinding:
    policy_id: str
    policy_sha256: str


@dataclass(frozen=True, slots=True)
class CanaryWindow:
    started_at: str
    ended_at: str


@dataclass(frozen=True, slots=True)
class CanaryAssignment:
    method: CanaryAssignmentMethod
    unit: CanaryAssignmentUnit
    sticky: bool
    cross_cohort_contamination_detected: bool


@dataclass(frozen=True, slots=True)
class CanaryMetricObservation:
    metric_id: str
    event_count: int


@dataclass(frozen=True, slots=True)
class CanaryCohort:
    deployment_ref: str
    sample_count: int
    evidence_ref: str
    metrics: tuple[CanaryMetricObservation, ...]


@dataclass(frozen=True, slots=True)
class CanaryObservation:
    schema_version: str
    comparison_id: str
    look_number: int
    observed_at: str
    change: CanaryChangeBinding
    policy: CanaryPolicyBinding
    window: CanaryWindow
    evaluator_ref: str
    assignment: CanaryAssignment
    baseline: CanaryCohort
    candidate: CanaryCohort


@dataclass(frozen=True, slots=True)
class CanaryCheck:
    code: str
    status: CheckStatus
    message: str


@dataclass(frozen=True, slots=True)
class CanaryMetricResult:
    metric_id: str
    direction: CanaryMetricDirection
    maximum_degradation: float
    baseline_rate: float
    candidate_rate: float
    observed_difference: float
    confidence_lower: float
    confidence_upper: float
    status: CanaryMetricStatus


@dataclass(frozen=True, slots=True)
class CanaryComparisonResult:
    schema_version: str
    engine_version: str
    comparison_id: str
    look_number: int
    maximum_looks: int
    case_id: str
    change_ref: str
    policy_id: str
    evaluator_ref: str
    assignment_method: CanaryAssignmentMethod
    assignment_unit: CanaryAssignmentUnit
    observation_sha256: str
    policy_sha256: str
    change_case_sha256: str
    review_result_sha256: str
    compared_at: str
    window_started_at: str
    window_ended_at: str
    observation_seconds: int
    baseline_deployment_ref: str
    candidate_deployment_ref: str
    baseline_sample_count: int
    candidate_sample_count: int
    confidence_level: float
    decision: CanaryDecision
    summary: str
    checks: tuple[CanaryCheck, ...]
    metrics: tuple[CanaryMetricResult, ...]


def _object(
    value: Any,
    *,
    document_name: str,
    path: str,
    required: set[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise CanaryValidationError(document_name, path, "expected an object")
    keys = set(value)
    missing = sorted(required - keys)
    if missing:
        raise CanaryValidationError(
            document_name,
            path,
            f"missing required field(s): {', '.join(missing)}",
        )
    unknown = sorted(keys - required)
    if unknown:
        raise CanaryValidationError(
            document_name,
            path,
            f"field(s) are not allowed: {', '.join(unknown)}",
        )
    return value


def _string(
    value: Any,
    *,
    document_name: str,
    path: str,
    pattern: re.Pattern[str],
    description: str,
) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise CanaryValidationError(document_name, path, description)
    return value


def _identifier(value: Any, *, document_name: str, path: str) -> str:
    return _string(
        value,
        document_name=document_name,
        path=path,
        pattern=_IDENTIFIER_PATTERN,
        description="expected a 3-128 character safe identifier",
    )


def _reference(value: Any, *, document_name: str, path: str) -> str:
    return _string(
        value,
        document_name=document_name,
        path=path,
        pattern=_REFERENCE_PATTERN,
        description="expected a 1-512 character bounded opaque reference",
    )


def _sha256(value: Any, *, document_name: str, path: str) -> str:
    return _string(
        value,
        document_name=document_name,
        path=path,
        pattern=_SHA256_PATTERN,
        description="expected a lowercase SHA-256 digest",
    )


def _timestamp(value: Any, *, document_name: str, path: str) -> str:
    result = _string(
        value,
        document_name=document_name,
        path=path,
        pattern=_UTC_TIMESTAMP_PATTERN,
        description="expected a UTC timestamp in YYYY-MM-DDTHH:MM:SSZ form",
    )
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CanaryValidationError(
            document_name,
            path,
            "expected a real UTC timestamp in YYYY-MM-DDTHH:MM:SSZ form",
        ) from exc
    if (
        parsed.tzinfo is None
        or parsed.utcoffset() is None
        or parsed.utcoffset().total_seconds() != 0
    ):
        raise CanaryValidationError(document_name, path, "expected a UTC timestamp")
    return result


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _integer(
    value: Any,
    *,
    document_name: str,
    path: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise CanaryValidationError(
            document_name,
            path,
            f"expected an integer from {minimum} through {maximum}",
        )
    return value


def _number(
    value: Any,
    *,
    document_name: str,
    path: str,
    minimum: float,
    maximum: float,
) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise CanaryValidationError(
            document_name,
            path,
            f"expected a number from {minimum:g} through {maximum:g}",
        )
    try:
        result = float(value)
    except OverflowError as exc:
        raise CanaryValidationError(
            document_name,
            path,
            f"expected a number from {minimum:g} through {maximum:g}",
        ) from exc
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise CanaryValidationError(
            document_name,
            path,
            f"expected a number from {minimum:g} through {maximum:g}",
        )
    return result


def _boolean(value: Any, *, document_name: str, path: str) -> bool:
    if type(value) is not bool:
        raise CanaryValidationError(document_name, path, "expected a boolean")
    return value


def _enum(
    value: Any,
    *,
    document_name: str,
    path: str,
    enum_type: type,
) -> Any:
    if not isinstance(value, str):
        raise CanaryValidationError(document_name, path, "expected a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in enum_type)
        raise CanaryValidationError(
            document_name,
            path,
            f"expected one of: {allowed}",
        ) from exc


def _parse_json_bytes(
    raw_bytes: bytes,
    *,
    document_name: str,
    maximum: int,
) -> Any:
    if not isinstance(raw_bytes, bytes):
        raise TypeError(f"{document_name}_bytes must be bytes")
    if not 1 <= len(raw_bytes) <= maximum:
        raise CanaryValidationError(
            document_name,
            "$",
            f"expected from 1 to {maximum} bytes",
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise CanaryValidationError(document_name, "$", "document is not valid UTF-8") from exc
    try:
        return parse_json_text(text, source=document_name, max_bytes=maximum)
    except InputDocumentError as exc:
        raise CanaryValidationError(document_name, "$", str(exc)) from exc


def parse_canary_policy(document: Any) -> CanaryPolicy:
    """Strictly parse a predeclared canary policy document."""

    name = "canary policy"
    root = _object(
        document,
        document_name=name,
        path="$",
        required={
            "schema_version",
            "policy_id",
            "declared_at",
            "confidence_level",
            "maximum_looks",
            "minimum_observation_seconds",
            "minimum_sample_size_per_cohort",
            "evaluator_ref",
            "assignment_unit",
            "assignment_method",
            "require_sticky_assignment",
            "metrics",
        },
    )
    if root["schema_version"] != CANARY_POLICY_SCHEMA_VERSION:
        raise CanaryValidationError(name, "$.schema_version", "unsupported schema version")

    metrics_value = root["metrics"]
    if not isinstance(metrics_value, list) or not 1 <= len(metrics_value) <= MAX_CANARY_METRICS:
        raise CanaryValidationError(
            name,
            "$.metrics",
            f"expected from 1 to {MAX_CANARY_METRICS} metrics",
        )
    metrics: list[CanaryMetricPolicy] = []
    for index, value in enumerate(metrics_value):
        path = f"$.metrics[{index}]"
        item = _object(
            value,
            document_name=name,
            path=path,
            required={"metric_id", "direction", "maximum_degradation"},
        )
        metrics.append(
            CanaryMetricPolicy(
                metric_id=_identifier(
                    item["metric_id"],
                    document_name=name,
                    path=f"{path}.metric_id",
                ),
                direction=_enum(
                    item["direction"],
                    document_name=name,
                    path=f"{path}.direction",
                    enum_type=CanaryMetricDirection,
                ),
                maximum_degradation=_number(
                    item["maximum_degradation"],
                    document_name=name,
                    path=f"{path}.maximum_degradation",
                    minimum=0.0,
                    maximum=1.0,
                ),
            )
        )
    metric_ids = [metric.metric_id for metric in metrics]
    if len(set(metric_ids)) != len(metric_ids):
        raise CanaryValidationError(name, "$.metrics", "metric IDs must be unique")

    return CanaryPolicy(
        schema_version=CANARY_POLICY_SCHEMA_VERSION,
        policy_id=_identifier(root["policy_id"], document_name=name, path="$.policy_id"),
        declared_at=_timestamp(root["declared_at"], document_name=name, path="$.declared_at"),
        confidence_level=_number(
            root["confidence_level"],
            document_name=name,
            path="$.confidence_level",
            minimum=0.90,
            maximum=0.999,
        ),
        maximum_looks=_integer(
            root["maximum_looks"],
            document_name=name,
            path="$.maximum_looks",
            minimum=1,
            maximum=100,
        ),
        minimum_observation_seconds=_integer(
            root["minimum_observation_seconds"],
            document_name=name,
            path="$.minimum_observation_seconds",
            minimum=60,
            maximum=2_592_000,
        ),
        minimum_sample_size_per_cohort=_integer(
            root["minimum_sample_size_per_cohort"],
            document_name=name,
            path="$.minimum_sample_size_per_cohort",
            minimum=30,
            maximum=MAX_CANARY_SAMPLE_COUNT,
        ),
        evaluator_ref=_reference(
            root["evaluator_ref"],
            document_name=name,
            path="$.evaluator_ref",
        ),
        assignment_unit=_enum(
            root["assignment_unit"],
            document_name=name,
            path="$.assignment_unit",
            enum_type=CanaryAssignmentUnit,
        ),
        assignment_method=_enum(
            root["assignment_method"],
            document_name=name,
            path="$.assignment_method",
            enum_type=CanaryAssignmentMethod,
        ),
        require_sticky_assignment=_boolean(
            root["require_sticky_assignment"],
            document_name=name,
            path="$.require_sticky_assignment",
        ),
        metrics=tuple(metrics),
    )


def parse_canary_policy_bytes(raw_bytes: bytes) -> CanaryPolicy:
    """Parse an exact bounded UTF-8 canary policy."""

    return parse_canary_policy(
        _parse_json_bytes(
            raw_bytes,
            document_name="canary policy",
            maximum=MAX_CANARY_POLICY_BYTES,
        )
    )


def _parse_metric_observations(
    value: Any,
    *,
    document_name: str,
    path: str,
    sample_count: int,
) -> tuple[CanaryMetricObservation, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= MAX_CANARY_METRICS:
        raise CanaryValidationError(
            document_name,
            path,
            f"expected from 1 to {MAX_CANARY_METRICS} metrics",
        )
    metrics: list[CanaryMetricObservation] = []
    for index, metric_value in enumerate(value):
        metric_path = f"{path}[{index}]"
        item = _object(
            metric_value,
            document_name=document_name,
            path=metric_path,
            required={"metric_id", "event_count"},
        )
        metrics.append(
            CanaryMetricObservation(
                metric_id=_identifier(
                    item["metric_id"],
                    document_name=document_name,
                    path=f"{metric_path}.metric_id",
                ),
                event_count=_integer(
                    item["event_count"],
                    document_name=document_name,
                    path=f"{metric_path}.event_count",
                    minimum=0,
                    maximum=sample_count,
                ),
            )
        )
    metric_ids = [metric.metric_id for metric in metrics]
    if len(set(metric_ids)) != len(metric_ids):
        raise CanaryValidationError(document_name, path, "metric IDs must be unique")
    return tuple(metrics)


def _parse_cohort(
    value: Any,
    *,
    document_name: str,
    path: str,
) -> CanaryCohort:
    item = _object(
        value,
        document_name=document_name,
        path=path,
        required={"deployment_ref", "sample_count", "evidence_ref", "metrics"},
    )
    sample_count = _integer(
        item["sample_count"],
        document_name=document_name,
        path=f"{path}.sample_count",
        minimum=1,
        maximum=MAX_CANARY_SAMPLE_COUNT,
    )
    return CanaryCohort(
        deployment_ref=_reference(
            item["deployment_ref"],
            document_name=document_name,
            path=f"{path}.deployment_ref",
        ),
        sample_count=sample_count,
        evidence_ref=_reference(
            item["evidence_ref"],
            document_name=document_name,
            path=f"{path}.evidence_ref",
        ),
        metrics=_parse_metric_observations(
            item["metrics"],
            document_name=document_name,
            path=f"{path}.metrics",
            sample_count=sample_count,
        ),
    )


def parse_canary_observation(document: Any) -> CanaryObservation:
    """Strictly parse a bounded two-cohort canary observation."""

    name = "canary observation"
    root = _object(
        document,
        document_name=name,
        path="$",
        required={
            "schema_version",
            "comparison_id",
            "look_number",
            "observed_at",
            "change",
            "policy",
            "window",
            "evaluator_ref",
            "assignment",
            "baseline",
            "candidate",
        },
    )
    if root["schema_version"] != CANARY_OBSERVATION_SCHEMA_VERSION:
        raise CanaryValidationError(name, "$.schema_version", "unsupported schema version")
    change = _object(
        root["change"],
        document_name=name,
        path="$.change",
        required={
            "case_id",
            "change_ref",
            "change_case_sha256",
            "review_result_sha256",
        },
    )
    policy = _object(
        root["policy"],
        document_name=name,
        path="$.policy",
        required={"policy_id", "policy_sha256"},
    )
    window = _object(
        root["window"],
        document_name=name,
        path="$.window",
        required={"started_at", "ended_at"},
    )
    assignment = _object(
        root["assignment"],
        document_name=name,
        path="$.assignment",
        required={
            "method",
            "unit",
            "sticky",
            "cross_cohort_contamination_detected",
        },
    )
    observation = CanaryObservation(
        schema_version=CANARY_OBSERVATION_SCHEMA_VERSION,
        comparison_id=_identifier(
            root["comparison_id"],
            document_name=name,
            path="$.comparison_id",
        ),
        look_number=_integer(
            root["look_number"],
            document_name=name,
            path="$.look_number",
            minimum=1,
            maximum=100,
        ),
        observed_at=_timestamp(root["observed_at"], document_name=name, path="$.observed_at"),
        change=CanaryChangeBinding(
            case_id=_identifier(
                change["case_id"],
                document_name=name,
                path="$.change.case_id",
            ),
            change_ref=_reference(
                change["change_ref"],
                document_name=name,
                path="$.change.change_ref",
            ),
            change_case_sha256=_sha256(
                change["change_case_sha256"],
                document_name=name,
                path="$.change.change_case_sha256",
            ),
            review_result_sha256=_sha256(
                change["review_result_sha256"],
                document_name=name,
                path="$.change.review_result_sha256",
            ),
        ),
        policy=CanaryPolicyBinding(
            policy_id=_identifier(
                policy["policy_id"],
                document_name=name,
                path="$.policy.policy_id",
            ),
            policy_sha256=_sha256(
                policy["policy_sha256"],
                document_name=name,
                path="$.policy.policy_sha256",
            ),
        ),
        window=CanaryWindow(
            started_at=_timestamp(
                window["started_at"],
                document_name=name,
                path="$.window.started_at",
            ),
            ended_at=_timestamp(
                window["ended_at"],
                document_name=name,
                path="$.window.ended_at",
            ),
        ),
        evaluator_ref=_reference(
            root["evaluator_ref"],
            document_name=name,
            path="$.evaluator_ref",
        ),
        assignment=CanaryAssignment(
            method=_enum(
                assignment["method"],
                document_name=name,
                path="$.assignment.method",
                enum_type=CanaryAssignmentMethod,
            ),
            unit=_enum(
                assignment["unit"],
                document_name=name,
                path="$.assignment.unit",
                enum_type=CanaryAssignmentUnit,
            ),
            sticky=_boolean(
                assignment["sticky"],
                document_name=name,
                path="$.assignment.sticky",
            ),
            cross_cohort_contamination_detected=_boolean(
                assignment["cross_cohort_contamination_detected"],
                document_name=name,
                path="$.assignment.cross_cohort_contamination_detected",
            ),
        ),
        baseline=_parse_cohort(
            root["baseline"],
            document_name=name,
            path="$.baseline",
        ),
        candidate=_parse_cohort(
            root["candidate"],
            document_name=name,
            path="$.candidate",
        ),
    )
    started = _timestamp_value(observation.window.started_at)
    ended = _timestamp_value(observation.window.ended_at)
    observed = _timestamp_value(observation.observed_at)
    if ended <= started:
        raise CanaryValidationError(
            name,
            "$.window",
            "ended_at must be later than started_at",
        )
    if (ended - started).total_seconds() > 2_592_000:
        raise CanaryValidationError(
            name,
            "$.window",
            "observation window must not exceed 2592000 seconds",
        )
    if observed < ended:
        raise CanaryValidationError(
            name,
            "$.observed_at",
            "must be at or after window.ended_at",
        )
    if observation.baseline.deployment_ref == observation.candidate.deployment_ref:
        raise CanaryValidationError(
            name,
            "$.candidate.deployment_ref",
            "baseline and candidate deployment references must differ",
        )
    return observation


def parse_canary_observation_bytes(raw_bytes: bytes) -> CanaryObservation:
    """Parse an exact bounded UTF-8 canary observation."""

    return parse_canary_observation(
        _parse_json_bytes(
            raw_bytes,
            document_name="canary observation",
            maximum=MAX_CANARY_OBSERVATION_BYTES,
        )
    )


def _bounded_text(
    value: Any,
    *,
    document_name: str,
    path: str,
    maximum: int = 8192,
) -> str:
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or _BOUNDED_TEXT_PATTERN.fullmatch(value) is None
    ):
        raise CanaryValidationError(
            document_name,
            path,
            f"expected from 1 to {maximum} printable characters",
        )
    return value


def parse_canary_result(document: Any) -> CanaryComparisonResult:
    """Strictly parse a deterministic canary comparison result."""

    name = "canary result"
    required = {
        "schema_version",
        "engine_version",
        "comparison_id",
        "look_number",
        "maximum_looks",
        "case_id",
        "change_ref",
        "policy_id",
        "evaluator_ref",
        "assignment_method",
        "assignment_unit",
        "observation_sha256",
        "policy_sha256",
        "change_case_sha256",
        "review_result_sha256",
        "compared_at",
        "window_started_at",
        "window_ended_at",
        "observation_seconds",
        "baseline_deployment_ref",
        "candidate_deployment_ref",
        "baseline_sample_count",
        "candidate_sample_count",
        "confidence_level",
        "decision",
        "summary",
        "checks",
        "metrics",
    }
    root = _object(document, document_name=name, path="$", required=required)
    if root["schema_version"] != CANARY_RESULT_SCHEMA_VERSION:
        raise CanaryValidationError(
            name,
            "$.schema_version",
            f"expected {CANARY_RESULT_SCHEMA_VERSION!r}",
        )

    look_number = _integer(
        root["look_number"],
        document_name=name,
        path="$.look_number",
        minimum=1,
        maximum=100,
    )
    maximum_looks = _integer(
        root["maximum_looks"],
        document_name=name,
        path="$.maximum_looks",
        minimum=1,
        maximum=100,
    )
    if look_number > maximum_looks:
        raise CanaryValidationError(
            name,
            "$.look_number",
            "must not exceed maximum_looks",
        )

    started_at = _timestamp(
        root["window_started_at"], document_name=name, path="$.window_started_at"
    )
    ended_at = _timestamp(root["window_ended_at"], document_name=name, path="$.window_ended_at")
    compared_at = _timestamp(root["compared_at"], document_name=name, path="$.compared_at")
    if not _timestamp_value(started_at) < _timestamp_value(ended_at):
        raise CanaryValidationError(name, "$.window_ended_at", "must be after window_started_at")
    if _timestamp_value(compared_at) < _timestamp_value(ended_at):
        raise CanaryValidationError(name, "$.compared_at", "must be at or after window_ended_at")
    observation_seconds = _integer(
        root["observation_seconds"],
        document_name=name,
        path="$.observation_seconds",
        minimum=1,
        maximum=2_592_000,
    )
    actual_seconds = int(
        (_timestamp_value(ended_at) - _timestamp_value(started_at)).total_seconds()
    )
    if observation_seconds != actual_seconds:
        raise CanaryValidationError(
            name,
            "$.observation_seconds",
            "must equal the exact observation-window duration",
        )

    checks_value = root["checks"]
    if not isinstance(checks_value, list) or len(checks_value) != 6:
        raise CanaryValidationError(name, "$.checks", "expected exactly 6 checks")
    checks: list[CanaryCheck] = []
    check_codes: set[str] = set()
    for index, value in enumerate(checks_value):
        path = f"$.checks[{index}]"
        item = _object(
            value,
            document_name=name,
            path=path,
            required={"code", "status", "message"},
        )
        code = _identifier(item["code"], document_name=name, path=f"{path}.code")
        if code in check_codes:
            raise CanaryValidationError(name, "$.checks", "check codes must be unique")
        check_codes.add(code)
        checks.append(
            CanaryCheck(
                code=code,
                status=_enum(
                    item["status"],
                    document_name=name,
                    path=f"{path}.status",
                    enum_type=CheckStatus,
                ),
                message=_bounded_text(
                    item["message"],
                    document_name=name,
                    path=f"{path}.message",
                ),
            )
        )

    metrics_value = root["metrics"]
    if not isinstance(metrics_value, list) or not 1 <= len(metrics_value) <= MAX_CANARY_METRICS:
        raise CanaryValidationError(
            name,
            "$.metrics",
            f"expected from 1 to {MAX_CANARY_METRICS} metrics",
        )
    metrics: list[CanaryMetricResult] = []
    metric_ids: set[str] = set()
    for index, value in enumerate(metrics_value):
        path = f"$.metrics[{index}]"
        item = _object(
            value,
            document_name=name,
            path=path,
            required={
                "metric_id",
                "direction",
                "maximum_degradation",
                "baseline_rate",
                "candidate_rate",
                "observed_difference",
                "confidence_lower",
                "confidence_upper",
                "status",
            },
        )
        metric_id = _identifier(
            item["metric_id"],
            document_name=name,
            path=f"{path}.metric_id",
        )
        if metric_id in metric_ids:
            raise CanaryValidationError(name, "$.metrics", "metric ids must be unique")
        metric_ids.add(metric_id)
        baseline_rate = _number(
            item["baseline_rate"],
            document_name=name,
            path=f"{path}.baseline_rate",
            minimum=0,
            maximum=1,
        )
        candidate_rate = _number(
            item["candidate_rate"],
            document_name=name,
            path=f"{path}.candidate_rate",
            minimum=0,
            maximum=1,
        )
        observed_difference = _number(
            item["observed_difference"],
            document_name=name,
            path=f"{path}.observed_difference",
            minimum=-1,
            maximum=1,
        )
        if abs(observed_difference - _rounded(candidate_rate - baseline_rate)) > 1e-11:
            raise CanaryValidationError(
                name,
                f"{path}.observed_difference",
                "must equal candidate_rate minus baseline_rate",
            )
        confidence_lower = _number(
            item["confidence_lower"],
            document_name=name,
            path=f"{path}.confidence_lower",
            minimum=-1,
            maximum=1,
        )
        confidence_upper = _number(
            item["confidence_upper"],
            document_name=name,
            path=f"{path}.confidence_upper",
            minimum=-1,
            maximum=1,
        )
        if confidence_lower > confidence_upper:
            raise CanaryValidationError(
                name,
                f"{path}.confidence_lower",
                "must not exceed confidence_upper",
            )
        metrics.append(
            CanaryMetricResult(
                metric_id=metric_id,
                direction=_enum(
                    item["direction"],
                    document_name=name,
                    path=f"{path}.direction",
                    enum_type=CanaryMetricDirection,
                ),
                maximum_degradation=_number(
                    item["maximum_degradation"],
                    document_name=name,
                    path=f"{path}.maximum_degradation",
                    minimum=0,
                    maximum=1,
                ),
                baseline_rate=baseline_rate,
                candidate_rate=candidate_rate,
                observed_difference=observed_difference,
                confidence_lower=confidence_lower,
                confidence_upper=confidence_upper,
                status=_enum(
                    item["status"],
                    document_name=name,
                    path=f"{path}.status",
                    enum_type=CanaryMetricStatus,
                ),
            )
        )

    baseline_ref = _reference(
        root["baseline_deployment_ref"],
        document_name=name,
        path="$.baseline_deployment_ref",
    )
    candidate_ref = _reference(
        root["candidate_deployment_ref"],
        document_name=name,
        path="$.candidate_deployment_ref",
    )
    if baseline_ref == candidate_ref:
        raise CanaryValidationError(
            name,
            "$.candidate_deployment_ref",
            "baseline and candidate deployment references must differ",
        )

    return CanaryComparisonResult(
        schema_version=CANARY_RESULT_SCHEMA_VERSION,
        engine_version=_bounded_text(
            root["engine_version"], document_name=name, path="$.engine_version", maximum=128
        ),
        comparison_id=_identifier(
            root["comparison_id"], document_name=name, path="$.comparison_id"
        ),
        look_number=look_number,
        maximum_looks=maximum_looks,
        case_id=_identifier(root["case_id"], document_name=name, path="$.case_id"),
        change_ref=_reference(root["change_ref"], document_name=name, path="$.change_ref"),
        policy_id=_identifier(root["policy_id"], document_name=name, path="$.policy_id"),
        evaluator_ref=_reference(root["evaluator_ref"], document_name=name, path="$.evaluator_ref"),
        assignment_method=_enum(
            root["assignment_method"],
            document_name=name,
            path="$.assignment_method",
            enum_type=CanaryAssignmentMethod,
        ),
        assignment_unit=_enum(
            root["assignment_unit"],
            document_name=name,
            path="$.assignment_unit",
            enum_type=CanaryAssignmentUnit,
        ),
        observation_sha256=_sha256(
            root["observation_sha256"], document_name=name, path="$.observation_sha256"
        ),
        policy_sha256=_sha256(root["policy_sha256"], document_name=name, path="$.policy_sha256"),
        change_case_sha256=_sha256(
            root["change_case_sha256"], document_name=name, path="$.change_case_sha256"
        ),
        review_result_sha256=_sha256(
            root["review_result_sha256"], document_name=name, path="$.review_result_sha256"
        ),
        compared_at=compared_at,
        window_started_at=started_at,
        window_ended_at=ended_at,
        observation_seconds=observation_seconds,
        baseline_deployment_ref=baseline_ref,
        candidate_deployment_ref=candidate_ref,
        baseline_sample_count=_integer(
            root["baseline_sample_count"],
            document_name=name,
            path="$.baseline_sample_count",
            minimum=1,
            maximum=MAX_CANARY_SAMPLE_COUNT,
        ),
        candidate_sample_count=_integer(
            root["candidate_sample_count"],
            document_name=name,
            path="$.candidate_sample_count",
            minimum=1,
            maximum=MAX_CANARY_SAMPLE_COUNT,
        ),
        confidence_level=_number(
            root["confidence_level"],
            document_name=name,
            path="$.confidence_level",
            minimum=0.90,
            maximum=0.999,
        ),
        decision=_enum(
            root["decision"],
            document_name=name,
            path="$.decision",
            enum_type=CanaryDecision,
        ),
        summary=_bounded_text(root["summary"], document_name=name, path="$.summary"),
        checks=tuple(checks),
        metrics=tuple(metrics),
    )


def parse_canary_result_bytes(raw_bytes: bytes) -> CanaryComparisonResult:
    """Parse exact bounded UTF-8 canary comparison-result bytes."""

    return parse_canary_result(
        _parse_json_bytes(
            raw_bytes,
            document_name="canary result",
            maximum=MAX_CANARY_RESULT_BYTES,
        )
    )


def _parse_change_case_bytes(raw_bytes: bytes) -> ChangeCase:
    document = _parse_json_bytes(
        raw_bytes,
        document_name="change case",
        maximum=MAX_CANARY_CHANGE_CASE_BYTES,
    )
    try:
        return parse_change_case(document)
    except ValueError as exc:
        raise CanaryValidationError(
            "change case", "$", "document is not a valid change case"
        ) from exc


def _rounded(value: float) -> float:
    result = round(value, 12)
    return 0.0 if result == 0 else result


def _wilson_interval(event_count: int, sample_count: int, z_score: float) -> tuple[float, float]:
    rate = event_count / sample_count
    z_squared = z_score * z_score
    denominator = 1.0 + (z_squared / sample_count)
    center = (rate + (z_squared / (2.0 * sample_count))) / denominator
    margin = (
        z_score
        * math.sqrt(
            (rate * (1.0 - rate) / sample_count) + (z_squared / (4.0 * sample_count * sample_count))
        )
        / denominator
    )
    return max(0.0, center - margin), min(1.0, center + margin)


def _metric_result(
    policy: CanaryMetricPolicy,
    *,
    baseline: CanaryMetricObservation,
    baseline_sample_count: int,
    candidate: CanaryMetricObservation,
    candidate_sample_count: int,
    confidence_level: float,
    simultaneous_comparisons: int,
) -> CanaryMetricResult:
    alpha = 1.0 - confidence_level
    z_score = NormalDist().inv_cdf(1.0 - (alpha / (4.0 * simultaneous_comparisons)))
    baseline_lower, baseline_upper = _wilson_interval(
        baseline.event_count,
        baseline_sample_count,
        z_score,
    )
    candidate_lower, candidate_upper = _wilson_interval(
        candidate.event_count,
        candidate_sample_count,
        z_score,
    )
    lower = candidate_lower - baseline_upper
    upper = candidate_upper - baseline_lower
    baseline_rate = baseline.event_count / baseline_sample_count
    candidate_rate = candidate.event_count / candidate_sample_count
    difference = candidate_rate - baseline_rate
    if policy.direction is CanaryMetricDirection.HIGHER:
        boundary = -policy.maximum_degradation
        if lower >= boundary:
            status = CanaryMetricStatus.NONINFERIOR
        elif upper < boundary:
            status = CanaryMetricStatus.REGRESSION
        else:
            status = CanaryMetricStatus.INCONCLUSIVE
    else:
        boundary = policy.maximum_degradation
        if upper <= boundary:
            status = CanaryMetricStatus.NONINFERIOR
        elif lower > boundary:
            status = CanaryMetricStatus.REGRESSION
        else:
            status = CanaryMetricStatus.INCONCLUSIVE
    return CanaryMetricResult(
        metric_id=policy.metric_id,
        direction=policy.direction,
        maximum_degradation=_rounded(policy.maximum_degradation),
        baseline_rate=_rounded(baseline_rate),
        candidate_rate=_rounded(candidate_rate),
        observed_difference=_rounded(difference),
        confidence_lower=_rounded(lower),
        confidence_upper=_rounded(upper),
        status=status,
    )


def _metric_map(
    cohort: CanaryCohort,
    *,
    expected_metric_ids: set[str],
    path: str,
) -> dict[str, CanaryMetricObservation]:
    metrics = {metric.metric_id: metric for metric in cohort.metrics}
    actual = set(metrics)
    missing = sorted(expected_metric_ids - actual)
    unknown = sorted(actual - expected_metric_ids)
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing metric(s): {', '.join(missing)}")
        if unknown:
            details.append(f"unknown metric(s): {', '.join(unknown)}")
        raise CanaryValidationError("canary observation", path, "; ".join(details))
    return metrics


def compare_canary_outcomes(
    observation_bytes: bytes,
    policy_bytes: bytes,
    change_case_bytes: bytes,
    review_result_bytes: bytes,
    *,
    compared_at: datetime | None = None,
) -> CanaryComparisonResult:
    """Compare exact baseline/candidate observations against a predeclared policy."""

    observation = parse_canary_observation_bytes(observation_bytes)
    policy = parse_canary_policy_bytes(policy_bytes)
    change_case = _parse_change_case_bytes(change_case_bytes)
    if not isinstance(review_result_bytes, bytes):
        raise TypeError("review_result_bytes must be bytes")
    if not 1 <= len(review_result_bytes) <= MAX_CANARY_REVIEW_RESULT_BYTES:
        raise CanaryValidationError(
            "review result",
            "$",
            f"expected from 1 to {MAX_CANARY_REVIEW_RESULT_BYTES} bytes",
        )
    try:
        review = parse_review_result_bytes(review_result_bytes)
    except ValueError as exc:
        raise CanaryValidationError(
            "review result",
            "$",
            "document is not a valid closed review result",
        ) from exc

    policy_sha256 = hashlib.sha256(policy_bytes).hexdigest()
    review_sha256 = hashlib.sha256(review_result_bytes).hexdigest()
    change_case_sha256 = document_sha256(change_case)
    if observation.policy.policy_id != policy.policy_id:
        raise CanaryValidationError(
            "canary observation",
            "$.policy.policy_id",
            "does not match the supplied canary policy",
        )
    if observation.policy.policy_sha256 != policy_sha256:
        raise CanaryValidationError(
            "canary observation",
            "$.policy.policy_sha256",
            "does not match the exact supplied canary policy bytes",
        )
    if observation.change.case_id != change_case.case_id:
        raise CanaryValidationError(
            "canary observation",
            "$.change.case_id",
            "does not match the supplied change case",
        )
    if observation.change.change_ref != change_case.proposed_change.change_ref:
        raise CanaryValidationError(
            "canary observation",
            "$.change.change_ref",
            "does not match the supplied change case",
        )
    if observation.change.change_case_sha256 != change_case_sha256:
        raise CanaryValidationError(
            "canary observation",
            "$.change.change_case_sha256",
            "does not match the canonical supplied change case",
        )
    if observation.change.review_result_sha256 != review_sha256:
        raise CanaryValidationError(
            "canary observation",
            "$.change.review_result_sha256",
            "does not match the exact supplied review-result bytes",
        )
    if (
        review.case_id != change_case.case_id
        or review.input_sha256 != change_case_sha256
        or review.component is not change_case.proposed_change.component
    ):
        raise CanaryValidationError(
            "review result",
            "$",
            "does not bind the supplied change case",
        )
    if review.decision not in {Decision.APPROVE, Decision.CONDITIONAL_PASS}:
        raise CanaryValidationError(
            "review result",
            "$.decision",
            "only an approved or conditional patch can enter canary comparison",
        )
    if review.recommended_action is not RecommendedAction.PATCH:
        raise CanaryValidationError(
            "review result",
            "$.recommended_action",
            "the reviewed action must be patch",
        )
    if observation.look_number > policy.maximum_looks:
        raise CanaryValidationError(
            "canary observation",
            "$.look_number",
            "exceeds the predeclared maximum number of looks",
        )
    if observation.evaluator_ref != policy.evaluator_ref:
        raise CanaryValidationError(
            "canary observation",
            "$.evaluator_ref",
            "does not match the predeclared evaluator reference",
        )
    if observation.assignment.unit is not policy.assignment_unit:
        raise CanaryValidationError(
            "canary observation",
            "$.assignment.unit",
            "does not match the predeclared assignment unit",
        )
    if observation.assignment.method is not policy.assignment_method:
        raise CanaryValidationError(
            "canary observation",
            "$.assignment.method",
            "does not match the predeclared assignment method",
        )

    policy_declared = _timestamp_value(policy.declared_at)
    window_started = _timestamp_value(observation.window.started_at)
    window_ended = _timestamp_value(observation.window.ended_at)
    review_time = datetime.fromisoformat(review.reviewed_at.replace("Z", "+00:00")).astimezone(UTC)
    if policy_declared > window_started:
        raise CanaryValidationError(
            "canary policy",
            "$.declared_at",
            "must be at or before the observation window starts",
        )
    if review_time > window_started:
        raise CanaryValidationError(
            "review result",
            "$.reviewed_at",
            "must be at or before the observation window starts",
        )
    compared_at_value = utc_timestamp(compared_at)
    if _timestamp_value(compared_at_value) < _timestamp_value(observation.observed_at):
        raise CanaryValidationError(
            "canary observation",
            "$.observed_at",
            "cannot be later than the comparison time",
        )

    expected_metric_ids = {metric.metric_id for metric in policy.metrics}
    baseline_metrics = _metric_map(
        observation.baseline,
        expected_metric_ids=expected_metric_ids,
        path="$.baseline.metrics",
    )
    candidate_metrics = _metric_map(
        observation.candidate,
        expected_metric_ids=expected_metric_ids,
        path="$.candidate.metrics",
    )
    metric_results = tuple(
        _metric_result(
            metric,
            baseline=baseline_metrics[metric.metric_id],
            baseline_sample_count=observation.baseline.sample_count,
            candidate=candidate_metrics[metric.metric_id],
            candidate_sample_count=observation.candidate.sample_count,
            confidence_level=policy.confidence_level,
            simultaneous_comparisons=(len(policy.metrics) * policy.maximum_looks),
        )
        for metric in policy.metrics
    )

    observation_seconds = int((window_ended - window_started).total_seconds())
    window_ready = observation_seconds >= policy.minimum_observation_seconds
    assignment_ready = (
        not policy.require_sticky_assignment or observation.assignment.sticky
    ) and not observation.assignment.cross_cohort_contamination_detected
    sample_ready = (
        observation.baseline.sample_count >= policy.minimum_sample_size_per_cohort
        and observation.candidate.sample_count >= policy.minimum_sample_size_per_cohort
    )
    metric_statuses = {metric.status for metric in metric_results}
    checks = (
        CanaryCheck(
            code="predeclared_policy",
            status=CheckStatus.PASS,
            message="The exact canary policy predates the observation window.",
        ),
        CanaryCheck(
            code="planned_look",
            status=CheckStatus.PASS,
            message="The comparison is within the predeclared sequential-look plan.",
        ),
        CanaryCheck(
            code="observation_window",
            status=CheckStatus.PASS if window_ready else CheckStatus.WARNING,
            message=(
                "The observation window meets the predeclared minimum."
                if window_ready
                else "The observation window is shorter than the predeclared minimum."
            ),
        ),
        CanaryCheck(
            code="assignment_integrity",
            status=CheckStatus.PASS if assignment_ready else CheckStatus.WARNING,
            message=(
                "Assignment declarations meet the predeclared integrity requirements."
                if assignment_ready
                else "Assignment declarations do not meet the predeclared integrity requirements."
            ),
        ),
        CanaryCheck(
            code="cohort_sample_size",
            status=CheckStatus.PASS if sample_ready else CheckStatus.WARNING,
            message=(
                "Both cohorts meet the predeclared minimum sample size."
                if sample_ready
                else "At least one cohort is below the predeclared minimum sample size."
            ),
        ),
        CanaryCheck(
            code="metric_outcomes",
            status=(
                CheckStatus.FAIL
                if CanaryMetricStatus.REGRESSION in metric_statuses
                else (
                    CheckStatus.WARNING
                    if CanaryMetricStatus.INCONCLUSIVE in metric_statuses
                    else CheckStatus.PASS
                )
            ),
            message=(
                "At least one outcome rate is conclusively beyond its degradation bound."
                if CanaryMetricStatus.REGRESSION in metric_statuses
                else (
                    "At least one outcome rate remains statistically inconclusive."
                    if CanaryMetricStatus.INCONCLUSIVE in metric_statuses
                    else "Every outcome rate is noninferior within its degradation bound."
                )
            ),
        ),
    )
    design_ready = window_ready and assignment_ready and sample_ready
    final_look_inconclusive = (
        observation.look_number == policy.maximum_looks
        and CanaryMetricStatus.INCONCLUSIVE in metric_statuses
    )
    if not design_ready:
        decision = CanaryDecision.NEEDS_EVIDENCE
    elif CanaryMetricStatus.REGRESSION in metric_statuses:
        decision = CanaryDecision.ROLLBACK
    elif final_look_inconclusive:
        decision = CanaryDecision.NEEDS_EVIDENCE
    elif CanaryMetricStatus.INCONCLUSIVE in metric_statuses:
        decision = CanaryDecision.CONTINUE
    else:
        decision = CanaryDecision.PROMOTE
    if final_look_inconclusive and design_ready:
        needs_evidence_summary = (
            "The predeclared final look remains inconclusive; a new prospective plan is required."
        )
    else:
        needs_evidence_summary = (
            "The observation does not meet the predeclared window, assignment, or sample contract."
        )
    summaries = {
        CanaryDecision.PROMOTE: (
            "The candidate is noninferior on every predeclared outcome rate and may be promoted."
        ),
        CanaryDecision.CONTINUE: (
            "The minimum design requirements are met, but more canary evidence is required."
        ),
        CanaryDecision.ROLLBACK: (
            "At least one predeclared outcome rate regressed beyond its allowed bound."
        ),
        CanaryDecision.NEEDS_EVIDENCE: needs_evidence_summary,
    }
    return CanaryComparisonResult(
        schema_version=CANARY_RESULT_SCHEMA_VERSION,
        engine_version=ENGINE_VERSION,
        comparison_id=observation.comparison_id,
        look_number=observation.look_number,
        maximum_looks=policy.maximum_looks,
        case_id=change_case.case_id,
        change_ref=change_case.proposed_change.change_ref,
        policy_id=policy.policy_id,
        evaluator_ref=policy.evaluator_ref,
        assignment_method=policy.assignment_method,
        assignment_unit=policy.assignment_unit,
        observation_sha256=hashlib.sha256(observation_bytes).hexdigest(),
        policy_sha256=policy_sha256,
        change_case_sha256=change_case_sha256,
        review_result_sha256=review_sha256,
        compared_at=compared_at_value,
        window_started_at=observation.window.started_at,
        window_ended_at=observation.window.ended_at,
        observation_seconds=observation_seconds,
        baseline_deployment_ref=observation.baseline.deployment_ref,
        candidate_deployment_ref=observation.candidate.deployment_ref,
        baseline_sample_count=observation.baseline.sample_count,
        candidate_sample_count=observation.candidate.sample_count,
        confidence_level=policy.confidence_level,
        decision=decision,
        summary=summaries[decision],
        checks=checks,
        metrics=metric_results,
    )


def render_canary_policy(policy: CanaryPolicy) -> str:
    """Render a canonical human-inspectable canary policy document."""

    return (
        json.dumps(
            to_jsonable(policy),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_canary_result(result: CanaryComparisonResult) -> str:
    """Render a stable machine-readable canary comparison result."""

    return (
        json.dumps(
            to_jsonable(result),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_canary_markdown(result: CanaryComparisonResult) -> str:
    """Render a compact human-readable canary comparison report."""

    metric_header = (
        "| Metric | Better | Baseline | Candidate | Difference | Confidence interval | "
        "Allowed degradation | Status |\n"
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |"
    )
    rows = "\n".join(
        (
            f"| `{metric.metric_id}` | {metric.direction.value} | "
            f"{metric.baseline_rate:.4%} | {metric.candidate_rate:.4%} | "
            f"{metric.observed_difference:+.4%} | "
            f"[{metric.confidence_lower:+.4%}, {metric.confidence_upper:+.4%}] | "
            f"{metric.maximum_degradation:.4%} | **{metric.status.value.upper()}** |"
        )
        for metric in result.metrics
    )
    checks = "\n".join(
        f"- **{check.status.value.upper()}** `{check.code}` — {check.message}"
        for check in result.checks
    )
    return f"""# Causure canary comparison

> **{result.decision.value.upper()}**

{result.summary}

| Field | Value |
| --- | --- |
| Comparison | `{result.comparison_id}` |
| Planned look | `{result.look_number}` of `{result.maximum_looks}` |
| Change case | `{result.case_id}` |
| Change reference | `{result.change_ref}` |
| Canary policy | `{result.policy_id}` |
| Evaluator | `{result.evaluator_ref}` |
| Assignment | `{result.assignment_method.value}` by `{result.assignment_unit.value}` |
| Baseline deployment | `{result.baseline_deployment_ref}` |
| Candidate deployment | `{result.candidate_deployment_ref}` |
| Window | `{result.window_started_at}` through `{result.window_ended_at}` |
| Samples | baseline `{result.baseline_sample_count}`, candidate `{result.candidate_sample_count}` |
| Joint confidence | `{result.confidence_level:.3f}` |
| Compared at | `{result.compared_at}` |

## Outcome rates

{metric_header}
{rows}

## Checks

{checks}

## Exact artifact bindings

- Observation SHA-256: `{result.observation_sha256}`
- Canary policy SHA-256: `{result.policy_sha256}`
- Canonical change-case SHA-256: `{result.change_case_sha256}`
- Review-result SHA-256: `{result.review_result_sha256}`
- Engine version: `{result.engine_version}`
"""
