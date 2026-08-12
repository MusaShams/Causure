"""Minimized, exact-artifact-bound records for the Team change-case dashboard."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, TypeVar

from causure.azure_devops import (
    MAX_AZURE_PUBLICATION_BYTES,
    MAX_AZURE_VERIFICATION_BYTES,
    AzureReviewPublication,
    AzureReviewVerification,
    ReviewBinding,
    TfvcChangesetTarget,
    TfvcShelvesetTarget,
    parse_azure_review_publication_bytes,
    parse_azure_review_verification_bytes,
    parse_review_result_bytes,
    parse_review_result_findings_bytes,
)
from causure.canary import (
    MAX_CANARY_RESULT_BYTES,
    CanaryComparisonResult,
    parse_canary_result_bytes,
)
from causure.constants import (
    APPROVAL_VERIFICATION_SCHEMA_VERSION,
    TEAM_CASE_RECORD_SCHEMA_VERSION,
    ApprovalAction,
    ApprovalAuthenticationMethod,
    ApprovalGateEffect,
    CanaryAssignmentMethod,
    CanaryAssignmentUnit,
    CanaryDecision,
    CanaryMetricDirection,
    CanaryMetricStatus,
    CheckStatus,
    Component,
    Consequence,
    Decision,
    IncidentSeverity,
    OracleKind,
    RecommendedAction,
    RequirementStatus,
    TfvcTargetKind,
)
from causure.io import InputDocumentError, parse_json_text
from causure.models import ChangeCase, document_sha256, parse_change_case, to_jsonable

MAX_TEAM_CASE_RECORD_BYTES = 1024 * 1024
MAX_TEAM_CASE_CHANGE_BYTES = 5 * 1024 * 1024
MAX_TEAM_CASE_REVIEW_BYTES = 5 * 1024 * 1024
MAX_TEAM_CASE_APPROVAL_VERIFICATION_BYTES = 1024 * 1024
MAX_TEAM_CASE_HYPOTHESES = 64
MAX_TEAM_CASE_FINDINGS = 128
MAX_TEAM_CASE_METRICS = 50
TEAM_CASE_RECORD_MEDIA_TYPE = "application/vnd.causure.team-case-record+json"

_CHANGE_CASE_MEDIA_TYPE = "application/vnd.causure.change-case+json"
_REVIEW_RESULT_MEDIA_TYPE = "application/vnd.causure.review-result+json"
_REVIEW_REPORT_MEDIA_TYPE = "text/markdown; charset=utf-8"
_AZURE_PUBLICATION_MEDIA_TYPE = "application/vnd.causure.azure-review-publication+json"
_AZURE_VERIFICATION_MEDIA_TYPE = "application/vnd.causure.azure-review-verification+json"
_APPROVAL_ASSERTION_MEDIA_TYPE = "application/vnd.causure.approval-assertion+json"
_APPROVAL_VERIFICATION_MEDIA_TYPE = "application/vnd.causure.approval-verification+json"
_CANARY_RESULT_MEDIA_TYPE = "application/vnd.causure.canary-result+json"

_CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$")
_FINDING_CODE_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_UTC_TIMESTAMP_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_NO_CONTROL_PATTERN = re.compile(r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+$")
_EnumT = TypeVar("_EnumT", bound=Enum)


class TeamCaseValidationError(ValueError):
    """Raised when a dashboard case record or its exact source chain is invalid."""

    def __init__(self, document_name: str, path: str, message: str) -> None:
        self.document_name = document_name
        self.path = path
        self.message = message
        super().__init__(f"Invalid {document_name} at {path}: {message}")


@dataclass(frozen=True, slots=True)
class TeamCaseArtifactSubject:
    media_type: str
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class TeamCaseChangeSubject:
    media_type: str
    sha256: str
    byte_count: int
    canonical_sha256: str


@dataclass(frozen=True, slots=True)
class TeamCaseSources:
    change_case: TeamCaseChangeSubject
    review_result: TeamCaseArtifactSubject
    review_report: TeamCaseArtifactSubject | None = field(
        default=None, metadata={"omit_none": True}
    )
    azure_publication: TeamCaseArtifactSubject | None = field(
        default=None, metadata={"omit_none": True}
    )
    azure_verification: TeamCaseArtifactSubject | None = field(
        default=None, metadata={"omit_none": True}
    )
    approval_verification: TeamCaseArtifactSubject | None = field(
        default=None, metadata={"omit_none": True}
    )
    canary_result: TeamCaseArtifactSubject | None = field(
        default=None, metadata={"omit_none": True}
    )


@dataclass(frozen=True, slots=True)
class TeamCaseHypothesisSummary:
    component: Component
    confidence: float
    evidence_count: int
    intervention_present: bool
    intervention_trial_count: int
    intervention_resolved_count: int
    intervention_isolated: bool | None = field(default=None, metadata={"omit_none": True})


@dataclass(frozen=True, slots=True)
class TeamCaseEvidenceSummary:
    title: str
    created_at: str
    severity: IncidentSeverity
    requirement_status: RequirementStatus
    oracle_kind: OracleKind
    oracle_independent: bool
    reproduction_trial_count: int
    reproduced_trial_count: int
    hypotheses: tuple[TeamCaseHypothesisSummary, ...]
    proposed_component: Component
    proposed_summary: str
    prediction: str
    change_ref: str
    changed_surface_count: int
    known_risk_count: int
    validation_case_count: int
    validation_candidate_passed_count: int
    validation_critical_failed_count: int


@dataclass(frozen=True, slots=True)
class TeamCaseFindingSummary:
    code: str
    status: CheckStatus
    consequence: Consequence


@dataclass(frozen=True, slots=True)
class TeamCaseReviewSummary:
    engine_version: str
    policy_name: str
    reviewed_at: str
    decision: Decision
    recommended_action: RecommendedAction
    summary: str
    findings: tuple[TeamCaseFindingSummary, ...]


@dataclass(frozen=True, slots=True)
class TeamCaseDeliverySummary:
    published_at: str
    verified_at: str
    server_path: str
    target_kind: TfvcTargetKind
    changeset_id: int | None = field(default=None, metadata={"omit_none": True})
    shelveset_name: str | None = field(default=None, metadata={"omit_none": True})
    shelveset_owner: str | None = field(default=None, metadata={"omit_none": True})
    build_id: int = 0
    build_number: str = ""
    work_item_ids: tuple[int, ...] = ()


@dataclass(frozen=True, slots=True)
class TeamCaseApprovalSummary:
    checked_at: str
    assertion: TeamCaseArtifactSubject
    authority_id: str
    key_id: str
    identity_provider: str
    subject_id: str
    authentication_method: ApprovalAuthenticationMethod
    authentication_event_id: str
    action: ApprovalAction
    gate_effect: ApprovalGateEffect
    issued_at: str
    expires_at: str
    trust_store_id: str
    revocation_list_id: str
    revocation_list_updated_at: str
    exception_finding_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TeamCaseCanaryMetricSummary:
    metric_id: str
    direction: CanaryMetricDirection
    maximum_degradation: float
    baseline_rate: float
    candidate_rate: float
    confidence_lower: float
    confidence_upper: float
    status: CanaryMetricStatus


@dataclass(frozen=True, slots=True)
class TeamCaseCanarySummary:
    comparison_id: str
    look_number: int
    maximum_looks: int
    policy_id: str
    evaluator_ref: str
    assignment_method: CanaryAssignmentMethod
    assignment_unit: CanaryAssignmentUnit
    compared_at: str
    window_started_at: str
    window_ended_at: str
    baseline_deployment_ref: str
    candidate_deployment_ref: str
    baseline_sample_count: int
    candidate_sample_count: int
    confidence_level: float
    decision: CanaryDecision
    summary: str
    metrics: tuple[TeamCaseCanaryMetricSummary, ...]


@dataclass(frozen=True, slots=True)
class TeamCaseRecord:
    schema_version: str
    tenant_id: str
    case_id: str
    revision: int
    published_at: str
    sources: TeamCaseSources
    evidence: TeamCaseEvidenceSummary
    review: TeamCaseReviewSummary
    delivery: TeamCaseDeliverySummary | None = field(default=None, metadata={"omit_none": True})
    approval: TeamCaseApprovalSummary | None = field(default=None, metadata={"omit_none": True})
    canary: TeamCaseCanarySummary | None = field(default=None, metadata={"omit_none": True})


def _object(
    value: Any,
    *,
    document_name: str,
    path: str,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TeamCaseValidationError(document_name, path, "expected an object")
    allowed = required | (optional or set())
    missing = sorted(required - set(value))
    if missing:
        raise TeamCaseValidationError(document_name, path, f"missing required field: {missing[0]}")
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise TeamCaseValidationError(document_name, path, f"unknown field: {unknown[0]}")
    return value


def _array(
    value: Any,
    *,
    document_name: str,
    path: str,
    minimum: int,
    maximum: int,
) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise TeamCaseValidationError(
            document_name,
            path,
            f"expected an array containing from {minimum} to {maximum} items",
        )
    return value


def _text(
    value: Any,
    *,
    document_name: str,
    path: str,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    selected_pattern = pattern or _NO_CONTROL_PATTERN
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or selected_pattern.fullmatch(value) is None
    ):
        raise TeamCaseValidationError(
            document_name,
            path,
            f"expected from 1 to {maximum} bounded characters",
        )
    return value


def _integer(
    value: Any,
    *,
    document_name: str,
    path: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise TeamCaseValidationError(
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
        raise TeamCaseValidationError(
            document_name, path, f"expected a number from {minimum:g} through {maximum:g}"
        )
    result = float(value)
    if not math.isfinite(result) or not minimum <= result <= maximum:
        raise TeamCaseValidationError(
            document_name, path, f"expected a number from {minimum:g} through {maximum:g}"
        )
    return result


def _boolean(value: Any, *, document_name: str, path: str) -> bool:
    if type(value) is not bool:
        raise TeamCaseValidationError(document_name, path, "expected a boolean")
    return value


def _enum(
    value: Any,
    *,
    document_name: str,
    path: str,
    enum_type: type[_EnumT],
) -> _EnumT:
    if not isinstance(value, str):
        raise TeamCaseValidationError(document_name, path, "expected a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in enum_type)
        raise TeamCaseValidationError(document_name, path, f"expected one of: {allowed}") from exc


def _timestamp(
    value: Any,
    *,
    document_name: str,
    path: str,
    require_utc_seconds: bool = False,
) -> str:
    maximum = 20 if require_utc_seconds else 64
    result = _text(
        value,
        document_name=document_name,
        path=path,
        maximum=maximum,
        pattern=_UTC_TIMESTAMP_PATTERN if require_utc_seconds else None,
    )
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TeamCaseValidationError(
            document_name, path, "expected an ISO 8601 timestamp"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise TeamCaseValidationError(document_name, path, "timestamp must include an offset")
    if require_utc_seconds and parsed.utcoffset().total_seconds() != 0:
        raise TeamCaseValidationError(document_name, path, "expected a whole-second UTC timestamp")
    return result


def _json_bytes(raw_bytes: bytes, *, document_name: str, maximum: int) -> Any:
    if not isinstance(raw_bytes, bytes):
        raise TypeError(f"{document_name}_bytes must be bytes")
    if not 1 <= len(raw_bytes) <= maximum:
        raise TeamCaseValidationError(document_name, "$", f"expected from 1 to {maximum} bytes")
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TeamCaseValidationError(document_name, "$", "document is not valid UTF-8") from exc
    try:
        return parse_json_text(text, source=document_name, max_bytes=maximum)
    except InputDocumentError as exc:
        raise TeamCaseValidationError(document_name, "$", str(exc)) from exc


def _sha256(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()


def _subject(raw_bytes: bytes, media_type: str) -> TeamCaseArtifactSubject:
    return TeamCaseArtifactSubject(
        media_type=media_type,
        sha256=_sha256(raw_bytes),
        byte_count=len(raw_bytes),
    )


def _parse_subject(
    value: Any,
    *,
    document_name: str,
    path: str,
    expected_media_type: str | None = None,
    maximum_bytes: int = MAX_TEAM_CASE_REVIEW_BYTES,
) -> TeamCaseArtifactSubject:
    obj = _object(
        value,
        document_name=document_name,
        path=path,
        required={"media_type", "sha256", "byte_count"},
    )
    media_type = _text(
        obj["media_type"], document_name=document_name, path=f"{path}.media_type", maximum=255
    )
    if expected_media_type is not None and media_type != expected_media_type:
        raise TeamCaseValidationError(
            document_name,
            f"{path}.media_type",
            f"expected {expected_media_type!r}",
        )
    return TeamCaseArtifactSubject(
        media_type=media_type,
        sha256=_text(
            obj["sha256"],
            document_name=document_name,
            path=f"{path}.sha256",
            maximum=64,
            pattern=_SHA256_PATTERN,
        ),
        byte_count=_integer(
            obj["byte_count"],
            document_name=document_name,
            path=f"{path}.byte_count",
            minimum=1,
            maximum=maximum_bytes,
        ),
    )


def _matches_bytes(subject: TeamCaseArtifactSubject, raw_bytes: bytes, *, role: str) -> None:
    if subject.sha256 != _sha256(raw_bytes) or subject.byte_count != len(raw_bytes):
        raise TeamCaseValidationError(
            "Team case source chain",
            f"$.{role}",
            "content subject does not match the supplied exact bytes",
        )


def _evidence_summary(case: ChangeCase) -> TeamCaseEvidenceSummary:
    hypotheses: list[TeamCaseHypothesisSummary] = []
    if len(case.attribution.hypotheses) > MAX_TEAM_CASE_HYPOTHESES:
        raise TeamCaseValidationError(
            "change case",
            "$.attribution.hypotheses",
            f"dashboard supports at most {MAX_TEAM_CASE_HYPOTHESES} hypotheses",
        )
    for hypothesis in case.attribution.hypotheses:
        intervention = hypothesis.intervention
        trials = () if intervention is None else intervention.trials
        hypotheses.append(
            TeamCaseHypothesisSummary(
                component=hypothesis.component,
                confidence=hypothesis.confidence,
                evidence_count=len(hypothesis.evidence_refs),
                intervention_present=intervention is not None,
                intervention_isolated=(None if intervention is None else intervention.isolated),
                intervention_trial_count=len(trials),
                intervention_resolved_count=sum(trial.failure_resolved for trial in trials),
            )
        )

    title = _text(case.title, document_name="change case", path="$.title", maximum=512)
    proposed_summary = _text(
        case.proposed_change.summary,
        document_name="change case",
        path="$.proposed_change.summary",
        maximum=2048,
    )
    prediction = _text(
        case.proposed_change.prediction,
        document_name="change case",
        path="$.proposed_change.prediction",
        maximum=2048,
    )
    validation_cases = case.validation.cases
    return TeamCaseEvidenceSummary(
        title=title,
        created_at=case.created_at,
        severity=case.incident.severity,
        requirement_status=case.incident.requirement_status,
        oracle_kind=case.verification.oracle.kind,
        oracle_independent=case.verification.oracle.independent,
        reproduction_trial_count=len(case.verification.reproduction_trials),
        reproduced_trial_count=sum(
            trial.reproduced for trial in case.verification.reproduction_trials
        ),
        hypotheses=tuple(hypotheses),
        proposed_component=case.proposed_change.component,
        proposed_summary=proposed_summary,
        prediction=prediction,
        change_ref=case.proposed_change.change_ref,
        changed_surface_count=case.proposed_change.changed_surface_count,
        known_risk_count=len(case.proposed_change.known_risks),
        validation_case_count=len(validation_cases),
        validation_candidate_passed_count=sum(item.candidate_passed for item in validation_cases),
        validation_critical_failed_count=sum(
            item.critical and not item.candidate_passed for item in validation_cases
        ),
    )


def _review_summary(
    review_bytes: bytes,
    review: ReviewBinding,
    document: dict[str, Any],
) -> TeamCaseReviewSummary:
    findings = parse_review_result_findings_bytes(review_bytes)
    if len(findings) > MAX_TEAM_CASE_FINDINGS:
        raise TeamCaseValidationError(
            "review result",
            "$.findings",
            f"dashboard supports at most {MAX_TEAM_CASE_FINDINGS} findings",
        )
    return TeamCaseReviewSummary(
        engine_version=review.engine_version,
        policy_name=review.policy_name,
        reviewed_at=review.reviewed_at,
        decision=review.decision,
        recommended_action=review.recommended_action,
        summary=_text(
            document["summary"],
            document_name="review result",
            path="$.summary",
            maximum=8192,
        ),
        findings=tuple(
            TeamCaseFindingSummary(
                code=item.code,
                status=item.status,
                consequence=item.consequence,
            )
            for item in findings
        ),
    )


def _validate_delivery_chain(
    publication_bytes: bytes,
    verification_bytes: bytes,
    review_bytes: bytes,
    review: ReviewBinding,
) -> tuple[AzureReviewPublication, AzureReviewVerification, TeamCaseDeliverySummary]:
    try:
        publication = parse_azure_review_publication_bytes(publication_bytes)
        verification = parse_azure_review_verification_bytes(verification_bytes)
    except ValueError as exc:
        raise TeamCaseValidationError(
            "Team case source chain", "$", "Azure review artifacts are invalid"
        ) from exc
    if publication.review != review:
        raise TeamCaseValidationError(
            "Team case source chain",
            "$.azure_publication.review",
            "does not match the supplied review result",
        )
    if publication.artifacts.review_result.sha256 != _sha256(
        review_bytes
    ) or publication.artifacts.review_result.byte_count != len(review_bytes):
        raise TeamCaseValidationError(
            "Team case source chain",
            "$.azure_publication.artifacts.review_result",
            "does not bind the supplied exact review-result bytes",
        )
    if (
        verification.publication.sha256 != _sha256(publication_bytes)
        or verification.publication.byte_count != len(publication_bytes)
        or verification.review != publication.review
        or verification.tfvc != publication.tfvc
        or verification.build_id != publication.build.build_id
        or verification.artifacts != publication.artifacts
    ):
        raise TeamCaseValidationError(
            "Team case source chain",
            "$.azure_verification",
            "does not bind the supplied publication and review artifacts",
        )

    target = publication.tfvc.target
    if isinstance(target, TfvcChangesetTarget):
        changeset_id = target.changeset_id
        shelveset_name = None
        shelveset_owner = None
    elif isinstance(target, TfvcShelvesetTarget):
        changeset_id = None
        shelveset_name = target.shelveset_name
        shelveset_owner = target.owner
    else:  # pragma: no cover - closed parser produces only the union members
        raise TeamCaseValidationError(
            "Team case source chain", "$.azure_publication.tfvc.target", "unknown target"
        )
    return (
        publication,
        verification,
        TeamCaseDeliverySummary(
            published_at=publication.created_at,
            verified_at=verification.verified_at,
            server_path=publication.tfvc.server_path,
            target_kind=target.kind,
            changeset_id=changeset_id,
            shelveset_name=shelveset_name,
            shelveset_owner=shelveset_owner,
            build_id=publication.build.build_id,
            build_number=publication.build.build_number,
            work_item_ids=publication.work_item_ids,
        ),
    )


def _approval_summary(
    raw_bytes: bytes,
    publication_bytes: bytes,
    verification_bytes: bytes,
    review_result_bytes: bytes,
    publication: AzureReviewPublication,
    azure_verification: AzureReviewVerification,
) -> TeamCaseApprovalSummary:
    name = "approval verification"
    document = _json_bytes(
        raw_bytes,
        document_name=name,
        maximum=MAX_TEAM_CASE_APPROVAL_VERIFICATION_BYTES,
    )
    root = _object(
        document,
        document_name=name,
        path="$",
        required={
            "schema_version",
            "verifier_version",
            "status",
            "checked_at",
            "assertion",
            "authority",
            "approver",
            "action",
            "gate_effect",
            "issued_at",
            "expires_at",
            "subject",
            "review",
            "tfvc",
            "build_id",
            "trust_store_id",
            "revocation_list_id",
            "revocation_list_updated_at",
        },
        optional={"exception"},
    )
    if root["schema_version"] != APPROVAL_VERIFICATION_SCHEMA_VERSION:
        raise TeamCaseValidationError(
            name,
            "$.schema_version",
            f"expected {APPROVAL_VERIFICATION_SCHEMA_VERSION!r}",
        )
    _text(root["verifier_version"], document_name=name, path="$.verifier_version", maximum=128)
    if root["status"] != "verified":
        raise TeamCaseValidationError(name, "$.status", "expected 'verified'")
    checked_at = _timestamp(
        root["checked_at"], document_name=name, path="$.checked_at", require_utc_seconds=True
    )

    assertion = _parse_subject(
        root["assertion"],
        document_name=name,
        path="$.assertion",
        expected_media_type=_APPROVAL_ASSERTION_MEDIA_TYPE,
        maximum_bytes=1024 * 1024,
    )
    authority = _object(
        root["authority"],
        document_name=name,
        path="$.authority",
        required={"authority_id", "key_id"},
    )
    authority_id = _text(
        authority["authority_id"],
        document_name=name,
        path="$.authority.authority_id",
        maximum=128,
        pattern=_SAFE_ID_PATTERN,
    )
    key_id = _text(
        authority["key_id"],
        document_name=name,
        path="$.authority.key_id",
        maximum=128,
        pattern=_SAFE_ID_PATTERN,
    )
    approver = _object(
        root["approver"],
        document_name=name,
        path="$.approver",
        required={
            "identity_provider",
            "subject_id",
            "authentication_method",
            "authentication_event_id",
            "authenticated_at",
        },
    )
    identity_provider = _text(
        approver["identity_provider"],
        document_name=name,
        path="$.approver.identity_provider",
        maximum=128,
        pattern=_SAFE_ID_PATTERN,
    )
    subject_id = _text(
        approver["subject_id"],
        document_name=name,
        path="$.approver.subject_id",
        maximum=128,
        pattern=_SAFE_ID_PATTERN,
    )
    authentication_method = _enum(
        approver["authentication_method"],
        document_name=name,
        path="$.approver.authentication_method",
        enum_type=ApprovalAuthenticationMethod,
    )
    authentication_event_id = _text(
        approver["authentication_event_id"],
        document_name=name,
        path="$.approver.authentication_event_id",
        maximum=128,
        pattern=_SAFE_ID_PATTERN,
    )
    _timestamp(
        approver["authenticated_at"],
        document_name=name,
        path="$.approver.authenticated_at",
        require_utc_seconds=True,
    )
    action = _enum(root["action"], document_name=name, path="$.action", enum_type=ApprovalAction)
    gate_effect = _enum(
        root["gate_effect"],
        document_name=name,
        path="$.gate_effect",
        enum_type=ApprovalGateEffect,
    )
    issued_at = _timestamp(
        root["issued_at"], document_name=name, path="$.issued_at", require_utc_seconds=True
    )
    expires_at = _timestamp(
        root["expires_at"], document_name=name, path="$.expires_at", require_utc_seconds=True
    )
    issued_time = datetime.fromisoformat(issued_at.replace("Z", "+00:00"))
    checked_time = datetime.fromisoformat(checked_at.replace("Z", "+00:00"))
    expires_time = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    if not issued_time <= checked_time < expires_time:
        raise TeamCaseValidationError(
            name,
            "$.checked_at",
            "must be within the recorded approval validity window",
        )

    subject = _object(
        root["subject"],
        document_name=name,
        path="$.subject",
        required={"publication", "verification"},
    )
    publication_subject = _parse_subject(
        subject["publication"],
        document_name=name,
        path="$.subject.publication",
        expected_media_type=_AZURE_PUBLICATION_MEDIA_TYPE,
        maximum_bytes=MAX_AZURE_PUBLICATION_BYTES,
    )
    verification_subject = _parse_subject(
        subject["verification"],
        document_name=name,
        path="$.subject.verification",
        expected_media_type=_AZURE_VERIFICATION_MEDIA_TYPE,
        maximum_bytes=MAX_AZURE_VERIFICATION_BYTES,
    )
    _matches_bytes(publication_subject, publication_bytes, role="subject.publication")
    _matches_bytes(verification_subject, verification_bytes, role="subject.verification")
    if root["review"] != to_jsonable(publication.review):
        raise TeamCaseValidationError(
            name, "$.review", "does not match the supplied Azure publication"
        )
    if root["tfvc"] != to_jsonable(publication.tfvc):
        raise TeamCaseValidationError(
            name, "$.tfvc", "does not match the supplied Azure publication"
        )
    if (
        type(root["build_id"]) is not int
        or root["build_id"] != publication.build.build_id
        or root["build_id"] != azure_verification.build_id
    ):
        raise TeamCaseValidationError(
            name, "$.build_id", "does not match the supplied Azure artifacts"
        )

    trust_store_id = _text(
        root["trust_store_id"],
        document_name=name,
        path="$.trust_store_id",
        maximum=128,
        pattern=_SAFE_ID_PATTERN,
    )
    revocation_list_id = _text(
        root["revocation_list_id"],
        document_name=name,
        path="$.revocation_list_id",
        maximum=128,
        pattern=_SAFE_ID_PATTERN,
    )
    revocation_updated = _timestamp(
        root["revocation_list_updated_at"],
        document_name=name,
        path="$.revocation_list_updated_at",
        require_utc_seconds=True,
    )
    if datetime.fromisoformat(revocation_updated.replace("Z", "+00:00")) > checked_time:
        raise TeamCaseValidationError(
            name,
            "$.revocation_list_updated_at",
            "must be at or before checked_at",
        )

    exception_codes: tuple[str, ...] = ()
    if "exception" in root:
        exception = _object(
            root["exception"],
            document_name=name,
            path="$.exception",
            required={"finding_codes", "justification"},
        )
        codes = tuple(
            _text(
                value,
                document_name=name,
                path=f"$.exception.finding_codes[{index}]",
                maximum=128,
                pattern=_FINDING_CODE_PATTERN,
            )
            for index, value in enumerate(
                _array(
                    exception["finding_codes"],
                    document_name=name,
                    path="$.exception.finding_codes",
                    minimum=1,
                    maximum=64,
                )
            )
        )
        if codes != tuple(sorted(set(codes))):
            raise TeamCaseValidationError(
                name, "$.exception.finding_codes", "must be unique and sorted"
            )
        _text(
            exception["justification"],
            document_name=name,
            path="$.exception.justification",
            maximum=2048,
        )
        exception_codes = codes
    if action is ApprovalAction.EXCEPTION and not exception_codes:
        raise TeamCaseValidationError(name, "$.exception", "is required for exception action")
    if action is ApprovalAction.APPROVE and exception_codes:
        raise TeamCaseValidationError(name, "$.exception", "is not allowed for approve action")
    consequential_codes = tuple(
        sorted(
            finding.code
            for finding in parse_review_result_findings_bytes(review_result_bytes)
            if finding.consequence is not Consequence.NONE
        )
    )
    if action is ApprovalAction.APPROVE:
        if publication.review.decision is not Decision.APPROVE:
            raise TeamCaseValidationError(
                name,
                "$.action",
                "approve is valid only for an approve gate decision",
            )
    elif publication.review.decision is Decision.APPROVE or exception_codes != consequential_codes:
        raise TeamCaseValidationError(
            name,
            "$.exception.finding_codes",
            "must exactly cover a non-approve review's decision-affecting findings",
        )

    return TeamCaseApprovalSummary(
        checked_at=checked_at,
        assertion=assertion,
        authority_id=authority_id,
        key_id=key_id,
        identity_provider=identity_provider,
        subject_id=subject_id,
        authentication_method=authentication_method,
        authentication_event_id=authentication_event_id,
        action=action,
        gate_effect=gate_effect,
        issued_at=issued_at,
        expires_at=expires_at,
        trust_store_id=trust_store_id,
        revocation_list_id=revocation_list_id,
        revocation_list_updated_at=revocation_updated,
        exception_finding_codes=exception_codes,
    )


def _canary_summary(result: CanaryComparisonResult) -> TeamCaseCanarySummary:
    return TeamCaseCanarySummary(
        comparison_id=result.comparison_id,
        look_number=result.look_number,
        maximum_looks=result.maximum_looks,
        policy_id=result.policy_id,
        evaluator_ref=result.evaluator_ref,
        assignment_method=result.assignment_method,
        assignment_unit=result.assignment_unit,
        compared_at=result.compared_at,
        window_started_at=result.window_started_at,
        window_ended_at=result.window_ended_at,
        baseline_deployment_ref=result.baseline_deployment_ref,
        candidate_deployment_ref=result.candidate_deployment_ref,
        baseline_sample_count=result.baseline_sample_count,
        candidate_sample_count=result.candidate_sample_count,
        confidence_level=result.confidence_level,
        decision=result.decision,
        summary=result.summary,
        metrics=tuple(
            TeamCaseCanaryMetricSummary(
                metric_id=metric.metric_id,
                direction=metric.direction,
                maximum_degradation=metric.maximum_degradation,
                baseline_rate=metric.baseline_rate,
                candidate_rate=metric.candidate_rate,
                confidence_lower=metric.confidence_lower,
                confidence_upper=metric.confidence_upper,
                status=metric.status,
            )
            for metric in result.metrics
        ),
    )


def create_team_case_record(
    change_case_bytes: bytes,
    review_result_bytes: bytes,
    *,
    tenant_id: str,
    revision: int,
    published_at: str,
    azure_publication_bytes: bytes | None = None,
    azure_verification_bytes: bytes | None = None,
    approval_verification_bytes: bytes | None = None,
    canary_result_bytes: bytes | None = None,
) -> TeamCaseRecord:
    """Derive one minimized dashboard record from exact, cross-bound source artifacts."""

    tenant = _text(
        tenant_id,
        document_name="Team case record",
        path="$.tenant_id",
        maximum=128,
        pattern=_SAFE_ID_PATTERN,
    )
    resolved_revision = _integer(
        revision,
        document_name="Team case record",
        path="$.revision",
        minimum=1,
        maximum=10_000,
    )
    published = _timestamp(
        published_at,
        document_name="Team case record",
        path="$.published_at",
        require_utc_seconds=True,
    )
    change_document = _json_bytes(
        change_case_bytes,
        document_name="change case",
        maximum=MAX_TEAM_CASE_CHANGE_BYTES,
    )
    try:
        change_case = parse_change_case(change_document)
    except ValueError as exc:
        raise TeamCaseValidationError(
            "change case", "$", "document is not a valid change case"
        ) from exc
    canonical_change_sha256 = document_sha256(change_case)

    review_document = _json_bytes(
        review_result_bytes,
        document_name="review result",
        maximum=MAX_TEAM_CASE_REVIEW_BYTES,
    )
    try:
        review = parse_review_result_bytes(review_result_bytes)
    except ValueError as exc:
        raise TeamCaseValidationError(
            "review result", "$", "document is not a valid review result"
        ) from exc
    if (
        review.case_id != change_case.case_id
        or review.component is not change_case.proposed_change.component
        or review.input_sha256 != canonical_change_sha256
    ):
        raise TeamCaseValidationError(
            "Team case source chain",
            "$.review_result",
            "does not bind the supplied change case",
        )
    if review_document["case_title"] != change_case.title:
        raise TeamCaseValidationError(
            "Team case source chain",
            "$.review_result.case_title",
            "does not match the supplied change case",
        )

    delivery: TeamCaseDeliverySummary | None = None
    publication: AzureReviewPublication | None = None
    verification: AzureReviewVerification | None = None
    if (azure_publication_bytes is None) != (azure_verification_bytes is None):
        raise TeamCaseValidationError(
            "Team case source chain",
            "$.azure_publication",
            "publication and verification bytes must be supplied together",
        )
    if azure_publication_bytes is not None and azure_verification_bytes is not None:
        publication, verification, delivery = _validate_delivery_chain(
            azure_publication_bytes,
            azure_verification_bytes,
            review_result_bytes,
            review,
        )
    if approval_verification_bytes is not None and (publication is None or verification is None):
        raise TeamCaseValidationError(
            "Team case source chain",
            "$.approval_verification",
            "requires the exact Azure publication and verification bytes",
        )

    approval: TeamCaseApprovalSummary | None = None
    if approval_verification_bytes is not None:
        assert azure_publication_bytes is not None
        assert azure_verification_bytes is not None
        assert publication is not None
        assert verification is not None
        approval = _approval_summary(
            approval_verification_bytes,
            azure_publication_bytes,
            azure_verification_bytes,
            review_result_bytes,
            publication,
            verification,
        )
    canary: TeamCaseCanarySummary | None = None
    canary_result: CanaryComparisonResult | None = None
    if canary_result_bytes is not None:
        try:
            canary_result = parse_canary_result_bytes(canary_result_bytes)
        except ValueError as exc:
            raise TeamCaseValidationError(
                "canary result", "$", "document is not a valid canary result"
            ) from exc
        if (
            canary_result.case_id != change_case.case_id
            or canary_result.change_ref != change_case.proposed_change.change_ref
            or canary_result.change_case_sha256 != canonical_change_sha256
            or canary_result.review_result_sha256 != _sha256(review_result_bytes)
        ):
            raise TeamCaseValidationError(
                "Team case source chain",
                "$.canary_result",
                "does not bind the supplied change case and review result",
            )
        canary = _canary_summary(canary_result)

    sources = TeamCaseSources(
        change_case=TeamCaseChangeSubject(
            media_type=_CHANGE_CASE_MEDIA_TYPE,
            sha256=_sha256(change_case_bytes),
            byte_count=len(change_case_bytes),
            canonical_sha256=canonical_change_sha256,
        ),
        review_result=_subject(review_result_bytes, _REVIEW_RESULT_MEDIA_TYPE),
        review_report=(
            None
            if publication is None
            else TeamCaseArtifactSubject(
                media_type=_REVIEW_REPORT_MEDIA_TYPE,
                sha256=publication.artifacts.review_report.sha256,
                byte_count=publication.artifacts.review_report.byte_count,
            )
        ),
        azure_publication=(
            None
            if azure_publication_bytes is None
            else _subject(azure_publication_bytes, _AZURE_PUBLICATION_MEDIA_TYPE)
        ),
        azure_verification=(
            None
            if azure_verification_bytes is None
            else _subject(azure_verification_bytes, _AZURE_VERIFICATION_MEDIA_TYPE)
        ),
        approval_verification=(
            None
            if approval_verification_bytes is None
            else _subject(approval_verification_bytes, _APPROVAL_VERIFICATION_MEDIA_TYPE)
        ),
        canary_result=(
            None
            if canary_result_bytes is None
            else _subject(canary_result_bytes, _CANARY_RESULT_MEDIA_TYPE)
        ),
    )
    record = TeamCaseRecord(
        schema_version=TEAM_CASE_RECORD_SCHEMA_VERSION,
        tenant_id=tenant,
        case_id=change_case.case_id,
        revision=resolved_revision,
        published_at=published,
        sources=sources,
        evidence=_evidence_summary(change_case),
        review=_review_summary(review_result_bytes, review, review_document),
        delivery=delivery,
        approval=approval,
        canary=canary,
    )
    encoded = render_team_case_record(record).encode("utf-8")
    if len(encoded) > MAX_TEAM_CASE_RECORD_BYTES:
        raise TeamCaseValidationError(
            "Team case record",
            "$",
            f"derived record exceeds the {MAX_TEAM_CASE_RECORD_BYTES}-byte limit",
        )
    return record


def _parse_change_subject(value: Any, *, path: str) -> TeamCaseChangeSubject:
    name = "Team case record"
    obj = _object(
        value,
        document_name=name,
        path=path,
        required={"media_type", "sha256", "byte_count", "canonical_sha256"},
    )
    subject = _parse_subject(
        {key: obj[key] for key in ("media_type", "sha256", "byte_count")},
        document_name=name,
        path=path,
        expected_media_type=_CHANGE_CASE_MEDIA_TYPE,
        maximum_bytes=MAX_TEAM_CASE_CHANGE_BYTES,
    )
    return TeamCaseChangeSubject(
        media_type=subject.media_type,
        sha256=subject.sha256,
        byte_count=subject.byte_count,
        canonical_sha256=_text(
            obj["canonical_sha256"],
            document_name=name,
            path=f"{path}.canonical_sha256",
            maximum=64,
            pattern=_SHA256_PATTERN,
        ),
    )


def _parse_sources(value: Any) -> TeamCaseSources:
    name = "Team case record"
    obj = _object(
        value,
        document_name=name,
        path="$.sources",
        required={"change_case", "review_result"},
        optional={
            "review_report",
            "azure_publication",
            "azure_verification",
            "approval_verification",
            "canary_result",
        },
    )
    publication_present = "azure_publication" in obj
    verification_present = "azure_verification" in obj
    report_present = "review_report" in obj
    if not (publication_present == verification_present == report_present):
        raise TeamCaseValidationError(
            name,
            "$.sources",
            "review report, Azure publication, and Azure verification must appear together",
        )
    if "approval_verification" in obj and not publication_present:
        raise TeamCaseValidationError(
            name,
            "$.sources.approval_verification",
            "requires Azure publication and verification subjects",
        )
    return TeamCaseSources(
        change_case=_parse_change_subject(obj["change_case"], path="$.sources.change_case"),
        review_result=_parse_subject(
            obj["review_result"],
            document_name=name,
            path="$.sources.review_result",
            expected_media_type=_REVIEW_RESULT_MEDIA_TYPE,
            maximum_bytes=MAX_TEAM_CASE_REVIEW_BYTES,
        ),
        review_report=(
            _parse_subject(
                obj["review_report"],
                document_name=name,
                path="$.sources.review_report",
                expected_media_type=_REVIEW_REPORT_MEDIA_TYPE,
                maximum_bytes=2 * 1024 * 1024,
            )
            if report_present
            else None
        ),
        azure_publication=(
            _parse_subject(
                obj["azure_publication"],
                document_name=name,
                path="$.sources.azure_publication",
                expected_media_type=_AZURE_PUBLICATION_MEDIA_TYPE,
                maximum_bytes=MAX_AZURE_PUBLICATION_BYTES,
            )
            if publication_present
            else None
        ),
        azure_verification=(
            _parse_subject(
                obj["azure_verification"],
                document_name=name,
                path="$.sources.azure_verification",
                expected_media_type=_AZURE_VERIFICATION_MEDIA_TYPE,
                maximum_bytes=MAX_AZURE_VERIFICATION_BYTES,
            )
            if verification_present
            else None
        ),
        approval_verification=(
            _parse_subject(
                obj["approval_verification"],
                document_name=name,
                path="$.sources.approval_verification",
                expected_media_type=_APPROVAL_VERIFICATION_MEDIA_TYPE,
                maximum_bytes=MAX_TEAM_CASE_APPROVAL_VERIFICATION_BYTES,
            )
            if "approval_verification" in obj
            else None
        ),
        canary_result=(
            _parse_subject(
                obj["canary_result"],
                document_name=name,
                path="$.sources.canary_result",
                expected_media_type=_CANARY_RESULT_MEDIA_TYPE,
                maximum_bytes=MAX_CANARY_RESULT_BYTES,
            )
            if "canary_result" in obj
            else None
        ),
    )


def _parse_evidence(value: Any) -> TeamCaseEvidenceSummary:
    name = "Team case record"
    path = "$.evidence"
    required = {
        "title",
        "created_at",
        "severity",
        "requirement_status",
        "oracle_kind",
        "oracle_independent",
        "reproduction_trial_count",
        "reproduced_trial_count",
        "hypotheses",
        "proposed_component",
        "proposed_summary",
        "prediction",
        "change_ref",
        "changed_surface_count",
        "known_risk_count",
        "validation_case_count",
        "validation_candidate_passed_count",
        "validation_critical_failed_count",
    }
    obj = _object(value, document_name=name, path=path, required=required)
    hypothesis_values = _array(
        obj["hypotheses"],
        document_name=name,
        path=f"{path}.hypotheses",
        minimum=1,
        maximum=MAX_TEAM_CASE_HYPOTHESES,
    )
    hypotheses: list[TeamCaseHypothesisSummary] = []
    for index, item in enumerate(hypothesis_values):
        item_path = f"{path}.hypotheses[{index}]"
        parsed = _object(
            item,
            document_name=name,
            path=item_path,
            required={
                "component",
                "confidence",
                "evidence_count",
                "intervention_present",
                "intervention_trial_count",
                "intervention_resolved_count",
            },
            optional={"intervention_isolated"},
        )
        intervention_present = _boolean(
            parsed["intervention_present"],
            document_name=name,
            path=f"{item_path}.intervention_present",
        )
        isolated = (
            _boolean(
                parsed["intervention_isolated"],
                document_name=name,
                path=f"{item_path}.intervention_isolated",
            )
            if "intervention_isolated" in parsed
            else None
        )
        if intervention_present != (isolated is not None):
            raise TeamCaseValidationError(
                name,
                f"{item_path}.intervention_isolated",
                "presence must match intervention_present",
            )
        trial_count = _integer(
            parsed["intervention_trial_count"],
            document_name=name,
            path=f"{item_path}.intervention_trial_count",
            minimum=0,
            maximum=10_000,
        )
        resolved_count = _integer(
            parsed["intervention_resolved_count"],
            document_name=name,
            path=f"{item_path}.intervention_resolved_count",
            minimum=0,
            maximum=10_000,
        )
        if resolved_count > trial_count or (not intervention_present and trial_count != 0):
            raise TeamCaseValidationError(
                name,
                f"{item_path}.intervention_trial_count",
                "intervention counts are inconsistent",
            )
        hypotheses.append(
            TeamCaseHypothesisSummary(
                component=_enum(
                    parsed["component"],
                    document_name=name,
                    path=f"{item_path}.component",
                    enum_type=Component,
                ),
                confidence=_number(
                    parsed["confidence"],
                    document_name=name,
                    path=f"{item_path}.confidence",
                    minimum=0,
                    maximum=1,
                ),
                evidence_count=_integer(
                    parsed["evidence_count"],
                    document_name=name,
                    path=f"{item_path}.evidence_count",
                    minimum=0,
                    maximum=10_000,
                ),
                intervention_present=intervention_present,
                intervention_isolated=isolated,
                intervention_trial_count=trial_count,
                intervention_resolved_count=resolved_count,
            )
        )
    reproduction_count = _integer(
        obj["reproduction_trial_count"],
        document_name=name,
        path=f"{path}.reproduction_trial_count",
        minimum=0,
        maximum=10_000,
    )
    reproduced_count = _integer(
        obj["reproduced_trial_count"],
        document_name=name,
        path=f"{path}.reproduced_trial_count",
        minimum=0,
        maximum=10_000,
    )
    validation_count = _integer(
        obj["validation_case_count"],
        document_name=name,
        path=f"{path}.validation_case_count",
        minimum=0,
        maximum=10_000,
    )
    candidate_passed = _integer(
        obj["validation_candidate_passed_count"],
        document_name=name,
        path=f"{path}.validation_candidate_passed_count",
        minimum=0,
        maximum=10_000,
    )
    critical_failed = _integer(
        obj["validation_critical_failed_count"],
        document_name=name,
        path=f"{path}.validation_critical_failed_count",
        minimum=0,
        maximum=10_000,
    )
    if reproduced_count > reproduction_count or candidate_passed > validation_count:
        raise TeamCaseValidationError(name, path, "summary counts are inconsistent")
    return TeamCaseEvidenceSummary(
        title=_text(obj["title"], document_name=name, path=f"{path}.title", maximum=512),
        created_at=_timestamp(obj["created_at"], document_name=name, path=f"{path}.created_at"),
        severity=_enum(
            obj["severity"], document_name=name, path=f"{path}.severity", enum_type=IncidentSeverity
        ),
        requirement_status=_enum(
            obj["requirement_status"],
            document_name=name,
            path=f"{path}.requirement_status",
            enum_type=RequirementStatus,
        ),
        oracle_kind=_enum(
            obj["oracle_kind"],
            document_name=name,
            path=f"{path}.oracle_kind",
            enum_type=OracleKind,
        ),
        oracle_independent=_boolean(
            obj["oracle_independent"],
            document_name=name,
            path=f"{path}.oracle_independent",
        ),
        reproduction_trial_count=reproduction_count,
        reproduced_trial_count=reproduced_count,
        hypotheses=tuple(hypotheses),
        proposed_component=_enum(
            obj["proposed_component"],
            document_name=name,
            path=f"{path}.proposed_component",
            enum_type=Component,
        ),
        proposed_summary=_text(
            obj["proposed_summary"],
            document_name=name,
            path=f"{path}.proposed_summary",
            maximum=2048,
        ),
        prediction=_text(
            obj["prediction"], document_name=name, path=f"{path}.prediction", maximum=2048
        ),
        change_ref=_text(
            obj["change_ref"], document_name=name, path=f"{path}.change_ref", maximum=512
        ),
        changed_surface_count=_integer(
            obj["changed_surface_count"],
            document_name=name,
            path=f"{path}.changed_surface_count",
            minimum=1,
            maximum=10_000,
        ),
        known_risk_count=_integer(
            obj["known_risk_count"],
            document_name=name,
            path=f"{path}.known_risk_count",
            minimum=0,
            maximum=10_000,
        ),
        validation_case_count=validation_count,
        validation_candidate_passed_count=candidate_passed,
        validation_critical_failed_count=critical_failed,
    )


def _parse_review(value: Any) -> TeamCaseReviewSummary:
    name = "Team case record"
    path = "$.review"
    obj = _object(
        value,
        document_name=name,
        path=path,
        required={
            "engine_version",
            "policy_name",
            "reviewed_at",
            "decision",
            "recommended_action",
            "summary",
            "findings",
        },
    )
    findings: list[TeamCaseFindingSummary] = []
    codes: set[str] = set()
    for index, item in enumerate(
        _array(
            obj["findings"],
            document_name=name,
            path=f"{path}.findings",
            minimum=0,
            maximum=MAX_TEAM_CASE_FINDINGS,
        )
    ):
        item_path = f"{path}.findings[{index}]"
        parsed = _object(
            item,
            document_name=name,
            path=item_path,
            required={"code", "status", "consequence"},
        )
        code = _text(
            parsed["code"],
            document_name=name,
            path=f"{item_path}.code",
            maximum=128,
            pattern=_FINDING_CODE_PATTERN,
        )
        if code in codes:
            raise TeamCaseValidationError(name, f"{path}.findings", "codes must be unique")
        codes.add(code)
        findings.append(
            TeamCaseFindingSummary(
                code=code,
                status=_enum(
                    parsed["status"],
                    document_name=name,
                    path=f"{item_path}.status",
                    enum_type=CheckStatus,
                ),
                consequence=_enum(
                    parsed["consequence"],
                    document_name=name,
                    path=f"{item_path}.consequence",
                    enum_type=Consequence,
                ),
            )
        )
    return TeamCaseReviewSummary(
        engine_version=_text(
            obj["engine_version"],
            document_name=name,
            path=f"{path}.engine_version",
            maximum=128,
        ),
        policy_name=_text(
            obj["policy_name"],
            document_name=name,
            path=f"{path}.policy_name",
            maximum=128,
        ),
        reviewed_at=_timestamp(obj["reviewed_at"], document_name=name, path=f"{path}.reviewed_at"),
        decision=_enum(
            obj["decision"], document_name=name, path=f"{path}.decision", enum_type=Decision
        ),
        recommended_action=_enum(
            obj["recommended_action"],
            document_name=name,
            path=f"{path}.recommended_action",
            enum_type=RecommendedAction,
        ),
        summary=_text(obj["summary"], document_name=name, path=f"{path}.summary", maximum=8192),
        findings=tuple(findings),
    )


def _parse_delivery(value: Any) -> TeamCaseDeliverySummary:
    name = "Team case record"
    path = "$.delivery"
    obj = _object(
        value,
        document_name=name,
        path=path,
        required={
            "published_at",
            "verified_at",
            "server_path",
            "target_kind",
            "build_id",
            "build_number",
            "work_item_ids",
        },
        optional={"changeset_id", "shelveset_name", "shelveset_owner"},
    )
    kind = _enum(
        obj["target_kind"],
        document_name=name,
        path=f"{path}.target_kind",
        enum_type=TfvcTargetKind,
    )
    changeset_id: int | None = None
    shelveset_name: str | None = None
    shelveset_owner: str | None = None
    if kind is TfvcTargetKind.CHANGESET:
        if set(obj) & {"shelveset_name", "shelveset_owner"} or "changeset_id" not in obj:
            raise TeamCaseValidationError(name, path, "changeset target fields are inconsistent")
        changeset_id = _integer(
            obj["changeset_id"],
            document_name=name,
            path=f"{path}.changeset_id",
            minimum=1,
            maximum=2_147_483_647,
        )
    else:
        if "changeset_id" in obj or not {"shelveset_name", "shelveset_owner"} <= set(obj):
            raise TeamCaseValidationError(name, path, "shelveset target fields are inconsistent")
        shelveset_name = _text(
            obj["shelveset_name"],
            document_name=name,
            path=f"{path}.shelveset_name",
            maximum=128,
        )
        shelveset_owner = _text(
            obj["shelveset_owner"],
            document_name=name,
            path=f"{path}.shelveset_owner",
            maximum=320,
        )
    work_items = tuple(
        _integer(
            item,
            document_name=name,
            path=f"{path}.work_item_ids[{index}]",
            minimum=1,
            maximum=2_147_483_647,
        )
        for index, item in enumerate(
            _array(
                obj["work_item_ids"],
                document_name=name,
                path=f"{path}.work_item_ids",
                minimum=0,
                maximum=10_000,
            )
        )
    )
    if len(set(work_items)) != len(work_items):
        raise TeamCaseValidationError(name, f"{path}.work_item_ids", "must be unique")
    result = TeamCaseDeliverySummary(
        published_at=_timestamp(
            obj["published_at"],
            document_name=name,
            path=f"{path}.published_at",
            require_utc_seconds=True,
        ),
        verified_at=_timestamp(
            obj["verified_at"],
            document_name=name,
            path=f"{path}.verified_at",
            require_utc_seconds=True,
        ),
        server_path=_text(
            obj["server_path"], document_name=name, path=f"{path}.server_path", maximum=512
        ),
        target_kind=kind,
        changeset_id=changeset_id,
        shelveset_name=shelveset_name,
        shelveset_owner=shelveset_owner,
        build_id=_integer(
            obj["build_id"],
            document_name=name,
            path=f"{path}.build_id",
            minimum=1,
            maximum=2_147_483_647,
        ),
        build_number=_text(
            obj["build_number"],
            document_name=name,
            path=f"{path}.build_number",
            maximum=128,
        ),
        work_item_ids=work_items,
    )
    if not result.server_path.startswith("$/"):
        raise TeamCaseValidationError(name, f"{path}.server_path", "must be a TFVC server path")
    if datetime.fromisoformat(result.verified_at.replace("Z", "+00:00")) < datetime.fromisoformat(
        result.published_at.replace("Z", "+00:00")
    ):
        raise TeamCaseValidationError(
            name,
            f"{path}.verified_at",
            "must be at or after published_at",
        )
    return result


def _parse_approval(value: Any) -> TeamCaseApprovalSummary:
    name = "Team case record"
    path = "$.approval"
    obj = _object(
        value,
        document_name=name,
        path=path,
        required={
            "checked_at",
            "assertion",
            "authority_id",
            "key_id",
            "identity_provider",
            "subject_id",
            "authentication_method",
            "authentication_event_id",
            "action",
            "gate_effect",
            "issued_at",
            "expires_at",
            "trust_store_id",
            "revocation_list_id",
            "revocation_list_updated_at",
            "exception_finding_codes",
        },
    )
    codes = tuple(
        _text(
            item,
            document_name=name,
            path=f"{path}.exception_finding_codes[{index}]",
            maximum=128,
            pattern=_FINDING_CODE_PATTERN,
        )
        for index, item in enumerate(
            _array(
                obj["exception_finding_codes"],
                document_name=name,
                path=f"{path}.exception_finding_codes",
                minimum=0,
                maximum=64,
            )
        )
    )
    if codes != tuple(sorted(set(codes))):
        raise TeamCaseValidationError(
            name, f"{path}.exception_finding_codes", "must be unique and sorted"
        )
    action = _enum(
        obj["action"], document_name=name, path=f"{path}.action", enum_type=ApprovalAction
    )
    if (action is ApprovalAction.EXCEPTION) != bool(codes):
        raise TeamCaseValidationError(name, path, "approval action and exception codes disagree")
    result = TeamCaseApprovalSummary(
        checked_at=_timestamp(
            obj["checked_at"],
            document_name=name,
            path=f"{path}.checked_at",
            require_utc_seconds=True,
        ),
        assertion=_parse_subject(
            obj["assertion"],
            document_name=name,
            path=f"{path}.assertion",
            expected_media_type=_APPROVAL_ASSERTION_MEDIA_TYPE,
            maximum_bytes=1024 * 1024,
        ),
        authority_id=_text(
            obj["authority_id"],
            document_name=name,
            path=f"{path}.authority_id",
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        key_id=_text(
            obj["key_id"],
            document_name=name,
            path=f"{path}.key_id",
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        identity_provider=_text(
            obj["identity_provider"],
            document_name=name,
            path=f"{path}.identity_provider",
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        subject_id=_text(
            obj["subject_id"],
            document_name=name,
            path=f"{path}.subject_id",
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        authentication_method=_enum(
            obj["authentication_method"],
            document_name=name,
            path=f"{path}.authentication_method",
            enum_type=ApprovalAuthenticationMethod,
        ),
        authentication_event_id=_text(
            obj["authentication_event_id"],
            document_name=name,
            path=f"{path}.authentication_event_id",
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        action=action,
        gate_effect=_enum(
            obj["gate_effect"],
            document_name=name,
            path=f"{path}.gate_effect",
            enum_type=ApprovalGateEffect,
        ),
        issued_at=_timestamp(
            obj["issued_at"],
            document_name=name,
            path=f"{path}.issued_at",
            require_utc_seconds=True,
        ),
        expires_at=_timestamp(
            obj["expires_at"],
            document_name=name,
            path=f"{path}.expires_at",
            require_utc_seconds=True,
        ),
        trust_store_id=_text(
            obj["trust_store_id"],
            document_name=name,
            path=f"{path}.trust_store_id",
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        revocation_list_id=_text(
            obj["revocation_list_id"],
            document_name=name,
            path=f"{path}.revocation_list_id",
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        revocation_list_updated_at=_timestamp(
            obj["revocation_list_updated_at"],
            document_name=name,
            path=f"{path}.revocation_list_updated_at",
            require_utc_seconds=True,
        ),
        exception_finding_codes=codes,
    )
    issued_at = datetime.fromisoformat(result.issued_at.replace("Z", "+00:00"))
    checked_at = datetime.fromisoformat(result.checked_at.replace("Z", "+00:00"))
    expires_at = datetime.fromisoformat(result.expires_at.replace("Z", "+00:00"))
    revocations_at = datetime.fromisoformat(
        result.revocation_list_updated_at.replace("Z", "+00:00")
    )
    if not issued_at <= checked_at < expires_at:
        raise TeamCaseValidationError(
            name,
            f"{path}.checked_at",
            "must be within the recorded approval validity window",
        )
    if revocations_at > checked_at:
        raise TeamCaseValidationError(
            name,
            f"{path}.revocation_list_updated_at",
            "must be at or before checked_at",
        )
    return result


def _parse_canary(value: Any) -> TeamCaseCanarySummary:
    name = "Team case record"
    path = "$.canary"
    required = {
        "comparison_id",
        "look_number",
        "maximum_looks",
        "policy_id",
        "evaluator_ref",
        "assignment_method",
        "assignment_unit",
        "compared_at",
        "window_started_at",
        "window_ended_at",
        "baseline_deployment_ref",
        "candidate_deployment_ref",
        "baseline_sample_count",
        "candidate_sample_count",
        "confidence_level",
        "decision",
        "summary",
        "metrics",
    }
    obj = _object(value, document_name=name, path=path, required=required)
    metrics: list[TeamCaseCanaryMetricSummary] = []
    metric_ids: set[str] = set()
    for index, item in enumerate(
        _array(
            obj["metrics"],
            document_name=name,
            path=f"{path}.metrics",
            minimum=1,
            maximum=MAX_TEAM_CASE_METRICS,
        )
    ):
        item_path = f"{path}.metrics[{index}]"
        parsed = _object(
            item,
            document_name=name,
            path=item_path,
            required={
                "metric_id",
                "direction",
                "maximum_degradation",
                "baseline_rate",
                "candidate_rate",
                "confidence_lower",
                "confidence_upper",
                "status",
            },
        )
        metric_id = _text(
            parsed["metric_id"],
            document_name=name,
            path=f"{item_path}.metric_id",
            maximum=128,
            pattern=_CASE_ID_PATTERN,
        )
        if metric_id in metric_ids:
            raise TeamCaseValidationError(name, f"{path}.metrics", "metric ids must be unique")
        metric_ids.add(metric_id)
        lower = _number(
            parsed["confidence_lower"],
            document_name=name,
            path=f"{item_path}.confidence_lower",
            minimum=-1,
            maximum=1,
        )
        upper = _number(
            parsed["confidence_upper"],
            document_name=name,
            path=f"{item_path}.confidence_upper",
            minimum=-1,
            maximum=1,
        )
        if lower > upper:
            raise TeamCaseValidationError(
                name, f"{item_path}.confidence_lower", "must not exceed confidence_upper"
            )
        metrics.append(
            TeamCaseCanaryMetricSummary(
                metric_id=metric_id,
                direction=_enum(
                    parsed["direction"],
                    document_name=name,
                    path=f"{item_path}.direction",
                    enum_type=CanaryMetricDirection,
                ),
                maximum_degradation=_number(
                    parsed["maximum_degradation"],
                    document_name=name,
                    path=f"{item_path}.maximum_degradation",
                    minimum=0,
                    maximum=1,
                ),
                baseline_rate=_number(
                    parsed["baseline_rate"],
                    document_name=name,
                    path=f"{item_path}.baseline_rate",
                    minimum=0,
                    maximum=1,
                ),
                candidate_rate=_number(
                    parsed["candidate_rate"],
                    document_name=name,
                    path=f"{item_path}.candidate_rate",
                    minimum=0,
                    maximum=1,
                ),
                confidence_lower=lower,
                confidence_upper=upper,
                status=_enum(
                    parsed["status"],
                    document_name=name,
                    path=f"{item_path}.status",
                    enum_type=CanaryMetricStatus,
                ),
            )
        )
    look_number = _integer(
        obj["look_number"],
        document_name=name,
        path=f"{path}.look_number",
        minimum=1,
        maximum=100,
    )
    maximum_looks = _integer(
        obj["maximum_looks"],
        document_name=name,
        path=f"{path}.maximum_looks",
        minimum=1,
        maximum=100,
    )
    if look_number > maximum_looks:
        raise TeamCaseValidationError(name, f"{path}.look_number", "exceeds maximum_looks")
    result = TeamCaseCanarySummary(
        comparison_id=_text(
            obj["comparison_id"],
            document_name=name,
            path=f"{path}.comparison_id",
            maximum=128,
            pattern=_CASE_ID_PATTERN,
        ),
        look_number=look_number,
        maximum_looks=maximum_looks,
        policy_id=_text(
            obj["policy_id"],
            document_name=name,
            path=f"{path}.policy_id",
            maximum=128,
            pattern=_CASE_ID_PATTERN,
        ),
        evaluator_ref=_text(
            obj["evaluator_ref"],
            document_name=name,
            path=f"{path}.evaluator_ref",
            maximum=512,
        ),
        assignment_method=_enum(
            obj["assignment_method"],
            document_name=name,
            path=f"{path}.assignment_method",
            enum_type=CanaryAssignmentMethod,
        ),
        assignment_unit=_enum(
            obj["assignment_unit"],
            document_name=name,
            path=f"{path}.assignment_unit",
            enum_type=CanaryAssignmentUnit,
        ),
        compared_at=_timestamp(
            obj["compared_at"],
            document_name=name,
            path=f"{path}.compared_at",
            require_utc_seconds=True,
        ),
        window_started_at=_timestamp(
            obj["window_started_at"],
            document_name=name,
            path=f"{path}.window_started_at",
            require_utc_seconds=True,
        ),
        window_ended_at=_timestamp(
            obj["window_ended_at"],
            document_name=name,
            path=f"{path}.window_ended_at",
            require_utc_seconds=True,
        ),
        baseline_deployment_ref=_text(
            obj["baseline_deployment_ref"],
            document_name=name,
            path=f"{path}.baseline_deployment_ref",
            maximum=512,
        ),
        candidate_deployment_ref=_text(
            obj["candidate_deployment_ref"],
            document_name=name,
            path=f"{path}.candidate_deployment_ref",
            maximum=512,
        ),
        baseline_sample_count=_integer(
            obj["baseline_sample_count"],
            document_name=name,
            path=f"{path}.baseline_sample_count",
            minimum=1,
            maximum=1_000_000_000,
        ),
        candidate_sample_count=_integer(
            obj["candidate_sample_count"],
            document_name=name,
            path=f"{path}.candidate_sample_count",
            minimum=1,
            maximum=1_000_000_000,
        ),
        confidence_level=_number(
            obj["confidence_level"],
            document_name=name,
            path=f"{path}.confidence_level",
            minimum=0.90,
            maximum=0.999,
        ),
        decision=_enum(
            obj["decision"],
            document_name=name,
            path=f"{path}.decision",
            enum_type=CanaryDecision,
        ),
        summary=_text(obj["summary"], document_name=name, path=f"{path}.summary", maximum=8192),
        metrics=tuple(metrics),
    )
    started_at = datetime.fromisoformat(result.window_started_at.replace("Z", "+00:00"))
    ended_at = datetime.fromisoformat(result.window_ended_at.replace("Z", "+00:00"))
    compared_at = datetime.fromisoformat(result.compared_at.replace("Z", "+00:00"))
    if not started_at < ended_at:
        raise TeamCaseValidationError(
            name,
            f"{path}.window_ended_at",
            "must be after window_started_at",
        )
    if compared_at < ended_at:
        raise TeamCaseValidationError(
            name,
            f"{path}.compared_at",
            "must be at or after window_ended_at",
        )
    if result.baseline_deployment_ref == result.candidate_deployment_ref:
        raise TeamCaseValidationError(
            name,
            f"{path}.candidate_deployment_ref",
            "must differ from baseline_deployment_ref",
        )
    return result


def parse_team_case_record(document: Any) -> TeamCaseRecord:
    """Strictly parse one minimized Team dashboard case record."""

    name = "Team case record"
    root = _object(
        document,
        document_name=name,
        path="$",
        required={
            "schema_version",
            "tenant_id",
            "case_id",
            "revision",
            "published_at",
            "sources",
            "evidence",
            "review",
        },
        optional={"delivery", "approval", "canary"},
    )
    if root["schema_version"] != TEAM_CASE_RECORD_SCHEMA_VERSION:
        raise TeamCaseValidationError(
            name,
            "$.schema_version",
            f"expected {TEAM_CASE_RECORD_SCHEMA_VERSION!r}",
        )
    sources = _parse_sources(root["sources"])
    delivery = _parse_delivery(root["delivery"]) if "delivery" in root else None
    approval = _parse_approval(root["approval"]) if "approval" in root else None
    canary = _parse_canary(root["canary"]) if "canary" in root else None
    review = _parse_review(root["review"])
    if (delivery is None) != (sources.azure_publication is None):
        raise TeamCaseValidationError(name, "$.delivery", "presence disagrees with sources")
    if (approval is None) != (sources.approval_verification is None):
        raise TeamCaseValidationError(name, "$.approval", "presence disagrees with sources")
    if (canary is None) != (sources.canary_result is None):
        raise TeamCaseValidationError(name, "$.canary", "presence disagrees with sources")
    if approval is not None:
        consequential_codes = tuple(
            sorted(
                finding.code
                for finding in review.findings
                if finding.consequence is not Consequence.NONE
            )
        )
        if approval.action is ApprovalAction.APPROVE:
            if review.decision is not Decision.APPROVE:
                raise TeamCaseValidationError(
                    name,
                    "$.approval.action",
                    "approve is valid only for an approve review decision",
                )
        elif (
            review.decision is Decision.APPROVE
            or approval.exception_finding_codes != consequential_codes
        ):
            raise TeamCaseValidationError(
                name,
                "$.approval.exception_finding_codes",
                "must exactly cover a non-approve review's decision-affecting findings",
            )
    return TeamCaseRecord(
        schema_version=TEAM_CASE_RECORD_SCHEMA_VERSION,
        tenant_id=_text(
            root["tenant_id"],
            document_name=name,
            path="$.tenant_id",
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        case_id=_text(
            root["case_id"],
            document_name=name,
            path="$.case_id",
            maximum=128,
            pattern=_CASE_ID_PATTERN,
        ),
        revision=_integer(
            root["revision"],
            document_name=name,
            path="$.revision",
            minimum=1,
            maximum=10_000,
        ),
        published_at=_timestamp(
            root["published_at"],
            document_name=name,
            path="$.published_at",
            require_utc_seconds=True,
        ),
        sources=sources,
        evidence=_parse_evidence(root["evidence"]),
        review=review,
        delivery=delivery,
        approval=approval,
        canary=canary,
    )


def parse_team_case_record_bytes(raw_bytes: bytes) -> TeamCaseRecord:
    """Parse exact bounded UTF-8 Team dashboard case-record bytes."""

    return parse_team_case_record(
        _json_bytes(
            raw_bytes,
            document_name="Team case record",
            maximum=MAX_TEAM_CASE_RECORD_BYTES,
        )
    )


def validate_team_case_successor(
    previous: TeamCaseRecord | None,
    candidate: TeamCaseRecord,
) -> TeamCaseRecord:
    """Require append-only case evolution while preserving exact base evidence."""

    if not isinstance(candidate, TeamCaseRecord):
        raise TypeError("candidate must be a TeamCaseRecord")
    if previous is None:
        if candidate.revision != 1:
            raise TeamCaseValidationError(
                "Team case record", "$.revision", "the first case revision must be 1"
            )
        return candidate
    if not isinstance(previous, TeamCaseRecord):
        raise TypeError("previous must be a TeamCaseRecord or None")
    if candidate.tenant_id != previous.tenant_id or candidate.case_id != previous.case_id:
        raise TeamCaseValidationError(
            "Team case record", "$", "successor tenant and case id must remain unchanged"
        )
    if candidate.revision != previous.revision + 1:
        raise TeamCaseValidationError(
            "Team case record", "$.revision", "must advance the previous revision by one"
        )
    if (
        candidate.sources.change_case != previous.sources.change_case
        or candidate.sources.review_result != previous.sources.review_result
        or candidate.evidence != previous.evidence
        or candidate.review != previous.review
    ):
        raise TeamCaseValidationError(
            "Team case record",
            "$.sources",
            "change-case, review, and derived evidence summaries are immutable",
        )
    for name, old, new in (
        ("delivery", previous.delivery, candidate.delivery),
        ("approval", previous.approval, candidate.approval),
    ):
        if old is not None and new is None:
            raise TeamCaseValidationError(
                "Team case record", f"$.{name}", "a recorded stage cannot be removed"
            )
    if previous.delivery is not None and candidate.delivery != previous.delivery:
        raise TeamCaseValidationError(
            "Team case record", "$.delivery", "recorded delivery evidence is immutable"
        )
    if previous.delivery is not None and (
        candidate.sources.review_report != previous.sources.review_report
        or candidate.sources.azure_publication != previous.sources.azure_publication
        or candidate.sources.azure_verification != previous.sources.azure_verification
    ):
        raise TeamCaseValidationError(
            "Team case record",
            "$.sources",
            "recorded Azure delivery subjects are immutable",
        )
    if previous.approval is not None and candidate.approval != previous.approval:
        raise TeamCaseValidationError(
            "Team case record", "$.approval", "recorded approval evidence is immutable"
        )
    if previous.approval is not None and (
        candidate.sources.approval_verification != previous.sources.approval_verification
    ):
        raise TeamCaseValidationError(
            "Team case record",
            "$.sources.approval_verification",
            "recorded approval subject is immutable",
        )
    if previous.canary is not None:
        if candidate.canary is None:
            raise TeamCaseValidationError(
                "Team case record", "$.canary", "a recorded canary result cannot be removed"
            )
        if candidate.canary == previous.canary:
            if candidate.sources.canary_result != previous.sources.canary_result:
                raise TeamCaseValidationError(
                    "Team case record",
                    "$.sources.canary_result",
                    "an unchanged canary summary must retain its exact source subject",
                )
        elif candidate.canary.comparison_id == previous.canary.comparison_id:
            if (
                previous.canary.decision is not CanaryDecision.CONTINUE
                or candidate.canary.look_number <= previous.canary.look_number
                or candidate.canary.maximum_looks != previous.canary.maximum_looks
                or candidate.canary.policy_id != previous.canary.policy_id
                or candidate.canary.baseline_deployment_ref
                != previous.canary.baseline_deployment_ref
                or candidate.canary.candidate_deployment_ref
                != previous.canary.candidate_deployment_ref
            ):
                raise TeamCaseValidationError(
                    "Team case record",
                    "$.canary",
                    "same-comparison canary updates must advance a nonterminal look",
                )
            if candidate.sources.canary_result == previous.sources.canary_result:
                raise TeamCaseValidationError(
                    "Team case record",
                    "$.sources.canary_result",
                    "an advancing canary look must bind a new exact source subject",
                )
        elif previous.canary.decision not in {
            CanaryDecision.ROLLBACK,
            CanaryDecision.NEEDS_EVIDENCE,
        }:
            raise TeamCaseValidationError(
                "Team case record",
                "$.canary.comparison_id",
                "a new comparison may follow only rollback or needs-evidence",
            )
        elif candidate.sources.canary_result == previous.sources.canary_result:
            raise TeamCaseValidationError(
                "Team case record",
                "$.sources.canary_result",
                "a new canary comparison must bind a new exact source subject",
            )
    if datetime.fromisoformat(
        candidate.published_at.replace("Z", "+00:00")
    ) <= datetime.fromisoformat(previous.published_at.replace("Z", "+00:00")):
        raise TeamCaseValidationError(
            "Team case record", "$.published_at", "must advance the previous publication time"
        )
    if (
        candidate.delivery == previous.delivery
        and candidate.approval == previous.approval
        and candidate.canary == previous.canary
    ):
        raise TeamCaseValidationError(
            "Team case record", "$", "successor must add or advance dashboard evidence"
        )
    return candidate


def render_team_case_record(record: TeamCaseRecord) -> str:
    """Render one canonical, minimized Team case record."""

    validated = parse_team_case_record(to_jsonable(record))
    return (
        json.dumps(
            to_jsonable(validated),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
