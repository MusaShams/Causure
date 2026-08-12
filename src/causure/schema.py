"""JSON Schemas for integration boundaries."""

from __future__ import annotations

from typing import Any

from causure.constants import (
    APPROVAL_ASSERTION_SCHEMA_VERSION,
    APPROVAL_REVOCATION_LIST_SCHEMA_VERSION,
    APPROVAL_TRUST_STORE_SCHEMA_VERSION,
    APPROVAL_VERIFICATION_SCHEMA_VERSION,
    ARTIFACT_ATTESTATION_SCHEMA_VERSION,
    ATTESTATION_REVOCATION_LIST_SCHEMA_VERSION,
    ATTESTATION_TRUST_STORE_SCHEMA_VERSION,
    ATTESTATION_VERIFICATION_SCHEMA_VERSION,
    AZURE_REVIEW_PUBLICATION_SCHEMA_VERSION,
    AZURE_REVIEW_VERIFICATION_SCHEMA_VERSION,
    CANARY_OBSERVATION_SCHEMA_VERSION,
    CANARY_POLICY_SCHEMA_VERSION,
    CANARY_RESULT_SCHEMA_VERSION,
    CASE_SCHEMA_VERSION,
    ENTRA_REFRESH_CONFIG_SCHEMA_VERSION,
    ENTRA_TRUST_STORE_SCHEMA_VERSION,
    GITHUB_CHECK_RUN_RECEIPT_SCHEMA_VERSION,
    GITHUB_CHECK_RUN_REQUEST_SCHEMA_VERSION,
    GITHUB_REVIEW_PUBLICATION_SCHEMA_VERSION,
    GITHUB_REVIEW_VERIFICATION_SCHEMA_VERSION,
    INVESTIGATION_FIXTURE_SCHEMA_VERSION,
    INVESTIGATION_SELECTION_SCHEMA_VERSION,
    OMITTED_TRACE_FIELD_GROUPS,
    OPENAI_QUOTA_CONFIG_SCHEMA_VERSION,
    OPENAI_QUOTA_HOST_CONFIG_SCHEMA_VERSION,
    SAFE_TRACE_NUMERIC_ATTRIBUTES,
    SAFE_TRACE_TEXT_ATTRIBUTES,
    SAFE_TRACE_TEXT_PATTERN,
    SANDBOX_POLICY_SCHEMA_VERSION,
    SANDBOX_WORKER_SCHEMA_VERSION,
    TEAM_ACCESS_POLICY_SCHEMA_VERSION,
    TEAM_AUDIT_EVENT_SCHEMA_VERSION,
    TEAM_AUDIT_EXPORT_SCHEMA_VERSION,
    TEAM_AUDIT_VERIFICATION_SCHEMA_VERSION,
    TEAM_AUTHORIZATION_SCHEMA_VERSION,
    TEAM_CASE_RECORD_SCHEMA_VERSION,
    TEAM_HOST_CONFIG_SCHEMA_VERSION,
    TEAM_INVESTIGATION_RECORD_SCHEMA_VERSION,
    TRACE_MANIFEST_SCHEMA_VERSION,
    TRUSTED_CASE_GENERATION_RECEIPT_SCHEMA_VERSION,
    ApprovalAction,
    ApprovalAuthenticationMethod,
    ApprovalGateEffect,
    AzureBuildReason,
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
    OpenInferenceSpanKind,
    OracleKind,
    RecommendedAction,
    RedactionStrategy,
    RequirementStatus,
    RevocationMode,
    SandboxNetworkMode,
    SandboxWorkerMode,
    SignatureAlgorithm,
    SignatureCanonicalization,
    TeamAction,
    TeamAuditOutcome,
    TeamAuthorizationReason,
    TeamInvestigationPriority,
    TeamInvestigationResolution,
    TeamInvestigationStatus,
    TeamResourceType,
    TeamRole,
    TfvcTargetKind,
    TraceSourceFormat,
    ValidationKind,
)
from causure.policy import GatePolicy, policy_to_dict

_SCHEMA_URI = "https://json-schema.org/draft/2020-12/schema"


def _enum_values(enum_type: type) -> list[str]:
    return [member.value for member in enum_type]


def _closed_object(
    properties: dict[str, Any],
    *,
    required: list[str] | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "object",
        "additionalProperties": False,
        "properties": properties,
    }
    if required:
        schema["required"] = required
    return schema


def _nonempty_string() -> dict[str, Any]:
    return {"type": "string", "minLength": 1}


def _string_array(*, minimum: int = 0) -> dict[str, Any]:
    schema: dict[str, Any] = {
        "type": "array",
        "items": _nonempty_string(),
        "uniqueItems": True,
    }
    if minimum:
        schema["minItems"] = minimum
    return schema


def change_case_schema() -> dict[str, Any]:
    """Return the versioned change-case schema."""

    definitions: dict[str, Any] = {
        "incident": _closed_object(
            {
                "claimed_failure": _nonempty_string(),
                "expected_behavior": _nonempty_string(),
                "observed_behavior": _nonempty_string(),
                "severity": {"enum": _enum_values(IncidentSeverity)},
                "requirement_status": {"enum": _enum_values(RequirementStatus)},
                "source_refs": _string_array(minimum=1),
            },
            required=[
                "claimed_failure",
                "expected_behavior",
                "observed_behavior",
                "severity",
                "requirement_status",
                "source_refs",
            ],
        ),
        "oracle": _closed_object(
            {
                "kind": {"enum": _enum_values(OracleKind)},
                "description": _nonempty_string(),
                "independent": {"type": "boolean"},
                "evidence_refs": _string_array(minimum=1),
            },
            required=["kind", "description", "independent", "evidence_refs"],
        ),
        "reproduction_trial": _closed_object(
            {
                "id": _nonempty_string(),
                "reproduced": {"type": "boolean"},
                "evidence_ref": _nonempty_string(),
            },
            required=["id", "reproduced", "evidence_ref"],
        ),
        "verification": _closed_object(
            {
                "oracle": {"$ref": "#/$defs/oracle"},
                "reproduction_trials": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/reproduction_trial"},
                },
            },
            required=["oracle", "reproduction_trials"],
        ),
        "intervention_trial": _closed_object(
            {
                "id": _nonempty_string(),
                "failure_resolved": {"type": "boolean"},
                "evidence_ref": _nonempty_string(),
            },
            required=["id", "failure_resolved", "evidence_ref"],
        ),
        "intervention": _closed_object(
            {
                "description": _nonempty_string(),
                "isolated": {"type": "boolean"},
                "held_constant": _string_array(minimum=1),
                "trials": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/intervention_trial"},
                },
            },
            required=["description", "isolated", "held_constant", "trials"],
        ),
        "hypothesis": _closed_object(
            {
                "component": {"enum": _enum_values(Component)},
                "confidence": {"type": "number", "minimum": 0, "maximum": 1},
                "evidence_refs": _string_array(minimum=1),
                "intervention": {"$ref": "#/$defs/intervention"},
            },
            required=["component", "confidence", "evidence_refs"],
        ),
        "attribution": _closed_object(
            {
                "hypotheses": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/hypothesis"},
                }
            },
            required=["hypotheses"],
        ),
        "proposed_change": _closed_object(
            {
                "component": {"enum": _enum_values(Component)},
                "summary": _nonempty_string(),
                "prediction": _nonempty_string(),
                "expected_unaffected_behaviors": _string_array(minimum=1),
                "known_risks": _string_array(),
                "changed_surface_count": {"type": "integer", "minimum": 1},
                "change_ref": _nonempty_string(),
            },
            required=[
                "component",
                "summary",
                "prediction",
                "expected_unaffected_behaviors",
                "known_risks",
                "changed_surface_count",
                "change_ref",
            ],
        ),
        "null_hypothesis": _closed_object(
            {
                "statement": _nonempty_string(),
                "evidence_against": _string_array(),
            },
            required=["statement", "evidence_against"],
        ),
        "validation_case": _closed_object(
            {
                "id": _nonempty_string(),
                "kind": {"enum": _enum_values(ValidationKind)},
                "critical": {"type": "boolean"},
                "baseline_passed": {"type": "boolean"},
                "candidate_passed": {"type": "boolean"},
                "evidence_ref": _nonempty_string(),
            },
            required=[
                "id",
                "kind",
                "critical",
                "baseline_passed",
                "candidate_passed",
                "evidence_ref",
            ],
        ),
        "metric_snapshot": _closed_object(
            {
                "p95_latency_ms": {"type": "number", "minimum": 0},
                "mean_cost_usd": {"type": "number", "minimum": 0},
                "mean_tokens": {"type": "number", "minimum": 0},
            }
        ),
        "metric_comparison": _closed_object(
            {
                "baseline": {"$ref": "#/$defs/metric_snapshot"},
                "candidate": {"$ref": "#/$defs/metric_snapshot"},
            },
            required=["baseline", "candidate"],
        ),
        "validation": _closed_object(
            {
                "cases": {
                    "type": "array",
                    "items": {"$ref": "#/$defs/validation_case"},
                },
                "metrics": {"$ref": "#/$defs/metric_comparison"},
            },
            required=["cases"],
        ),
    }
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure change case",
        "type": "object",
        "additionalProperties": False,
        "required": [
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
        ],
        "properties": {
            "schema_version": {"const": CASE_SCHEMA_VERSION},
            "case_id": {
                "type": "string",
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
            },
            "title": _nonempty_string(),
            "created_at": {"type": "string", "format": "date-time"},
            "incident": {"$ref": "#/$defs/incident"},
            "verification": {"$ref": "#/$defs/verification"},
            "attribution": {"$ref": "#/$defs/attribution"},
            "proposed_change": {"$ref": "#/$defs/proposed_change"},
            "null_hypothesis": {"$ref": "#/$defs/null_hypothesis"},
            "validation": {"$ref": "#/$defs/validation"},
        },
        "$defs": definitions,
    }


def policy_schema() -> dict[str, Any]:
    """Return the sparse policy-override schema."""

    defaults = policy_to_dict(GatePolicy())
    properties: dict[str, Any] = {"name": _nonempty_string()}
    integer_fields = {
        "min_reproduction_trials",
        "min_intervention_trials",
        "max_changed_surfaces",
        "min_positive_controls",
        "min_negative_controls",
        "min_regression_controls",
    }
    boolean_fields = {
        "require_independent_oracle",
        "require_isolated_intervention",
        "allow_critical_regressions",
        "require_metrics_for_approval",
        "block_on_metric_regression",
    }
    ratio_limit_fields = {"max_cost_increase_ratio", "max_latency_increase_ratio"}
    for key, default in defaults.items():
        if key == "name":
            properties[key]["default"] = default
        elif key in integer_fields:
            properties[key] = {"type": "integer", "minimum": 1, "default": default}
        elif key in boolean_fields:
            properties[key] = {"type": "boolean", "default": default}
        elif key in ratio_limit_fields:
            properties[key] = {"type": "number", "minimum": 0, "default": default}
        else:
            properties[key] = {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
                "default": default,
            }
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure policy override",
        **_closed_object(properties),
    }


def review_result_schema() -> dict[str, Any]:
    """Return the machine-readable review-result schema."""

    finding = _closed_object(
        {
            "code": _nonempty_string(),
            "status": {"enum": _enum_values(CheckStatus)},
            "consequence": {"enum": _enum_values(Consequence)},
            "message": _nonempty_string(),
            "details": {"type": "object"},
        },
        required=["code", "status", "consequence", "message", "details"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure review result",
        **_closed_object(
            {
                "schema_version": {"const": "1.0"},
                "engine_version": _nonempty_string(),
                "policy_name": _nonempty_string(),
                "case_id": _nonempty_string(),
                "case_title": _nonempty_string(),
                "component": {"enum": _enum_values(Component)},
                "input_sha256": {
                    "type": "string",
                    "pattern": "^[a-f0-9]{64}$",
                },
                "reviewed_at": {"type": "string", "format": "date-time"},
                "decision": {"enum": _enum_values(Decision)},
                "recommended_action": {"enum": _enum_values(RecommendedAction)},
                "summary": _nonempty_string(),
                "metrics": {"type": "object"},
                "findings": {"type": "array", "items": finding},
            },
            required=[
                "schema_version",
                "engine_version",
                "policy_name",
                "case_id",
                "case_title",
                "component",
                "input_sha256",
                "reviewed_at",
                "decision",
                "recommended_action",
                "summary",
                "metrics",
                "findings",
            ],
        ),
    }


def trace_manifest_schema() -> dict[str, Any]:
    """Return the redacted trace-manifest schema."""

    sha256 = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
    safe_text_value = {
        "type": "string",
        "pattern": SAFE_TRACE_TEXT_PATTERN,
    }
    safe_number_value = {"type": "number", "minimum": 0}
    safe_attribute_properties = {
        key: safe_text_value
        for key in SAFE_TRACE_TEXT_ATTRIBUTES
        if key != "openinference.span.kind"
    }
    safe_attribute_properties["openinference.span.kind"] = {
        "enum": _enum_values(OpenInferenceSpanKind)
    }
    for key in SAFE_TRACE_NUMERIC_ATTRIBUTES:
        safe_attribute_properties[key] = safe_number_value
    source = _closed_object(
        {
            "artifact_id": {
                "type": "string",
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
            },
            "format": {"enum": _enum_values(TraceSourceFormat)},
            "media_type": {"const": "application/json"},
            "sha256": sha256,
            "byte_count": {"type": "integer", "minimum": 1},
            "trace_count": {"type": "integer", "minimum": 1},
            "span_count": {"type": "integer", "minimum": 1},
            "source_embedded": {"const": False},
        },
        required=[
            "artifact_id",
            "format",
            "media_type",
            "sha256",
            "byte_count",
            "trace_count",
            "span_count",
            "source_embedded",
        ],
    )
    redaction = _closed_object(
        {
            "strategy": {"enum": _enum_values(RedactionStrategy)},
            "raw_content_included": {"const": False},
            "retained_attribute_count": {"type": "integer", "minimum": 0},
            "redacted_attribute_count": {"type": "integer", "minimum": 0},
            "dropped_attribute_count": {"type": "integer", "minimum": 0},
            "omitted_field_groups": {
                "type": "array",
                "items": {"enum": list(OMITTED_TRACE_FIELD_GROUPS)},
                "minItems": len(OMITTED_TRACE_FIELD_GROUPS),
                "maxItems": len(OMITTED_TRACE_FIELD_GROUPS),
                "uniqueItems": True,
            },
        },
        required=[
            "strategy",
            "raw_content_included",
            "retained_attribute_count",
            "redacted_attribute_count",
            "dropped_attribute_count",
            "omitted_field_groups",
        ],
    )
    span = _closed_object(
        {
            "evidence_ref": {
                "type": "string",
                "pattern": r"^trace-sha256://[a-f0-9]{64}/spans/[a-f0-9]{64}$",
            },
            "trace_id_sha256": sha256,
            "span_id_sha256": sha256,
            "parent_span_id_sha256": sha256,
            "start_time_unix_nano": {"type": "string", "pattern": r"^[0-9]+$"},
            "end_time_unix_nano": {"type": "string", "pattern": r"^[0-9]+$"},
            "duration_nano": {"type": "string", "pattern": r"^[0-9]+$"},
            "kind": {"type": "integer", "minimum": 0, "maximum": 5},
            "status_code": {"type": "integer", "minimum": 0, "maximum": 2},
            "attributes": {
                "type": "object",
                "additionalProperties": False,
                "properties": safe_attribute_properties,
            },
        },
        required=[
            "evidence_ref",
            "trace_id_sha256",
            "span_id_sha256",
            "attributes",
        ],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure redacted trace manifest",
        **_closed_object(
            {
                "schema_version": {"const": TRACE_MANIFEST_SCHEMA_VERSION},
                "collector_version": _nonempty_string(),
                "source": source,
                "redaction": redaction,
                "spans": {
                    "type": "array",
                    "items": span,
                    "minItems": 1,
                },
            },
            required=[
                "schema_version",
                "collector_version",
                "source",
                "redaction",
                "spans",
            ],
        ),
    }


def investigation_fixture_schema() -> dict[str, Any]:
    """Return the draft investigation-fixture schema."""

    sha256 = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
    decimal = {"type": "string", "pattern": r"^(0|[1-9][0-9]*)$"}
    named_count = _closed_object(
        {
            "name": {"enum": _enum_values(OpenInferenceSpanKind)},
            "count": {"type": "integer", "minimum": 1},
        },
        required=["name", "count"],
    )
    status_count = _closed_object(
        {
            "code": {"type": "integer", "minimum": 0, "maximum": 2},
            "count": {"type": "integer", "minimum": 1},
        },
        required=["code", "count"],
    )
    source = _closed_object(
        {
            "manifest_sha256": sha256,
            "trace_artifact_id": {
                "type": "string",
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
            },
            "trace_source_sha256": sha256,
            "trace_count": {"type": "integer", "minimum": 1},
            "span_count": {"type": "integer", "minimum": 1},
        },
        required=[
            "manifest_sha256",
            "trace_artifact_id",
            "trace_source_sha256",
            "trace_count",
            "span_count",
        ],
    )
    cluster = _closed_object(
        {
            "cluster_id": {
                "type": "string",
                "pattern": r"^trace-[a-f0-9]{64}$",
            },
            "trace_ref": {
                "type": "string",
                "pattern": (r"^trace-sha256://[a-f0-9]{64}/traces/[a-f0-9]{64}$"),
            },
            "trace_id_sha256": sha256,
            "span_evidence_refs": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": (r"^trace-sha256://[a-f0-9]{64}/spans/[a-f0-9]{64}$"),
                },
                "minItems": 1,
                "uniqueItems": True,
            },
            "span_count": {"type": "integer", "minimum": 1},
            "root_span_count": {"type": "integer", "minimum": 0},
            "error_span_count": {"type": "integer", "minimum": 0},
            "span_kind_counts": {
                "type": "array",
                "items": named_count,
            },
            "status_code_counts": {
                "type": "array",
                "items": status_count,
            },
            "model_identifiers": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": SAFE_TRACE_TEXT_PATTERN,
                },
                "uniqueItems": True,
            },
            "provider_identifiers": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": SAFE_TRACE_TEXT_PATTERN,
                },
                "uniqueItems": True,
            },
            "earliest_start_time_unix_nano": decimal,
            "latest_end_time_unix_nano": decimal,
            "observed_duration_nano": decimal,
        },
        required=[
            "cluster_id",
            "trace_ref",
            "trace_id_sha256",
            "span_evidence_refs",
            "span_count",
            "root_span_count",
            "error_span_count",
            "span_kind_counts",
            "status_code_counts",
            "model_identifiers",
            "provider_identifiers",
        ],
    )
    missing_evidence = [
        "incident_claim",
        "governing_requirement",
        "independent_oracle",
        "reproduction_outcomes",
        "causal_attribution",
        "proposed_change",
        "negative_and_regression_controls",
    ]
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure draft investigation fixture",
        **_closed_object(
            {
                "schema_version": {"const": INVESTIGATION_FIXTURE_SCHEMA_VERSION},
                "generator_version": _nonempty_string(),
                "fixture_id": {
                    "type": "string",
                    "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
                },
                "draft_only": {"const": True},
                "gate_eligible": {"const": False},
                "causal_claims_inferred": {"const": False},
                "clustering_basis": {"const": "trace_identity"},
                "source": source,
                "missing_evidence": {
                    "type": "array",
                    "items": {"enum": missing_evidence},
                    "minItems": len(missing_evidence),
                    "maxItems": len(missing_evidence),
                    "uniqueItems": True,
                },
                "candidate_clusters": {
                    "type": "array",
                    "items": cluster,
                    "minItems": 1,
                },
            },
            required=[
                "schema_version",
                "generator_version",
                "fixture_id",
                "draft_only",
                "gate_eligible",
                "causal_claims_inferred",
                "clustering_basis",
                "source",
                "missing_evidence",
                "candidate_clusters",
            ],
        ),
    }


def investigation_selection_schema() -> dict[str, Any]:
    """Return the local investigation-selection schema."""

    sha256 = {"type": "string", "pattern": "^[a-f0-9]{64}$"}

    def artifact_subject(path: str) -> dict[str, Any]:
        return _closed_object(
            {
                "byte_count": {"type": "integer", "minimum": 1},
                "path": {"const": path},
                "sha256": sha256,
            },
            required=["byte_count", "path", "sha256"],
        )

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure investigation selection",
        **_closed_object(
            {
                "candidate_only": {"const": True},
                "causal_claims_inferred": {"const": False},
                "fixture": artifact_subject("investigation-fixture.json"),
                "gate_eligible": {"const": False},
                "manifest": artifact_subject("trace-manifest.json"),
                "schema_version": {"const": INVESTIGATION_SELECTION_SCHEMA_VERSION},
                "selected_cluster_ids": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "pattern": r"^trace-[a-f0-9]{64}$",
                    },
                    "minItems": 1,
                    "uniqueItems": True,
                },
                "source": _closed_object(
                    {
                        "artifact_id": {
                            "type": "string",
                            "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
                        },
                        "byte_count": {"type": "integer", "minimum": 1},
                        "raw_content_stored": {"const": False},
                        "sha256": sha256,
                    },
                    required=[
                        "artifact_id",
                        "byte_count",
                        "raw_content_stored",
                        "sha256",
                    ],
                ),
            },
            required=[
                "candidate_only",
                "causal_claims_inferred",
                "fixture",
                "gate_eligible",
                "manifest",
                "schema_version",
                "selected_cluster_ids",
                "source",
            ],
        ),
    }


def _attestation_safe_id() -> dict[str, Any]:
    return {
        "type": "string",
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{2,127}$",
    }


def _attestation_timestamp() -> dict[str, Any]:
    return {
        "type": "string",
        "format": "date-time",
        "pattern": (
            r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])"
            r"T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
        ),
    }


def _artifact_subject_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "artifact_id": _attestation_safe_id(),
            "media_type": {
                "type": "string",
                "pattern": (
                    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/"
                    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$"
                ),
            },
            "sha256": {
                "type": "string",
                "pattern": "^[a-f0-9]{64}$",
            },
            "byte_count": {"type": "integer", "minimum": 1},
        },
        required=["artifact_id", "media_type", "sha256", "byte_count"],
    )


def _producer_identity_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "producer_id": _attestation_safe_id(),
            "key_id": _attestation_safe_id(),
        },
        required=["producer_id", "key_id"],
    )


def _retention_requirement_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "class_id": _attestation_safe_id(),
            "retain_until": _attestation_timestamp(),
        },
        required=["class_id", "retain_until"],
    )


def artifact_attestation_schema() -> dict[str, Any]:
    """Return the detached artifact-attestation schema."""

    signature = _closed_object(
        {
            "algorithm": {"enum": _enum_values(SignatureAlgorithm)},
            "canonicalization": {
                "enum": _enum_values(SignatureCanonicalization),
            },
            "value": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_-]{86}$",
            },
        },
        required=["algorithm", "canonicalization", "value"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure artifact attestation",
        **_closed_object(
            {
                "schema_version": {
                    "const": ARTIFACT_ATTESTATION_SCHEMA_VERSION,
                },
                "artifact": _artifact_subject_schema(),
                "producer": _producer_identity_schema(),
                "issued_at": _attestation_timestamp(),
                "expires_at": _attestation_timestamp(),
                "retention": _retention_requirement_schema(),
                "revocation_list_id": _attestation_safe_id(),
                "signature": signature,
            },
            required=[
                "schema_version",
                "artifact",
                "producer",
                "issued_at",
                "expires_at",
                "retention",
                "revocation_list_id",
                "signature",
            ],
        ),
    }


def attestation_trust_store_schema() -> dict[str, Any]:
    """Return the trusted producer-key binding schema."""

    key = _closed_object(
        {
            "key_id": _attestation_safe_id(),
            "producer_id": _attestation_safe_id(),
            "algorithm": {"enum": _enum_values(SignatureAlgorithm)},
            "public_key_base64url": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_-]{43}$",
            },
            "valid_from": _attestation_timestamp(),
            "valid_until": _attestation_timestamp(),
        },
        required=[
            "key_id",
            "producer_id",
            "algorithm",
            "public_key_base64url",
            "valid_from",
            "valid_until",
        ],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure attestation trust store",
        **_closed_object(
            {
                "schema_version": {
                    "const": ATTESTATION_TRUST_STORE_SCHEMA_VERSION,
                },
                "store_id": _attestation_safe_id(),
                "revocation_list_id": _attestation_safe_id(),
                "keys": {
                    "type": "array",
                    "items": key,
                    "minItems": 1,
                    "maxItems": 1_000,
                },
            },
            required=[
                "schema_version",
                "store_id",
                "revocation_list_id",
                "keys",
            ],
        ),
    }


def attestation_revocation_list_schema() -> dict[str, Any]:
    """Return the producer-key revocation-list schema."""

    revoked_key = _closed_object(
        {
            "key_id": _attestation_safe_id(),
            "revoked_at": _attestation_timestamp(),
            "mode": {"enum": _enum_values(RevocationMode)},
            "reason": {
                "type": "string",
                "minLength": 1,
                "maxLength": 256,
            },
        },
        required=["key_id", "revoked_at", "mode", "reason"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure attestation revocation list",
        **_closed_object(
            {
                "schema_version": {
                    "const": ATTESTATION_REVOCATION_LIST_SCHEMA_VERSION,
                },
                "list_id": _attestation_safe_id(),
                "updated_at": _attestation_timestamp(),
                "revoked_keys": {
                    "type": "array",
                    "items": revoked_key,
                    "maxItems": 10_000,
                },
            },
            required=[
                "schema_version",
                "list_id",
                "updated_at",
                "revoked_keys",
            ],
        ),
    }


def attestation_verification_schema() -> dict[str, Any]:
    """Return the successful attestation-verification receipt schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure attestation verification",
        **_closed_object(
            {
                "schema_version": {
                    "const": ATTESTATION_VERIFICATION_SCHEMA_VERSION,
                },
                "verifier_version": _nonempty_string(),
                "status": {"const": "verified"},
                "artifact": _artifact_subject_schema(),
                "producer": _producer_identity_schema(),
                "issued_at": _attestation_timestamp(),
                "expires_at": _attestation_timestamp(),
                "retention": _retention_requirement_schema(),
                "signature_algorithm": {
                    "enum": _enum_values(SignatureAlgorithm),
                },
                "canonicalization": {
                    "enum": _enum_values(SignatureCanonicalization),
                },
                "trust_store_id": _attestation_safe_id(),
                "revocation_list_id": _attestation_safe_id(),
                "revocation_list_updated_at": _attestation_timestamp(),
                "checked_at": _attestation_timestamp(),
            },
            required=[
                "schema_version",
                "verifier_version",
                "status",
                "artifact",
                "producer",
                "issued_at",
                "expires_at",
                "retention",
                "signature_algorithm",
                "canonicalization",
                "trust_store_id",
                "revocation_list_id",
                "revocation_list_updated_at",
                "checked_at",
            ],
        ),
    }


def _sandbox_text() -> dict[str, Any]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": 2_048,
    }


def sandbox_policy_schema() -> dict[str, Any]:
    """Return the trusted OCI sandbox deployment-policy schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure sandbox policy",
        **_closed_object(
            {
                "schema_version": {"const": SANDBOX_POLICY_SCHEMA_VERSION},
                "policy_id": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": 128,
                    "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{2,127}$",
                },
                "worker_protocol": {"const": SANDBOX_WORKER_SCHEMA_VERSION},
                "image": {
                    "type": "string",
                    "maxLength": 328,
                    "pattern": (
                        r"^[a-z0-9][a-z0-9._:/-]{0,255}"
                        r"@sha256:[a-f0-9]{64}$"
                    ),
                },
                "network_mode": {"enum": _enum_values(SandboxNetworkMode)},
                "cpu_limit": {
                    "type": "number",
                    "minimum": 0.1,
                    "maximum": 64,
                },
                "memory_mb": {
                    "type": "integer",
                    "minimum": 64,
                    "maximum": 65_536,
                },
                "pids_limit": {
                    "type": "integer",
                    "minimum": 8,
                    "maximum": 4_096,
                },
                "tmpfs_mb": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 4_096,
                },
                "max_output_bytes": {
                    "type": "integer",
                    "minimum": 1_024,
                    "maximum": 16 * 1_024 * 1_024,
                },
                "user": {
                    "type": "string",
                    "pattern": r"^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$",
                },
            },
            required=[
                "schema_version",
                "policy_id",
                "worker_protocol",
                "image",
                "network_mode",
                "cpu_limit",
                "memory_mb",
                "pids_limit",
                "tmpfs_mb",
                "max_output_bytes",
                "user",
            ],
        ),
    }


def openai_quota_config_schema() -> dict[str, Any]:
    """Return the protected OpenAI-compatible quota configuration schema."""

    price = {
        "type": "string",
        "pattern": r"^(0|[1-9][0-9]{0,5})\.[0-9]{1,9}$",
    }
    model = _closed_object(
        {
            "model": {
                "type": "string",
                "minLength": 2,
                "maxLength": 128,
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:/-]{1,127}$",
            },
            "input_usd_per_million_tokens": {"$ref": "#/$defs/price"},
            "cached_input_usd_per_million_tokens": {"$ref": "#/$defs/price"},
            "output_usd_per_million_tokens": {"$ref": "#/$defs/price"},
            "max_input_tokens": {
                "type": "integer",
                "minimum": 1,
                "maximum": 10_000_000,
            },
            "max_output_tokens": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1_000_000,
            },
        },
        required=[
            "model",
            "input_usd_per_million_tokens",
            "cached_input_usd_per_million_tokens",
            "output_usd_per_million_tokens",
            "max_input_tokens",
            "max_output_tokens",
        ],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure OpenAI-compatible quota proxy configuration",
        **_closed_object(
            {
                "schema_version": {"const": OPENAI_QUOTA_CONFIG_SCHEMA_VERSION},
                "service_id": {
                    "type": "string",
                    "minLength": 3,
                    "maxLength": 128,
                    "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{2,127}$",
                },
                "upstream_responses_url": {
                    "type": "string",
                    "maxLength": 2_048,
                    "pattern": r"^https://[^/?#]+/v1/responses$",
                },
                "worker_proxy_url": {
                    "type": "string",
                    "maxLength": 2_048,
                    "pattern": r"^https://[^/?#]+/v1$",
                },
                "proxy_container_name": {
                    "type": "string",
                    "minLength": 2,
                    "maxLength": 63,
                    "pattern": r"^[a-z0-9][a-z0-9.-]{1,62}$",
                },
                "network_name": {
                    "type": "string",
                    "minLength": 2,
                    "maxLength": 128,
                    "pattern": r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$",
                },
                "lease_cleanup_seconds": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": 3_600,
                },
                "upstream_timeout_seconds": {
                    "type": "number",
                    "minimum": 1,
                    "maximum": 300,
                },
                "max_request_bytes": {
                    "type": "integer",
                    "minimum": 1_024,
                    "maximum": 4_194_304,
                },
                "max_response_bytes": {
                    "type": "integer",
                    "minimum": 1_024,
                    "maximum": 16_777_216,
                },
                "models": {
                    "type": "array",
                    "minItems": 1,
                    "maxItems": 1_000,
                    "uniqueItems": True,
                    "items": model,
                },
            },
            required=[
                "schema_version",
                "service_id",
                "upstream_responses_url",
                "worker_proxy_url",
                "proxy_container_name",
                "network_name",
                "lease_cleanup_seconds",
                "upstream_timeout_seconds",
                "max_request_bytes",
                "max_response_bytes",
                "models",
            ],
        ),
        "$defs": {"price": price},
    }


def openai_quota_host_config_schema() -> dict[str, Any]:
    """Return the closed OpenAI-compatible quota host configuration schema."""

    path = {
        "type": "string",
        "minLength": 1,
        "maxLength": 4096,
        "pattern": r"^[^\u0000-\u001f\u007f]+$",
    }
    quota_configuration = _closed_object(
        {
            "path": path,
            "sha256": {"type": "string", "pattern": r"^[a-f0-9]{64}$"},
            "byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 65_536,
            },
        },
        required=["path", "sha256", "byte_count"],
    )
    database = _closed_object(
        {
            "path": path,
            "busy_timeout_ms": {
                "type": "integer",
                "minimum": 1,
                "maximum": 60_000,
            },
        },
        required=["path", "busy_timeout_ms"],
    )
    secrets = _closed_object(
        {
            "admin_token_path": path,
            "provider_api_key_path": path,
        },
        required=["admin_token_path", "provider_api_key_path"],
    )
    server = _closed_object(
        {
            "implementation": {"const": "waitress"},
            "version": {"const": "3.0.2"},
            "listen_host": {"enum": ["0.0.0.0", "127.0.0.1", "::", "::1"]},
            "listen_port": {
                "type": "integer",
                "minimum": 1,
                "maximum": 65_535,
            },
            "trusted_external_scheme": {"const": "https"},
            "threads": {
                "type": "integer",
                "minimum": 1,
                "maximum": 256,
            },
            "connection_limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 10_000,
            },
            "backlog": {
                "type": "integer",
                "minimum": 1,
                "maximum": 4096,
            },
            "channel_timeout_seconds": {
                "type": "integer",
                "minimum": 5,
                "maximum": 3600,
            },
            "max_request_header_bytes": {
                "type": "integer",
                "minimum": 1024,
                "maximum": 65_536,
            },
        },
        required=[
            "implementation",
            "version",
            "listen_host",
            "listen_port",
            "trusted_external_scheme",
            "threads",
            "connection_limit",
            "backlog",
            "channel_timeout_seconds",
            "max_request_header_bytes",
        ],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure OpenAI-compatible quota service host configuration",
        **_closed_object(
            {
                "schema_version": {"const": OPENAI_QUOTA_HOST_CONFIG_SCHEMA_VERSION},
                "quota_configuration": quota_configuration,
                "database": database,
                "secrets": secrets,
                "server": server,
            },
            required=[
                "schema_version",
                "quota_configuration",
                "database",
                "secrets",
                "server",
            ],
        ),
    }


def _sandbox_worker_budget_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "timeout_seconds": {
                "type": "number",
                "exclusiveMinimum": 0,
                "maximum": 86_400,
            },
            "max_concurrency": {"const": 1},
            "max_cases": {"const": 1},
            "max_cost_usd": {"type": "number", "minimum": 0},
        },
        required=["timeout_seconds", "max_concurrency", "max_cases"],
    )


def _sandbox_worker_quota_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "lease_id": {
                "type": "string",
                "minLength": 3,
                "maxLength": 128,
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{2,127}$",
            },
            "lease_token": {
                "type": "string",
                "minLength": 16,
                "maxLength": 8_192,
                "pattern": r"^\S+$",
                "writeOnly": True,
            },
            "proxy_url": {
                "type": "string",
                "maxLength": 2_048,
                "format": "uri",
                "pattern": (
                    r"^https://[A-Za-z0-9][A-Za-z0-9.-]*"
                    r"(?::[0-9]{1,5})?(?:/[^?#]*)?$"
                ),
            },
        },
        required=["lease_id", "lease_token", "proxy_url"],
    )


def sandbox_worker_request_schema() -> dict[str, Any]:
    """Return the one-reference sandbox worker request schema."""

    common = {
        "schema_version": {"const": SANDBOX_WORKER_SCHEMA_VERSION},
        "case_id": _sandbox_text(),
        "input_ref": _sandbox_text(),
        "budget": {"$ref": "#/$defs/budget"},
        "quota": {"$ref": "#/$defs/quota"},
    }
    replay = _closed_object(
        {
            **common,
            "mode": {"const": SandboxWorkerMode.REPLAY.value},
            "baseline_ref": _sandbox_text(),
            "candidate_ref": _sandbox_text(),
            "seed": {
                "type": "integer",
                "minimum": 0,
                "maximum": 2**63 - 1,
            },
        },
        required=[
            "schema_version",
            "mode",
            "case_id",
            "input_ref",
            "budget",
            "baseline_ref",
            "candidate_ref",
            "seed",
        ],
    )
    evaluation = _closed_object(
        {
            **common,
            "mode": {"const": SandboxWorkerMode.EVALUATION.value},
            "evaluator_ref": _sandbox_text(),
        },
        required=[
            "schema_version",
            "mode",
            "case_id",
            "input_ref",
            "budget",
            "evaluator_ref",
        ],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure sandbox worker request",
        "$defs": {
            "budget": _sandbox_worker_budget_schema(),
            "quota": _sandbox_worker_quota_schema(),
            "replay": replay,
            "evaluation": evaluation,
        },
        "oneOf": [
            {"$ref": "#/$defs/replay"},
            {"$ref": "#/$defs/evaluation"},
        ],
    }


def _sandbox_outcome_common() -> dict[str, Any]:
    return {
        "evidence_ref": _sandbox_text(),
        "latency_ms": {"type": "number", "minimum": 0},
        "cost_usd": {"type": "number", "minimum": 0},
    }


def sandbox_worker_response_schema() -> dict[str, Any]:
    """Return the one-outcome sandbox worker response schema."""

    replay_outcome = _closed_object(
        {
            "trial_id": _sandbox_text(),
            "reproduced": {"type": "boolean"},
            **_sandbox_outcome_common(),
        },
        required=[
            "trial_id",
            "reproduced",
            "evidence_ref",
            "latency_ms",
            "cost_usd",
        ],
    )
    evaluation_outcome = _closed_object(
        {
            "validation_case_id": _sandbox_text(),
            "passed": {"type": "boolean"},
            **_sandbox_outcome_common(),
            "score": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
            },
        },
        required=[
            "validation_case_id",
            "passed",
            "evidence_ref",
            "latency_ms",
            "cost_usd",
        ],
    )
    common = {
        "schema_version": {"const": SANDBOX_WORKER_SCHEMA_VERSION},
        "case_id": _sandbox_text(),
        "input_ref": _sandbox_text(),
    }
    replay = _closed_object(
        {
            **common,
            "mode": {"const": SandboxWorkerMode.REPLAY.value},
            "outcome": replay_outcome,
        },
        required=["schema_version", "mode", "case_id", "input_ref", "outcome"],
    )
    evaluation = _closed_object(
        {
            **common,
            "mode": {"const": SandboxWorkerMode.EVALUATION.value},
            "outcome": evaluation_outcome,
        },
        required=["schema_version", "mode", "case_id", "input_ref", "outcome"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure sandbox worker response",
        "$defs": {
            "replay": replay,
            "evaluation": evaluation,
        },
        "oneOf": [
            {"$ref": "#/$defs/replay"},
            {"$ref": "#/$defs/evaluation"},
        ],
    }


def _azure_sha256_schema() -> dict[str, Any]:
    return {"type": "string", "pattern": "^[a-f0-9]{64}$"}


def _azure_timestamp_schema(*, whole_seconds: bool) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "format": "date-time"}
    if whole_seconds:
        schema["pattern"] = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"
    else:
        schema["pattern"] = (
            "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\\.[0-9]{1,6})?Z$"
        )
    return schema


def _azure_artifact_schema(media_type: str, *, maximum_bytes: int) -> dict[str, Any]:
    return _closed_object(
        {
            "media_type": {"const": media_type},
            "sha256": _azure_sha256_schema(),
            "byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": maximum_bytes,
            },
        },
        required=["media_type", "sha256", "byte_count"],
    )


def _azure_review_binding_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "result_schema_version": {"const": "1.0"},
            "engine_version": {"type": "string", "minLength": 1, "maxLength": 128},
            "policy_name": {"type": "string", "minLength": 1, "maxLength": 128},
            "case_id": {
                "type": "string",
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
            },
            "component": {"enum": _enum_values(Component)},
            "input_sha256": _azure_sha256_schema(),
            "reviewed_at": _azure_timestamp_schema(whole_seconds=False),
            "decision": {"enum": _enum_values(Decision)},
            "recommended_action": {"enum": _enum_values(RecommendedAction)},
        },
        required=[
            "result_schema_version",
            "engine_version",
            "policy_name",
            "case_id",
            "component",
            "input_sha256",
            "reviewed_at",
            "decision",
            "recommended_action",
        ],
    )


def _azure_tfvc_schema() -> dict[str, Any]:
    changeset = _closed_object(
        {
            "kind": {"const": TfvcTargetKind.CHANGESET.value},
            "changeset_id": {"type": "integer", "minimum": 1},
        },
        required=["kind", "changeset_id"],
    )
    shelveset = _closed_object(
        {
            "kind": {"const": TfvcTargetKind.SHELVESET.value},
            "shelveset_name": {"type": "string", "minLength": 1, "maxLength": 128},
            "owner": {"type": "string", "minLength": 1, "maxLength": 320},
        },
        required=["kind", "shelveset_name", "owner"],
    )
    return _closed_object(
        {
            "server_path": {
                "type": "string",
                "pattern": r"^\$/[^/;](?:[^;]*[^/;])?$",
                "maxLength": 512,
            },
            "target": {"oneOf": [changeset, shelveset]},
        },
        required=["server_path", "target"],
    )


def _azure_build_schema() -> dict[str, Any]:
    uuid_schema = {
        "type": "string",
        "pattern": (
            "^(?!00000000-0000-0000-0000-000000000000$)"
            "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-"
            "[0-9a-f]{4}-[0-9a-f]{12}$"
        ),
    }
    return _closed_object(
        {
            "collection_uri": {
                "type": "string",
                "format": "uri",
                "pattern": "^https://[^/?#@]+(?:/[^?#]*)?/$",
                "maxLength": 2048,
            },
            "project_id": uuid_schema,
            "project_name": {"type": "string", "minLength": 1, "maxLength": 256},
            "build_id": {"type": "integer", "minimum": 1},
            "build_number": {"type": "string", "minLength": 1, "maxLength": 256},
            "definition_id": {"type": "integer", "minimum": 1},
            "definition_name": {"type": "string", "minLength": 1, "maxLength": 256},
            "reason": {"enum": _enum_values(AzureBuildReason)},
            "repository_provider": {"const": "TfsVersionControl"},
            "source_version": {"type": "string", "minLength": 1, "maxLength": 256},
            "source_branch": {"type": "string", "minLength": 1, "maxLength": 512},
            "source_tfvc_shelveset": {
                "type": "string",
                "minLength": 3,
                "maxLength": 512,
                "pattern": "^.+;.+$",
            },
            "requested_for_id": uuid_schema,
        },
        required=[
            "collection_uri",
            "project_id",
            "project_name",
            "build_id",
            "build_number",
            "definition_id",
            "definition_name",
            "reason",
            "repository_provider",
            "source_version",
            "source_branch",
            "requested_for_id",
        ],
    )


def _azure_artifacts_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "review_result": _azure_artifact_schema(
                "application/vnd.causure.review-result+json",
                maximum_bytes=5242880,
            ),
            "review_report": _azure_artifact_schema(
                "text/markdown; charset=utf-8",
                maximum_bytes=2097152,
            ),
        },
        required=["review_result", "review_report"],
    )


def azure_review_publication_schema() -> dict[str, Any]:
    """Return the Azure build and TFVC review-publication schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Azure review publication",
        **_closed_object(
            {
                "schema_version": {"const": AZURE_REVIEW_PUBLICATION_SCHEMA_VERSION},
                "created_at": _azure_timestamp_schema(whole_seconds=True),
                "review": {"$ref": "#/$defs/review"},
                "tfvc": {"$ref": "#/$defs/tfvc"},
                "build": {"$ref": "#/$defs/build"},
                "work_item_ids": {
                    "type": "array",
                    "items": {"type": "integer", "minimum": 1},
                    "uniqueItems": True,
                },
                "artifacts": {"$ref": "#/$defs/artifacts"},
            },
            required=[
                "schema_version",
                "created_at",
                "review",
                "tfvc",
                "build",
                "work_item_ids",
                "artifacts",
            ],
        ),
        "$defs": {
            "review": _azure_review_binding_schema(),
            "tfvc": _azure_tfvc_schema(),
            "build": _azure_build_schema(),
            "artifacts": _azure_artifacts_schema(),
        },
    }


def azure_review_verification_schema() -> dict[str, Any]:
    """Return the successful pre-approval verification-receipt schema."""

    publication_subject = _closed_object(
        {
            "media_type": {"const": ("application/vnd.causure.azure-review-publication+json")},
            "sha256": _azure_sha256_schema(),
            "byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1048576,
            },
        },
        required=["media_type", "sha256", "byte_count"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Azure review verification",
        **_closed_object(
            {
                "schema_version": {"const": AZURE_REVIEW_VERIFICATION_SCHEMA_VERSION},
                "status": {"const": "verified"},
                "verified_at": _azure_timestamp_schema(whole_seconds=True),
                "maximum_age_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 86400,
                },
                "publication_age_seconds": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 86400,
                },
                "publication": publication_subject,
                "review": {"$ref": "#/$defs/review"},
                "tfvc": {"$ref": "#/$defs/tfvc"},
                "build_id": {"type": "integer", "minimum": 1},
                "artifacts": {"$ref": "#/$defs/artifacts"},
            },
            required=[
                "schema_version",
                "status",
                "verified_at",
                "maximum_age_seconds",
                "publication_age_seconds",
                "publication",
                "review",
                "tfvc",
                "build_id",
                "artifacts",
            ],
        ),
        "$defs": {
            "review": _azure_review_binding_schema(),
            "tfvc": _azure_tfvc_schema(),
            "artifacts": _azure_artifacts_schema(),
        },
    }


def _github_artifact_schema(media_type: str, *, maximum_bytes: int) -> dict[str, Any]:
    return _closed_object(
        {
            "media_type": {"const": media_type},
            "sha256": _azure_sha256_schema(),
            "byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": maximum_bytes,
            },
        },
        required=["media_type", "sha256", "byte_count"],
    )


def _github_repository_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "repository_id": {"type": "integer", "minimum": 1},
            "owner_id": {"type": "integer", "minimum": 1},
            "full_name": {
                "type": "string",
                "minLength": 3,
                "maxLength": 255,
                "pattern": r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
            },
        },
        required=["repository_id", "owner_id", "full_name"],
    )


def _github_pull_request_schema() -> dict[str, Any]:
    commit = {
        "type": "string",
        "pattern": r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$",
    }
    ref = {
        "type": "string",
        "minLength": 1,
        "maxLength": 255,
        "pattern": r"^[^\u0000-\u001f\u007f]+$",
    }
    return _closed_object(
        {
            "number": {"type": "integer", "minimum": 1},
            "base_repository": {"$ref": "#/$defs/repository"},
            "base_ref": ref,
            "base_sha": commit,
            "head_repository": {"$ref": "#/$defs/repository"},
            "head_ref": ref,
            "head_sha": commit,
            "is_fork": {"type": "boolean"},
            "draft": {"type": "boolean"},
        },
        required=[
            "number",
            "base_repository",
            "base_ref",
            "base_sha",
            "head_repository",
            "head_ref",
            "head_sha",
            "is_fork",
            "draft",
        ],
    )


def _github_workflow_schema() -> dict[str, Any]:
    commit = {
        "type": "string",
        "pattern": r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$",
    }
    safe_text = {
        "type": "string",
        "minLength": 1,
        "pattern": r"^[^\u0000-\u001f\u007f]+$",
    }
    return _closed_object(
        {
            "server_url": {
                "type": "string",
                "format": "uri",
                "maxLength": 2048,
                "pattern": r"^https://[^/?#@]+$",
            },
            "event_name": {"const": "pull_request"},
            "event_action": {"enum": ["opened", "ready_for_review", "reopened", "synchronize"]},
            "event_sha": commit,
            "ref": {**safe_text, "maxLength": 512},
            "workflow_ref": {**safe_text, "maxLength": 1024},
            "workflow_sha": commit,
            "run_id": {"type": "integer", "minimum": 1},
            "run_number": {"type": "integer", "minimum": 1},
            "run_attempt": {"type": "integer", "minimum": 1},
            "job": {**safe_text, "maxLength": 255},
            "event_payload": _github_artifact_schema(
                "application/json",
                maximum_bytes=26214400,
            ),
        },
        required=[
            "server_url",
            "event_name",
            "event_action",
            "event_sha",
            "ref",
            "workflow_ref",
            "workflow_sha",
            "run_id",
            "run_number",
            "run_attempt",
            "job",
            "event_payload",
        ],
    )


def _github_review_artifacts_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "change_case": _github_artifact_schema(
                "application/vnd.causure.change-case+json",
                maximum_bytes=5242880,
            ),
            "review_result": _github_artifact_schema(
                "application/vnd.causure.review-result+json",
                maximum_bytes=5242880,
            ),
            "review_report": _github_artifact_schema(
                "text/markdown; charset=utf-8",
                maximum_bytes=2097152,
            ),
        },
        required=["change_case", "review_result", "review_report"],
    )


def github_review_publication_schema() -> dict[str, Any]:
    """Return the GitHub pull-request review-publication schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure GitHub review publication",
        **_closed_object(
            {
                "schema_version": {"const": GITHUB_REVIEW_PUBLICATION_SCHEMA_VERSION},
                "created_at": _azure_timestamp_schema(whole_seconds=True),
                "review": {"$ref": "#/$defs/review"},
                "pull_request": {"$ref": "#/$defs/pull_request"},
                "workflow": {"$ref": "#/$defs/workflow"},
                "artifacts": {"$ref": "#/$defs/artifacts"},
            },
            required=[
                "schema_version",
                "created_at",
                "review",
                "pull_request",
                "workflow",
                "artifacts",
            ],
        ),
        "$defs": {
            "review": _azure_review_binding_schema(),
            "repository": _github_repository_schema(),
            "pull_request": _github_pull_request_schema(),
            "workflow": _github_workflow_schema(),
            "artifacts": _github_review_artifacts_schema(),
        },
    }


def github_review_verification_schema() -> dict[str, Any]:
    """Return the successful GitHub publication-verification schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure GitHub review verification",
        **_closed_object(
            {
                "schema_version": {"const": GITHUB_REVIEW_VERIFICATION_SCHEMA_VERSION},
                "status": {"const": "verified"},
                "verified_at": _azure_timestamp_schema(whole_seconds=True),
                "maximum_age_seconds": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 86400,
                },
                "publication_age_seconds": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 86400,
                },
                "publication": _github_artifact_schema(
                    "application/vnd.causure.github-review-publication+json",
                    maximum_bytes=1048576,
                ),
                "review": {"$ref": "#/$defs/review"},
                "pull_request": {"$ref": "#/$defs/pull_request"},
                "workflow": {"$ref": "#/$defs/workflow"},
                "artifacts": {"$ref": "#/$defs/artifacts"},
            },
            required=[
                "schema_version",
                "status",
                "verified_at",
                "maximum_age_seconds",
                "publication_age_seconds",
                "publication",
                "review",
                "pull_request",
                "workflow",
                "artifacts",
            ],
        ),
        "$defs": {
            "review": _azure_review_binding_schema(),
            "repository": _github_repository_schema(),
            "pull_request": _github_pull_request_schema(),
            "workflow": _github_workflow_schema(),
            "artifacts": _github_review_artifacts_schema(),
        },
    }


def _github_check_run_finding_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "code": {
                "type": "string",
                "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
            },
            "status": {"enum": _enum_values(CheckStatus)},
            "consequence": {
                "enum": [
                    Consequence.CONDITIONAL.value,
                    Consequence.NEEDS_EVIDENCE.value,
                    Consequence.REJECT.value,
                    Consequence.HUMAN_REVIEW.value,
                ]
            },
            "path": {
                "type": "string",
                "minLength": 1,
                "maxLength": 1024,
                "pattern": (
                    r"^(?!/)(?!.*//)(?![^/]*:)"
                    r"(?!.*(?:^|/)\.{1,2}(?:/|$))"
                    r"[^\\\u0000-\u001f\u007f]+"
                    r"[^/\\\u0000-\u001f\u007f]$|"
                    r"^[^/\\:\u0000-\u001f\u007f]$"
                ),
            },
            "start_line": {"type": "integer", "minimum": 1},
            "end_line": {"type": "integer", "minimum": 1},
            "message": {"type": "string", "minLength": 1, "maxLength": 4096},
        },
        required=[
            "code",
            "status",
            "consequence",
            "path",
            "start_line",
            "end_line",
            "message",
        ],
    )


def github_check_run_request_schema() -> dict[str, Any]:
    """Return the token-free GitHub Check Run request-plan schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure GitHub Check Run request",
        **_closed_object(
            {
                "schema_version": {"const": GITHUB_CHECK_RUN_REQUEST_SCHEMA_VERSION},
                "created_at": _azure_timestamp_schema(whole_seconds=True),
                "repository": {"$ref": "#/$defs/repository"},
                "pull_request_number": {"type": "integer", "minimum": 1},
                "head_sha": {
                    "type": "string",
                    "pattern": r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$",
                },
                "is_fork": {"type": "boolean"},
                "workflow_run_id": {"type": "integer", "minimum": 1},
                "run_attempt": {"type": "integer", "minimum": 1},
                "verification": _github_artifact_schema(
                    "application/vnd.causure.github-review-verification+json",
                    maximum_bytes=1048576,
                ),
                "review": {"$ref": "#/$defs/review"},
                "allow_conditional": {"type": "boolean"},
                "name": {"const": "Causure evidence gate"},
                "conclusion": {"enum": ["success", "failure", "action_required"]},
                "details_url": {
                    "type": "string",
                    "format": "uri",
                    "maxLength": 2048,
                    "pattern": (
                        r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/"
                        r"actions/runs/[1-9][0-9]*$"
                    ),
                },
                "external_id": {
                    "type": "string",
                    "maxLength": 255,
                    "pattern": (
                        r"^causure:[1-9][0-9]*:[1-9][0-9]*:"
                        r"[1-9][0-9]*:[1-9][0-9]*:[a-f0-9]{16}$"
                    ),
                },
                "findings": {
                    "type": "array",
                    "maxItems": 50,
                    "items": {"$ref": "#/$defs/finding"},
                },
            },
            required=[
                "schema_version",
                "created_at",
                "repository",
                "pull_request_number",
                "head_sha",
                "is_fork",
                "workflow_run_id",
                "run_attempt",
                "verification",
                "review",
                "allow_conditional",
                "name",
                "conclusion",
                "details_url",
                "external_id",
                "findings",
            ],
        ),
        "$defs": {
            "repository": _github_repository_schema(),
            "review": _azure_review_binding_schema(),
            "finding": _github_check_run_finding_schema(),
        },
    }


def github_check_run_receipt_schema() -> dict[str, Any]:
    """Return the minimized successful GitHub Check Run receipt schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure GitHub Check Run receipt",
        **_closed_object(
            {
                "schema_version": {"const": GITHUB_CHECK_RUN_RECEIPT_SCHEMA_VERSION},
                "status": {"const": "published"},
                "published_at": _azure_timestamp_schema(whole_seconds=True),
                "repository": {"$ref": "#/$defs/repository"},
                "pull_request_number": {"type": "integer", "minimum": 1},
                "head_sha": {
                    "type": "string",
                    "pattern": r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$",
                },
                "workflow_run_id": {"type": "integer", "minimum": 1},
                "run_attempt": {"type": "integer", "minimum": 1},
                "check_run_id": {"type": "integer", "minimum": 1},
                "name": {"const": "Causure evidence gate"},
                "conclusion": {"enum": ["success", "failure", "action_required"]},
                "external_id": {
                    "type": "string",
                    "maxLength": 255,
                    "pattern": (
                        r"^causure:[1-9][0-9]*:[1-9][0-9]*:"
                        r"[1-9][0-9]*:[1-9][0-9]*:[a-f0-9]{16}$"
                    ),
                },
                "html_url": {
                    "type": "string",
                    "format": "uri",
                    "maxLength": 2048,
                    "pattern": (
                        r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/"
                        r"runs/[1-9][0-9]*$"
                    ),
                },
                "annotation_count": {
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 50,
                },
                "request": _github_artifact_schema(
                    "application/vnd.causure.github-check-run-request+json",
                    maximum_bytes=1048576,
                ),
                "verification": _github_artifact_schema(
                    "application/vnd.causure.github-review-verification+json",
                    maximum_bytes=1048576,
                ),
            },
            required=[
                "schema_version",
                "status",
                "published_at",
                "repository",
                "pull_request_number",
                "head_sha",
                "workflow_run_id",
                "run_attempt",
                "check_run_id",
                "name",
                "conclusion",
                "external_id",
                "html_url",
                "annotation_count",
                "request",
                "verification",
            ],
        ),
        "$defs": {"repository": _github_repository_schema()},
    }


def trusted_case_generation_receipt_schema() -> dict[str, Any]:
    """Return the minimized trusted adapter case-generation receipt schema."""

    sha256 = {"type": "string", "pattern": r"^[a-f0-9]{64}$"}
    safe_id = {
        "type": "string",
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
    }
    commit = {
        "type": "string",
        "pattern": r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$",
    }
    bounded_path = {"type": "string", "minLength": 1, "maxLength": 4096}
    adapter = _closed_object(
        {
            "adapter_id": safe_id,
            "directory_byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 8 * 1024 * 1024,
            },
            "directory_file_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 256,
            },
            "directory_sha256": sha256,
            "entry_module_byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 2 * 1024 * 1024,
            },
            "entry_module_path": bounded_path,
            "entry_module_sha256": sha256,
            "entry_point": {
                "type": "string",
                "pattern": (
                    r"^[A-Za-z_][A-Za-z0-9_.]{0,126}:"
                    r"[A-Za-z_][A-Za-z0-9_.]{0,126}$"
                ),
            },
            "kind": {"const": "case_generator"},
        },
        required=[
            "adapter_id",
            "directory_byte_count",
            "directory_file_count",
            "directory_sha256",
            "entry_module_byte_count",
            "entry_module_path",
            "entry_module_sha256",
            "entry_point",
            "kind",
        ],
    )
    change_case = _closed_object(
        {
            "byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 5 * 1024 * 1024,
            },
            "case_id": safe_id,
            "path": bounded_path,
            "sha256": sha256,
        },
        required=["byte_count", "case_id", "path", "sha256"],
    )
    component = _closed_object(
        {
            "byte_count": {
                "type": "integer",
                "minimum": 0,
                "maximum": 2 * 1024 * 1024,
            },
            "change_ref": {"type": "string", "format": "uri", "maxLength": 4096},
            "component": {"enum": _enum_values(Component)},
            "component_id": safe_id,
            "path": bounded_path,
            "sha256": sha256,
        },
        required=[
            "byte_count",
            "change_ref",
            "component",
            "component_id",
            "path",
            "sha256",
        ],
    )
    execution = _closed_object(
        {
            "adapter_loaded_from_trusted_directory": {"const": True},
            "candidate_code_executed": {"const": False},
            "candidate_component_content_embedded_in_receipt": {"const": False},
            "candidate_root_stored": {"const": False},
            "maximum_case_bytes": {
                "type": "integer",
                "minimum": 1,
                "maximum": 5 * 1024 * 1024,
            },
            "timeout_seconds": {
                "type": "number",
                "exclusiveMinimum": 0,
                "maximum": 3600,
            },
        },
        required=[
            "adapter_loaded_from_trusted_directory",
            "candidate_code_executed",
            "candidate_component_content_embedded_in_receipt",
            "candidate_root_stored",
            "maximum_case_bytes",
            "timeout_seconds",
        ],
    )
    pull_request = _closed_object(
        {
            "base_sha": commit,
            "head_sha": commit,
            "number": {"type": "integer", "minimum": 1},
            "repository": {
                "type": "string",
                "pattern": r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$",
                "maxLength": 255,
            },
        },
        required=["base_sha", "head_sha", "number", "repository"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure trusted case-generation receipt",
        **_closed_object(
            {
                "adapter": adapter,
                "change_case": change_case,
                "component": component,
                "execution": execution,
                "generated_at": _azure_timestamp_schema(whole_seconds=True),
                "generator_version": _nonempty_string(),
                "project_id": safe_id,
                "pull_request": pull_request,
                "request_id": safe_id,
                "schema_version": {"const": TRUSTED_CASE_GENERATION_RECEIPT_SCHEMA_VERSION},
            },
            required=[
                "adapter",
                "change_case",
                "component",
                "execution",
                "generated_at",
                "generator_version",
                "project_id",
                "pull_request",
                "request_id",
                "schema_version",
            ],
        ),
    }


def _approval_document_subject_schema(
    media_type: str,
    *,
    maximum_bytes: int,
) -> dict[str, Any]:
    return _closed_object(
        {
            "media_type": {"const": media_type},
            "sha256": _azure_sha256_schema(),
            "byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": maximum_bytes,
            },
        },
        required=["media_type", "sha256", "byte_count"],
    )


def _approval_subject_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "publication": _approval_document_subject_schema(
                "application/vnd.causure.azure-review-publication+json",
                maximum_bytes=1048576,
            ),
            "verification": _approval_document_subject_schema(
                "application/vnd.causure.azure-review-verification+json",
                maximum_bytes=1048576,
            ),
        },
        required=["publication", "verification"],
    )


def _approval_authority_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "authority_id": _attestation_safe_id(),
            "key_id": _attestation_safe_id(),
        },
        required=["authority_id", "key_id"],
    )


def _approver_identity_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "identity_provider": _attestation_safe_id(),
            "subject_id": _attestation_safe_id(),
            "authentication_method": {
                "enum": _enum_values(ApprovalAuthenticationMethod),
            },
            "authentication_event_id": _attestation_safe_id(),
            "authenticated_at": _attestation_timestamp(),
        },
        required=[
            "identity_provider",
            "subject_id",
            "authentication_method",
            "authentication_event_id",
            "authenticated_at",
        ],
    )


def _policy_exception_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "finding_codes": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
                },
                "minItems": 1,
                "maxItems": 64,
                "uniqueItems": True,
            },
            "justification": {
                "type": "string",
                "minLength": 1,
                "maxLength": 2048,
                "pattern": r"^[^\u0000-\u001f\u007f]+$",
            },
        },
        required=["finding_codes", "justification"],
    )


def _approval_signature_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "algorithm": {"const": SignatureAlgorithm.ED25519.value},
            "canonicalization": {
                "const": SignatureCanonicalization.CAUSURE_JSON_V1.value,
            },
            "value": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_-]{86}$",
            },
        },
        required=["algorithm", "canonicalization", "value"],
    )


def _approval_action_conditionals() -> list[dict[str, Any]]:
    return [
        {
            "if": {
                "properties": {
                    "action": {"const": ApprovalAction.APPROVE.value},
                },
                "required": ["action"],
            },
            "then": {"not": {"required": ["exception"]}},
        },
        {
            "if": {
                "properties": {
                    "action": {"const": ApprovalAction.EXCEPTION.value},
                },
                "required": ["action"],
            },
            "then": {"required": ["exception"]},
        },
    ]


def approval_assertion_schema() -> dict[str, Any]:
    """Return the signed authenticated-approver assertion schema."""

    body = _closed_object(
        {
            "schema_version": {"const": APPROVAL_ASSERTION_SCHEMA_VERSION},
            "assertion_id": _attestation_safe_id(),
            "authority": _approval_authority_schema(),
            "approver": _approver_identity_schema(),
            "action": {"enum": _enum_values(ApprovalAction)},
            "gate_effect": {"const": ApprovalGateEffect.RECORD_ONLY.value},
            "issued_at": _attestation_timestamp(),
            "expires_at": _attestation_timestamp(),
            "subject": _approval_subject_schema(),
            "revocation_list_id": _attestation_safe_id(),
            "signature": _approval_signature_schema(),
            "exception": _policy_exception_schema(),
        },
        required=[
            "schema_version",
            "assertion_id",
            "authority",
            "approver",
            "action",
            "gate_effect",
            "issued_at",
            "expires_at",
            "subject",
            "revocation_list_id",
            "signature",
        ],
    )
    body["allOf"] = _approval_action_conditionals()
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure approval assertion",
        **body,
    }


def approval_trust_store_schema() -> dict[str, Any]:
    """Return the protected approval-authority trust-store schema."""

    trusted_key = _closed_object(
        {
            "key_id": _attestation_safe_id(),
            "authority_id": _attestation_safe_id(),
            "algorithm": {"const": SignatureAlgorithm.ED25519.value},
            "public_key_base64url": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_-]{43}$",
            },
            "valid_from": _attestation_timestamp(),
            "valid_until": _attestation_timestamp(),
            "allowed_actions": {
                "type": "array",
                "items": {"enum": _enum_values(ApprovalAction)},
                "minItems": 1,
                "maxItems": len(ApprovalAction),
                "uniqueItems": True,
            },
        },
        required=[
            "key_id",
            "authority_id",
            "algorithm",
            "public_key_base64url",
            "valid_from",
            "valid_until",
            "allowed_actions",
        ],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure approval trust store",
        **_closed_object(
            {
                "schema_version": {"const": APPROVAL_TRUST_STORE_SCHEMA_VERSION},
                "store_id": _attestation_safe_id(),
                "revocation_list_id": _attestation_safe_id(),
                "keys": {
                    "type": "array",
                    "items": trusted_key,
                    "minItems": 1,
                    "maxItems": 1000,
                },
            },
            required=[
                "schema_version",
                "store_id",
                "revocation_list_id",
                "keys",
            ],
        ),
    }


def approval_revocation_list_schema() -> dict[str, Any]:
    """Return the approval-authority key revocation-list schema."""

    revoked_key = _closed_object(
        {
            "key_id": _attestation_safe_id(),
            "revoked_at": _attestation_timestamp(),
            "mode": {"enum": _enum_values(RevocationMode)},
            "reason": {
                "type": "string",
                "minLength": 1,
                "maxLength": 512,
                "pattern": r"^[^\u0000-\u001f\u007f]+$",
            },
        },
        required=["key_id", "revoked_at", "mode", "reason"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure approval revocation list",
        **_closed_object(
            {
                "schema_version": {
                    "const": APPROVAL_REVOCATION_LIST_SCHEMA_VERSION,
                },
                "list_id": _attestation_safe_id(),
                "updated_at": _attestation_timestamp(),
                "revoked_keys": {
                    "type": "array",
                    "items": revoked_key,
                    "maxItems": 10000,
                },
            },
            required=[
                "schema_version",
                "list_id",
                "updated_at",
                "revoked_keys",
            ],
        ),
    }


def approval_verification_schema() -> dict[str, Any]:
    """Return the successful authenticated-approval verification schema."""

    body = _closed_object(
        {
            "schema_version": {"const": APPROVAL_VERIFICATION_SCHEMA_VERSION},
            "verifier_version": _nonempty_string(),
            "status": {"const": "verified"},
            "checked_at": _attestation_timestamp(),
            "assertion": _approval_document_subject_schema(
                "application/vnd.causure.approval-assertion+json",
                maximum_bytes=1048576,
            ),
            "authority": _approval_authority_schema(),
            "approver": _approver_identity_schema(),
            "action": {"enum": _enum_values(ApprovalAction)},
            "gate_effect": {"const": ApprovalGateEffect.RECORD_ONLY.value},
            "issued_at": _attestation_timestamp(),
            "expires_at": _attestation_timestamp(),
            "subject": _approval_subject_schema(),
            "review": {"$ref": "#/$defs/review"},
            "tfvc": {"$ref": "#/$defs/tfvc"},
            "build_id": {"type": "integer", "minimum": 1},
            "trust_store_id": _attestation_safe_id(),
            "revocation_list_id": _attestation_safe_id(),
            "revocation_list_updated_at": _attestation_timestamp(),
            "exception": _policy_exception_schema(),
        },
        required=[
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
        ],
    )
    body["allOf"] = _approval_action_conditionals()
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure approval verification",
        **body,
        "$defs": {
            "review": _azure_review_binding_schema(),
            "tfvc": _azure_tfvc_schema(),
        },
    }


def _team_safe_id_schema() -> dict[str, Any]:
    return {
        "type": "string",
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$",
    }


def _team_principal_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "identity_provider": _team_safe_id_schema(),
            "subject_id": _team_safe_id_schema(),
        },
        required=["identity_provider", "subject_id"],
    )


def _team_roles_schema(*, minimum: int) -> dict[str, Any]:
    return {
        "type": "array",
        "items": {"enum": _enum_values(TeamRole)},
        "minItems": minimum,
        "maxItems": len(TeamRole),
        "uniqueItems": True,
    }


def _team_policy_subject_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "media_type": {"const": "application/vnd.causure.team-access-policy+json"},
            "policy_id": _team_safe_id_schema(),
            "revision": {"type": "integer", "minimum": 1},
            "sha256": _azure_sha256_schema(),
            "byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 4194304,
            },
        },
        required=["media_type", "policy_id", "revision", "sha256", "byte_count"],
    )


def _team_resource_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "resource_type": {"enum": _enum_values(TeamResourceType)},
            "resource_id": _team_safe_id_schema(),
        },
        required=["resource_type", "resource_id"],
    )


def _team_authorization_schema_body() -> dict[str, Any]:
    body = _closed_object(
        {
            "schema_version": {"const": TEAM_AUTHORIZATION_SCHEMA_VERSION},
            "decision_id": _team_safe_id_schema(),
            "tenant_id": _team_safe_id_schema(),
            "principal": _team_principal_schema(),
            "action": {"enum": _enum_values(TeamAction)},
            "resource": _team_resource_schema(),
            "authorized": {"type": "boolean"},
            "assigned_roles": _team_roles_schema(minimum=0),
            "granting_roles": _team_roles_schema(minimum=0),
            "reason": {"enum": _enum_values(TeamAuthorizationReason)},
            "decided_at": _attestation_timestamp(),
            "policy": _team_policy_subject_schema(),
        },
        required=[
            "schema_version",
            "decision_id",
            "tenant_id",
            "principal",
            "action",
            "resource",
            "authorized",
            "assigned_roles",
            "granting_roles",
            "reason",
            "decided_at",
            "policy",
        ],
    )
    body["allOf"] = [
        {
            "if": {
                "properties": {"authorized": {"const": True}},
                "required": ["authorized"],
            },
            "then": {
                "properties": {
                    "reason": {"const": TeamAuthorizationReason.ROLE_GRANT.value},
                    "granting_roles": {"minItems": 1},
                }
            },
            "else": {
                "properties": {
                    "reason": {
                        "enum": [
                            TeamAuthorizationReason.PRINCIPAL_NOT_MEMBER.value,
                            TeamAuthorizationReason.ROLE_NOT_GRANTED.value,
                        ]
                    },
                    "granting_roles": {"maxItems": 0},
                }
            },
        }
    ]
    return body


def team_access_policy_schema() -> dict[str, Any]:
    """Return the protected Team tenant access-policy schema."""

    membership = _closed_object(
        {
            "principal": _team_principal_schema(),
            "roles": _team_roles_schema(minimum=1),
        },
        required=["principal", "roles"],
    )
    retention_class = _closed_object(
        {
            "class_id": _team_safe_id_schema(),
            "minimum_days": {
                "type": "integer",
                "minimum": 1,
                "maximum": 3650,
            },
        },
        required=["class_id", "minimum_days"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team access policy",
        **_closed_object(
            {
                "schema_version": {"const": TEAM_ACCESS_POLICY_SCHEMA_VERSION},
                "tenant_id": _team_safe_id_schema(),
                "policy_id": _team_safe_id_schema(),
                "revision": {"type": "integer", "minimum": 1},
                "effective_at": _attestation_timestamp(),
                "default_retention_class_id": _team_safe_id_schema(),
                "memberships": {
                    "type": "array",
                    "items": membership,
                    "maxItems": 10000,
                    "uniqueItems": True,
                },
                "retention_classes": {
                    "type": "array",
                    "items": retention_class,
                    "minItems": 1,
                    "maxItems": 32,
                    "uniqueItems": True,
                },
            },
            required=[
                "schema_version",
                "tenant_id",
                "policy_id",
                "revision",
                "effective_at",
                "default_retention_class_id",
                "memberships",
                "retention_classes",
            ],
        ),
    }


def team_authorization_schema() -> dict[str, Any]:
    """Return the Team tenant authorization-decision schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team authorization decision",
        **_team_authorization_schema_body(),
    }


def _team_document_subject_schema(
    *,
    media_type: str | None = None,
    maximum_bytes: int = 16777216,
) -> dict[str, Any]:
    media_type_schema: dict[str, Any]
    if media_type is None:
        media_type_schema = {
            "type": "string",
            "pattern": (
                r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/"
                r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$"
            ),
        }
    else:
        media_type_schema = {"const": media_type}
    return _closed_object(
        {
            "media_type": media_type_schema,
            "sha256": _azure_sha256_schema(),
            "byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": maximum_bytes,
            },
        },
        required=["media_type", "sha256", "byte_count"],
    )


def _team_retention_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "class_id": _team_safe_id_schema(),
            "retain_until": _attestation_timestamp(),
        },
        required=["class_id", "retain_until"],
    )


def _team_audit_event_schema_body() -> dict[str, Any]:
    entry = _closed_object(
        {
            "event_id": _team_safe_id_schema(),
            "tenant_id": _team_safe_id_schema(),
            "sequence": {"type": "integer", "minimum": 1},
            "occurred_at": _attestation_timestamp(),
            "authorization": _team_authorization_schema_body(),
            "outcome": {"enum": _enum_values(TeamAuditOutcome)},
            "payload": _team_document_subject_schema(),
            "retention": _team_retention_schema(),
            "previous_event_sha256": {
                "oneOf": [
                    {"type": "null"},
                    _azure_sha256_schema(),
                ]
            },
        },
        required=[
            "event_id",
            "tenant_id",
            "sequence",
            "occurred_at",
            "authorization",
            "outcome",
            "payload",
            "retention",
            "previous_event_sha256",
        ],
    )
    entry["allOf"] = [
        {
            "if": {
                "properties": {"sequence": {"const": 1}},
                "required": ["sequence"],
            },
            "then": {"properties": {"previous_event_sha256": {"type": "null"}}},
            "else": {"properties": {"previous_event_sha256": _azure_sha256_schema()}},
        },
        {
            "if": {
                "properties": {
                    "authorization": {
                        "properties": {"authorized": {"const": True}},
                        "required": ["authorized"],
                    }
                },
                "required": ["authorization"],
            },
            "then": {
                "properties": {
                    "outcome": {
                        "enum": [
                            TeamAuditOutcome.SUCCEEDED.value,
                            TeamAuditOutcome.FAILED.value,
                        ]
                    }
                }
            },
            "else": {"properties": {"outcome": {"const": TeamAuditOutcome.DENIED.value}}},
        },
    ]
    return _closed_object(
        {
            "schema_version": {"const": TEAM_AUDIT_EVENT_SCHEMA_VERSION},
            "entry": entry,
            "event_sha256": _azure_sha256_schema(),
        },
        required=["schema_version", "entry", "event_sha256"],
    )


def team_audit_event_schema() -> dict[str, Any]:
    """Return the self-hashed Team audit-event schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team audit event",
        **_team_audit_event_schema_body(),
    }


def _team_audit_range_schema() -> dict[str, Any]:
    return _closed_object(
        {
            "first_sequence": {"type": "integer", "minimum": 1},
            "last_sequence": {"type": "integer", "minimum": 1},
            "event_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 10000,
            },
        },
        required=["first_sequence", "last_sequence", "event_count"],
    )


def team_audit_export_schema() -> dict[str, Any]:
    """Return the complete tenant audit-export schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team audit export",
        **_closed_object(
            {
                "schema_version": {"const": TEAM_AUDIT_EXPORT_SCHEMA_VERSION},
                "export_id": _team_safe_id_schema(),
                "tenant_id": _team_safe_id_schema(),
                "created_at": _attestation_timestamp(),
                "authorization": _team_authorization_schema_body(),
                "audit_range": _team_audit_range_schema(),
                "head_event_sha256": _azure_sha256_schema(),
                "retention": _team_retention_schema(),
                "events": {
                    "type": "array",
                    "items": _team_audit_event_schema_body(),
                    "minItems": 1,
                    "maxItems": 10000,
                },
            },
            required=[
                "schema_version",
                "export_id",
                "tenant_id",
                "created_at",
                "authorization",
                "audit_range",
                "head_event_sha256",
                "retention",
                "events",
            ],
        ),
    }


def team_audit_verification_schema() -> dict[str, Any]:
    """Return the successful Team audit-verification receipt schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team audit verification",
        **_closed_object(
            {
                "schema_version": {"const": TEAM_AUDIT_VERIFICATION_SCHEMA_VERSION},
                "verifier_version": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": 64,
                },
                "status": {"const": "verified"},
                "checked_at": _attestation_timestamp(),
                "export": _team_document_subject_schema(
                    media_type=("application/vnd.causure.team-audit-export+json"),
                    maximum_bytes=67108864,
                ),
                "export_id": _team_safe_id_schema(),
                "tenant_id": _team_safe_id_schema(),
                "audit_range": _team_audit_range_schema(),
                "head_event_sha256": _azure_sha256_schema(),
                "retention": _team_retention_schema(),
                "exporter": _team_principal_schema(),
                "policy": _team_policy_subject_schema(),
            },
            required=[
                "schema_version",
                "verifier_version",
                "status",
                "checked_at",
                "export",
                "export_id",
                "tenant_id",
                "audit_range",
                "head_event_sha256",
                "retention",
                "exporter",
                "policy",
            ],
        ),
    }


def team_http_action_request_schema() -> dict[str, Any]:
    """Return the closed request schema for the Team action-recording endpoint."""

    resource = _closed_object(
        {
            "type": {"enum": _enum_values(TeamResourceType)},
            "id": _team_safe_id_schema(),
        },
        required=["type", "id"],
    )
    payload = _closed_object(
        {
            "media_type": {
                "type": "string",
                "pattern": (
                    r"^[a-z0-9][a-z0-9!#$&^_.+-]{0,126}/"
                    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,126}$"
                ),
            },
            "base64url": {
                "type": "string",
                "minLength": 2,
                "maxLength": 22369624,
                "pattern": (
                    r"^(?:[A-Za-z0-9_-]{4})*"
                    r"(?:[A-Za-z0-9_-]{2}|[A-Za-z0-9_-]{3}|[A-Za-z0-9_-]{4})$"
                ),
            },
        },
        required=["media_type", "base64url"],
    )
    body = _closed_object(
        {
            "action": {"enum": _enum_values(TeamAction)},
            "resource": resource,
            "outcome": {
                "enum": [
                    TeamAuditOutcome.SUCCEEDED.value,
                    TeamAuditOutcome.FAILED.value,
                ]
            },
            "payload": payload,
            "expected_head_sha256": {
                "oneOf": [
                    {"type": "null"},
                    _azure_sha256_schema(),
                ]
            },
            "retention_class_id": _team_safe_id_schema(),
        },
        required=[
            "action",
            "resource",
            "outcome",
            "payload",
            "expected_head_sha256",
        ],
    )
    action_resources = {
        TeamAction.EVIDENCE_READ: [
            TeamResourceType.EVIDENCE_CASE,
            TeamResourceType.INVESTIGATION,
        ],
        TeamAction.INVESTIGATION_WRITE: [TeamResourceType.INVESTIGATION],
        TeamAction.POLICY_WRITE: [TeamResourceType.GATE_POLICY],
        TeamAction.APPROVAL_ISSUE: [TeamResourceType.APPROVAL],
        TeamAction.AUDIT_EXPORT: [TeamResourceType.AUDIT_EXPORT],
    }
    body["allOf"] = [
        {
            "if": {
                "properties": {"action": {"const": action.value}},
                "required": ["action"],
            },
            "then": {
                "properties": {
                    "resource": {
                        "properties": {
                            "type": {"enum": [resource_type.value for resource_type in resources]}
                        }
                    }
                }
            },
        }
        for action, resources in action_resources.items()
    ]
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team HTTP action request",
        **body,
    }


def team_http_event_page_schema() -> dict[str, Any]:
    """Return the closed response schema for a bounded Team event-summary page."""

    head = _closed_object(
        {
            "tenant_id": _team_safe_id_schema(),
            "sequence": {
                "type": "integer",
                "minimum": 0,
                "maximum": 10000,
            },
            "event_sha256": {
                "oneOf": [
                    {"type": "null"},
                    _azure_sha256_schema(),
                ]
            },
        },
        required=["tenant_id", "sequence", "event_sha256"],
    )
    head["allOf"] = [
        {
            "if": {
                "properties": {"sequence": {"const": 0}},
                "required": ["sequence"],
            },
            "then": {"properties": {"event_sha256": {"type": "null"}}},
            "else": {"properties": {"event_sha256": _azure_sha256_schema()}},
        }
    ]
    summary = _closed_object(
        {
            "tenant_id": _team_safe_id_schema(),
            "policy_id": _team_safe_id_schema(),
            "policy_revision": {"type": "integer", "minimum": 1},
            "policy_effective_at": _attestation_timestamp(),
            "policy_sha256": _azure_sha256_schema(),
            "policy_byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 4194304,
            },
            "assigned_roles": _team_roles_schema(minimum=1),
            "head": head,
        },
        required=[
            "tenant_id",
            "policy_id",
            "policy_revision",
            "policy_effective_at",
            "policy_sha256",
            "policy_byte_count",
            "assigned_roles",
            "head",
        ],
    )
    event_summary = _closed_object(
        {
            "sequence": {
                "type": "integer",
                "minimum": 1,
                "maximum": 10000,
            },
            "event_id": _team_safe_id_schema(),
            "event_sha256": _azure_sha256_schema(),
            "decision_id": _team_safe_id_schema(),
            "occurred_at": _attestation_timestamp(),
            "principal": _team_principal_schema(),
            "action": {"enum": _enum_values(TeamAction)},
            "resource": _team_resource_schema(),
            "authorized": {"type": "boolean"},
            "authorization_reason": {
                "enum": _enum_values(TeamAuthorizationReason),
            },
            "outcome": {"enum": _enum_values(TeamAuditOutcome)},
            "payload": _team_document_subject_schema(),
            "retention": _team_retention_schema(),
            "policy": _team_policy_subject_schema(),
        },
        required=[
            "sequence",
            "event_id",
            "event_sha256",
            "decision_id",
            "occurred_at",
            "principal",
            "action",
            "resource",
            "authorized",
            "authorization_reason",
            "outcome",
            "payload",
            "retention",
            "policy",
        ],
    )
    event_summary["allOf"] = [
        {
            "if": {
                "properties": {"authorized": {"const": True}},
                "required": ["authorized"],
            },
            "then": {
                "properties": {
                    "authorization_reason": {"const": TeamAuthorizationReason.ROLE_GRANT.value},
                    "outcome": {
                        "enum": [
                            TeamAuditOutcome.SUCCEEDED.value,
                            TeamAuditOutcome.FAILED.value,
                        ]
                    },
                }
            },
            "else": {
                "properties": {
                    "authorization_reason": {
                        "enum": [
                            TeamAuthorizationReason.PRINCIPAL_NOT_MEMBER.value,
                            TeamAuthorizationReason.ROLE_NOT_GRANTED.value,
                        ]
                    },
                    "outcome": {"const": TeamAuditOutcome.DENIED.value},
                }
            },
        }
    ]
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team HTTP event page",
        **_closed_object(
            {
                "summary": summary,
                "events": {
                    "type": "array",
                    "items": event_summary,
                    "maxItems": 100,
                },
                "next_before_sequence": {
                    "oneOf": [
                        {"type": "null"},
                        {
                            "type": "integer",
                            "minimum": 1,
                            "maximum": 10000,
                        },
                    ]
                },
            },
            required=["summary", "events", "next_before_sequence"],
        ),
    }


def entra_trust_store_schema() -> dict[str, Any]:
    """Return the protected Microsoft Entra tenant/key snapshot contract."""

    timestamp = {
        "type": "string",
        "format": "date-time",
        "pattern": (
            "^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])"
            "T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
        ),
    }
    canonical_uuid = {
        "type": "string",
        "pattern": ("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    }
    permission = {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$",
    }
    permission_set = {
        "type": "array",
        "items": permission,
        "uniqueItems": True,
        "minItems": 0,
        "maxItems": 100,
    }
    key = _closed_object(
        {
            "kid": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_-]{1,256}$",
            },
            "kty": {"const": "RSA"},
            "use": {"const": "sig"},
            "alg": {"const": "RS256"},
            "n": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_-]{342,1366}$",
            },
            "e": {
                "type": "string",
                "pattern": "^[A-Za-z0-9_-]{2,8}$",
            },
        },
        required=["kid", "kty", "use", "alg", "n", "e"],
    )
    tenant = _closed_object(
        {
            "entra_tenant_id": canonical_uuid,
            "team_tenant_id": {
                "type": "string",
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$",
            },
            "issuer": {
                "type": "string",
                "format": "uri",
                "pattern": "^https://",
                "maxLength": 256,
            },
            "audience": canonical_uuid,
            "allowed_client_ids": {
                "type": "array",
                "items": canonical_uuid,
                "uniqueItems": True,
                "minItems": 1,
                "maxItems": 100,
            },
            "accepted_delegated_scopes": permission_set,
            "accepted_application_roles": permission_set,
            "max_token_lifetime_seconds": {
                "type": "integer",
                "minimum": 300,
                "maximum": 86400,
            },
            "keys": {
                "type": "array",
                "items": key,
                "minItems": 1,
                "maxItems": 100,
            },
        },
        required=[
            "entra_tenant_id",
            "team_tenant_id",
            "issuer",
            "audience",
            "allowed_client_ids",
            "accepted_delegated_scopes",
            "accepted_application_roles",
            "max_token_lifetime_seconds",
            "keys",
        ],
    )
    tenant["anyOf"] = [
        {
            "properties": {
                "accepted_delegated_scopes": {
                    "minItems": 1,
                }
            }
        },
        {
            "properties": {
                "accepted_application_roles": {
                    "minItems": 1,
                }
            }
        },
    ]
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Entra trust store",
        **_closed_object(
            {
                "schema_version": {"const": ENTRA_TRUST_STORE_SCHEMA_VERSION},
                "store_id": {
                    "type": "string",
                    "pattern": "^[A-Za-z0-9][A-Za-z0-9._:+/@-]{2,127}$",
                },
                "refreshed_at": timestamp,
                "expires_at": timestamp,
                "tenants": {
                    "type": "array",
                    "items": tenant,
                    "minItems": 1,
                    "maxItems": 100,
                },
            },
            required=[
                "schema_version",
                "store_id",
                "refreshed_at",
                "expires_at",
                "tenants",
            ],
        ),
    }


def entra_refresh_config_schema() -> dict[str, Any]:
    """Return the protected Microsoft Entra discovery/JWKS source contract."""

    canonical_uuid = {
        "type": "string",
        "pattern": ("^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$"),
    }
    permission_set = {
        "type": "array",
        "items": {
            "type": "string",
            "pattern": "^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$",
        },
        "uniqueItems": True,
        "minItems": 0,
        "maxItems": 100,
    }
    tenant = _closed_object(
        {
            "entra_tenant_id": canonical_uuid,
            "team_tenant_id": {
                "type": "string",
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$",
            },
            "issuer": {
                "type": "string",
                "format": "uri",
                "pattern": "^https://",
                "maxLength": 256,
            },
            "jwks_uri": {
                "type": "string",
                "format": "uri",
                "pattern": "^https://",
                "maxLength": 512,
            },
            "audience": canonical_uuid,
            "allowed_client_ids": {
                "type": "array",
                "items": canonical_uuid,
                "uniqueItems": True,
                "minItems": 1,
                "maxItems": 100,
            },
            "accepted_delegated_scopes": permission_set,
            "accepted_application_roles": permission_set,
            "max_token_lifetime_seconds": {
                "type": "integer",
                "minimum": 300,
                "maximum": 86400,
            },
        },
        required=[
            "entra_tenant_id",
            "team_tenant_id",
            "issuer",
            "jwks_uri",
            "audience",
            "allowed_client_ids",
            "accepted_delegated_scopes",
            "accepted_application_roles",
            "max_token_lifetime_seconds",
        ],
    )
    tenant["anyOf"] = [
        {
            "properties": {
                "accepted_delegated_scopes": {
                    "minItems": 1,
                }
            }
        },
        {
            "properties": {
                "accepted_application_roles": {
                    "minItems": 1,
                }
            }
        },
    ]
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Entra refresh configuration",
        **_closed_object(
            {
                "schema_version": {"const": ENTRA_REFRESH_CONFIG_SCHEMA_VERSION},
                "store_id": {
                    "type": "string",
                    "pattern": "^[A-Za-z0-9][A-Za-z0-9._:+/@-]{2,127}$",
                },
                "snapshot_ttl_seconds": {
                    "type": "integer",
                    "minimum": 3600,
                    "maximum": 86400,
                },
                "tenants": {
                    "type": "array",
                    "items": tenant,
                    "minItems": 1,
                    "maxItems": 100,
                },
            },
            required=[
                "schema_version",
                "store_id",
                "snapshot_ttl_seconds",
                "tenants",
            ],
        ),
    }


def team_host_config_schema() -> dict[str, Any]:
    """Return the closed single-host Team service composition contract."""

    path = {
        "type": "string",
        "minLength": 1,
        "maxLength": 4096,
        "pattern": r"^[^\u0000-\u001f\u007f]+$",
    }
    database = _closed_object(
        {
            "path": path,
            "busy_timeout_ms": {
                "type": "integer",
                "minimum": 100,
                "maximum": 60000,
            },
        },
        required=["path", "busy_timeout_ms"],
    )
    server = _closed_object(
        {
            "implementation": {"const": "waitress"},
            "version": {"const": "3.0.2"},
            "listen_host": {"enum": ["127.0.0.1", "::1"]},
            "listen_port": {
                "type": "integer",
                "minimum": 1024,
                "maximum": 65535,
            },
            "trusted_external_scheme": {"const": "https"},
            "threads": {
                "type": "integer",
                "minimum": 1,
                "maximum": 64,
            },
            "connection_limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1024,
            },
            "backlog": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1024,
            },
            "channel_timeout_seconds": {
                "type": "integer",
                "minimum": 5,
                "maximum": 300,
            },
            "max_request_header_bytes": {
                "type": "integer",
                "minimum": 8192,
                "maximum": 65536,
            },
        },
        required=[
            "implementation",
            "version",
            "listen_host",
            "listen_port",
            "trusted_external_scheme",
            "threads",
            "connection_limit",
            "backlog",
            "channel_timeout_seconds",
            "max_request_header_bytes",
        ],
    )
    identity = _closed_object(
        {
            "refresh_configuration_path": path,
            "refresh_configuration_sha256": {
                "type": "string",
                "pattern": "^[a-f0-9]{64}$",
            },
            "refresh_configuration_byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 524288,
            },
            "trust_store_path": path,
            "store_id": {
                "type": "string",
                "pattern": "^[A-Za-z0-9][A-Za-z0-9._:+/@-]{2,127}$",
            },
            "clock_skew_seconds": {
                "type": "integer",
                "minimum": 0,
                "maximum": 300,
            },
            "refresh_timeout_seconds": {
                "type": "number",
                "minimum": 1,
                "maximum": 30,
            },
            "refresh_interval_seconds": {
                "type": "number",
                "minimum": 60,
                "maximum": 86400,
            },
            "failure_retry_seconds": {
                "type": "number",
                "minimum": 30,
                "maximum": 86400,
            },
            "unknown_key_refresh_seconds": {
                "type": "number",
                "minimum": 300,
                "maximum": 86400,
            },
        },
        required=[
            "refresh_configuration_path",
            "refresh_configuration_sha256",
            "refresh_configuration_byte_count",
            "trust_store_path",
            "store_id",
            "clock_skew_seconds",
            "refresh_timeout_seconds",
            "refresh_interval_seconds",
            "failure_retry_seconds",
            "unknown_key_refresh_seconds",
        ],
    )
    admission = _closed_object(
        {
            "max_concurrency": {
                "type": "integer",
                "minimum": 1,
                "maximum": 64,
            },
            "global_requests_per_window": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1000000,
            },
            "per_source_requests_per_window": {
                "oneOf": [
                    {"type": "null"},
                    {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 1000000,
                    },
                ]
            },
            "rate_window_seconds": {
                "type": "number",
                "minimum": 1,
                "maximum": 3600,
            },
            "max_tracked_sources": {
                "type": "integer",
                "minimum": 1,
                "maximum": 100000,
            },
            "source_idle_seconds": {
                "type": "number",
                "minimum": 1,
                "maximum": 86400,
            },
        },
        required=[
            "max_concurrency",
            "global_requests_per_window",
            "per_source_requests_per_window",
            "rate_window_seconds",
            "max_tracked_sources",
            "source_idle_seconds",
        ],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team service host configuration",
        **_closed_object(
            {
                "schema_version": {"const": TEAM_HOST_CONFIG_SCHEMA_VERSION},
                "database": database,
                "server": server,
                "identity": identity,
                "admission": admission,
            },
            required=["schema_version", "database", "server", "identity", "admission"],
        ),
    }


def canary_policy_schema() -> dict[str, Any]:
    """Return the predeclared post-deployment canary policy contract."""

    identifier = {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
    }
    reference = {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:+/@#$%?=&-]{0,511}$",
    }
    timestamp = {
        "type": "string",
        "format": "date-time",
        "pattern": ("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"),
    }
    metric = _closed_object(
        {
            "metric_id": identifier,
            "direction": {"enum": _enum_values(CanaryMetricDirection)},
            "maximum_degradation": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
            },
        },
        required=["metric_id", "direction", "maximum_degradation"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure canary policy",
        **_closed_object(
            {
                "schema_version": {"const": CANARY_POLICY_SCHEMA_VERSION},
                "policy_id": identifier,
                "declared_at": timestamp,
                "confidence_level": {
                    "type": "number",
                    "minimum": 0.90,
                    "maximum": 0.999,
                },
                "maximum_looks": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                },
                "minimum_observation_seconds": {
                    "type": "integer",
                    "minimum": 60,
                    "maximum": 2_592_000,
                },
                "minimum_sample_size_per_cohort": {
                    "type": "integer",
                    "minimum": 30,
                    "maximum": 1_000_000_000,
                },
                "evaluator_ref": reference,
                "assignment_unit": {
                    "enum": _enum_values(CanaryAssignmentUnit),
                },
                "assignment_method": {
                    "enum": _enum_values(CanaryAssignmentMethod),
                },
                "require_sticky_assignment": {"type": "boolean"},
                "metrics": {
                    "type": "array",
                    "items": metric,
                    "minItems": 1,
                    "maxItems": 50,
                },
            },
            required=[
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
            ],
        ),
    }


def canary_observation_schema() -> dict[str, Any]:
    """Return the exact-artifact-bound two-cohort canary observation contract."""

    identifier = {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
    }
    reference = {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:+/@#$%?=&-]{0,511}$",
    }
    digest = {
        "type": "string",
        "pattern": "^[0-9a-f]{64}$",
    }
    timestamp = {
        "type": "string",
        "format": "date-time",
        "pattern": ("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"),
    }
    metric = _closed_object(
        {
            "metric_id": identifier,
            "event_count": {
                "type": "integer",
                "minimum": 0,
                "maximum": 1_000_000_000,
            },
        },
        required=["metric_id", "event_count"],
    )
    cohort = _closed_object(
        {
            "deployment_ref": reference,
            "sample_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1_000_000_000,
            },
            "evidence_ref": reference,
            "metrics": {
                "type": "array",
                "items": metric,
                "minItems": 1,
                "maxItems": 50,
            },
        },
        required=["deployment_ref", "sample_count", "evidence_ref", "metrics"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure canary observation",
        **_closed_object(
            {
                "schema_version": {"const": CANARY_OBSERVATION_SCHEMA_VERSION},
                "comparison_id": identifier,
                "look_number": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                },
                "observed_at": timestamp,
                "change": _closed_object(
                    {
                        "case_id": identifier,
                        "change_ref": reference,
                        "change_case_sha256": digest,
                        "review_result_sha256": digest,
                    },
                    required=[
                        "case_id",
                        "change_ref",
                        "change_case_sha256",
                        "review_result_sha256",
                    ],
                ),
                "policy": _closed_object(
                    {
                        "policy_id": identifier,
                        "policy_sha256": digest,
                    },
                    required=["policy_id", "policy_sha256"],
                ),
                "window": _closed_object(
                    {
                        "started_at": timestamp,
                        "ended_at": timestamp,
                    },
                    required=["started_at", "ended_at"],
                ),
                "evaluator_ref": reference,
                "assignment": _closed_object(
                    {
                        "method": {"enum": _enum_values(CanaryAssignmentMethod)},
                        "unit": {"enum": _enum_values(CanaryAssignmentUnit)},
                        "sticky": {"type": "boolean"},
                        "cross_cohort_contamination_detected": {
                            "type": "boolean",
                        },
                    },
                    required=[
                        "method",
                        "unit",
                        "sticky",
                        "cross_cohort_contamination_detected",
                    ],
                ),
                "baseline": cohort,
                "candidate": cohort,
            },
            required=[
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
            ],
        ),
    }


def canary_result_schema() -> dict[str, Any]:
    """Return the deterministic canary comparison result contract."""

    identifier = {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
    }
    reference = {
        "type": "string",
        "pattern": "^[A-Za-z0-9][A-Za-z0-9._:+/@#$%?=&-]{0,511}$",
    }
    digest = {
        "type": "string",
        "pattern": "^[0-9a-f]{64}$",
    }
    timestamp = {
        "type": "string",
        "format": "date-time",
        "pattern": ("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$"),
    }
    check = _closed_object(
        {
            "code": identifier,
            "status": {"enum": _enum_values(CheckStatus)},
            "message": {
                "type": "string",
                "minLength": 1,
                "maxLength": 8192,
                "pattern": r"^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]+$",
            },
        },
        required=["code", "status", "message"],
    )
    metric = _closed_object(
        {
            "metric_id": identifier,
            "direction": {"enum": _enum_values(CanaryMetricDirection)},
            "maximum_degradation": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
            },
            "baseline_rate": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
            },
            "candidate_rate": {
                "type": "number",
                "minimum": 0,
                "maximum": 1,
            },
            "observed_difference": {
                "type": "number",
                "minimum": -1,
                "maximum": 1,
            },
            "confidence_lower": {
                "type": "number",
                "minimum": -1,
                "maximum": 1,
            },
            "confidence_upper": {
                "type": "number",
                "minimum": -1,
                "maximum": 1,
            },
            "status": {"enum": _enum_values(CanaryMetricStatus)},
        },
        required=[
            "metric_id",
            "direction",
            "maximum_degradation",
            "baseline_rate",
            "candidate_rate",
            "observed_difference",
            "confidence_lower",
            "confidence_upper",
            "status",
        ],
    )
    properties: dict[str, Any] = {
        "schema_version": {"const": CANARY_RESULT_SCHEMA_VERSION},
        "engine_version": {"type": "string", "minLength": 1, "maxLength": 128},
        "comparison_id": identifier,
        "look_number": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
        },
        "maximum_looks": {
            "type": "integer",
            "minimum": 1,
            "maximum": 100,
        },
        "case_id": identifier,
        "change_ref": reference,
        "policy_id": identifier,
        "evaluator_ref": reference,
        "assignment_method": {
            "enum": _enum_values(CanaryAssignmentMethod),
        },
        "assignment_unit": {
            "enum": _enum_values(CanaryAssignmentUnit),
        },
        "observation_sha256": digest,
        "policy_sha256": digest,
        "change_case_sha256": digest,
        "review_result_sha256": digest,
        "compared_at": timestamp,
        "window_started_at": timestamp,
        "window_ended_at": timestamp,
        "observation_seconds": {
            "type": "integer",
            "minimum": 1,
            "maximum": 2_592_000,
        },
        "baseline_deployment_ref": reference,
        "candidate_deployment_ref": reference,
        "baseline_sample_count": {
            "type": "integer",
            "minimum": 1,
            "maximum": 1_000_000_000,
        },
        "candidate_sample_count": {
            "type": "integer",
            "minimum": 1,
            "maximum": 1_000_000_000,
        },
        "confidence_level": {
            "type": "number",
            "minimum": 0.90,
            "maximum": 0.999,
        },
        "decision": {"enum": _enum_values(CanaryDecision)},
        "summary": {
            "type": "string",
            "minLength": 1,
            "maxLength": 8192,
            "pattern": r"^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]+$",
        },
        "checks": {
            "type": "array",
            "items": check,
            "minItems": 6,
            "maxItems": 6,
        },
        "metrics": {
            "type": "array",
            "items": metric,
            "minItems": 1,
            "maxItems": 50,
        },
    }
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure canary comparison result",
        **_closed_object(
            properties,
            required=list(properties),
        ),
    }


def _team_case_id_schema() -> dict[str, Any]:
    return {
        "type": "string",
        "pattern": r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
    }


def _team_case_text_schema(maximum: int) -> dict[str, Any]:
    return {
        "type": "string",
        "minLength": 1,
        "maxLength": maximum,
        "pattern": r"^[^\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]+$",
    }


def _team_case_subject_schema(media_type: str, maximum_bytes: int) -> dict[str, Any]:
    return _closed_object(
        {
            "media_type": {"const": media_type},
            "sha256": _azure_sha256_schema(),
            "byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": maximum_bytes,
            },
        },
        required=["media_type", "sha256", "byte_count"],
    )


def team_case_record_schema() -> dict[str, Any]:
    """Return the closed minimized Team dashboard case-record schema."""

    count = {"type": "integer", "minimum": 0, "maximum": 10000}
    hypothesis = _closed_object(
        {
            "component": {"enum": _enum_values(Component)},
            "confidence": {"type": "number", "minimum": 0, "maximum": 1},
            "evidence_count": count,
            "intervention_present": {"type": "boolean"},
            "intervention_trial_count": count,
            "intervention_resolved_count": count,
            "intervention_isolated": {"type": "boolean"},
        },
        required=[
            "component",
            "confidence",
            "evidence_count",
            "intervention_present",
            "intervention_trial_count",
            "intervention_resolved_count",
        ],
    )
    hypothesis["allOf"] = [
        {
            "if": {
                "properties": {"intervention_present": {"const": True}},
                "required": ["intervention_present"],
            },
            "then": {"required": ["intervention_isolated"]},
            "else": {
                "properties": {
                    "intervention_trial_count": {"const": 0},
                    "intervention_resolved_count": {"const": 0},
                },
                "not": {"required": ["intervention_isolated"]},
            },
        }
    ]
    evidence = _closed_object(
        {
            "title": _team_case_text_schema(512),
            "created_at": {
                "type": "string",
                "format": "date-time",
                "minLength": 1,
                "maxLength": 64,
            },
            "severity": {"enum": _enum_values(IncidentSeverity)},
            "requirement_status": {"enum": _enum_values(RequirementStatus)},
            "oracle_kind": {"enum": _enum_values(OracleKind)},
            "oracle_independent": {"type": "boolean"},
            "reproduction_trial_count": count,
            "reproduced_trial_count": count,
            "hypotheses": {
                "type": "array",
                "items": {"$ref": "#/$defs/hypothesis"},
                "minItems": 1,
                "maxItems": 64,
            },
            "proposed_component": {"enum": _enum_values(Component)},
            "proposed_summary": _team_case_text_schema(2048),
            "prediction": _team_case_text_schema(2048),
            "change_ref": _team_case_text_schema(512),
            "changed_surface_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 10000,
            },
            "known_risk_count": count,
            "validation_case_count": count,
            "validation_candidate_passed_count": count,
            "validation_critical_failed_count": count,
        },
        required=[
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
        ],
    )
    finding = _closed_object(
        {
            "code": _team_case_id_schema(),
            "status": {"enum": _enum_values(CheckStatus)},
            "consequence": {"enum": _enum_values(Consequence)},
        },
        required=["code", "status", "consequence"],
    )
    review = _closed_object(
        {
            "engine_version": _team_case_text_schema(128),
            "policy_name": _team_case_text_schema(128),
            "reviewed_at": {
                "type": "string",
                "format": "date-time",
                "minLength": 1,
                "maxLength": 64,
            },
            "decision": {"enum": _enum_values(Decision)},
            "recommended_action": {"enum": _enum_values(RecommendedAction)},
            "summary": _team_case_text_schema(8192),
            "findings": {
                "type": "array",
                "items": {"$ref": "#/$defs/finding"},
                "maxItems": 128,
            },
        },
        required=[
            "engine_version",
            "policy_name",
            "reviewed_at",
            "decision",
            "recommended_action",
            "summary",
            "findings",
        ],
    )
    sources = _closed_object(
        {
            "change_case": {"$ref": "#/$defs/change_subject"},
            "review_result": {"$ref": "#/$defs/review_result_subject"},
            "review_report": {"$ref": "#/$defs/review_report_subject"},
            "azure_publication": {"$ref": "#/$defs/azure_publication_subject"},
            "azure_verification": {"$ref": "#/$defs/azure_verification_subject"},
            "approval_verification": {"$ref": "#/$defs/approval_subject"},
            "canary_result": {"$ref": "#/$defs/canary_subject"},
        },
        required=["change_case", "review_result"],
    )
    sources["dependentRequired"] = {
        "review_report": ["azure_publication", "azure_verification"],
        "azure_publication": ["review_report", "azure_verification"],
        "azure_verification": ["review_report", "azure_publication"],
        "approval_verification": [
            "review_report",
            "azure_publication",
            "azure_verification",
        ],
    }
    delivery = _closed_object(
        {
            "published_at": _attestation_timestamp(),
            "verified_at": _attestation_timestamp(),
            "server_path": {
                **_team_case_text_schema(512),
                "pattern": r"^\$/[^\u0000-\u001f\u007f]+$",
            },
            "target_kind": {"enum": _enum_values(TfvcTargetKind)},
            "changeset_id": {
                "type": "integer",
                "minimum": 1,
                "maximum": 2147483647,
            },
            "shelveset_name": _team_case_text_schema(128),
            "shelveset_owner": _team_case_text_schema(320),
            "build_id": {
                "type": "integer",
                "minimum": 1,
                "maximum": 2147483647,
            },
            "build_number": _team_case_text_schema(128),
            "work_item_ids": {
                "type": "array",
                "items": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 2147483647,
                },
                "maxItems": 10000,
                "uniqueItems": True,
            },
        },
        required=[
            "published_at",
            "verified_at",
            "server_path",
            "target_kind",
            "build_id",
            "build_number",
            "work_item_ids",
        ],
    )
    delivery["allOf"] = [
        {
            "if": {
                "properties": {"target_kind": {"const": TfvcTargetKind.CHANGESET.value}},
                "required": ["target_kind"],
            },
            "then": {
                "required": ["changeset_id"],
                "not": {
                    "anyOf": [
                        {"required": ["shelveset_name"]},
                        {"required": ["shelveset_owner"]},
                    ]
                },
            },
            "else": {
                "required": ["shelveset_name", "shelveset_owner"],
                "not": {"required": ["changeset_id"]},
            },
        }
    ]
    approval = _closed_object(
        {
            "checked_at": _attestation_timestamp(),
            "assertion": {"$ref": "#/$defs/approval_assertion_subject"},
            "authority_id": _team_safe_id_schema(),
            "key_id": _team_safe_id_schema(),
            "identity_provider": _team_safe_id_schema(),
            "subject_id": _team_safe_id_schema(),
            "authentication_method": {"enum": _enum_values(ApprovalAuthenticationMethod)},
            "authentication_event_id": _team_safe_id_schema(),
            "action": {"enum": _enum_values(ApprovalAction)},
            "gate_effect": {"enum": _enum_values(ApprovalGateEffect)},
            "issued_at": _attestation_timestamp(),
            "expires_at": _attestation_timestamp(),
            "trust_store_id": _team_safe_id_schema(),
            "revocation_list_id": _team_safe_id_schema(),
            "revocation_list_updated_at": _attestation_timestamp(),
            "exception_finding_codes": {
                "type": "array",
                "items": _team_case_id_schema(),
                "maxItems": 64,
                "uniqueItems": True,
            },
        },
        required=[
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
        ],
    )
    approval["allOf"] = [
        {
            "if": {
                "properties": {"action": {"const": ApprovalAction.EXCEPTION.value}},
                "required": ["action"],
            },
            "then": {"properties": {"exception_finding_codes": {"minItems": 1}}},
            "else": {"properties": {"exception_finding_codes": {"maxItems": 0}}},
        }
    ]
    metric = _closed_object(
        {
            "metric_id": _team_case_id_schema(),
            "direction": {"enum": _enum_values(CanaryMetricDirection)},
            "maximum_degradation": {"type": "number", "minimum": 0, "maximum": 1},
            "baseline_rate": {"type": "number", "minimum": 0, "maximum": 1},
            "candidate_rate": {"type": "number", "minimum": 0, "maximum": 1},
            "confidence_lower": {"type": "number", "minimum": -1, "maximum": 1},
            "confidence_upper": {"type": "number", "minimum": -1, "maximum": 1},
            "status": {"enum": _enum_values(CanaryMetricStatus)},
        },
        required=[
            "metric_id",
            "direction",
            "maximum_degradation",
            "baseline_rate",
            "candidate_rate",
            "confidence_lower",
            "confidence_upper",
            "status",
        ],
    )
    canary = _closed_object(
        {
            "comparison_id": _team_case_id_schema(),
            "look_number": {"type": "integer", "minimum": 1, "maximum": 100},
            "maximum_looks": {"type": "integer", "minimum": 1, "maximum": 100},
            "policy_id": _team_case_id_schema(),
            "evaluator_ref": _team_case_text_schema(512),
            "assignment_method": {"enum": _enum_values(CanaryAssignmentMethod)},
            "assignment_unit": {"enum": _enum_values(CanaryAssignmentUnit)},
            "compared_at": _attestation_timestamp(),
            "window_started_at": _attestation_timestamp(),
            "window_ended_at": _attestation_timestamp(),
            "baseline_deployment_ref": _team_case_text_schema(512),
            "candidate_deployment_ref": _team_case_text_schema(512),
            "baseline_sample_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1000000000,
            },
            "candidate_sample_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 1000000000,
            },
            "confidence_level": {"type": "number", "minimum": 0.90, "maximum": 0.999},
            "decision": {"enum": _enum_values(CanaryDecision)},
            "summary": _team_case_text_schema(8192),
            "metrics": {
                "type": "array",
                "items": {"$ref": "#/$defs/canary_metric"},
                "minItems": 1,
                "maxItems": 50,
            },
        },
        required=[
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
        ],
    )
    record = _closed_object(
        {
            "schema_version": {"const": TEAM_CASE_RECORD_SCHEMA_VERSION},
            "tenant_id": _team_safe_id_schema(),
            "case_id": _team_case_id_schema(),
            "revision": {"type": "integer", "minimum": 1, "maximum": 10000},
            "published_at": _attestation_timestamp(),
            "sources": {"$ref": "#/$defs/sources"},
            "evidence": {"$ref": "#/$defs/evidence"},
            "review": {"$ref": "#/$defs/review"},
            "delivery": {"$ref": "#/$defs/delivery"},
            "approval": {"$ref": "#/$defs/approval"},
            "canary": {"$ref": "#/$defs/canary"},
        },
        required=[
            "schema_version",
            "tenant_id",
            "case_id",
            "revision",
            "published_at",
            "sources",
            "evidence",
            "review",
        ],
    )
    record["allOf"] = [
        {
            "if": {
                "properties": {
                    "sources": {"required": [source_name]},
                },
                "required": ["sources"],
            },
            "then": {"required": [stage_name]},
            "else": {"not": {"required": [stage_name]}},
        }
        for source_name, stage_name in (
            ("azure_publication", "delivery"),
            ("approval_verification", "approval"),
            ("canary_result", "canary"),
        )
    ]
    record["allOf"].extend(
        [
            {
                "if": {
                    "properties": {
                        "approval": {
                            "properties": {"action": {"const": ApprovalAction.APPROVE.value}},
                            "required": ["action"],
                        }
                    },
                    "required": ["approval"],
                },
                "then": {
                    "properties": {
                        "review": {"properties": {"decision": {"const": Decision.APPROVE.value}}}
                    }
                },
            },
            {
                "if": {
                    "properties": {
                        "approval": {
                            "properties": {"action": {"const": ApprovalAction.EXCEPTION.value}},
                            "required": ["action"],
                        }
                    },
                    "required": ["approval"],
                },
                "then": {
                    "properties": {
                        "review": {
                            "properties": {
                                "decision": {
                                    "enum": [
                                        value
                                        for value in _enum_values(Decision)
                                        if value != Decision.APPROVE.value
                                    ]
                                }
                            }
                        }
                    }
                },
            },
        ]
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team dashboard case record",
        **record,
        "$defs": {
            "change_subject": _closed_object(
                {
                    "media_type": {"const": "application/vnd.causure.change-case+json"},
                    "sha256": _azure_sha256_schema(),
                    "byte_count": {
                        "type": "integer",
                        "minimum": 1,
                        "maximum": 5242880,
                    },
                    "canonical_sha256": _azure_sha256_schema(),
                },
                required=["media_type", "sha256", "byte_count", "canonical_sha256"],
            ),
            "review_result_subject": _team_case_subject_schema(
                "application/vnd.causure.review-result+json", 5242880
            ),
            "review_report_subject": _team_case_subject_schema(
                "text/markdown; charset=utf-8", 2097152
            ),
            "azure_publication_subject": _team_case_subject_schema(
                "application/vnd.causure.azure-review-publication+json", 1048576
            ),
            "azure_verification_subject": _team_case_subject_schema(
                "application/vnd.causure.azure-review-verification+json", 1048576
            ),
            "approval_subject": _team_case_subject_schema(
                "application/vnd.causure.approval-verification+json", 1048576
            ),
            "approval_assertion_subject": _team_case_subject_schema(
                "application/vnd.causure.approval-assertion+json", 1048576
            ),
            "canary_subject": _team_case_subject_schema(
                "application/vnd.causure.canary-result+json", 2097152
            ),
            "sources": sources,
            "hypothesis": hypothesis,
            "evidence": evidence,
            "finding": finding,
            "review": review,
            "delivery": delivery,
            "approval": approval,
            "canary_metric": metric,
            "canary": canary,
        },
    }


def team_investigation_record_schema() -> dict[str, Any]:
    """Return the closed minimized Team investigation-record schema."""

    subject = _closed_object(
        {
            "media_type": {"const": "application/vnd.causure.investigation-fixture+json"},
            "sha256": _azure_sha256_schema(),
            "byte_count": {
                "type": "integer",
                "minimum": 1,
                "maximum": 8388608,
            },
        },
        required=["media_type", "sha256", "byte_count"],
    )
    named_count = _closed_object(
        {
            "name": {"enum": _enum_values(OpenInferenceSpanKind)},
            "count": {"type": "integer", "minimum": 1, "maximum": 1000000},
        },
        required=["name", "count"],
    )
    status_count = _closed_object(
        {
            "code": {"type": "integer", "minimum": 0, "maximum": 2},
            "count": {"type": "integer", "minimum": 1, "maximum": 1000000},
        },
        required=["code", "count"],
    )
    decimal = {
        "type": "string",
        "pattern": r"^(0|[1-9][0-9]{0,19})$",
    }
    observation = _closed_object(
        {
            "observation_id": {
                "type": "string",
                "pattern": r"^observation-[a-f0-9]{64}$",
            },
            "attached_at": _attestation_timestamp(),
            "attached_by": _team_principal_schema(),
            "fixture": {"$ref": "#/$defs/fixture_subject"},
            "fixture_id": _team_case_id_schema(),
            "manifest_sha256": _azure_sha256_schema(),
            "trace_source_sha256": _azure_sha256_schema(),
            "cluster_id": {
                "type": "string",
                "pattern": r"^trace-[a-f0-9]{64}$",
            },
            "trace_id_sha256": _azure_sha256_schema(),
            "span_count": {"type": "integer", "minimum": 1, "maximum": 1000000},
            "root_span_count": {
                "type": "integer",
                "minimum": 0,
                "maximum": 1000000,
            },
            "error_span_count": {
                "type": "integer",
                "minimum": 0,
                "maximum": 1000000,
            },
            "span_kind_counts": {
                "type": "array",
                "items": {"$ref": "#/$defs/named_count"},
                "maxItems": len(OpenInferenceSpanKind),
            },
            "status_code_counts": {
                "type": "array",
                "items": {"$ref": "#/$defs/status_count"},
                "maxItems": 3,
            },
            "model_identifiers": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": SAFE_TRACE_TEXT_PATTERN,
                },
                "maxItems": 10000,
                "uniqueItems": True,
            },
            "provider_identifiers": {
                "type": "array",
                "items": {
                    "type": "string",
                    "pattern": SAFE_TRACE_TEXT_PATTERN,
                },
                "maxItems": 10000,
                "uniqueItems": True,
            },
            "earliest_start_time_unix_nano": decimal,
            "latest_end_time_unix_nano": decimal,
            "observed_duration_nano": decimal,
        },
        required=[
            "observation_id",
            "attached_at",
            "attached_by",
            "fixture",
            "fixture_id",
            "manifest_sha256",
            "trace_source_sha256",
            "cluster_id",
            "trace_id_sha256",
            "span_count",
            "root_span_count",
            "error_span_count",
            "span_kind_counts",
            "status_code_counts",
            "model_identifiers",
            "provider_identifiers",
        ],
    )
    record = _closed_object(
        {
            "schema_version": {"const": TEAM_INVESTIGATION_RECORD_SCHEMA_VERSION},
            "tenant_id": _team_safe_id_schema(),
            "investigation_id": _team_case_id_schema(),
            "revision": {"type": "integer", "minimum": 1, "maximum": 10000},
            "created_at": _attestation_timestamp(),
            "updated_at": _attestation_timestamp(),
            "title": _team_case_text_schema(256),
            "status": {"enum": _enum_values(TeamInvestigationStatus)},
            "priority": {"enum": _enum_values(TeamInvestigationPriority)},
            "opened_by": _team_principal_schema(),
            "candidate_only": {"const": True},
            "gate_eligible": {"const": False},
            "causal_claims_inferred": {"const": False},
            "observations": {
                "type": "array",
                "items": {"$ref": "#/$defs/observation"},
                "minItems": 1,
                "maxItems": 128,
            },
            "assigned_to": _team_principal_schema(),
            "resolution": {"enum": _enum_values(TeamInvestigationResolution)},
            "linked_case_id": _team_case_id_schema(),
            "duplicate_of": _team_case_id_schema(),
        },
        required=[
            "schema_version",
            "tenant_id",
            "investigation_id",
            "revision",
            "created_at",
            "updated_at",
            "title",
            "status",
            "priority",
            "opened_by",
            "candidate_only",
            "gate_eligible",
            "causal_claims_inferred",
            "observations",
        ],
    )
    record["allOf"] = [
        {
            "if": {
                "properties": {"status": {"const": TeamInvestigationStatus.CLOSED.value}},
                "required": ["status"],
            },
            "then": {"required": ["resolution"]},
            "else": {
                "not": {
                    "anyOf": [
                        {"required": ["resolution"]},
                        {"required": ["linked_case_id"]},
                        {"required": ["duplicate_of"]},
                    ]
                }
            },
        },
        {
            "if": {
                "properties": {
                    "resolution": {"const": TeamInvestigationResolution.CHANGE_CASE_OPENED.value}
                },
                "required": ["resolution"],
            },
            "then": {
                "required": ["linked_case_id"],
                "not": {"required": ["duplicate_of"]},
            },
        },
        {
            "if": {
                "properties": {
                    "resolution": {"const": TeamInvestigationResolution.DUPLICATE.value}
                },
                "required": ["resolution"],
            },
            "then": {
                "required": ["duplicate_of"],
                "not": {"required": ["linked_case_id"]},
            },
        },
        {
            "if": {
                "properties": {
                    "resolution": {
                        "enum": [
                            TeamInvestigationResolution.NOT_A_FAILURE.value,
                            TeamInvestigationResolution.NO_CHANGE_REQUIRED.value,
                            TeamInvestigationResolution.INSUFFICIENT_EVIDENCE.value,
                        ]
                    }
                },
                "required": ["resolution"],
            },
            "then": {
                "not": {
                    "anyOf": [
                        {"required": ["linked_case_id"]},
                        {"required": ["duplicate_of"]},
                    ]
                }
            },
        },
    ]
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team investigation record",
        **record,
        "$defs": {
            "fixture_subject": subject,
            "named_count": named_count,
            "status_count": status_count,
            "observation": observation,
        },
    }


def _team_http_case_artifact_schema(maximum_bytes: int) -> dict[str, Any]:
    return _closed_object(
        {
            "base64url": {
                "type": "string",
                "minLength": 2,
                "maxLength": ((maximum_bytes + 2) // 3) * 4,
                "pattern": r"^[A-Za-z0-9_-]+$",
            }
        },
        required=["base64url"],
    )


def team_http_case_publication_request_schema() -> dict[str, Any]:
    """Return the closed exact-artifact Team case-publication request schema."""

    body = _closed_object(
        {
            "case_id": _team_case_id_schema(),
            "change_case": _team_http_case_artifact_schema(5242880),
            "review_result": _team_http_case_artifact_schema(5242880),
            "azure_publication": _team_http_case_artifact_schema(1048576),
            "azure_verification": _team_http_case_artifact_schema(1048576),
            "approval_verification": _team_http_case_artifact_schema(1048576),
            "canary_result": _team_http_case_artifact_schema(2097152),
            "expected_head_sha256": {"oneOf": [{"type": "null"}, _azure_sha256_schema()]},
            "retention_class_id": _team_safe_id_schema(),
        },
        required=["case_id", "change_case", "review_result", "expected_head_sha256"],
    )
    body["dependentRequired"] = {
        "azure_publication": ["azure_verification"],
        "azure_verification": ["azure_publication"],
        "approval_verification": ["azure_publication", "azure_verification"],
    }
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team HTTP case-publication request",
        **body,
    }


def _team_http_case_record_definition() -> tuple[dict[str, Any], dict[str, Any]]:
    schema = team_case_record_schema()
    record = {
        key: value for key, value in schema.items() if key not in {"$schema", "title", "$defs"}
    }
    definitions = dict(schema["$defs"])
    definitions["team_case_record"] = record
    return record, definitions


def team_http_case_page_schema() -> dict[str, Any]:
    """Return the closed response schema for a bounded Team case page."""

    event_page = team_http_event_page_schema()
    _, definitions = _team_http_case_record_definition()
    case_view = _closed_object(
        {
            "record": {"$ref": "#/$defs/team_case_record"},
            "event": event_page["properties"]["events"]["items"],
        },
        required=["record", "event"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team HTTP case page",
        **_closed_object(
            {
                "summary": event_page["properties"]["summary"],
                "cases": {
                    "type": "array",
                    "items": case_view,
                    "maxItems": 100,
                },
                "next_before_sequence": {
                    "oneOf": [
                        {"type": "null"},
                        {"type": "integer", "minimum": 1, "maximum": 10001},
                    ]
                },
            },
            required=["summary", "cases", "next_before_sequence"],
        ),
        "$defs": definitions,
    }


def team_http_case_detail_schema() -> dict[str, Any]:
    """Return the closed response schema for one Team case detail."""

    event_page = team_http_event_page_schema()
    _, definitions = _team_http_case_record_definition()
    case_view = _closed_object(
        {
            "record": {"$ref": "#/$defs/team_case_record"},
            "event": event_page["properties"]["events"]["items"],
        },
        required=["record", "event"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team HTTP case detail",
        **_closed_object(
            {
                "summary": event_page["properties"]["summary"],
                "case": case_view,
            },
            required=["summary", "case"],
        ),
        "$defs": definitions,
    }


def _team_http_investigation_fixture_schema() -> dict[str, Any]:
    return _team_http_case_artifact_schema(8388608)


def _team_http_expected_head_schema() -> dict[str, Any]:
    return {"oneOf": [{"type": "null"}, _azure_sha256_schema()]}


def team_http_investigation_open_request_schema() -> dict[str, Any]:
    """Return the closed Team investigation-open request schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team HTTP investigation-open request",
        **_closed_object(
            {
                "investigation_id": _team_case_id_schema(),
                "fixture": _team_http_investigation_fixture_schema(),
                "cluster_id": {
                    "type": "string",
                    "pattern": r"^trace-[a-f0-9]{64}$",
                },
                "title": _team_case_text_schema(256),
                "priority": {"enum": _enum_values(TeamInvestigationPriority)},
                "expected_revision": {"const": 0},
                "expected_head_sha256": _team_http_expected_head_schema(),
                "retention_class_id": _team_safe_id_schema(),
            },
            required=[
                "investigation_id",
                "fixture",
                "cluster_id",
                "title",
                "priority",
                "expected_revision",
                "expected_head_sha256",
            ],
        ),
    }


def team_http_investigation_attach_request_schema() -> dict[str, Any]:
    """Return the closed Team investigation-observation request schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team HTTP investigation-observation request",
        **_closed_object(
            {
                "fixture": _team_http_investigation_fixture_schema(),
                "cluster_id": {
                    "type": "string",
                    "pattern": r"^trace-[a-f0-9]{64}$",
                },
                "expected_revision": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 9999,
                },
                "expected_head_sha256": _team_http_expected_head_schema(),
                "retention_class_id": _team_safe_id_schema(),
            },
            required=[
                "fixture",
                "cluster_id",
                "expected_revision",
                "expected_head_sha256",
            ],
        ),
    }


def team_http_investigation_transition_request_schema() -> dict[str, Any]:
    """Return the closed Team investigation queue-transition request schema."""

    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team HTTP investigation-transition request",
        **_closed_object(
            {
                "title": _team_case_text_schema(256),
                "status": {"enum": _enum_values(TeamInvestigationStatus)},
                "priority": {"enum": _enum_values(TeamInvestigationPriority)},
                "assigned_to": {"oneOf": [{"type": "null"}, _team_principal_schema()]},
                "expected_revision": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 9999,
                },
                "expected_head_sha256": _team_http_expected_head_schema(),
                "resolution": {"enum": _enum_values(TeamInvestigationResolution)},
                "linked_case_id": {"oneOf": [{"type": "null"}, _team_case_id_schema()]},
                "duplicate_of": {"oneOf": [{"type": "null"}, _team_case_id_schema()]},
                "retention_class_id": _team_safe_id_schema(),
            },
            required=[
                "title",
                "status",
                "priority",
                "assigned_to",
                "expected_revision",
                "expected_head_sha256",
            ],
        ),
    }


def _team_http_investigation_record_definition() -> dict[str, Any]:
    schema = team_investigation_record_schema()
    definitions = dict(schema["$defs"])
    definitions["team_investigation_record"] = {
        key: value for key, value in schema.items() if key not in {"$schema", "title", "$defs"}
    }
    return definitions


def team_http_investigation_page_schema() -> dict[str, Any]:
    """Return the closed response schema for an investigation queue page."""

    event_page = team_http_event_page_schema()
    definitions = _team_http_investigation_record_definition()
    view = _closed_object(
        {
            "record": {"$ref": "#/$defs/team_investigation_record"},
            "event": event_page["properties"]["events"]["items"],
        },
        required=["record", "event"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team HTTP investigation page",
        **_closed_object(
            {
                "summary": event_page["properties"]["summary"],
                "investigations": {
                    "type": "array",
                    "items": view,
                    "maxItems": 100,
                },
                "next_before_sequence": {
                    "oneOf": [
                        {"type": "null"},
                        {"type": "integer", "minimum": 1, "maximum": 10001},
                    ]
                },
            },
            required=["summary", "investigations", "next_before_sequence"],
        ),
        "$defs": definitions,
    }


def team_http_investigation_detail_schema() -> dict[str, Any]:
    """Return the closed response schema for one Team investigation detail."""

    event_page = team_http_event_page_schema()
    definitions = _team_http_investigation_record_definition()
    view = _closed_object(
        {
            "record": {"$ref": "#/$defs/team_investigation_record"},
            "event": event_page["properties"]["events"]["items"],
        },
        required=["record", "event"],
    )
    return {
        "$schema": _SCHEMA_URI,
        "title": "Causure Team HTTP investigation detail",
        **_closed_object(
            {
                "summary": event_page["properties"]["summary"],
                "investigation": view,
            },
            required=["summary", "investigation"],
        ),
        "$defs": definitions,
    }


def get_schema(name: str) -> dict[str, Any]:
    """Resolve a CLI schema name."""

    schemas = {
        "approval-assertion": approval_assertion_schema,
        "approval-revocations": approval_revocation_list_schema,
        "approval-trust-store": approval_trust_store_schema,
        "approval-verification": approval_verification_schema,
        "artifact-attestation": artifact_attestation_schema,
        "attestation-revocations": attestation_revocation_list_schema,
        "attestation-trust-store": attestation_trust_store_schema,
        "attestation-verification": attestation_verification_schema,
        "azure-review-publication": azure_review_publication_schema,
        "azure-review-verification": azure_review_verification_schema,
        "canary-observation": canary_observation_schema,
        "canary-policy": canary_policy_schema,
        "canary-result": canary_result_schema,
        "change-case": change_case_schema,
        "entra-refresh-config": entra_refresh_config_schema,
        "entra-trust-store": entra_trust_store_schema,
        "investigation-fixture": investigation_fixture_schema,
        "investigation-selection": investigation_selection_schema,
        "github-review-publication": github_review_publication_schema,
        "github-review-verification": github_review_verification_schema,
        "github-check-run-request": github_check_run_request_schema,
        "github-check-run-receipt": github_check_run_receipt_schema,
        "trusted-case-generation": trusted_case_generation_receipt_schema,
        "openai-quota-config": openai_quota_config_schema,
        "openai-quota-host-config": openai_quota_host_config_schema,
        "policy": policy_schema,
        "review-result": review_result_schema,
        "sandbox-policy": sandbox_policy_schema,
        "sandbox-worker-request": sandbox_worker_request_schema,
        "sandbox-worker-response": sandbox_worker_response_schema,
        "team-access-policy": team_access_policy_schema,
        "team-audit-event": team_audit_event_schema,
        "team-audit-export": team_audit_export_schema,
        "team-audit-verification": team_audit_verification_schema,
        "team-authorization": team_authorization_schema,
        "team-http-action-request": team_http_action_request_schema,
        "team-http-case-detail": team_http_case_detail_schema,
        "team-http-case-page": team_http_case_page_schema,
        "team-http-case-publication-request": team_http_case_publication_request_schema,
        "team-http-event-page": team_http_event_page_schema,
        "team-http-investigation-attach-request": (team_http_investigation_attach_request_schema),
        "team-http-investigation-detail": team_http_investigation_detail_schema,
        "team-http-investigation-open-request": (team_http_investigation_open_request_schema),
        "team-http-investigation-page": team_http_investigation_page_schema,
        "team-http-investigation-transition-request": (
            team_http_investigation_transition_request_schema
        ),
        "team-case-record": team_case_record_schema,
        "team-host-config": team_host_config_schema,
        "team-investigation-record": team_investigation_record_schema,
        "trace-manifest": trace_manifest_schema,
    }
    try:
        return schemas[name]()
    except KeyError as exc:
        raise ValueError(f"unknown schema: {name}") from exc
