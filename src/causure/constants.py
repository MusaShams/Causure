"""Shared constants and wire-format enums."""

from enum import StrEnum

ENGINE_VERSION = "0.4.0a18"
PACKAGE_VERSION = "0.4.0a18"
CASE_SCHEMA_VERSION = "1.0"
RESULT_SCHEMA_VERSION = "1.0"
TRACE_MANIFEST_SCHEMA_VERSION = "1.0"
INVESTIGATION_FIXTURE_SCHEMA_VERSION = "1.0"
INVESTIGATION_SELECTION_SCHEMA_VERSION = "1.0"
ARTIFACT_ATTESTATION_SCHEMA_VERSION = "1.0"
ATTESTATION_TRUST_STORE_SCHEMA_VERSION = "1.0"
ATTESTATION_REVOCATION_LIST_SCHEMA_VERSION = "1.0"
ATTESTATION_VERIFICATION_SCHEMA_VERSION = "1.0"
SANDBOX_POLICY_SCHEMA_VERSION = "1.0"
SANDBOX_WORKER_SCHEMA_VERSION = "1.0"
AZURE_REVIEW_PUBLICATION_SCHEMA_VERSION = "1.0"
AZURE_REVIEW_VERIFICATION_SCHEMA_VERSION = "1.0"
GITHUB_REVIEW_PUBLICATION_SCHEMA_VERSION = "1.0"
GITHUB_REVIEW_VERIFICATION_SCHEMA_VERSION = "1.0"
GITHUB_CHECK_RUN_REQUEST_SCHEMA_VERSION = "1.0"
GITHUB_CHECK_RUN_RECEIPT_SCHEMA_VERSION = "1.0"
TRUSTED_CASE_GENERATION_RECEIPT_SCHEMA_VERSION = "1.0"
APPROVAL_ASSERTION_SCHEMA_VERSION = "1.0"
APPROVAL_TRUST_STORE_SCHEMA_VERSION = "1.0"
APPROVAL_REVOCATION_LIST_SCHEMA_VERSION = "1.0"
APPROVAL_VERIFICATION_SCHEMA_VERSION = "1.0"
TEAM_ACCESS_POLICY_SCHEMA_VERSION = "1.0"
TEAM_AUTHORIZATION_SCHEMA_VERSION = "1.0"
TEAM_AUDIT_EVENT_SCHEMA_VERSION = "1.0"
TEAM_AUDIT_EXPORT_SCHEMA_VERSION = "1.0"
TEAM_AUDIT_VERIFICATION_SCHEMA_VERSION = "1.0"
ENTRA_TRUST_STORE_SCHEMA_VERSION = "1.0"
ENTRA_REFRESH_CONFIG_SCHEMA_VERSION = "1.0"
CANARY_POLICY_SCHEMA_VERSION = "1.0"
CANARY_OBSERVATION_SCHEMA_VERSION = "1.0"
CANARY_RESULT_SCHEMA_VERSION = "1.0"
TEAM_CASE_RECORD_SCHEMA_VERSION = "1.0"
TEAM_INVESTIGATION_RECORD_SCHEMA_VERSION = "1.0"
TEAM_HOST_CONFIG_SCHEMA_VERSION = "1.0"
OPENAI_QUOTA_CONFIG_SCHEMA_VERSION = "1.0"
OPENAI_QUOTA_HOST_CONFIG_SCHEMA_VERSION = "1.0"
DEFAULT_POLICY_NAME = "default-v1"
SAFE_TRACE_TEXT_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$"

OMITTED_TRACE_FIELD_GROUPS = (
    "resource_attributes",
    "scope_attributes",
    "span_events",
    "span_links",
    "span_names",
    "span_status_messages",
)

SAFE_TRACE_TEXT_ATTRIBUTES = (
    "embedding.model_name",
    "gen_ai.operation.name",
    "gen_ai.provider.name",
    "gen_ai.request.model",
    "gen_ai.response.model",
    "llm.model_name",
    "llm.provider",
    "llm.system",
    "openinference.span.kind",
)

SAFE_TRACE_NUMERIC_ATTRIBUTES = (
    "gen_ai.usage.completion_tokens",
    "gen_ai.usage.input_tokens",
    "gen_ai.usage.output_tokens",
    "gen_ai.usage.prompt_tokens",
    "llm.cost.completion",
    "llm.cost.completion_details.audio",
    "llm.cost.completion_details.output",
    "llm.cost.completion_details.reasoning",
    "llm.cost.prompt",
    "llm.cost.prompt_details.audio",
    "llm.cost.prompt_details.cache_input",
    "llm.cost.prompt_details.cache_read",
    "llm.cost.prompt_details.cache_write",
    "llm.cost.prompt_details.input",
    "llm.cost.total",
    "llm.token_count.completion",
    "llm.token_count.completion_details.audio",
    "llm.token_count.completion_details.reasoning",
    "llm.token_count.prompt",
    "llm.token_count.prompt_details.audio",
    "llm.token_count.prompt_details.cache_read",
    "llm.token_count.prompt_details.cache_write",
    "llm.token_count.total",
)


class Component(StrEnum):
    SYSTEM_PROMPT = "system_prompt"
    TOOL_DESCRIPTION = "tool_description"
    TOOL_SCHEMA = "tool_schema"
    MODEL_ROUTING = "model_routing"
    RETRIEVAL_CONFIGURATION = "retrieval_configuration"
    REVIEWER = "reviewer"
    VERIFICATION_STEP = "verification_step"
    RETRY_POLICY = "retry_policy"
    STOPPING_POLICY = "stopping_policy"
    MEMORY_POLICY = "memory_policy"
    TOOL_IMPLEMENTATION = "tool_implementation"
    EVALUATOR = "evaluator"
    ENVIRONMENT = "environment"
    MODEL_REASONING = "model_reasoning"
    REQUIREMENT = "requirement"
    OTHER = "other"


class RequirementStatus(StrEnum):
    CLEAR = "clear"
    AMBIGUOUS = "ambiguous"
    CONFLICTING = "conflicting"
    UNKNOWN = "unknown"


class IncidentSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class OracleKind(StrEnum):
    EXACT_MATCH = "exact_match"
    EXECUTABLE = "executable"
    POLICY = "policy"
    HUMAN_LABEL = "human_label"
    CONSENSUS = "consensus"
    CUSTOM = "custom"


class ValidationKind(StrEnum):
    POSITIVE = "positive"
    NEGATIVE = "negative"
    REGRESSION = "regression"


class Decision(StrEnum):
    APPROVE = "approve"
    CONDITIONAL_PASS = "conditional_pass"
    REJECT = "reject"
    NEEDS_EVIDENCE = "needs_evidence"
    HUMAN_REVIEW = "human_review"


class RecommendedAction(StrEnum):
    PATCH = "patch"
    DO_NOT_PATCH = "do_not_patch"
    COLLECT_EVIDENCE = "collect_evidence"
    ESCALATE = "escalate"


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"


class CanaryAssignmentMethod(StrEnum):
    RANDOMIZED = "randomized"
    DETERMINISTIC_HASH = "deterministic_hash"


class CanaryAssignmentUnit(StrEnum):
    REQUEST = "request"
    SESSION = "session"
    PRINCIPAL = "principal"
    TENANT = "tenant"


class CanaryMetricDirection(StrEnum):
    HIGHER = "higher"
    LOWER = "lower"


class CanaryMetricStatus(StrEnum):
    NONINFERIOR = "noninferior"
    REGRESSION = "regression"
    INCONCLUSIVE = "inconclusive"


class CanaryDecision(StrEnum):
    PROMOTE = "promote"
    CONTINUE = "continue"
    ROLLBACK = "rollback"
    NEEDS_EVIDENCE = "needs_evidence"


class Consequence(StrEnum):
    NONE = "none"
    CONDITIONAL = "conditional"
    NEEDS_EVIDENCE = "needs_evidence"
    REJECT = "reject"
    HUMAN_REVIEW = "human_review"


class TraceSourceFormat(StrEnum):
    OTLP_JSON = "otlp-json"


class RedactionStrategy(StrEnum):
    METADATA_ALLOWLIST_V1 = "metadata-allowlist-v1"


class SignatureAlgorithm(StrEnum):
    ED25519 = "ed25519"


class SignatureCanonicalization(StrEnum):
    CAUSURE_JSON_V1 = "causure-json-v1"


class RevocationMode(StrEnum):
    ALL_SIGNATURES = "all_signatures"
    ISSUED_AT_OR_AFTER = "issued_at_or_after"


class ApprovalAction(StrEnum):
    APPROVE = "approve"
    EXCEPTION = "exception"


class ApprovalAuthenticationMethod(StrEnum):
    AZURE_DEVOPS_APPROVAL = "azure_devops_approval"
    ORGANIZATIONAL_SSO = "organizational_sso"


class ApprovalGateEffect(StrEnum):
    RECORD_ONLY = "record_only"


class TeamRole(StrEnum):
    INVESTIGATOR = "investigator"
    POLICY_ADMINISTRATOR = "policy_administrator"
    APPROVER = "approver"


class TeamAction(StrEnum):
    EVIDENCE_READ = "evidence_read"
    INVESTIGATION_WRITE = "investigation_write"
    POLICY_WRITE = "policy_write"
    APPROVAL_ISSUE = "approval_issue"
    AUDIT_EXPORT = "audit_export"


class TeamResourceType(StrEnum):
    EVIDENCE_CASE = "evidence_case"
    INVESTIGATION = "investigation"
    GATE_POLICY = "gate_policy"
    APPROVAL = "approval"
    AUDIT_EXPORT = "audit_export"


class TeamAuthorizationReason(StrEnum):
    ROLE_GRANT = "role_grant"
    PRINCIPAL_NOT_MEMBER = "principal_not_member"
    ROLE_NOT_GRANTED = "role_not_granted"


class TeamAuditOutcome(StrEnum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    DENIED = "denied"


class TeamInvestigationStatus(StrEnum):
    QUEUED = "queued"
    INVESTIGATING = "investigating"
    BLOCKED = "blocked"
    CLOSED = "closed"


class TeamInvestigationPriority(StrEnum):
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    CRITICAL = "critical"


class TeamInvestigationResolution(StrEnum):
    CHANGE_CASE_OPENED = "change_case_opened"
    DUPLICATE = "duplicate"
    NOT_A_FAILURE = "not_a_failure"
    NO_CHANGE_REQUIRED = "no_change_required"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class SandboxNetworkMode(StrEnum):
    NONE = "none"
    QUOTA_PROXY = "quota_proxy"


class SandboxWorkerMode(StrEnum):
    REPLAY = "replay"
    EVALUATION = "evaluation"


class QuotaEnforcement(StrEnum):
    PROVIDER_HARD_LIMIT = "provider_hard_limit"


class TfvcTargetKind(StrEnum):
    CHANGESET = "changeset"
    SHELVESET = "shelveset"


class AzureBuildReason(StrEnum):
    MANUAL = "Manual"
    INDIVIDUAL_CI = "IndividualCI"
    BATCHED_CI = "BatchedCI"
    SCHEDULE = "Schedule"
    VALIDATE_SHELVESET = "ValidateShelveset"
    CHECK_IN_SHELVESET = "CheckInShelveset"
    BUILD_COMPLETION = "BuildCompletion"
    RESOURCE_TRIGGER = "ResourceTrigger"


class OpenInferenceSpanKind(StrEnum):
    AGENT = "AGENT"
    CHAIN = "CHAIN"
    EMBEDDING = "EMBEDDING"
    EVALUATOR = "EVALUATOR"
    GUARDRAIL = "GUARDRAIL"
    LLM = "LLM"
    PROMPT = "PROMPT"
    RERANKER = "RERANKER"
    RETRIEVER = "RETRIEVER"
    TOOL = "TOOL"
