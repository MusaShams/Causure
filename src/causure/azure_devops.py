"""Tamper-evident Azure DevOps and TFVC review publication records."""

from __future__ import annotations

import hashlib
import html
import json
import re
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any
from urllib.parse import quote, urlsplit, urlunsplit

from causure.constants import (
    AZURE_REVIEW_PUBLICATION_SCHEMA_VERSION,
    AZURE_REVIEW_VERIFICATION_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
    AzureBuildReason,
    CheckStatus,
    Component,
    Consequence,
    Decision,
    RecommendedAction,
    TfvcTargetKind,
)
from causure.io import InputDocumentError, parse_json_text
from causure.models import to_jsonable

MAX_REVIEW_RESULT_BYTES = 5 * 1024 * 1024
MAX_REVIEW_REPORT_BYTES = 2 * 1024 * 1024
MAX_AZURE_PUBLICATION_BYTES = 1024 * 1024
MAX_AZURE_VERIFICATION_BYTES = 1024 * 1024
DEFAULT_MAX_PUBLICATION_AGE_SECONDS = 3600
MAX_PUBLICATION_AGE_SECONDS = 24 * 60 * 60
MAX_REVIEW_TO_PUBLICATION_SECONDS = 300

_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_UTC_TIMESTAMP_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_REVIEW_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_NO_CONTROL_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]+$")

_REVIEW_RESULT_MEDIA_TYPE = "application/vnd.causure.review-result+json"
_REVIEW_REPORT_MEDIA_TYPE = "text/markdown; charset=utf-8"
_PUBLICATION_MEDIA_TYPE = "application/vnd.causure.azure-review-publication+json"
_TFVC_REPOSITORY_PROVIDER = "TfsVersionControl"


class AzureReviewValidationError(ValueError):
    """Raised when an Azure review boundary document is structurally invalid."""

    def __init__(self, document_name: str, path: str, message: str) -> None:
        self.document_name = document_name
        self.path = path
        self.message = message
        super().__init__(f"Invalid {document_name} at {path}: {message}")


class AzureReviewVerificationError(ValueError):
    """Raised when publication verification fails closed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


@dataclass(frozen=True, slots=True)
class ReviewBinding:
    result_schema_version: str
    engine_version: str
    policy_name: str
    case_id: str
    component: Component
    input_sha256: str
    reviewed_at: str
    decision: Decision
    recommended_action: RecommendedAction


@dataclass(frozen=True, slots=True)
class ReviewFindingBinding:
    code: str
    status: CheckStatus
    consequence: Consequence


@dataclass(frozen=True, slots=True)
class ArtifactIntegrity:
    media_type: str
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class ReviewArtifacts:
    review_result: ArtifactIntegrity
    review_report: ArtifactIntegrity


@dataclass(frozen=True, slots=True)
class TfvcChangesetTarget:
    kind: TfvcTargetKind
    changeset_id: int


@dataclass(frozen=True, slots=True)
class TfvcShelvesetTarget:
    kind: TfvcTargetKind
    shelveset_name: str
    owner: str


TfvcTarget = TfvcChangesetTarget | TfvcShelvesetTarget


@dataclass(frozen=True, slots=True)
class TfvcAssociation:
    server_path: str
    target: TfvcTarget


@dataclass(frozen=True, slots=True)
class AzureBuildContext:
    collection_uri: str
    project_id: str
    project_name: str
    build_id: int
    build_number: str
    definition_id: int
    definition_name: str
    reason: AzureBuildReason
    repository_provider: str
    source_version: str
    source_branch: str
    requested_for_id: str
    source_tfvc_shelveset: str | None = field(
        default=None,
        metadata={"omit_none": True},
    )


@dataclass(frozen=True, slots=True)
class AzureReviewPublication:
    schema_version: str
    created_at: str
    review: ReviewBinding
    tfvc: TfvcAssociation
    build: AzureBuildContext
    work_item_ids: tuple[int, ...]
    artifacts: ReviewArtifacts


@dataclass(frozen=True, slots=True)
class PublicationSubject:
    media_type: str
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class AzureReviewVerification:
    schema_version: str
    status: str
    verified_at: str
    maximum_age_seconds: int
    publication_age_seconds: int
    publication: PublicationSubject
    review: ReviewBinding
    tfvc: TfvcAssociation
    build_id: int
    artifacts: ReviewArtifacts


def _object(
    value: Any,
    path: str,
    document_name: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AzureReviewValidationError(document_name, path, "expected an object")
    allowed = required | (optional or set())
    missing = sorted(required - value.keys())
    if missing:
        raise AzureReviewValidationError(
            document_name,
            f"{path}.{missing[0]}",
            "required property is missing",
        )
    unknown = sorted(value.keys() - allowed)
    if unknown:
        raise AzureReviewValidationError(
            document_name,
            f"{path}.{unknown[0]}",
            "property is not allowed",
        )
    return value


def _string(
    value: Any,
    path: str,
    document_name: str,
    *,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if not isinstance(value, str):
        raise AzureReviewValidationError(document_name, path, "expected a string")
    if not value or value != value.strip():
        raise AzureReviewValidationError(
            document_name,
            path,
            "expected a non-empty string without surrounding whitespace",
        )
    if len(value) > maximum:
        raise AzureReviewValidationError(
            document_name,
            path,
            f"expected at most {maximum} characters",
        )
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise AzureReviewValidationError(
            document_name,
            path,
            "expected valid Unicode scalar values",
        ) from exc
    if not _NO_CONTROL_PATTERN.fullmatch(value):
        raise AzureReviewValidationError(
            document_name,
            path,
            "control characters are not allowed",
        )
    if pattern is not None and not pattern.fullmatch(value):
        raise AzureReviewValidationError(
            document_name,
            path,
            "value does not match the required format",
        )
    return value


def _integer(
    value: Any,
    path: str,
    document_name: str,
    *,
    minimum: int = 1,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise AzureReviewValidationError(document_name, path, "expected an integer")
    if value < minimum:
        raise AzureReviewValidationError(
            document_name,
            path,
            f"expected an integer of at least {minimum}",
        )
    return value


def _enum(
    value: Any,
    path: str,
    document_name: str,
    enum_type: type[Any],
) -> Any:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(member.value for member in enum_type)
        raise AzureReviewValidationError(
            document_name,
            path,
            f"expected one of: {allowed}",
        ) from exc


def _utc_timestamp(
    value: Any,
    path: str,
    document_name: str,
    *,
    whole_seconds: bool,
) -> str:
    maximum = 20 if whole_seconds else 40
    result = _string(value, path, document_name, maximum=maximum)
    timestamp_pattern = _UTC_TIMESTAMP_PATTERN if whole_seconds else _REVIEW_TIMESTAMP_PATTERN
    if not timestamp_pattern.fullmatch(result):
        raise AzureReviewValidationError(
            document_name,
            path,
            (
                "expected a UTC timestamp in YYYY-MM-DDTHH:MM:SSZ form"
                if whole_seconds
                else "expected an ISO 8601 UTC timestamp with optional fractional seconds"
            ),
        )
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AzureReviewValidationError(
            document_name,
            path,
            "expected a real ISO 8601 UTC timestamp",
        ) from exc
    if parsed.utcoffset() != timedelta(0):
        raise AzureReviewValidationError(document_name, path, "expected a UTC timestamp")
    return result


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _canonical_uuid(value: Any, path: str, document_name: str) -> str:
    raw = _string(value, path, document_name, maximum=36)
    try:
        parsed_uuid = uuid.UUID(raw)
    except (ValueError, AttributeError) as exc:
        raise AzureReviewValidationError(
            document_name,
            path,
            "expected a UUID",
        ) from exc
    parsed = str(parsed_uuid)
    if parsed_uuid.int == 0:
        raise AzureReviewValidationError(
            document_name,
            path,
            "the nil UUID is not allowed",
        )
    if raw != parsed:
        raise AzureReviewValidationError(
            document_name,
            path,
            "expected a canonical lowercase UUID",
        )
    return parsed


def _collection_uri(value: Any, path: str, document_name: str) -> str:
    raw = _string(value, path, document_name, maximum=2048)
    parsed = urlsplit(raw)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise AzureReviewValidationError(
            document_name,
            path,
            "expected an HTTPS collection URI without credentials, query, or fragment",
        )
    canonical = urlunsplit(
        (
            "https",
            parsed.netloc.lower(),
            f"{parsed.path.rstrip('/')}/",
            "",
            "",
        )
    )
    if raw != canonical:
        raise AzureReviewValidationError(
            document_name,
            path,
            f"expected canonical collection URI {canonical!r}",
        )
    return canonical


def _tfvc_server_path(value: Any, path: str, document_name: str) -> str:
    result = _string(value, path, document_name, maximum=512)
    if not result.startswith("$/") or result.endswith("/") or ";" in result:
        raise AzureReviewValidationError(
            document_name,
            path,
            "expected a TFVC server path beginning with '$/' and without a trailing slash",
        )
    return result


def _parse_review_binding(document: Any, *, document_name: str) -> ReviewBinding:
    root = _object(
        document,
        "$",
        document_name,
        required={
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
        },
    )
    schema_version = _string(
        root["schema_version"],
        "$.schema_version",
        document_name,
        maximum=16,
    )
    if schema_version != RESULT_SCHEMA_VERSION:
        raise AzureReviewValidationError(
            document_name,
            "$.schema_version",
            f"unsupported version {schema_version!r}; expected {RESULT_SCHEMA_VERSION!r}",
        )
    _string(root["case_title"], "$.case_title", document_name, maximum=2048)
    _string(root["summary"], "$.summary", document_name, maximum=8192)
    if not isinstance(root["metrics"], dict):
        raise AzureReviewValidationError(
            document_name,
            "$.metrics",
            "expected an object",
        )
    findings = root["findings"]
    if not isinstance(findings, list):
        raise AzureReviewValidationError(
            document_name,
            "$.findings",
            "expected an array",
        )
    finding_codes: list[str] = []
    for index, value in enumerate(findings):
        path = f"$.findings[{index}]"
        finding = _object(
            value,
            path,
            document_name,
            required={"code", "status", "consequence", "message", "details"},
        )
        finding_codes.append(_string(finding["code"], f"{path}.code", document_name, maximum=128))
        _enum(finding["status"], f"{path}.status", document_name, CheckStatus)
        _enum(
            finding["consequence"],
            f"{path}.consequence",
            document_name,
            Consequence,
        )
        _string(finding["message"], f"{path}.message", document_name, maximum=4096)
        if not isinstance(finding["details"], dict):
            raise AzureReviewValidationError(
                document_name,
                f"{path}.details",
                "expected an object",
            )
    if len(set(finding_codes)) != len(finding_codes):
        raise AzureReviewValidationError(
            document_name,
            "$.findings",
            "finding codes must be unique",
        )
    return ReviewBinding(
        result_schema_version=schema_version,
        engine_version=_string(
            root["engine_version"],
            "$.engine_version",
            document_name,
            maximum=128,
        ),
        policy_name=_string(
            root["policy_name"],
            "$.policy_name",
            document_name,
            maximum=128,
        ),
        case_id=_string(
            root["case_id"],
            "$.case_id",
            document_name,
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        component=_enum(root["component"], "$.component", document_name, Component),
        input_sha256=_string(
            root["input_sha256"],
            "$.input_sha256",
            document_name,
            maximum=64,
            pattern=_SHA256_PATTERN,
        ),
        reviewed_at=_utc_timestamp(
            root["reviewed_at"],
            "$.reviewed_at",
            document_name,
            whole_seconds=False,
        ),
        decision=_enum(root["decision"], "$.decision", document_name, Decision),
        recommended_action=_enum(
            root["recommended_action"],
            "$.recommended_action",
            document_name,
            RecommendedAction,
        ),
    )


def _parse_json_bytes(
    raw_bytes: bytes,
    *,
    description: str,
    maximum: int,
) -> Any:
    if not raw_bytes:
        raise AzureReviewValidationError(description, "$", "document must not be empty")
    if len(raw_bytes) > maximum:
        raise AzureReviewValidationError(
            description,
            "$",
            f"document exceeds the {maximum}-byte limit",
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AzureReviewValidationError(
            description,
            "$",
            "document is not valid UTF-8",
        ) from exc
    try:
        return parse_json_text(text, source=description, max_bytes=maximum)
    except InputDocumentError as exc:
        raise AzureReviewValidationError(description, "$", str(exc)) from exc


def parse_review_result_bytes(raw_bytes: bytes) -> ReviewBinding:
    """Strictly parse the review-result fields used by an Azure publication."""

    return _parse_review_binding(
        _parse_json_bytes(
            raw_bytes,
            description="review result",
            maximum=MAX_REVIEW_RESULT_BYTES,
        ),
        document_name="review result",
    )


def parse_review_result_findings_bytes(
    raw_bytes: bytes,
) -> tuple[ReviewFindingBinding, ...]:
    """Strictly parse the stable finding fields from exact review-result bytes."""

    document = _parse_json_bytes(
        raw_bytes,
        description="review result",
        maximum=MAX_REVIEW_RESULT_BYTES,
    )
    _parse_review_binding(document, document_name="review result")
    return tuple(
        ReviewFindingBinding(
            code=item["code"],
            status=CheckStatus(item["status"]),
            consequence=Consequence(item["consequence"]),
        )
        for item in document["findings"]
    )


def _validate_report(raw_bytes: bytes, review: ReviewBinding) -> None:
    if not raw_bytes or len(raw_bytes) > MAX_REVIEW_REPORT_BYTES:
        raise AzureReviewValidationError(
            "review report",
            "$",
            f"expected from 1 to {MAX_REVIEW_REPORT_BYTES} bytes",
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise AzureReviewValidationError(
            "review report",
            "$",
            "expected UTF-8 Markdown",
        ) from exc
    required_fragments = (
        f"> **{review.decision.value.replace('_', ' ').upper()}**",
        f"| Case | `{review.case_id}` |",
        f"| Proposed component | `{review.component.value}` |",
        (
            "| Recommended action | "
            f"**{review.recommended_action.value.replace('_', ' ').upper()}** |"
        ),
        f"| Policy | `{review.policy_name}` |",
        f"- Evidence document SHA-256: `{review.input_sha256}`",
        f"- Engine version: `{review.engine_version}`",
        f"- Reviewed at: `{review.reviewed_at}`",
    )
    if (
        "\x00" in text
        or not text.startswith("# Causure evidence report\n\n")
        or any(fragment not in text for fragment in required_fragments)
    ):
        raise AzureReviewValidationError(
            "review report",
            "$",
            "Markdown does not correspond to the supplied review result",
        )


def _artifact_integrity(raw_bytes: bytes, media_type: str) -> ArtifactIntegrity:
    return ArtifactIntegrity(
        media_type=media_type,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        byte_count=len(raw_bytes),
    )


def _required_environment(
    environment: Mapping[str, str],
    name: str,
    *,
    maximum: int = 2048,
) -> str:
    value = environment.get(name)
    if value is None or not value.strip():
        raise AzureReviewValidationError(
            "Azure Pipelines environment",
            name,
            "required variable is missing or empty",
        )
    return _string(
        value,
        name,
        "Azure Pipelines environment",
        maximum=maximum,
    )


def _environment_integer(environment: Mapping[str, str], name: str) -> int:
    value = _required_environment(environment, name, maximum=32)
    try:
        parsed = int(value)
    except ValueError as exc:
        raise AzureReviewValidationError(
            "Azure Pipelines environment",
            name,
            "expected a positive integer",
        ) from exc
    return _integer(
        parsed,
        name,
        "Azure Pipelines environment",
    )


def _environment_uuid(environment: Mapping[str, str], name: str) -> str:
    value = _required_environment(environment, name, maximum=36)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise AzureReviewValidationError(
            "Azure Pipelines environment",
            name,
            "expected a UUID",
        ) from exc
    if parsed.int == 0:
        raise AzureReviewValidationError(
            "Azure Pipelines environment",
            name,
            "the nil UUID is not allowed",
        )
    return str(parsed)


def _parse_shelveset_reference(value: str, *, document_name: str, path: str) -> tuple[str, str]:
    name, separator, owner = value.rpartition(";")
    if not separator:
        raise AzureReviewValidationError(
            document_name,
            path,
            "expected shelveset reference 'name;owner'",
        )
    return (
        _string(name, f"{path}.name", document_name, maximum=128),
        _string(owner, f"{path}.owner", document_name, maximum=320),
    )


def azure_context_from_environment(
    environment: Mapping[str, str],
    *,
    tfvc_server_path: str,
) -> tuple[TfvcAssociation, AzureBuildContext]:
    """Read and validate the current TFVC build identity from Azure agent variables."""

    if _required_environment(environment, "TF_BUILD", maximum=8).lower() != "true":
        raise AzureReviewValidationError(
            "Azure Pipelines environment",
            "TF_BUILD",
            "expected 'True' on an Azure Pipelines agent",
        )
    repository_provider = _required_environment(
        environment,
        "BUILD_REPOSITORY_PROVIDER",
        maximum=64,
    )
    if repository_provider != _TFVC_REPOSITORY_PROVIDER:
        raise AzureReviewValidationError(
            "Azure Pipelines environment",
            "BUILD_REPOSITORY_PROVIDER",
            f"expected {_TFVC_REPOSITORY_PROVIDER!r}",
        )

    server_path = _tfvc_server_path(
        tfvc_server_path,
        "tfvc_server_path",
        "Azure Pipelines environment",
    )
    source_version = _required_environment(environment, "BUILD_SOURCEVERSION", maximum=256)
    source_branch = _required_environment(environment, "BUILD_SOURCEBRANCH", maximum=512)
    shelveset_reference = environment.get("BUILD_SOURCETFVCSHELVESET", "").strip()
    reason = _enum(
        _required_environment(environment, "BUILD_REASON", maximum=64),
        "BUILD_REASON",
        "Azure Pipelines environment",
        AzureBuildReason,
    )

    if shelveset_reference:
        shelveset_reference = _string(
            shelveset_reference,
            "BUILD_SOURCETFVCSHELVESET",
            "Azure Pipelines environment",
            maximum=512,
        )
        shelveset_name, owner = _parse_shelveset_reference(
            shelveset_reference,
            document_name="Azure Pipelines environment",
            path="BUILD_SOURCETFVCSHELVESET",
        )
        if reason not in {
            AzureBuildReason.VALIDATE_SHELVESET,
            AzureBuildReason.CHECK_IN_SHELVESET,
        }:
            raise AzureReviewValidationError(
                "Azure Pipelines environment",
                "BUILD_REASON",
                "shelveset builds require ValidateShelveset or CheckInShelveset",
            )
        if source_branch.casefold() != shelveset_reference.casefold():
            raise AzureReviewValidationError(
                "Azure Pipelines environment",
                "BUILD_SOURCEBRANCH",
                "does not identify BUILD_SOURCETFVCSHELVESET",
            )
        target: TfvcTarget = TfvcShelvesetTarget(
            kind=TfvcTargetKind.SHELVESET,
            shelveset_name=shelveset_name,
            owner=owner,
        )
        source_tfvc_shelveset: str | None = shelveset_reference
    else:
        try:
            changeset_id = int(source_version)
        except ValueError as exc:
            raise AzureReviewValidationError(
                "Azure Pipelines environment",
                "BUILD_SOURCEVERSION",
                "expected a positive TFVC changeset ID",
            ) from exc
        _integer(
            changeset_id,
            "BUILD_SOURCEVERSION",
            "Azure Pipelines environment",
        )
        if reason in {
            AzureBuildReason.VALIDATE_SHELVESET,
            AzureBuildReason.CHECK_IN_SHELVESET,
        }:
            raise AzureReviewValidationError(
                "Azure Pipelines environment",
                "BUILD_SOURCETFVCSHELVESET",
                "is required for a shelveset build reason",
            )
        if source_branch.casefold() != server_path.casefold():
            raise AzureReviewValidationError(
                "Azure Pipelines environment",
                "BUILD_SOURCEBRANCH",
                "does not match the configured TFVC server path",
            )
        target = TfvcChangesetTarget(
            kind=TfvcTargetKind.CHANGESET,
            changeset_id=changeset_id,
        )
        source_tfvc_shelveset = None

    collection_uri_raw = _required_environment(environment, "SYSTEM_COLLECTIONURI")
    parsed_collection = urlsplit(collection_uri_raw)
    if (
        parsed_collection.scheme.lower() != "https"
        or not parsed_collection.hostname
        or parsed_collection.username is not None
        or parsed_collection.password is not None
        or parsed_collection.query
        or parsed_collection.fragment
    ):
        raise AzureReviewValidationError(
            "Azure Pipelines environment",
            "SYSTEM_COLLECTIONURI",
            "expected an HTTPS URI without credentials, query, or fragment",
        )
    canonical_collection = urlunsplit(
        (
            parsed_collection.scheme.lower(),
            parsed_collection.netloc.lower(),
            f"{parsed_collection.path.rstrip('/')}/",
            "",
            "",
        )
    )
    context = AzureBuildContext(
        collection_uri=_collection_uri(
            canonical_collection,
            "SYSTEM_COLLECTIONURI",
            "Azure Pipelines environment",
        ),
        project_id=_environment_uuid(environment, "SYSTEM_TEAMPROJECTID"),
        project_name=_required_environment(
            environment,
            "SYSTEM_TEAMPROJECT",
            maximum=256,
        ),
        build_id=_environment_integer(environment, "BUILD_BUILDID"),
        build_number=_required_environment(environment, "BUILD_BUILDNUMBER", maximum=256),
        definition_id=_environment_integer(environment, "SYSTEM_DEFINITIONID"),
        definition_name=_required_environment(
            environment,
            "BUILD_DEFINITIONNAME",
            maximum=256,
        ),
        reason=reason,
        repository_provider=repository_provider,
        source_version=source_version,
        source_branch=source_branch,
        requested_for_id=_environment_uuid(environment, "BUILD_REQUESTEDFORID"),
        source_tfvc_shelveset=source_tfvc_shelveset,
    )
    return TfvcAssociation(server_path=server_path, target=target), context


def _parse_artifact(
    value: Any,
    path: str,
    document_name: str,
    *,
    expected_media_type: str,
    maximum_bytes: int,
) -> ArtifactIntegrity:
    obj = _object(
        value,
        path,
        document_name,
        required={"media_type", "sha256", "byte_count"},
    )
    media_type = _string(
        obj["media_type"],
        f"{path}.media_type",
        document_name,
        maximum=255,
    )
    if media_type != expected_media_type:
        raise AzureReviewValidationError(
            document_name,
            f"{path}.media_type",
            f"expected {expected_media_type!r}",
        )
    artifact = ArtifactIntegrity(
        media_type=media_type,
        sha256=_string(
            obj["sha256"],
            f"{path}.sha256",
            document_name,
            maximum=64,
            pattern=_SHA256_PATTERN,
        ),
        byte_count=_integer(
            obj["byte_count"],
            f"{path}.byte_count",
            document_name,
        ),
    )
    if artifact.byte_count > maximum_bytes:
        raise AzureReviewValidationError(
            document_name,
            f"{path}.byte_count",
            f"expected at most {maximum_bytes}",
        )
    return artifact


def _parse_review(value: Any, path: str, document_name: str) -> ReviewBinding:
    obj = _object(
        value,
        path,
        document_name,
        required={
            "result_schema_version",
            "engine_version",
            "policy_name",
            "case_id",
            "component",
            "input_sha256",
            "reviewed_at",
            "decision",
            "recommended_action",
        },
    )
    result_schema_version = _string(
        obj["result_schema_version"],
        f"{path}.result_schema_version",
        document_name,
        maximum=16,
    )
    if result_schema_version != RESULT_SCHEMA_VERSION:
        raise AzureReviewValidationError(
            document_name,
            f"{path}.result_schema_version",
            f"expected {RESULT_SCHEMA_VERSION!r}",
        )
    return ReviewBinding(
        result_schema_version=result_schema_version,
        engine_version=_string(
            obj["engine_version"],
            f"{path}.engine_version",
            document_name,
            maximum=128,
        ),
        policy_name=_string(
            obj["policy_name"],
            f"{path}.policy_name",
            document_name,
            maximum=128,
        ),
        case_id=_string(
            obj["case_id"],
            f"{path}.case_id",
            document_name,
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        component=_enum(
            obj["component"],
            f"{path}.component",
            document_name,
            Component,
        ),
        input_sha256=_string(
            obj["input_sha256"],
            f"{path}.input_sha256",
            document_name,
            maximum=64,
            pattern=_SHA256_PATTERN,
        ),
        reviewed_at=_utc_timestamp(
            obj["reviewed_at"],
            f"{path}.reviewed_at",
            document_name,
            whole_seconds=False,
        ),
        decision=_enum(
            obj["decision"],
            f"{path}.decision",
            document_name,
            Decision,
        ),
        recommended_action=_enum(
            obj["recommended_action"],
            f"{path}.recommended_action",
            document_name,
            RecommendedAction,
        ),
    )


def _parse_target(value: Any, path: str, document_name: str) -> TfvcTarget:
    if not isinstance(value, dict):
        raise AzureReviewValidationError(document_name, path, "expected an object")
    kind = _enum(
        value.get("kind"),
        f"{path}.kind",
        document_name,
        TfvcTargetKind,
    )
    if kind is TfvcTargetKind.CHANGESET:
        obj = _object(
            value,
            path,
            document_name,
            required={"kind", "changeset_id"},
        )
        return TfvcChangesetTarget(
            kind=kind,
            changeset_id=_integer(
                obj["changeset_id"],
                f"{path}.changeset_id",
                document_name,
            ),
        )
    obj = _object(
        value,
        path,
        document_name,
        required={"kind", "shelveset_name", "owner"},
    )
    return TfvcShelvesetTarget(
        kind=kind,
        shelveset_name=_string(
            obj["shelveset_name"],
            f"{path}.shelveset_name",
            document_name,
            maximum=128,
        ),
        owner=_string(
            obj["owner"],
            f"{path}.owner",
            document_name,
            maximum=320,
        ),
    )


def _parse_tfvc(value: Any, path: str, document_name: str) -> TfvcAssociation:
    obj = _object(
        value,
        path,
        document_name,
        required={"server_path", "target"},
    )
    return TfvcAssociation(
        server_path=_tfvc_server_path(
            obj["server_path"],
            f"{path}.server_path",
            document_name,
        ),
        target=_parse_target(
            obj["target"],
            f"{path}.target",
            document_name,
        ),
    )


def _parse_build(value: Any, path: str, document_name: str) -> AzureBuildContext:
    obj = _object(
        value,
        path,
        document_name,
        required={
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
        },
        optional={"source_tfvc_shelveset"},
    )
    repository_provider = _string(
        obj["repository_provider"],
        f"{path}.repository_provider",
        document_name,
        maximum=64,
    )
    if repository_provider != _TFVC_REPOSITORY_PROVIDER:
        raise AzureReviewValidationError(
            document_name,
            f"{path}.repository_provider",
            f"expected {_TFVC_REPOSITORY_PROVIDER!r}",
        )
    source_tfvc_shelveset = obj.get("source_tfvc_shelveset")
    return AzureBuildContext(
        collection_uri=_collection_uri(
            obj["collection_uri"],
            f"{path}.collection_uri",
            document_name,
        ),
        project_id=_canonical_uuid(
            obj["project_id"],
            f"{path}.project_id",
            document_name,
        ),
        project_name=_string(
            obj["project_name"],
            f"{path}.project_name",
            document_name,
            maximum=256,
        ),
        build_id=_integer(obj["build_id"], f"{path}.build_id", document_name),
        build_number=_string(
            obj["build_number"],
            f"{path}.build_number",
            document_name,
            maximum=256,
        ),
        definition_id=_integer(
            obj["definition_id"],
            f"{path}.definition_id",
            document_name,
        ),
        definition_name=_string(
            obj["definition_name"],
            f"{path}.definition_name",
            document_name,
            maximum=256,
        ),
        reason=_enum(
            obj["reason"],
            f"{path}.reason",
            document_name,
            AzureBuildReason,
        ),
        repository_provider=repository_provider,
        source_version=_string(
            obj["source_version"],
            f"{path}.source_version",
            document_name,
            maximum=256,
        ),
        source_branch=_string(
            obj["source_branch"],
            f"{path}.source_branch",
            document_name,
            maximum=512,
        ),
        source_tfvc_shelveset=(
            _string(
                source_tfvc_shelveset,
                f"{path}.source_tfvc_shelveset",
                document_name,
                maximum=512,
            )
            if source_tfvc_shelveset is not None
            else None
        ),
        requested_for_id=_canonical_uuid(
            obj["requested_for_id"],
            f"{path}.requested_for_id",
            document_name,
        ),
    )


def _validate_target_build_consistency(
    tfvc: TfvcAssociation,
    build: AzureBuildContext,
    *,
    document_name: str,
) -> None:
    if isinstance(tfvc.target, TfvcChangesetTarget):
        if build.source_version != str(tfvc.target.changeset_id):
            raise AzureReviewValidationError(
                document_name,
                "$.build.source_version",
                "does not match the TFVC changeset target",
            )
        if build.source_tfvc_shelveset is not None:
            raise AzureReviewValidationError(
                document_name,
                "$.build.source_tfvc_shelveset",
                "is not allowed for a changeset target",
            )
        if build.source_branch.casefold() != tfvc.server_path.casefold():
            raise AzureReviewValidationError(
                document_name,
                "$.build.source_branch",
                "does not match the TFVC server path",
            )
        if build.reason in {
            AzureBuildReason.VALIDATE_SHELVESET,
            AzureBuildReason.CHECK_IN_SHELVESET,
        }:
            raise AzureReviewValidationError(
                document_name,
                "$.build.reason",
                "a shelveset build reason is invalid for a changeset target",
            )
        return

    reference = f"{tfvc.target.shelveset_name};{tfvc.target.owner}"
    if build.source_tfvc_shelveset is None:
        raise AzureReviewValidationError(
            document_name,
            "$.build.source_tfvc_shelveset",
            "is required for a shelveset target",
        )
    if build.source_tfvc_shelveset.casefold() != reference.casefold():
        raise AzureReviewValidationError(
            document_name,
            "$.build.source_tfvc_shelveset",
            "does not match the TFVC shelveset target",
        )
    if build.source_branch.casefold() != reference.casefold():
        raise AzureReviewValidationError(
            document_name,
            "$.build.source_branch",
            "does not match the TFVC shelveset target",
        )
    if build.reason not in {
        AzureBuildReason.VALIDATE_SHELVESET,
        AzureBuildReason.CHECK_IN_SHELVESET,
    }:
        raise AzureReviewValidationError(
            document_name,
            "$.build.reason",
            "expected a shelveset build reason",
        )


def parse_azure_review_publication(document: Any) -> AzureReviewPublication:
    """Strictly parse an untrusted Azure review publication document."""

    name = "Azure review publication"
    root = _object(
        document,
        "$",
        name,
        required={
            "schema_version",
            "created_at",
            "review",
            "tfvc",
            "build",
            "work_item_ids",
            "artifacts",
        },
    )
    schema_version = _string(
        root["schema_version"],
        "$.schema_version",
        name,
        maximum=16,
    )
    if schema_version != AZURE_REVIEW_PUBLICATION_SCHEMA_VERSION:
        raise AzureReviewValidationError(
            name,
            "$.schema_version",
            f"expected {AZURE_REVIEW_PUBLICATION_SCHEMA_VERSION!r}",
        )
    work_item_values = root["work_item_ids"]
    if not isinstance(work_item_values, list):
        raise AzureReviewValidationError(name, "$.work_item_ids", "expected an array")
    work_item_ids = tuple(
        _integer(value, f"$.work_item_ids[{index}]", name)
        for index, value in enumerate(work_item_values)
    )
    if tuple(sorted(work_item_ids)) != work_item_ids or len(set(work_item_ids)) != len(
        work_item_ids
    ):
        raise AzureReviewValidationError(
            name,
            "$.work_item_ids",
            "expected unique IDs in ascending order",
        )
    artifact_obj = _object(
        root["artifacts"],
        "$.artifacts",
        name,
        required={"review_result", "review_report"},
    )
    publication = AzureReviewPublication(
        schema_version=schema_version,
        created_at=_utc_timestamp(
            root["created_at"],
            "$.created_at",
            name,
            whole_seconds=True,
        ),
        review=_parse_review(root["review"], "$.review", name),
        tfvc=_parse_tfvc(root["tfvc"], "$.tfvc", name),
        build=_parse_build(root["build"], "$.build", name),
        work_item_ids=work_item_ids,
        artifacts=ReviewArtifacts(
            review_result=_parse_artifact(
                artifact_obj["review_result"],
                "$.artifacts.review_result",
                name,
                expected_media_type=_REVIEW_RESULT_MEDIA_TYPE,
                maximum_bytes=MAX_REVIEW_RESULT_BYTES,
            ),
            review_report=_parse_artifact(
                artifact_obj["review_report"],
                "$.artifacts.review_report",
                name,
                expected_media_type=_REVIEW_REPORT_MEDIA_TYPE,
                maximum_bytes=MAX_REVIEW_REPORT_BYTES,
            ),
        ),
    )
    review_gap_seconds = (
        _timestamp_value(publication.created_at) - _timestamp_value(publication.review.reviewed_at)
    ).total_seconds()
    if review_gap_seconds < -1 or review_gap_seconds > MAX_REVIEW_TO_PUBLICATION_SECONDS:
        raise AzureReviewValidationError(
            name,
            "$.created_at",
            (
                "must be within one second before and "
                f"{MAX_REVIEW_TO_PUBLICATION_SECONDS} seconds after review.reviewed_at"
            ),
        )
    _validate_target_build_consistency(publication.tfvc, publication.build, document_name=name)
    return publication


def parse_azure_review_publication_bytes(raw_bytes: bytes) -> AzureReviewPublication:
    """Parse a bounded Azure publication from its exact UTF-8 bytes."""

    return parse_azure_review_publication(
        _parse_json_bytes(
            raw_bytes,
            description="Azure review publication",
            maximum=MAX_AZURE_PUBLICATION_BYTES,
        )
    )


def create_azure_review_publication(
    review_result_bytes: bytes,
    review_report_bytes: bytes,
    *,
    tfvc: TfvcAssociation,
    build: AzureBuildContext,
    work_item_ids: Sequence[int],
    created_at: str,
) -> AzureReviewPublication:
    """Bind exact gate artifacts to the current Azure TFVC build."""

    review = parse_review_result_bytes(review_result_bytes)
    _validate_report(review_report_bytes, review)
    _validate_target_build_consistency(tfvc, build, document_name="Azure review publication")
    invalid_work_item = any(
        isinstance(value, bool) or not isinstance(value, int) or value < 1
        for value in work_item_ids
    )
    if invalid_work_item or len(set(work_item_ids)) != len(work_item_ids):
        raise AzureReviewValidationError(
            "Azure review publication",
            "$.work_item_ids",
            "expected unique positive integer IDs",
        )
    normalized_work_items = tuple(sorted(work_item_ids))
    publication = AzureReviewPublication(
        schema_version=AZURE_REVIEW_PUBLICATION_SCHEMA_VERSION,
        created_at=_utc_timestamp(
            created_at,
            "$.created_at",
            "Azure review publication",
            whole_seconds=True,
        ),
        review=review,
        tfvc=tfvc,
        build=build,
        work_item_ids=normalized_work_items,
        artifacts=ReviewArtifacts(
            review_result=_artifact_integrity(
                review_result_bytes,
                _REVIEW_RESULT_MEDIA_TYPE,
            ),
            review_report=_artifact_integrity(
                review_report_bytes,
                _REVIEW_REPORT_MEDIA_TYPE,
            ),
        ),
    )
    return parse_azure_review_publication(to_jsonable(publication))


def render_azure_review_publication(publication: AzureReviewPublication) -> str:
    """Render a stable Azure review publication document."""

    validated = parse_azure_review_publication(to_jsonable(publication))
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


def _verify_artifact(
    raw_bytes: bytes,
    expected: ArtifactIntegrity,
    *,
    role: str,
    maximum_bytes: int,
) -> None:
    if len(raw_bytes) > maximum_bytes:
        raise AzureReviewVerificationError(
            "artifact_too_large",
            f"{role} exceeds the {maximum_bytes}-byte verification limit",
        )
    if len(raw_bytes) != expected.byte_count:
        raise AzureReviewVerificationError(
            "artifact_size_mismatch",
            f"{role} byte count does not match the publication",
        )
    if hashlib.sha256(raw_bytes).hexdigest() != expected.sha256:
        raise AzureReviewVerificationError(
            "artifact_digest_mismatch",
            f"{role} SHA-256 does not match the publication",
        )


def verify_azure_review_publication(
    publication_bytes: bytes,
    review_result_bytes: bytes,
    review_report_bytes: bytes,
    *,
    expected_tfvc: TfvcAssociation,
    expected_build: AzureBuildContext,
    verified_at: str,
    maximum_age_seconds: int = DEFAULT_MAX_PUBLICATION_AGE_SECONDS,
) -> AzureReviewVerification:
    """Recheck exact artifacts and current Azure build identity before approval."""

    if (
        isinstance(maximum_age_seconds, bool)
        or not isinstance(maximum_age_seconds, int)
        or not 1 <= maximum_age_seconds <= MAX_PUBLICATION_AGE_SECONDS
    ):
        raise AzureReviewVerificationError(
            "maximum_age_invalid",
            f"maximum age must be from 1 to {MAX_PUBLICATION_AGE_SECONDS} seconds",
        )
    try:
        publication = parse_azure_review_publication_bytes(publication_bytes)
        checked_at = _utc_timestamp(
            verified_at,
            "$.verified_at",
            "Azure review verification",
            whole_seconds=True,
        )
    except AzureReviewValidationError as exc:
        raise AzureReviewVerificationError("publication_invalid", str(exc)) from exc

    if publication.tfvc != expected_tfvc:
        raise AzureReviewVerificationError(
            "tfvc_target_mismatch",
            "publication target does not match the current TFVC build",
        )
    if publication.build != expected_build:
        raise AzureReviewVerificationError(
            "build_context_mismatch",
            "publication build identity does not match the current Azure build",
        )

    created = _timestamp_value(publication.created_at)
    checked = _timestamp_value(checked_at)
    if checked < created:
        raise AzureReviewVerificationError(
            "publication_from_future",
            "publication creation time is later than verification time",
        )
    age_seconds = int((checked - created).total_seconds())
    if age_seconds > maximum_age_seconds:
        raise AzureReviewVerificationError(
            "publication_stale",
            "publication is older than the permitted pre-approval window",
        )

    _verify_artifact(
        review_result_bytes,
        publication.artifacts.review_result,
        role="review result",
        maximum_bytes=MAX_REVIEW_RESULT_BYTES,
    )
    _verify_artifact(
        review_report_bytes,
        publication.artifacts.review_report,
        role="review report",
        maximum_bytes=MAX_REVIEW_REPORT_BYTES,
    )
    try:
        current_review = parse_review_result_bytes(review_result_bytes)
        _validate_report(review_report_bytes, current_review)
    except (AzureReviewValidationError, InputDocumentError) as exc:
        raise AzureReviewVerificationError("review_artifact_invalid", str(exc)) from exc
    if current_review != publication.review:
        raise AzureReviewVerificationError(
            "review_binding_mismatch",
            "review-result identity does not match the publication",
        )

    return AzureReviewVerification(
        schema_version=AZURE_REVIEW_VERIFICATION_SCHEMA_VERSION,
        status="verified",
        verified_at=checked_at,
        maximum_age_seconds=maximum_age_seconds,
        publication_age_seconds=age_seconds,
        publication=PublicationSubject(
            media_type=_PUBLICATION_MEDIA_TYPE,
            sha256=hashlib.sha256(publication_bytes).hexdigest(),
            byte_count=len(publication_bytes),
        ),
        review=publication.review,
        tfvc=publication.tfvc,
        build_id=publication.build.build_id,
        artifacts=publication.artifacts,
    )


def parse_azure_review_verification(document: Any) -> AzureReviewVerification:
    """Strictly parse an untrusted successful publication-verification receipt."""

    name = "Azure review verification"
    root = _object(
        document,
        "$",
        name,
        required={
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
        },
    )
    schema_version = _string(
        root["schema_version"],
        "$.schema_version",
        name,
        maximum=16,
    )
    if schema_version != AZURE_REVIEW_VERIFICATION_SCHEMA_VERSION:
        raise AzureReviewValidationError(
            name,
            "$.schema_version",
            f"expected {AZURE_REVIEW_VERIFICATION_SCHEMA_VERSION!r}",
        )
    status = _string(root["status"], "$.status", name, maximum=16)
    if status != "verified":
        raise AzureReviewValidationError(name, "$.status", "expected 'verified'")
    maximum_age = _integer(
        root["maximum_age_seconds"],
        "$.maximum_age_seconds",
        name,
    )
    if maximum_age > MAX_PUBLICATION_AGE_SECONDS:
        raise AzureReviewValidationError(
            name,
            "$.maximum_age_seconds",
            f"expected at most {MAX_PUBLICATION_AGE_SECONDS}",
        )
    publication_age = _integer(
        root["publication_age_seconds"],
        "$.publication_age_seconds",
        name,
        minimum=0,
    )
    if publication_age > maximum_age:
        raise AzureReviewValidationError(
            name,
            "$.publication_age_seconds",
            "cannot exceed maximum_age_seconds",
        )
    publication_obj = _object(
        root["publication"],
        "$.publication",
        name,
        required={"media_type", "sha256", "byte_count"},
    )
    media_type = _string(
        publication_obj["media_type"],
        "$.publication.media_type",
        name,
        maximum=255,
    )
    if media_type != _PUBLICATION_MEDIA_TYPE:
        raise AzureReviewValidationError(
            name,
            "$.publication.media_type",
            f"expected {_PUBLICATION_MEDIA_TYPE!r}",
        )
    publication_byte_count = _integer(
        publication_obj["byte_count"],
        "$.publication.byte_count",
        name,
    )
    if publication_byte_count > MAX_AZURE_PUBLICATION_BYTES:
        raise AzureReviewValidationError(
            name,
            "$.publication.byte_count",
            f"expected at most {MAX_AZURE_PUBLICATION_BYTES}",
        )
    artifact_obj = _object(
        root["artifacts"],
        "$.artifacts",
        name,
        required={"review_result", "review_report"},
    )
    return AzureReviewVerification(
        schema_version=schema_version,
        status=status,
        verified_at=_utc_timestamp(
            root["verified_at"],
            "$.verified_at",
            name,
            whole_seconds=True,
        ),
        maximum_age_seconds=maximum_age,
        publication_age_seconds=publication_age,
        publication=PublicationSubject(
            media_type=media_type,
            sha256=_string(
                publication_obj["sha256"],
                "$.publication.sha256",
                name,
                maximum=64,
                pattern=_SHA256_PATTERN,
            ),
            byte_count=publication_byte_count,
        ),
        review=_parse_review(root["review"], "$.review", name),
        tfvc=_parse_tfvc(root["tfvc"], "$.tfvc", name),
        build_id=_integer(root["build_id"], "$.build_id", name),
        artifacts=ReviewArtifacts(
            review_result=_parse_artifact(
                artifact_obj["review_result"],
                "$.artifacts.review_result",
                name,
                expected_media_type=_REVIEW_RESULT_MEDIA_TYPE,
                maximum_bytes=MAX_REVIEW_RESULT_BYTES,
            ),
            review_report=_parse_artifact(
                artifact_obj["review_report"],
                "$.artifacts.review_report",
                name,
                expected_media_type=_REVIEW_REPORT_MEDIA_TYPE,
                maximum_bytes=MAX_REVIEW_REPORT_BYTES,
            ),
        ),
    )


def parse_azure_review_verification_bytes(raw_bytes: bytes) -> AzureReviewVerification:
    """Strictly parse bounded exact Azure review-verification bytes."""

    return parse_azure_review_verification(
        _parse_json_bytes(
            raw_bytes,
            description="Azure review verification",
            maximum=MAX_AZURE_VERIFICATION_BYTES,
        )
    )


def render_azure_review_verification(verification: AzureReviewVerification) -> str:
    """Render a stable successful verification receipt."""

    validated = parse_azure_review_verification(to_jsonable(verification))
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


def _markdown_text(value: str) -> str:
    escaped = html.escape(value, quote=True)
    replacements = {
        "\\": "&#92;",
        "`": "&#96;",
        "|": "&#124;",
        "[": "&#91;",
        "]": "&#93;",
        "(": "&#40;",
        ")": "&#41;",
    }
    for character, entity in replacements.items():
        escaped = escaped.replace(character, entity)
    return escaped


def _target_label(target: TfvcTarget) -> str:
    if isinstance(target, TfvcChangesetTarget):
        return f"changeset {target.changeset_id}"
    return f"shelveset {target.shelveset_name};{target.owner}"


def render_azure_build_summary(
    publication_bytes: bytes,
    verification: AzureReviewVerification,
) -> str:
    """Render the verified decision details for an Azure build summary."""

    publication = parse_azure_review_publication_bytes(publication_bytes)
    if (
        len(publication_bytes) != verification.publication.byte_count
        or hashlib.sha256(publication_bytes).hexdigest() != verification.publication.sha256
        or verification.review != publication.review
        or verification.tfvc != publication.tfvc
        or verification.build_id != publication.build.build_id
        or verification.artifacts != publication.artifacts
    ):
        raise ValueError("verification receipt does not correspond to the publication")

    build_url = (
        f"{publication.build.collection_uri}"
        f"{quote(publication.build.project_name, safe='')}/_build/results"
        f"?buildId={publication.build.build_id}"
    )
    work_items = "None recorded"
    if publication.work_item_ids:
        links = [
            (
                f"[#{work_item_id}]("
                f"{publication.build.collection_uri}"
                f"{quote(publication.build.project_name, safe='')}"
                f"/_workitems/edit/{work_item_id})"
            )
            for work_item_id in publication.work_item_ids
        ]
        work_items = ", ".join(links)

    review = publication.review
    target = _markdown_text(_target_label(publication.tfvc.target))
    lines = [
        "# Causure Azure review",
        "",
        (
            f"> **{review.decision.value.upper()}** — exact gate artifacts were "
            f"rechecked for this Azure build."
        ),
        "",
        "## Decision and association",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Case | `{review.case_id}` |",
        f"| Decision | **{review.decision.value.upper()}** |",
        f"| Recommended action | `{review.recommended_action.value}` |",
        f"| Policy | {_markdown_text(review.policy_name)} |",
        f"| Engine | {_markdown_text(review.engine_version)} |",
        f"| TFVC target | {target} |",
        f"| TFVC path | {_markdown_text(publication.tfvc.server_path)} |",
        f"| Azure build | [{_markdown_text(publication.build.build_number)}]({build_url}) |",
        f"| Work items | {work_items} |",
        "",
        "## Exact artifact integrity",
        "",
        "| Artifact | Bytes | SHA-256 |",
        "| --- | ---: | --- |",
        (
            f"| Review result (JSON) | "
            f"{publication.artifacts.review_result.byte_count} | "
            f"`{publication.artifacts.review_result.sha256}` |"
        ),
        (
            f"| Review report (Markdown) | "
            f"{publication.artifacts.review_report.byte_count} | "
            f"`{publication.artifacts.review_report.sha256}` |"
        ),
        (
            f"| Publication manifest | {verification.publication.byte_count} | "
            f"`{verification.publication.sha256}` |"
        ),
        "",
        "## Verification boundary",
        "",
        f"- Status: **{verification.status.upper()}**",
        f"- Rechecked at: `{verification.verified_at}`",
        f"- Publication age: {verification.publication_age_seconds} second(s)",
        (
            "- This receipt verifies exact bytes and current build/TFVC identity. "
            "It does not authenticate an approver or grant a policy exception."
        ),
        "",
    ]
    return "\n".join(lines)
