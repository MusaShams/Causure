"""Closed WSGI JSON boundary for the trusted-identity Team application service."""

from __future__ import annotations

import base64
import binascii
import json
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from causure.azure_devops import (
    MAX_AZURE_PUBLICATION_BYTES,
    MAX_AZURE_VERIFICATION_BYTES,
)
from causure.canary import MAX_CANARY_RESULT_BYTES
from causure.constants import (
    PACKAGE_VERSION,
    TeamAction,
    TeamAuditOutcome,
    TeamInvestigationPriority,
    TeamInvestigationResolution,
    TeamInvestigationStatus,
    TeamResourceType,
)
from causure.io import InputDocumentError, parse_json_text
from causure.models import to_jsonable
from causure.team_application import (
    AuthenticatedTeamIdentity,
    TeamAccessDeniedError,
    TeamApplicationError,
    TeamApplicationService,
    TeamCasePublication,
    TeamIdentityError,
    TeamInvestigationMutation,
    TeamRecordedAction,
)
from causure.team_cases import (
    MAX_TEAM_CASE_APPROVAL_VERIFICATION_BYTES,
    MAX_TEAM_CASE_CHANGE_BYTES,
    MAX_TEAM_CASE_REVIEW_BYTES,
)
from causure.team_dashboard import (
    TEAM_DASHBOARD_CSS,
    render_team_case_dashboard,
    render_team_case_detail,
    render_team_dashboard,
    render_team_investigation_dashboard,
    render_team_investigation_detail,
)
from causure.team_investigations import MAX_TEAM_INVESTIGATION_SOURCE_BYTES
from causure.team_service import (
    MAX_TEAM_AUDIT_PAYLOAD_BYTES,
    MAX_TEAM_EXPORT_EVENTS,
    TeamPrincipal,
    TeamValidationError,
    render_team_audit_export,
)
from causure.team_store import (
    MAX_TEAM_EVENT_PAGE_SIZE,
    MAX_TEAM_INVESTIGATION_PAGE_SIZE,
    TeamStoreConflictError,
    TeamStoreError,
)

TEAM_IDENTITY_ENVIRON_KEY = "causure.authenticated_team_identity"
TEAM_REQUEST_INTEGRITY_ENVIRON_KEY = "causure.request_integrity_verified"
MAX_TEAM_HTTP_REQUEST_BYTES = 24 * 1024 * 1024

_EVENT_PATH_PATTERN = re.compile(r"^/v1/team/events/([1-9][0-9]{0,9})$")
_CASE_API_PATH_PATTERN = re.compile(r"^/v1/team/cases/([A-Za-z0-9][A-Za-z0-9._-]{2,127})$")
_CASE_HTML_PATH_PATTERN = re.compile(r"^/team/cases/([A-Za-z0-9][A-Za-z0-9._-]{2,127})$")
_INVESTIGATION_API_PATH_PATTERN = re.compile(
    r"^/v1/team/investigations/([A-Za-z0-9][A-Za-z0-9._-]{2,127})$"
)
_INVESTIGATION_OBSERVATIONS_PATH_PATTERN = re.compile(
    r"^/v1/team/investigations/([A-Za-z0-9][A-Za-z0-9._-]{2,127})/observations$"
)
_INVESTIGATION_TRANSITION_PATH_PATTERN = re.compile(
    r"^/v1/team/investigations/([A-Za-z0-9][A-Za-z0-9._-]{2,127})/transition$"
)
_INVESTIGATION_HTML_PATH_PATTERN = re.compile(
    r"^/team/investigations/([A-Za-z0-9][A-Za-z0-9._-]{2,127})$"
)
_CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_CLUSTER_ID_PATTERN = re.compile(r"^trace-[a-f0-9]{64}$")
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_CONTENT_LENGTH_PATTERN = re.compile(r"^(0|[1-9][0-9]*)$")
_QUERY_INTEGER_PATTERN = re.compile(r"^[1-9][0-9]{0,5}$")
_DEFAULT_EVENT_PAGE_SIZE = 50
_DEFAULT_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"
)
_DASHBOARD_CONTENT_SECURITY_POLICY = (
    "default-src 'none'; style-src 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'none'"
)
_STATUS_REASONS = {
    200: "OK",
    201: "Created",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    411: "Length Required",
    413: "Content Too Large",
    415: "Unsupported Media Type",
    500: "Internal Server Error",
    503: "Service Unavailable",
}
_SERVER_APPLICATION_ERROR_CODES = frozenset(
    {
        "generated_identifier_invalid",
        "generated_timestamp_invalid",
        "event_snapshot_invalid",
        "case_snapshot_invalid",
        "investigation_snapshot_invalid",
        "stored_export_mismatch",
    }
)
_StartResponse = Callable[[str, list[tuple[str, str]]], Any]


@dataclass(frozen=True, slots=True)
class _ActionRequest:
    action: TeamAction
    resource_type: TeamResourceType
    resource_id: str
    outcome: TeamAuditOutcome
    payload_media_type: str
    payload_bytes: bytes
    expected_head_sha256: str | None
    retention_class_id: str | None


@dataclass(frozen=True, slots=True)
class _CasePublicationRequest:
    case_id: str
    change_case_bytes: bytes
    review_result_bytes: bytes
    azure_publication_bytes: bytes | None
    azure_verification_bytes: bytes | None
    approval_verification_bytes: bytes | None
    canary_result_bytes: bytes | None
    expected_head_sha256: str | None
    retention_class_id: str | None


@dataclass(frozen=True, slots=True)
class _InvestigationOpenRequest:
    investigation_id: str
    fixture_bytes: bytes
    cluster_id: str
    title: str
    priority: TeamInvestigationPriority
    expected_revision: int
    expected_head_sha256: str | None
    retention_class_id: str | None


@dataclass(frozen=True, slots=True)
class _InvestigationAttachRequest:
    fixture_bytes: bytes
    cluster_id: str
    expected_revision: int
    expected_head_sha256: str | None
    retention_class_id: str | None


@dataclass(frozen=True, slots=True)
class _InvestigationTransitionRequest:
    title: str
    status: TeamInvestigationStatus
    priority: TeamInvestigationPriority
    assigned_to: TeamPrincipal | None
    expected_revision: int
    expected_head_sha256: str | None
    resolution: TeamInvestigationResolution | None
    linked_case_id: str | None
    duplicate_of: str | None
    retention_class_id: str | None


class _HttpRequestError(ValueError):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.status = status
        self.code = code
        self.message = message
        self.headers = headers
        super().__init__(message)


def _closed_object(
    value: Any,
    *,
    path: str,
    required: set[str],
    optional: set[str] | None = None,
) -> Mapping[str, Any]:
    if not isinstance(value, dict):
        raise _HttpRequestError(400, "request_invalid", f"{path} must be an object")
    allowed = required | (optional or set())
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - allowed)
    if missing:
        raise _HttpRequestError(
            400,
            "request_invalid",
            f"{path} is missing required field(s)",
        )
    if unknown:
        raise _HttpRequestError(
            400,
            "request_invalid",
            f"{path} contains unknown field(s)",
        )
    return value


def _request_string(
    value: Any,
    *,
    path: str,
    maximum: int = 255,
) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise _HttpRequestError(
            400,
            "request_invalid",
            f"{path} must be a non-empty bounded string without control characters",
        )
    return value


def _parse_content_type(environ: Mapping[str, Any]) -> None:
    raw_value = environ.get("CONTENT_TYPE")
    if not isinstance(raw_value, str) or not raw_value:
        raise _HttpRequestError(
            415,
            "content_type_required",
            "Content-Type must be application/json",
        )
    segments = [segment.strip() for segment in raw_value.split(";")]
    if segments[0].lower() != "application/json":
        raise _HttpRequestError(
            415,
            "content_type_unsupported",
            "Content-Type must be application/json",
        )
    for parameter in segments[1:]:
        if parameter.lower() not in {"charset=utf-8", 'charset="utf-8"'}:
            raise _HttpRequestError(
                415,
                "content_type_unsupported",
                "only the UTF-8 application/json media type is supported",
            )


def _read_json_request(environ: Mapping[str, Any]) -> Mapping[str, Any]:
    _parse_content_type(environ)
    raw_length = environ.get("CONTENT_LENGTH")
    if not isinstance(raw_length, str) or not raw_length:
        raise _HttpRequestError(
            411,
            "content_length_required",
            "Content-Length is required",
        )
    if len(raw_length) > 20:
        raise _HttpRequestError(
            400,
            "content_length_invalid",
            "Content-Length must be a bounded non-negative decimal integer",
        )
    if _CONTENT_LENGTH_PATTERN.fullmatch(raw_length) is None:
        raise _HttpRequestError(
            400,
            "content_length_invalid",
            "Content-Length must be a non-negative decimal integer",
        )
    length = int(raw_length, 10)
    if length > MAX_TEAM_HTTP_REQUEST_BYTES:
        raise _HttpRequestError(
            413,
            "request_too_large",
            f"request body exceeds {MAX_TEAM_HTTP_REQUEST_BYTES} bytes",
        )
    if length == 0:
        raise _HttpRequestError(400, "request_empty", "request body must contain JSON")
    stream = environ.get("wsgi.input")
    if stream is None or not hasattr(stream, "read"):
        raise _HttpRequestError(
            500,
            "wsgi_input_missing",
            "the WSGI server input integration is unavailable",
        )
    raw_bytes = stream.read(length)
    if not isinstance(raw_bytes, bytes) or len(raw_bytes) != length:
        raise _HttpRequestError(
            400,
            "request_truncated",
            "request body did not match Content-Length",
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise _HttpRequestError(
            400,
            "request_encoding_invalid",
            "request body must be UTF-8 JSON",
        ) from exc
    try:
        document = parse_json_text(
            text,
            source="Team HTTP request",
            max_bytes=MAX_TEAM_HTTP_REQUEST_BYTES,
        )
    except InputDocumentError as exc:
        raise _HttpRequestError(
            400,
            "request_json_invalid",
            "request body must be valid JSON without duplicate keys",
        ) from exc
    if not isinstance(document, dict):
        raise _HttpRequestError(400, "request_invalid", "$ must be an object")
    return document


def _decode_exact_base64url(
    value: Any,
    *,
    path: str,
    maximum_bytes: int,
    role: str,
) -> bytes:
    encoded = _request_string(
        value,
        path=path,
        maximum=((maximum_bytes + 2) // 3) * 4,
    )
    if _BASE64URL_PATTERN.fullmatch(encoded) is None:
        raise _HttpRequestError(
            400,
            "payload_encoding_invalid",
            f"{path} must use unpadded base64url",
        )
    padding = "=" * (-len(encoded) % 4)
    try:
        raw_bytes = base64.b64decode(
            encoded + padding,
            altchars=b"-_",
            validate=True,
        )
    except (binascii.Error, ValueError) as exc:
        raise _HttpRequestError(
            400,
            "payload_encoding_invalid",
            f"{path} is not valid base64url",
        ) from exc
    canonical = base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")
    if canonical != encoded:
        raise _HttpRequestError(
            400,
            "payload_encoding_invalid",
            f"{path} is not canonical unpadded base64url",
        )
    if not 1 <= len(raw_bytes) <= maximum_bytes:
        raise _HttpRequestError(
            400,
            "payload_size_invalid",
            f"decoded {role} must contain from 1 to {maximum_bytes} bytes",
        )
    return raw_bytes


def _decode_payload(value: Any) -> bytes:
    return _decode_exact_base64url(
        value,
        path="$.payload.base64url",
        maximum_bytes=MAX_TEAM_AUDIT_PAYLOAD_BYTES,
        role="payload",
    )


def _parse_action_request(document: Mapping[str, Any]) -> _ActionRequest:
    root = _closed_object(
        document,
        path="$",
        required={
            "action",
            "resource",
            "outcome",
            "payload",
            "expected_head_sha256",
        },
        optional={"retention_class_id"},
    )
    resource = _closed_object(
        root["resource"],
        path="$.resource",
        required={"type", "id"},
    )
    payload = _closed_object(
        root["payload"],
        path="$.payload",
        required={"media_type", "base64url"},
    )
    try:
        action = TeamAction(_request_string(root["action"], path="$.action", maximum=64))
    except ValueError as exc:
        raise _HttpRequestError(400, "action_invalid", "$.action is not supported") from exc
    try:
        resource_type = TeamResourceType(
            _request_string(resource["type"], path="$.resource.type", maximum=64)
        )
    except ValueError as exc:
        raise _HttpRequestError(
            400,
            "resource_type_invalid",
            "$.resource.type is not supported",
        ) from exc
    try:
        outcome = TeamAuditOutcome(_request_string(root["outcome"], path="$.outcome", maximum=16))
    except ValueError as exc:
        raise _HttpRequestError(
            400,
            "outcome_invalid",
            "$.outcome must be succeeded or failed",
        ) from exc
    if outcome is TeamAuditOutcome.DENIED:
        raise _HttpRequestError(
            400,
            "outcome_invalid",
            "$.outcome must be succeeded or failed; the service derives denied",
        )
    expected_head = root["expected_head_sha256"]
    if expected_head is not None and (
        not isinstance(expected_head, str) or _SHA256_PATTERN.fullmatch(expected_head) is None
    ):
        raise _HttpRequestError(
            400,
            "expected_head_invalid",
            "$.expected_head_sha256 must be null or a lowercase SHA-256 digest",
        )
    retention_class_id = root.get("retention_class_id")
    if retention_class_id is not None:
        retention_class_id = _request_string(
            retention_class_id,
            path="$.retention_class_id",
            maximum=128,
        )
    return _ActionRequest(
        action=action,
        resource_type=resource_type,
        resource_id=_request_string(resource["id"], path="$.resource.id", maximum=128),
        outcome=outcome,
        payload_media_type=_request_string(
            payload["media_type"],
            path="$.payload.media_type",
            maximum=255,
        ),
        payload_bytes=_decode_payload(payload["base64url"]),
        expected_head_sha256=expected_head,
        retention_class_id=retention_class_id,
    )


def _case_artifact_bytes(
    root: Mapping[str, Any],
    field_name: str,
    *,
    maximum_bytes: int,
) -> bytes:
    artifact = _closed_object(
        root[field_name],
        path=f"$.{field_name}",
        required={"base64url"},
    )
    return _decode_exact_base64url(
        artifact["base64url"],
        path=f"$.{field_name}.base64url",
        maximum_bytes=maximum_bytes,
        role=field_name.replace("_", " "),
    )


def _parse_case_publication_request(
    document: Mapping[str, Any],
) -> _CasePublicationRequest:
    root = _closed_object(
        document,
        path="$",
        required={
            "case_id",
            "change_case",
            "review_result",
            "expected_head_sha256",
        },
        optional={
            "azure_publication",
            "azure_verification",
            "approval_verification",
            "canary_result",
            "retention_class_id",
        },
    )
    case_id = _request_string(root["case_id"], path="$.case_id", maximum=128)
    if _CASE_ID_PATTERN.fullmatch(case_id) is None:
        raise _HttpRequestError(
            400,
            "case_id_invalid",
            "$.case_id must use the closed 3-128 character case identifier format",
        )
    publication_present = "azure_publication" in root
    verification_present = "azure_verification" in root
    if publication_present != verification_present:
        raise _HttpRequestError(
            400,
            "case_chain_invalid",
            "Azure publication and verification artifacts must be supplied together",
        )
    if "approval_verification" in root and not publication_present:
        raise _HttpRequestError(
            400,
            "case_chain_invalid",
            "approval verification requires Azure publication and verification artifacts",
        )
    expected_head = root["expected_head_sha256"]
    if expected_head is not None and (
        not isinstance(expected_head, str) or _SHA256_PATTERN.fullmatch(expected_head) is None
    ):
        raise _HttpRequestError(
            400,
            "expected_head_invalid",
            "$.expected_head_sha256 must be null or a lowercase SHA-256 digest",
        )
    retention_class_id = root.get("retention_class_id")
    if retention_class_id is not None:
        retention_class_id = _request_string(
            retention_class_id,
            path="$.retention_class_id",
            maximum=128,
        )
    return _CasePublicationRequest(
        case_id=case_id,
        change_case_bytes=_case_artifact_bytes(
            root, "change_case", maximum_bytes=MAX_TEAM_CASE_CHANGE_BYTES
        ),
        review_result_bytes=_case_artifact_bytes(
            root, "review_result", maximum_bytes=MAX_TEAM_CASE_REVIEW_BYTES
        ),
        azure_publication_bytes=(
            _case_artifact_bytes(
                root,
                "azure_publication",
                maximum_bytes=MAX_AZURE_PUBLICATION_BYTES,
            )
            if publication_present
            else None
        ),
        azure_verification_bytes=(
            _case_artifact_bytes(
                root,
                "azure_verification",
                maximum_bytes=MAX_AZURE_VERIFICATION_BYTES,
            )
            if verification_present
            else None
        ),
        approval_verification_bytes=(
            _case_artifact_bytes(
                root,
                "approval_verification",
                maximum_bytes=MAX_TEAM_CASE_APPROVAL_VERIFICATION_BYTES,
            )
            if "approval_verification" in root
            else None
        ),
        canary_result_bytes=(
            _case_artifact_bytes(
                root,
                "canary_result",
                maximum_bytes=MAX_CANARY_RESULT_BYTES,
            )
            if "canary_result" in root
            else None
        ),
        expected_head_sha256=expected_head,
        retention_class_id=retention_class_id,
    )


def _expected_head(value: Any) -> str | None:
    if value is not None and (
        not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None
    ):
        raise _HttpRequestError(
            400,
            "expected_head_invalid",
            "$.expected_head_sha256 must be null or a lowercase SHA-256 digest",
        )
    return value


def _expected_revision(value: Any, *, minimum: int) -> int:
    if type(value) is not int or not minimum <= value < 10_000:
        raise _HttpRequestError(
            400,
            "expected_revision_invalid",
            f"$.expected_revision must be an integer from {minimum} through 9999",
        )
    return value


def _retention_class(root: Mapping[str, Any]) -> str | None:
    value = root.get("retention_class_id")
    if value is None:
        return None
    return _request_string(value, path="$.retention_class_id", maximum=128)


def _fixture_bytes(root: Mapping[str, Any]) -> bytes:
    fixture = _closed_object(
        root["fixture"],
        path="$.fixture",
        required={"base64url"},
    )
    return _decode_exact_base64url(
        fixture["base64url"],
        path="$.fixture.base64url",
        maximum_bytes=MAX_TEAM_INVESTIGATION_SOURCE_BYTES,
        role="investigation fixture",
    )


def _cluster_id(value: Any) -> str:
    result = _request_string(value, path="$.cluster_id", maximum=70)
    if _CLUSTER_ID_PATTERN.fullmatch(result) is None:
        raise _HttpRequestError(
            400,
            "cluster_id_invalid",
            "$.cluster_id must be a trace candidate cluster id",
        )
    return result


def _investigation_id(value: Any, *, path: str = "$.investigation_id") -> str:
    result = _request_string(value, path=path, maximum=128)
    if _CASE_ID_PATTERN.fullmatch(result) is None:
        raise _HttpRequestError(
            400,
            "investigation_id_invalid",
            f"{path} must use the closed 3-128 character identifier format",
        )
    return result


def _parse_investigation_open_request(
    document: Mapping[str, Any],
) -> _InvestigationOpenRequest:
    root = _closed_object(
        document,
        path="$",
        required={
            "investigation_id",
            "fixture",
            "cluster_id",
            "title",
            "priority",
            "expected_revision",
            "expected_head_sha256",
        },
        optional={"retention_class_id"},
    )
    try:
        priority = TeamInvestigationPriority(
            _request_string(root["priority"], path="$.priority", maximum=16)
        )
    except ValueError as exc:
        raise _HttpRequestError(
            400,
            "investigation_priority_invalid",
            "$.priority is not supported",
        ) from exc
    expected_revision = _expected_revision(root["expected_revision"], minimum=0)
    if expected_revision != 0:
        raise _HttpRequestError(
            400,
            "expected_revision_invalid",
            "$.expected_revision must be 0 when opening an investigation",
        )
    return _InvestigationOpenRequest(
        investigation_id=_investigation_id(root["investigation_id"]),
        fixture_bytes=_fixture_bytes(root),
        cluster_id=_cluster_id(root["cluster_id"]),
        title=_request_string(root["title"], path="$.title", maximum=256),
        priority=priority,
        expected_revision=expected_revision,
        expected_head_sha256=_expected_head(root["expected_head_sha256"]),
        retention_class_id=_retention_class(root),
    )


def _parse_investigation_attach_request(
    document: Mapping[str, Any],
) -> _InvestigationAttachRequest:
    root = _closed_object(
        document,
        path="$",
        required={
            "fixture",
            "cluster_id",
            "expected_revision",
            "expected_head_sha256",
        },
        optional={"retention_class_id"},
    )
    return _InvestigationAttachRequest(
        fixture_bytes=_fixture_bytes(root),
        cluster_id=_cluster_id(root["cluster_id"]),
        expected_revision=_expected_revision(root["expected_revision"], minimum=1),
        expected_head_sha256=_expected_head(root["expected_head_sha256"]),
        retention_class_id=_retention_class(root),
    )


def _optional_investigation_id(value: Any, *, path: str) -> str | None:
    if value is None:
        return None
    return _investigation_id(value, path=path)


def _parse_assignee(value: Any) -> TeamPrincipal | None:
    if value is None:
        return None
    principal = _closed_object(
        value,
        path="$.assigned_to",
        required={"identity_provider", "subject_id"},
    )
    return TeamPrincipal(
        identity_provider=_request_string(
            principal["identity_provider"],
            path="$.assigned_to.identity_provider",
            maximum=128,
        ),
        subject_id=_request_string(
            principal["subject_id"],
            path="$.assigned_to.subject_id",
            maximum=128,
        ),
    )


def _parse_investigation_transition_request(
    document: Mapping[str, Any],
) -> _InvestigationTransitionRequest:
    root = _closed_object(
        document,
        path="$",
        required={
            "title",
            "status",
            "priority",
            "assigned_to",
            "expected_revision",
            "expected_head_sha256",
        },
        optional={
            "resolution",
            "linked_case_id",
            "duplicate_of",
            "retention_class_id",
        },
    )
    try:
        status = TeamInvestigationStatus(
            _request_string(root["status"], path="$.status", maximum=16)
        )
    except ValueError as exc:
        raise _HttpRequestError(
            400,
            "investigation_status_invalid",
            "$.status is not supported",
        ) from exc
    try:
        priority = TeamInvestigationPriority(
            _request_string(root["priority"], path="$.priority", maximum=16)
        )
    except ValueError as exc:
        raise _HttpRequestError(
            400,
            "investigation_priority_invalid",
            "$.priority is not supported",
        ) from exc
    raw_resolution = root.get("resolution")
    if raw_resolution is None:
        resolution = None
    else:
        try:
            resolution = TeamInvestigationResolution(
                _request_string(raw_resolution, path="$.resolution", maximum=32)
            )
        except ValueError as exc:
            raise _HttpRequestError(
                400,
                "investigation_resolution_invalid",
                "$.resolution is not supported",
            ) from exc
    return _InvestigationTransitionRequest(
        title=_request_string(root["title"], path="$.title", maximum=256),
        status=status,
        priority=priority,
        assigned_to=_parse_assignee(root["assigned_to"]),
        expected_revision=_expected_revision(root["expected_revision"], minimum=1),
        expected_head_sha256=_expected_head(root["expected_head_sha256"]),
        resolution=resolution,
        linked_case_id=_optional_investigation_id(
            root.get("linked_case_id"),
            path="$.linked_case_id",
        ),
        duplicate_of=_optional_investigation_id(
            root.get("duplicate_of"),
            path="$.duplicate_of",
        ),
        retention_class_id=_retention_class(root),
    )


def _event_page_query(environ: Mapping[str, Any]) -> tuple[int, int | None]:
    raw_query = environ.get("QUERY_STRING", "")
    if not isinstance(raw_query, str) or len(raw_query) > 128:
        raise _HttpRequestError(
            400,
            "query_invalid",
            "event pagination query is invalid",
        )
    values: dict[str, int] = {}
    if raw_query:
        for segment in raw_query.split("&"):
            if segment.count("=") != 1:
                raise _HttpRequestError(
                    400,
                    "query_invalid",
                    "event pagination query is invalid",
                )
            name, raw_value = segment.split("=", maxsplit=1)
            if (
                name not in {"limit", "before_sequence"}
                or name in values
                or _QUERY_INTEGER_PATTERN.fullmatch(raw_value) is None
            ):
                raise _HttpRequestError(
                    400,
                    "query_invalid",
                    "event pagination query is invalid",
                )
            values[name] = int(raw_value, 10)
    limit = values.get("limit", _DEFAULT_EVENT_PAGE_SIZE)
    before_sequence = values.get("before_sequence")
    if not 1 <= limit <= MAX_TEAM_EVENT_PAGE_SIZE or (
        before_sequence is not None and not 1 <= before_sequence <= MAX_TEAM_EXPORT_EVENTS + 1
    ):
        raise _HttpRequestError(
            400,
            "query_invalid",
            "event pagination values are outside the supported bounds",
        )
    return limit, before_sequence


def _investigation_page_query(
    environ: Mapping[str, Any],
) -> tuple[
    int,
    int | None,
    TeamInvestigationStatus | None,
    TeamInvestigationPriority | None,
]:
    raw_query = environ.get("QUERY_STRING", "")
    if not isinstance(raw_query, str) or len(raw_query) > 256:
        raise _HttpRequestError(400, "query_invalid", "investigation query is invalid")
    values: dict[str, str] = {}
    if raw_query:
        for segment in raw_query.split("&"):
            if segment.count("=") != 1:
                raise _HttpRequestError(
                    400,
                    "query_invalid",
                    "investigation query is invalid",
                )
            name, raw_value = segment.split("=", maxsplit=1)
            if name not in {"limit", "before_sequence", "status", "priority"} or name in values:
                raise _HttpRequestError(
                    400,
                    "query_invalid",
                    "investigation query is invalid",
                )
            values[name] = raw_value
    for numeric_name in ("limit", "before_sequence"):
        if numeric_name in values and (
            _QUERY_INTEGER_PATTERN.fullmatch(values[numeric_name]) is None
        ):
            raise _HttpRequestError(
                400,
                "query_invalid",
                "investigation pagination values are invalid",
            )
    limit = int(values.get("limit", str(_DEFAULT_EVENT_PAGE_SIZE)), 10)
    before_sequence = (
        None if "before_sequence" not in values else int(values["before_sequence"], 10)
    )
    if not 1 <= limit <= MAX_TEAM_INVESTIGATION_PAGE_SIZE or (
        before_sequence is not None and not 1 <= before_sequence <= MAX_TEAM_EXPORT_EVENTS + 1
    ):
        raise _HttpRequestError(
            400,
            "query_invalid",
            "investigation pagination values are outside the supported bounds",
        )
    try:
        status = None if "status" not in values else TeamInvestigationStatus(values["status"])
        priority = (
            None if "priority" not in values else TeamInvestigationPriority(values["priority"])
        )
    except ValueError as exc:
        raise _HttpRequestError(
            400,
            "query_invalid",
            "investigation status or priority filter is invalid",
        ) from exc
    return limit, before_sequence, status, priority


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            to_jsonable(value),
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


class TeamWSGIApplication:
    """A WSGI app that trusts only a typed identity injected by hosting middleware."""

    def __init__(self, service: TeamApplicationService) -> None:
        if not isinstance(service, TeamApplicationService):
            raise TypeError("service must be a TeamApplicationService")
        self._service = service

    def _response(
        self,
        start_response: _StartResponse,
        status: int,
        body: bytes,
        *,
        content_type: str = "application/json; charset=utf-8",
        headers: Iterable[tuple[str, str]] = (),
        content_security_policy: str = _DEFAULT_CONTENT_SECURITY_POLICY,
    ) -> list[bytes]:
        response_headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", content_security_policy),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            *headers,
        ]
        start_response(f"{status} {_STATUS_REASONS[status]}", response_headers)
        return [body]

    def _error(
        self,
        start_response: _StartResponse,
        status: int,
        code: str,
        message: str,
        *,
        headers: Iterable[tuple[str, str]] = (),
        extra: Mapping[str, Any] | None = None,
    ) -> list[bytes]:
        document: dict[str, Any] = {
            "error": {
                "code": code,
                "message": message,
            }
        }
        if extra:
            document.update(extra)
        return self._response(
            start_response,
            status,
            _json_bytes(document),
            headers=headers,
        )

    @staticmethod
    def _identity(environ: Mapping[str, Any]) -> AuthenticatedTeamIdentity:
        identity = environ.get(TEAM_IDENTITY_ENVIRON_KEY)
        if identity is None:
            raise _HttpRequestError(
                401,
                "authentication_required",
                "trusted hosting middleware did not authenticate this request",
                headers=(("WWW-Authenticate", "Causure-External"),),
            )
        if type(identity) is not AuthenticatedTeamIdentity:
            raise TeamIdentityError(
                "identity_context_invalid",
                "the trusted WSGI identity extension has an invalid type",
            )
        return identity

    @staticmethod
    def _require_no_query(environ: Mapping[str, Any]) -> None:
        query = environ.get("QUERY_STRING", "")
        if query:
            raise _HttpRequestError(
                400,
                "query_unsupported",
                "this endpoint does not accept query parameters",
            )

    @staticmethod
    def _require_request_integrity(environ: Mapping[str, Any]) -> None:
        if environ.get(TEAM_REQUEST_INTEGRITY_ENVIRON_KEY) is not True:
            raise _HttpRequestError(
                403,
                "request_integrity_required",
                "trusted middleware did not verify this state-changing request",
            )

    @staticmethod
    def _method_not_allowed(method: str, allowed: str) -> _HttpRequestError:
        return _HttpRequestError(
            405,
            "method_not_allowed",
            f"{method} is not allowed for this endpoint",
            headers=(("Allow", allowed),),
        )

    @staticmethod
    def _action_document(record: TeamRecordedAction) -> dict[str, Any]:
        return {
            "status": "recorded" if record.authorization.authorized else "denied",
            "authorization": record.authorization,
            "event": record.event,
            "head": record.head,
        }

    @staticmethod
    def _case_publication_document(publication: TeamCasePublication) -> dict[str, Any]:
        document: dict[str, Any] = {
            "status": "published" if publication.record is not None else "denied",
            "authorization": publication.authorization,
            "event": publication.event,
            "head": publication.head,
        }
        if publication.record is not None:
            document["record"] = publication.record
        return document

    @staticmethod
    def _investigation_mutation_document(
        mutation: TeamInvestigationMutation,
    ) -> dict[str, Any]:
        document: dict[str, Any] = {
            "status": "recorded" if mutation.record is not None else "denied",
            "authorization": mutation.authorization,
            "event": mutation.event,
            "head": mutation.head,
        }
        if mutation.record is not None:
            document["record"] = mutation.record
        return document

    def _dispatch(
        self,
        environ: Mapping[str, Any],
        start_response: _StartResponse,
    ) -> list[bytes]:
        method = str(environ.get("REQUEST_METHOD", "")).upper()
        path = str(environ.get("PATH_INFO", "") or "/")
        if path not in {
            "/",
            "/team",
            "/team/cases",
            "/team/investigations",
            "/v1/team/events",
            "/v1/team/cases",
            "/v1/team/investigations",
        }:
            self._require_no_query(environ)

        if path == "/team.css":
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            return self._response(
                start_response,
                200,
                TEAM_DASHBOARD_CSS,
                content_type="text/css; charset=utf-8",
            )

        if path == "/healthz":
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            return self._response(
                start_response,
                200,
                _json_bytes({"status": "ok", "version": PACKAGE_VERSION}),
            )

        if path == "/readyz":
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            self._service.store.check()
            return self._response(
                start_response,
                200,
                _json_bytes({"status": "ready", "version": PACKAGE_VERSION}),
            )

        if path == "/v1/team/summary":
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            identity = self._identity(environ)
            summary = self._service.get_tenant_summary(identity)
            return self._response(start_response, 200, _json_bytes(summary))

        if path == "/v1/team/events":
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            identity = self._identity(environ)
            limit, before_sequence = _event_page_query(environ)
            page = self._service.list_recent_events(
                identity,
                limit=limit,
                before_sequence=before_sequence,
            )
            return self._response(start_response, 200, _json_bytes(page))

        if path == "/v1/team/cases":
            identity = self._identity(environ)
            if method == "GET":
                limit, before_sequence = _event_page_query(environ)
                page = self._service.list_cases(
                    identity,
                    limit=limit,
                    before_sequence=before_sequence,
                )
                return self._response(start_response, 200, _json_bytes(page))
            if method != "POST":
                raise self._method_not_allowed(method, "GET, POST")
            self._require_no_query(environ)
            self._require_request_integrity(environ)
            request = _parse_case_publication_request(_read_json_request(environ))
            publication = self._service.publish_case(
                identity,
                case_id=request.case_id,
                change_case_bytes=request.change_case_bytes,
                review_result_bytes=request.review_result_bytes,
                expected_head_sha256=request.expected_head_sha256,
                azure_publication_bytes=request.azure_publication_bytes,
                azure_verification_bytes=request.azure_verification_bytes,
                approval_verification_bytes=request.approval_verification_bytes,
                canary_result_bytes=request.canary_result_bytes,
                retention_class_id=request.retention_class_id,
            )
            document = self._case_publication_document(publication)
            if publication.record is None:
                return self._error(
                    start_response,
                    403,
                    "action_denied",
                    "the active tenant policy does not grant case publication",
                    extra=document,
                )
            return self._response(start_response, 201, _json_bytes(document))

        if path == "/v1/team/investigations":
            identity = self._identity(environ)
            if method == "GET":
                limit, before_sequence, status, priority = _investigation_page_query(environ)
                page = self._service.list_investigations(
                    identity,
                    limit=limit,
                    before_sequence=before_sequence,
                    status=status,
                    priority=priority,
                )
                return self._response(start_response, 200, _json_bytes(page))
            if method != "POST":
                raise self._method_not_allowed(method, "GET, POST")
            self._require_no_query(environ)
            self._require_request_integrity(environ)
            request = _parse_investigation_open_request(_read_json_request(environ))
            mutation = self._service.open_investigation(
                identity,
                investigation_id=request.investigation_id,
                fixture_bytes=request.fixture_bytes,
                cluster_id=request.cluster_id,
                title=request.title,
                priority=request.priority,
                expected_revision=request.expected_revision,
                expected_head_sha256=request.expected_head_sha256,
                retention_class_id=request.retention_class_id,
            )
            document = self._investigation_mutation_document(mutation)
            if mutation.record is None:
                return self._error(
                    start_response,
                    403,
                    "action_denied",
                    "the active tenant policy does not grant investigation writes",
                    extra=document,
                )
            return self._response(start_response, 201, _json_bytes(document))

        observation_match = _INVESTIGATION_OBSERVATIONS_PATH_PATTERN.fullmatch(path)
        if observation_match is not None:
            if method != "POST":
                raise self._method_not_allowed(method, "POST")
            identity = self._identity(environ)
            self._require_request_integrity(environ)
            request = _parse_investigation_attach_request(_read_json_request(environ))
            mutation = self._service.attach_investigation_observation(
                identity,
                investigation_id=observation_match.group(1),
                fixture_bytes=request.fixture_bytes,
                cluster_id=request.cluster_id,
                expected_revision=request.expected_revision,
                expected_head_sha256=request.expected_head_sha256,
                retention_class_id=request.retention_class_id,
            )
            document = self._investigation_mutation_document(mutation)
            if mutation.record is None:
                return self._error(
                    start_response,
                    403,
                    "action_denied",
                    "the active tenant policy does not grant investigation writes",
                    extra=document,
                )
            return self._response(start_response, 200, _json_bytes(document))

        transition_match = _INVESTIGATION_TRANSITION_PATH_PATTERN.fullmatch(path)
        if transition_match is not None:
            if method != "POST":
                raise self._method_not_allowed(method, "POST")
            identity = self._identity(environ)
            self._require_request_integrity(environ)
            request = _parse_investigation_transition_request(_read_json_request(environ))
            mutation = self._service.transition_investigation(
                identity,
                investigation_id=transition_match.group(1),
                title=request.title,
                status=request.status,
                priority=request.priority,
                assigned_to=request.assigned_to,
                expected_revision=request.expected_revision,
                expected_head_sha256=request.expected_head_sha256,
                resolution=request.resolution,
                linked_case_id=request.linked_case_id,
                duplicate_of=request.duplicate_of,
                retention_class_id=request.retention_class_id,
            )
            document = self._investigation_mutation_document(mutation)
            if mutation.record is None:
                return self._error(
                    start_response,
                    403,
                    "action_denied",
                    "the active tenant policy does not grant investigation writes",
                    extra=document,
                )
            return self._response(start_response, 200, _json_bytes(document))

        investigation_api_match = _INVESTIGATION_API_PATH_PATTERN.fullmatch(path)
        if investigation_api_match is not None:
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            identity = self._identity(environ)
            detail = self._service.get_investigation(
                identity,
                investigation_api_match.group(1),
            )
            return self._response(start_response, 200, _json_bytes(detail))

        case_api_match = _CASE_API_PATH_PATTERN.fullmatch(path)
        if case_api_match is not None:
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            identity = self._identity(environ)
            detail = self._service.get_case(identity, case_api_match.group(1))
            return self._response(start_response, 200, _json_bytes(detail))

        event_match = _EVENT_PATH_PATTERN.fullmatch(path)
        if event_match is not None:
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            identity = self._identity(environ)
            event_bytes = self._service.get_event_bytes(
                identity,
                int(event_match.group(1)),
            )
            return self._response(
                start_response,
                200,
                event_bytes,
                content_type="application/vnd.causure.team-audit-event+json",
            )

        if path in {"/", "/team"}:
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            identity = self._identity(environ)
            limit, before_sequence = _event_page_query(environ)
            page = self._service.list_recent_events(
                identity,
                limit=limit,
                before_sequence=before_sequence,
            )
            return self._response(
                start_response,
                200,
                render_team_dashboard(page, page_size=limit),
                content_type="text/html; charset=utf-8",
                content_security_policy=_DASHBOARD_CONTENT_SECURITY_POLICY,
            )

        if path == "/team/cases":
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            identity = self._identity(environ)
            limit, before_sequence = _event_page_query(environ)
            page = self._service.list_cases(
                identity,
                limit=limit,
                before_sequence=before_sequence,
            )
            return self._response(
                start_response,
                200,
                render_team_case_dashboard(page, page_size=limit),
                content_type="text/html; charset=utf-8",
                content_security_policy=_DASHBOARD_CONTENT_SECURITY_POLICY,
            )

        if path == "/team/investigations":
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            identity = self._identity(environ)
            limit, before_sequence, status, priority = _investigation_page_query(environ)
            page = self._service.list_investigations(
                identity,
                limit=limit,
                before_sequence=before_sequence,
                status=status,
                priority=priority,
            )
            return self._response(
                start_response,
                200,
                render_team_investigation_dashboard(
                    page,
                    page_size=limit,
                    status=status,
                    priority=priority,
                ),
                content_type="text/html; charset=utf-8",
                content_security_policy=_DASHBOARD_CONTENT_SECURITY_POLICY,
            )

        investigation_html_match = _INVESTIGATION_HTML_PATH_PATTERN.fullmatch(path)
        if investigation_html_match is not None:
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            identity = self._identity(environ)
            detail = self._service.get_investigation(
                identity,
                investigation_html_match.group(1),
            )
            return self._response(
                start_response,
                200,
                render_team_investigation_detail(detail),
                content_type="text/html; charset=utf-8",
                content_security_policy=_DASHBOARD_CONTENT_SECURITY_POLICY,
            )

        case_html_match = _CASE_HTML_PATH_PATTERN.fullmatch(path)
        if case_html_match is not None:
            if method != "GET":
                raise self._method_not_allowed(method, "GET")
            identity = self._identity(environ)
            detail = self._service.get_case(identity, case_html_match.group(1))
            return self._response(
                start_response,
                200,
                render_team_case_detail(detail),
                content_type="text/html; charset=utf-8",
                content_security_policy=_DASHBOARD_CONTENT_SECURITY_POLICY,
            )

        if path == "/v1/team/actions":
            if method != "POST":
                raise self._method_not_allowed(method, "POST")
            identity = self._identity(environ)
            self._require_request_integrity(environ)
            action_request = _parse_action_request(_read_json_request(environ))
            record = self._service.record_action(
                identity,
                action_request.payload_bytes,
                payload_media_type=action_request.payload_media_type,
                action=action_request.action,
                resource_type=action_request.resource_type,
                resource_id=action_request.resource_id,
                outcome=action_request.outcome,
                expected_head_sha256=action_request.expected_head_sha256,
                retention_class_id=action_request.retention_class_id,
            )
            document = self._action_document(record)
            if not record.authorization.authorized:
                return self._error(
                    start_response,
                    403,
                    "action_denied",
                    "the active tenant policy does not grant the requested action",
                    extra=document,
                )
            return self._response(start_response, 201, _json_bytes(document))

        if path == "/v1/team/audit-exports":
            if method != "POST":
                raise self._method_not_allowed(method, "POST")
            identity = self._identity(environ)
            self._require_request_integrity(environ)
            _closed_object(
                _read_json_request(environ),
                path="$",
                required=set(),
            )
            export = self._service.create_audit_export(identity)
            export_bytes = self._service.store.get_export_bytes(
                export.tenant_id,
                export.export_id,
            )
            if export_bytes != render_team_audit_export(export).encode("utf-8"):
                raise TeamApplicationError(
                    "stored_export_mismatch",
                    "the stored export bytes do not match the service result",
                )
            return self._response(
                start_response,
                201,
                export_bytes,
                content_type="application/vnd.causure.team-audit-export+json",
            )

        raise _HttpRequestError(404, "route_not_found", "the requested route does not exist")

    def __call__(
        self,
        environ: Mapping[str, Any],
        start_response: _StartResponse,
    ) -> list[bytes]:
        try:
            return self._dispatch(environ, start_response)
        except _HttpRequestError as exc:
            return self._error(
                start_response,
                exc.status,
                exc.code,
                exc.message,
                headers=exc.headers,
            )
        except TeamAccessDeniedError as exc:
            extra = {"authorization": exc.decision} if exc.decision is not None else None
            return self._error(
                start_response,
                403,
                exc.code,
                "the authenticated principal is not authorized for this operation",
                extra=extra,
            )
        except TeamIdentityError:
            return self._error(
                start_response,
                500,
                "identity_context_invalid",
                "the trusted hosting identity integration is invalid",
            )
        except TeamStoreConflictError as exc:
            if exc.code == "store_busy":
                return self._error(
                    start_response,
                    503,
                    "store_busy",
                    "the Team store is busy; retry the request",
                    headers=(("Retry-After", "1"),),
                )
            return self._error(
                start_response,
                409,
                exc.code,
                "the requested Team state transition conflicts with current state",
            )
        except TeamStoreError as exc:
            if exc.code in {
                "event_not_found",
                "case_not_found",
                "investigation_not_found",
            }:
                noun = {
                    "event_not_found": "event",
                    "case_not_found": "case",
                    "investigation_not_found": "investigation",
                }[exc.code]
                return self._error(
                    start_response,
                    404,
                    exc.code,
                    f"the requested Team {noun} does not exist",
                )
            if exc.code == "tenant_not_found":
                return self._error(
                    start_response,
                    403,
                    "tenant_unavailable",
                    "the trusted tenant is unavailable to this principal",
                )
            return self._error(
                start_response,
                503,
                "store_unavailable",
                "the Team store is unavailable",
            )
        except TeamApplicationError as exc:
            if exc.code in _SERVER_APPLICATION_ERROR_CODES:
                return self._error(
                    start_response,
                    500,
                    "server_integration_invalid",
                    "the Team API server integration is invalid",
                )
            return self._error(start_response, 400, exc.code, exc.message)
        except TeamValidationError as exc:
            return self._error(start_response, 400, "request_invalid", str(exc))
        except Exception:
            error_stream = environ.get("wsgi.errors")
            if error_stream is not None and hasattr(error_stream, "write"):
                error_stream.write("Causure Team API internal error\n")
            return self._error(
                start_response,
                500,
                "internal_error",
                "the Team API could not complete the request",
            )
