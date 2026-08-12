"""Closed GitHub Check Run request plans and a bounded HTTPS publisher."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from causure.azure_devops import (
    ArtifactIntegrity,
    ReviewBinding,
    parse_review_result_bytes,
)
from causure.constants import (
    GITHUB_CHECK_RUN_RECEIPT_SCHEMA_VERSION,
    GITHUB_CHECK_RUN_REQUEST_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
    CheckStatus,
    Component,
    Consequence,
    Decision,
    RecommendedAction,
)
from causure.github_review import (
    GITHUB_REVIEW_VERIFICATION_MEDIA_TYPE,
    MAX_GITHUB_REVIEW_RESULT_BYTES,
    MAX_GITHUB_VERIFICATION_BYTES,
    GitHubPullRequestContext,
    GitHubRepositoryIdentity,
    GitHubReviewValidationError,
    GitHubReviewVerificationError,
    GitHubWorkflowRunContext,
    parse_github_review_verification_bytes,
    verify_github_review_publication,
)
from causure.io import InputDocumentError, parse_json_text
from causure.models import to_jsonable

MAX_GITHUB_CHECK_RUN_REQUEST_BYTES = 1024 * 1024
MAX_GITHUB_CHECK_RUN_RECEIPT_BYTES = 1024 * 1024
MAX_GITHUB_CHECK_RUN_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_GITHUB_CHECK_RUN_ANNOTATIONS = 50
MAX_GITHUB_CHECK_RUN_TIMEOUT_SECONDS = 60.0
DEFAULT_GITHUB_CHECK_RUN_TIMEOUT_SECONDS = 15.0
MAX_VERIFICATION_TO_CHECK_REQUEST_SECONDS = 300
MAX_CHECK_REQUEST_TO_PUBLICATION_SECONDS = 300

GITHUB_CHECK_RUN_REQUEST_MEDIA_TYPE = "application/vnd.causure.github-check-run-request+json"
GITHUB_CHECK_RUN_RECEIPT_MEDIA_TYPE = "application/vnd.causure.github-check-run-receipt+json"
GITHUB_CHECK_RUN_NAME = "Causure evidence gate"
GITHUB_REST_API_VERSION = "2022-11-28"

_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_GIT_COMMIT_PATTERN = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_PATH_SEGMENT_PATTERN = re.compile(r"^[^\x00-\x1f\x7f\\]+$")
_UTC_TIMESTAMP_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_REVIEW_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)


class GitHubCheckRunValidationError(ValueError):
    """Raised when a Check Run boundary document is invalid."""

    def __init__(self, document_name: str, path: str, message: str) -> None:
        self.document_name = document_name
        self.path = path
        self.message = message
        super().__init__(f"Invalid {document_name} at {path}: {message}")


class GitHubCheckRunPublishError(ValueError):
    """Raised when the bounded GitHub Checks API publication fails."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


@dataclass(frozen=True, slots=True)
class GitHubCheckRunFinding:
    """One decision-affecting finding mapped to a repository location."""

    code: str
    status: CheckStatus
    consequence: Consequence
    path: str
    start_line: int
    end_line: int
    message: str


@dataclass(frozen=True, slots=True)
class GitHubCheckRunRequest:
    """A closed, token-free plan for one completed GitHub Check Run."""

    schema_version: str
    created_at: str
    repository: GitHubRepositoryIdentity
    pull_request_number: int
    head_sha: str
    is_fork: bool
    workflow_run_id: int
    run_attempt: int
    verification: ArtifactIntegrity
    review: ReviewBinding
    allow_conditional: bool
    name: str
    conclusion: str
    details_url: str
    external_id: str
    findings: tuple[GitHubCheckRunFinding, ...]


@dataclass(frozen=True, slots=True)
class GitHubCheckRunReceipt:
    """Minimized evidence that GitHub accepted the exact request plan."""

    schema_version: str
    status: str
    published_at: str
    repository: GitHubRepositoryIdentity
    pull_request_number: int
    head_sha: str
    workflow_run_id: int
    run_attempt: int
    check_run_id: int
    name: str
    conclusion: str
    external_id: str
    html_url: str
    annotation_count: int
    request: ArtifactIntegrity
    verification: ArtifactIntegrity


@dataclass(frozen=True, slots=True)
class GitHubHTTPResponse:
    """Bounded HTTP response returned by a Check Run transport."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes


class GitHubCheckRunTransport(Protocol):
    """Injectable HTTPS transport used by the network publisher."""

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> GitHubHTTPResponse: ...


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class UrllibGitHubCheckRunTransport:
    """Standard-library HTTPS transport with redirects disabled and bounded responses."""

    def post(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> GitHubHTTPResponse:
        request = Request(url, data=body, headers=dict(headers), method="POST")
        opener = build_opener(_NoRedirectHandler(), HTTPSHandler())
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                response_body = response.read(MAX_GITHUB_CHECK_RUN_RESPONSE_BYTES + 1)
                status_code = response.status
                response_headers = {key.lower(): value for key, value in response.headers.items()}
        except HTTPError as exc:
            response_body = exc.read(MAX_GITHUB_CHECK_RUN_RESPONSE_BYTES + 1)
            status_code = exc.code
            response_headers = {key.lower(): value for key, value in exc.headers.items()}
        except (OSError, URLError) as exc:
            raise GitHubCheckRunPublishError(
                "network_error",
                f"GitHub Checks API request failed: {type(exc).__name__}",
            ) from exc
        if len(response_body) > MAX_GITHUB_CHECK_RUN_RESPONSE_BYTES:
            raise GitHubCheckRunPublishError(
                "response_too_large",
                "GitHub Checks API response exceeded the bounded response limit",
            )
        return GitHubHTTPResponse(
            status_code=status_code,
            headers=response_headers,
            body=response_body,
        )


def _object(
    value: Any,
    path: str,
    document_name: str,
    *,
    required: set[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubCheckRunValidationError(document_name, path, "expected an object")
    missing = sorted(required - value.keys())
    if missing:
        raise GitHubCheckRunValidationError(
            document_name,
            f"{path}.{missing[0]}",
            "required property is missing",
        )
    unknown = sorted(value.keys() - required)
    if unknown:
        raise GitHubCheckRunValidationError(
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
        raise GitHubCheckRunValidationError(document_name, path, "expected a string")
    if not value or value != value.strip():
        raise GitHubCheckRunValidationError(
            document_name,
            path,
            "expected a non-empty string without surrounding whitespace",
        )
    if len(value) > maximum:
        raise GitHubCheckRunValidationError(
            document_name,
            path,
            f"must contain at most {maximum} characters",
        )
    if "\x00" in value or (pattern is not None and pattern.fullmatch(value) is None):
        raise GitHubCheckRunValidationError(document_name, path, "has an invalid format")
    return value


def _integer(
    value: Any,
    path: str,
    document_name: str,
    *,
    minimum: int = 1,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise GitHubCheckRunValidationError(document_name, path, "expected an integer")
    if value < minimum or (maximum is not None and value > maximum):
        upper = f" and at most {maximum}" if maximum is not None else ""
        raise GitHubCheckRunValidationError(
            document_name,
            path,
            f"must be at least {minimum}{upper}",
        )
    return value


def _boolean(value: Any, path: str, document_name: str) -> bool:
    if not isinstance(value, bool):
        raise GitHubCheckRunValidationError(document_name, path, "expected a boolean")
    return value


def _enum(value: Any, path: str, document_name: str, enum_type: type) -> Any:
    if not isinstance(value, str):
        raise GitHubCheckRunValidationError(document_name, path, "expected a string")
    try:
        return enum_type(value)
    except ValueError as exc:
        raise GitHubCheckRunValidationError(
            document_name,
            path,
            f"unsupported value {value!r}",
        ) from exc


def _timestamp(
    value: Any,
    path: str,
    document_name: str,
    *,
    review_timestamp: bool = False,
) -> str:
    pattern = _REVIEW_TIMESTAMP_PATTERN if review_timestamp else _UTC_TIMESTAMP_PATTERN
    candidate = _string(value, path, document_name, maximum=32, pattern=pattern)
    try:
        parsed = datetime.fromisoformat(candidate[:-1] + "+00:00")
    except ValueError as exc:
        raise GitHubCheckRunValidationError(
            document_name,
            path,
            "expected a valid UTC timestamp",
        ) from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise GitHubCheckRunValidationError(document_name, path, "expected UTC")
    return candidate


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value[:-1] + "+00:00")


def _parse_json_bytes(raw_bytes: bytes, *, description: str, maximum: int) -> Any:
    if not raw_bytes or len(raw_bytes) > maximum:
        raise GitHubCheckRunValidationError(
            description,
            "$",
            f"expected from 1 to {maximum} bytes",
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GitHubCheckRunValidationError(description, "$", "expected UTF-8 JSON") from exc
    try:
        return parse_json_text(text, source=description, max_bytes=maximum)
    except InputDocumentError as exc:
        raise GitHubCheckRunValidationError(description, "$", str(exc)) from exc


def _parse_repository(value: Any, path: str, document_name: str) -> GitHubRepositoryIdentity:
    obj = _object(
        value,
        path,
        document_name,
        required={"repository_id", "owner_id", "full_name"},
    )
    return GitHubRepositoryIdentity(
        repository_id=_integer(obj["repository_id"], f"{path}.repository_id", document_name),
        owner_id=_integer(obj["owner_id"], f"{path}.owner_id", document_name),
        full_name=_string(
            obj["full_name"],
            f"{path}.full_name",
            document_name,
            maximum=255,
            pattern=_REPOSITORY_PATTERN,
        ),
    )


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
    media_type = _string(obj["media_type"], f"{path}.media_type", document_name, maximum=128)
    if media_type != expected_media_type:
        raise GitHubCheckRunValidationError(
            document_name,
            f"{path}.media_type",
            f"expected {expected_media_type!r}",
        )
    return ArtifactIntegrity(
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
            maximum=maximum_bytes,
        ),
    )


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
    schema_version = _string(
        obj["result_schema_version"],
        f"{path}.result_schema_version",
        document_name,
        maximum=16,
    )
    if schema_version != RESULT_SCHEMA_VERSION:
        raise GitHubCheckRunValidationError(
            document_name,
            f"{path}.result_schema_version",
            f"expected {RESULT_SCHEMA_VERSION!r}",
        )
    review = ReviewBinding(
        result_schema_version=schema_version,
        engine_version=_string(
            obj["engine_version"], f"{path}.engine_version", document_name, maximum=128
        ),
        policy_name=_string(obj["policy_name"], f"{path}.policy_name", document_name, maximum=128),
        case_id=_string(
            obj["case_id"],
            f"{path}.case_id",
            document_name,
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        component=_enum(obj["component"], f"{path}.component", document_name, Component),
        input_sha256=_string(
            obj["input_sha256"],
            f"{path}.input_sha256",
            document_name,
            maximum=64,
            pattern=_SHA256_PATTERN,
        ),
        reviewed_at=_timestamp(
            obj["reviewed_at"],
            f"{path}.reviewed_at",
            document_name,
            review_timestamp=True,
        ),
        decision=_enum(obj["decision"], f"{path}.decision", document_name, Decision),
        recommended_action=_enum(
            obj["recommended_action"],
            f"{path}.recommended_action",
            document_name,
            RecommendedAction,
        ),
    )
    expected_action = {
        Decision.APPROVE: RecommendedAction.PATCH,
        Decision.CONDITIONAL_PASS: RecommendedAction.PATCH,
        Decision.REJECT: RecommendedAction.DO_NOT_PATCH,
        Decision.NEEDS_EVIDENCE: RecommendedAction.COLLECT_EVIDENCE,
        Decision.HUMAN_REVIEW: RecommendedAction.ESCALATE,
    }[review.decision]
    if review.recommended_action is not expected_action:
        raise GitHubCheckRunValidationError(
            document_name,
            f"{path}.recommended_action",
            "does not correspond to the decision",
        )
    return review


def _repository_path(value: Any, path: str, document_name: str) -> str:
    candidate = _string(
        value,
        path,
        document_name,
        maximum=1024,
        pattern=_PATH_SEGMENT_PATTERN,
    )
    if (
        candidate.startswith("/")
        or candidate.endswith("/")
        or "//" in candidate
        or any(segment in {"", ".", ".."} for segment in candidate.split("/"))
        or ":" in candidate.split("/", 1)[0]
    ):
        raise GitHubCheckRunValidationError(
            document_name,
            path,
            "expected a normalized repository-relative path",
        )
    return candidate


def _parse_finding(value: Any, path: str, document_name: str) -> GitHubCheckRunFinding:
    obj = _object(
        value,
        path,
        document_name,
        required={"code", "status", "consequence", "path", "start_line", "end_line", "message"},
    )
    consequence = _enum(obj["consequence"], f"{path}.consequence", document_name, Consequence)
    if consequence is Consequence.NONE:
        raise GitHubCheckRunValidationError(
            document_name,
            f"{path}.consequence",
            "only decision-affecting findings may be annotated",
        )
    start_line = _integer(obj["start_line"], f"{path}.start_line", document_name)
    end_line = _integer(obj["end_line"], f"{path}.end_line", document_name)
    if end_line < start_line:
        raise GitHubCheckRunValidationError(
            document_name,
            f"{path}.end_line",
            "must be at or after start_line",
        )
    return GitHubCheckRunFinding(
        code=_string(
            obj["code"],
            f"{path}.code",
            document_name,
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        status=_enum(obj["status"], f"{path}.status", document_name, CheckStatus),
        consequence=consequence,
        path=_repository_path(obj["path"], f"{path}.path", document_name),
        start_line=start_line,
        end_line=end_line,
        message=_string(obj["message"], f"{path}.message", document_name, maximum=4096),
    )


def _decision_for_findings(findings: tuple[GitHubCheckRunFinding, ...]) -> Decision:
    consequences = {finding.consequence for finding in findings}
    if Consequence.HUMAN_REVIEW in consequences:
        return Decision.HUMAN_REVIEW
    if Consequence.REJECT in consequences:
        return Decision.REJECT
    if Consequence.NEEDS_EVIDENCE in consequences:
        return Decision.NEEDS_EVIDENCE
    if Consequence.CONDITIONAL in consequences:
        return Decision.CONDITIONAL_PASS
    return Decision.APPROVE


def _conclusion(decision: Decision, *, allow_conditional: bool) -> str:
    if decision is Decision.APPROVE:
        return "success"
    if decision is Decision.CONDITIONAL_PASS:
        return "success" if allow_conditional else "action_required"
    if decision is Decision.REJECT:
        return "failure"
    return "action_required"


def _details_url(repository: GitHubRepositoryIdentity, workflow_run_id: int) -> str:
    return f"https://github.com/{repository.full_name}/actions/runs/{workflow_run_id}"


def _external_id(
    repository: GitHubRepositoryIdentity,
    pull_request_number: int,
    workflow_run_id: int,
    run_attempt: int,
    verification_sha256: str,
) -> str:
    return (
        f"causure:{repository.repository_id}:{pull_request_number}:"
        f"{workflow_run_id}:{run_attempt}:{verification_sha256[:16]}"
    )


def _validate_request_consistency(request: GitHubCheckRunRequest, *, document_name: str) -> None:
    if request.review.decision is not _decision_for_findings(request.findings):
        raise GitHubCheckRunValidationError(
            document_name,
            "$.findings",
            "decision-affecting findings do not reproduce review.decision",
        )
    if request.conclusion != _conclusion(
        request.review.decision,
        allow_conditional=request.allow_conditional,
    ):
        raise GitHubCheckRunValidationError(
            document_name,
            "$.conclusion",
            "does not correspond to the review decision and conditional policy",
        )
    expected_details = _details_url(request.repository, request.workflow_run_id)
    if request.details_url != expected_details:
        raise GitHubCheckRunValidationError(
            document_name,
            "$.details_url",
            "does not identify the bound GitHub Actions run",
        )
    expected_external = _external_id(
        request.repository,
        request.pull_request_number,
        request.workflow_run_id,
        request.run_attempt,
        request.verification.sha256,
    )
    if request.external_id != expected_external:
        raise GitHubCheckRunValidationError(
            document_name,
            "$.external_id",
            "does not match the bound repository, PR, run, attempt, and verification",
        )
    if len(request.findings) > MAX_GITHUB_CHECK_RUN_ANNOTATIONS:
        raise GitHubCheckRunValidationError(
            document_name,
            "$.findings",
            f"at most {MAX_GITHUB_CHECK_RUN_ANNOTATIONS} annotations are supported",
        )
    codes = [finding.code for finding in request.findings]
    if len(set(codes)) != len(codes):
        raise GitHubCheckRunValidationError(
            document_name,
            "$.findings",
            "finding codes must be unique",
        )


def parse_github_check_run_request(document: Any) -> GitHubCheckRunRequest:
    """Strictly parse a token-free Check Run request plan."""

    name = "GitHub Check Run request"
    root = _object(
        document,
        "$",
        name,
        required={
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
        },
    )
    schema_version = _string(root["schema_version"], "$.schema_version", name, maximum=16)
    if schema_version != GITHUB_CHECK_RUN_REQUEST_SCHEMA_VERSION:
        raise GitHubCheckRunValidationError(
            name,
            "$.schema_version",
            f"expected {GITHUB_CHECK_RUN_REQUEST_SCHEMA_VERSION!r}",
        )
    raw_findings = root["findings"]
    if not isinstance(raw_findings, list):
        raise GitHubCheckRunValidationError(name, "$.findings", "expected an array")
    if len(raw_findings) > MAX_GITHUB_CHECK_RUN_ANNOTATIONS:
        raise GitHubCheckRunValidationError(
            name,
            "$.findings",
            f"at most {MAX_GITHUB_CHECK_RUN_ANNOTATIONS} annotations are supported",
        )
    request = GitHubCheckRunRequest(
        schema_version=schema_version,
        created_at=_timestamp(root["created_at"], "$.created_at", name),
        repository=_parse_repository(root["repository"], "$.repository", name),
        pull_request_number=_integer(root["pull_request_number"], "$.pull_request_number", name),
        head_sha=_string(
            root["head_sha"],
            "$.head_sha",
            name,
            maximum=64,
            pattern=_GIT_COMMIT_PATTERN,
        ),
        is_fork=_boolean(root["is_fork"], "$.is_fork", name),
        workflow_run_id=_integer(root["workflow_run_id"], "$.workflow_run_id", name),
        run_attempt=_integer(root["run_attempt"], "$.run_attempt", name),
        verification=_parse_artifact(
            root["verification"],
            "$.verification",
            name,
            expected_media_type=GITHUB_REVIEW_VERIFICATION_MEDIA_TYPE,
            maximum_bytes=MAX_GITHUB_VERIFICATION_BYTES,
        ),
        review=_parse_review(root["review"], "$.review", name),
        allow_conditional=_boolean(root["allow_conditional"], "$.allow_conditional", name),
        name=_string(root["name"], "$.name", name, maximum=128),
        conclusion=_string(root["conclusion"], "$.conclusion", name, maximum=32),
        details_url=_string(root["details_url"], "$.details_url", name, maximum=2048),
        external_id=_string(root["external_id"], "$.external_id", name, maximum=255),
        findings=tuple(
            _parse_finding(value, f"$.findings[{index}]", name)
            for index, value in enumerate(raw_findings)
        ),
    )
    if request.name != GITHUB_CHECK_RUN_NAME:
        raise GitHubCheckRunValidationError(
            name,
            "$.name",
            f"expected the stable name {GITHUB_CHECK_RUN_NAME!r}",
        )
    if request.conclusion not in {"success", "failure", "action_required"}:
        raise GitHubCheckRunValidationError(name, "$.conclusion", "unsupported conclusion")
    _validate_request_consistency(request, document_name=name)
    _github_check_run_api_body(request)
    return request


def parse_github_check_run_request_bytes(raw_bytes: bytes) -> GitHubCheckRunRequest:
    """Parse bounded exact Check Run request bytes."""

    return parse_github_check_run_request(
        _parse_json_bytes(
            raw_bytes,
            description="GitHub Check Run request",
            maximum=MAX_GITHUB_CHECK_RUN_REQUEST_BYTES,
        )
    )


def _result_findings(raw_bytes: bytes) -> tuple[dict[str, Any], ...]:
    try:
        review = parse_review_result_bytes(raw_bytes)
    except ValueError as exc:
        raise GitHubCheckRunValidationError("review result", "$", str(exc)) from exc
    document = _parse_json_bytes(
        raw_bytes,
        description="review result",
        maximum=MAX_GITHUB_REVIEW_RESULT_BYTES,
    )
    if not isinstance(document, dict) or not isinstance(document.get("findings"), list):
        raise GitHubCheckRunValidationError("review result", "$.findings", "expected an array")
    if review != parse_review_result_bytes(raw_bytes):
        raise GitHubCheckRunValidationError("review result", "$", "changed while parsing")
    return tuple(document["findings"])


def create_github_check_run_request(
    publication_bytes: bytes,
    verification_bytes: bytes,
    change_case_bytes: bytes,
    review_result_bytes: bytes,
    review_report_bytes: bytes,
    *,
    expected_pull_request: GitHubPullRequestContext,
    expected_workflow: GitHubWorkflowRunContext,
    component_path: str,
    created_at: str,
    allow_conditional: bool = False,
) -> GitHubCheckRunRequest:
    """Reproduce verification and create one closed completed-check request."""

    if expected_workflow.server_url != "https://github.com":
        raise GitHubCheckRunValidationError(
            "GitHub Check Run request",
            "$.repository",
            "the first publisher supports github.com only",
        )
    if not isinstance(allow_conditional, bool):
        raise GitHubCheckRunValidationError(
            "GitHub Check Run request",
            "$.allow_conditional",
            "expected a boolean",
        )
    annotation_path = _repository_path(
        component_path,
        "$.findings[*].path",
        "GitHub Check Run request",
    )
    try:
        verification = parse_github_review_verification_bytes(verification_bytes)
        reproduced = verify_github_review_publication(
            publication_bytes,
            change_case_bytes,
            review_result_bytes,
            review_report_bytes,
            expected_pull_request=expected_pull_request,
            expected_workflow=expected_workflow,
            verified_at=verification.verified_at,
            maximum_age_seconds=verification.maximum_age_seconds,
        )
    except (GitHubReviewValidationError, GitHubReviewVerificationError) as exc:
        raise GitHubCheckRunValidationError(
            "GitHub Check Run request",
            "$.verification",
            str(exc),
        ) from exc
    if verification != reproduced:
        raise GitHubCheckRunValidationError(
            "GitHub Check Run request",
            "$.verification",
            "receipt does not reproduce from the exact publication, artifacts, and context",
        )
    request_time = _timestamp(
        created_at,
        "$.created_at",
        "GitHub Check Run request",
    )
    gap_seconds = (
        _timestamp_value(request_time) - _timestamp_value(verification.verified_at)
    ).total_seconds()
    if gap_seconds < -1 or gap_seconds > MAX_VERIFICATION_TO_CHECK_REQUEST_SECONDS:
        raise GitHubCheckRunValidationError(
            "GitHub Check Run request",
            "$.created_at",
            (
                "must be within one second before and "
                f"{MAX_VERIFICATION_TO_CHECK_REQUEST_SECONDS} seconds after verification"
            ),
        )

    raw_findings = _result_findings(review_result_bytes)
    findings: list[GitHubCheckRunFinding] = []
    for index, raw in enumerate(raw_findings):
        if not isinstance(raw, dict):
            raise GitHubCheckRunValidationError(
                "review result",
                f"$.findings[{index}]",
                "expected an object",
            )
        consequence = Consequence(raw["consequence"])
        if consequence is Consequence.NONE:
            continue
        findings.append(
            GitHubCheckRunFinding(
                code=raw["code"],
                status=CheckStatus(raw["status"]),
                consequence=consequence,
                path=annotation_path,
                start_line=1,
                end_line=1,
                message=raw["message"],
            )
        )
    if len(findings) > MAX_GITHUB_CHECK_RUN_ANNOTATIONS:
        raise GitHubCheckRunValidationError(
            "GitHub Check Run request",
            "$.findings",
            (
                f"{len(findings)} decision-affecting findings exceed the "
                f"{MAX_GITHUB_CHECK_RUN_ANNOTATIONS}-annotation single-request limit"
            ),
        )
    verification_subject = ArtifactIntegrity(
        media_type=GITHUB_REVIEW_VERIFICATION_MEDIA_TYPE,
        sha256=hashlib.sha256(verification_bytes).hexdigest(),
        byte_count=len(verification_bytes),
    )
    request = GitHubCheckRunRequest(
        schema_version=GITHUB_CHECK_RUN_REQUEST_SCHEMA_VERSION,
        created_at=request_time,
        repository=expected_pull_request.base_repository,
        pull_request_number=expected_pull_request.number,
        head_sha=expected_pull_request.head_sha,
        is_fork=expected_pull_request.is_fork,
        workflow_run_id=expected_workflow.run_id,
        run_attempt=expected_workflow.run_attempt,
        verification=verification_subject,
        review=verification.review,
        allow_conditional=allow_conditional,
        name=GITHUB_CHECK_RUN_NAME,
        conclusion=_conclusion(
            verification.review.decision,
            allow_conditional=allow_conditional,
        ),
        details_url=_details_url(expected_pull_request.base_repository, expected_workflow.run_id),
        external_id=_external_id(
            expected_pull_request.base_repository,
            expected_pull_request.number,
            expected_workflow.run_id,
            expected_workflow.run_attempt,
            verification_subject.sha256,
        ),
        findings=tuple(findings),
    )
    return parse_github_check_run_request(to_jsonable(request))


def render_github_check_run_request(request: GitHubCheckRunRequest) -> str:
    """Render a stable token-free Check Run request plan."""

    validated = parse_github_check_run_request(to_jsonable(request))
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


def _markdown_text(value: str, *, maximum: int = 512) -> str:
    text = " ".join(value.split())[:maximum]
    for character in ("\\", "`", "*", "_", "{", "}", "[", "]", "<", ">", "|"):
        text = text.replace(character, f"\\{character}")
    return text


def _render_github_check_run_summary(request: GitHubCheckRunRequest) -> str:
    review = request.review
    lines = [
        "## Causure evidence gate",
        "",
        f"> **{review.decision.value.upper()}** — exact gate artifacts and PR identity verified.",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Case | `{review.case_id}` |",
        f"| Component | `{review.component.value}` |",
        f"| Decision | **{review.decision.value.upper()}** |",
        f"| Recommended action | `{review.recommended_action.value}` |",
        f"| Check conclusion | `{request.conclusion}` |",
        f"| Policy | {_markdown_text(review.policy_name)} |",
        f"| Candidate | `{request.head_sha}` |",
        f"| Pull request | `#{request.pull_request_number}` |",
        f"| Workflow run | [{request.workflow_run_id}]({request.details_url}) |",
    ]
    if request.findings:
        lines.extend(["", "### Required resolution", ""])
        for finding in request.findings:
            lines.append(
                f"- `{finding.code}` (`{finding.consequence.value}`): "
                f"{_markdown_text(finding.message)}"
            )
    else:
        lines.extend(["", "No decision-affecting findings remain."])
    lines.extend(
        [
            "",
            "### Verification boundary",
            "",
            f"- Verification SHA-256: `{request.verification.sha256}`",
            f"- Request created: `{request.created_at}`",
            (
                "- This check reports the deterministic gate; it does not authenticate "
                "a human approval."
            ),
            "",
        ]
    )
    summary = "\n".join(lines)
    if len(summary.encode("utf-8")) > 65535:
        raise GitHubCheckRunValidationError(
            "GitHub Check Run request",
            "$.findings",
            "rendered summary exceeds the bounded GitHub output size",
        )
    return summary


def render_github_check_run_summary(request: GitHubCheckRunRequest) -> str:
    """Render the minimized Markdown summary sent to GitHub."""

    validated = parse_github_check_run_request(to_jsonable(request))
    return _render_github_check_run_summary(validated)


def _annotation_level(consequence: Consequence) -> str:
    return "failure" if consequence is Consequence.REJECT else "warning"


def _github_check_run_api_body(request: GitHubCheckRunRequest) -> bytes:
    summary = _render_github_check_run_summary(request)
    payload = {
        "name": request.name,
        "head_sha": request.head_sha,
        "status": "completed",
        "conclusion": request.conclusion,
        "completed_at": request.created_at,
        "details_url": request.details_url,
        "external_id": request.external_id,
        "output": {
            "title": f"Causure: {request.review.decision.value.upper()}",
            "summary": summary,
            "annotations": [
                {
                    "path": finding.path,
                    "start_line": finding.start_line,
                    "end_line": finding.end_line,
                    "annotation_level": _annotation_level(finding.consequence),
                    "title": finding.code,
                    "message": finding.message,
                    "raw_details": (
                        f"status={finding.status.value}; consequence={finding.consequence.value}"
                    ),
                }
                for finding in request.findings
            ],
        },
    }
    body = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(body) > MAX_GITHUB_CHECK_RUN_REQUEST_BYTES:
        raise GitHubCheckRunValidationError(
            "GitHub Check Run request",
            "$",
            "rendered API request exceeds the bounded request size",
        )
    return body


def github_check_run_api_body(request: GitHubCheckRunRequest) -> bytes:
    """Return the exact deterministic JSON body sent to GitHub."""

    validated = parse_github_check_run_request(to_jsonable(request))
    return _github_check_run_api_body(validated)


def _response_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubCheckRunPublishError("response_invalid", f"expected an object at {path}")
    return value


def _response_string(value: Any, path: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise GitHubCheckRunPublishError(
            "response_invalid", f"expected a bounded non-empty string at {path}"
        )
    return value


def _response_integer(value: Any, path: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise GitHubCheckRunPublishError(
            "response_invalid", f"expected a positive integer at {path}"
        )
    return value


def _github_api_endpoint(repository: GitHubRepositoryIdentity) -> str:
    return f"https://api.github.com/repos/{repository.full_name}/check-runs"


def publish_github_check_run(
    request_bytes: bytes,
    *,
    token: str,
    published_at: str,
    timeout_seconds: float = DEFAULT_GITHUB_CHECK_RUN_TIMEOUT_SECONDS,
    transport: GitHubCheckRunTransport | None = None,
) -> GitHubCheckRunReceipt:
    """Publish one completed Check Run and return a minimized response receipt."""

    request = parse_github_check_run_request_bytes(request_bytes)
    if request.is_fork:
        raise GitHubCheckRunPublishError(
            "fork_unsupported",
            (
                "direct Check Run publication is unavailable for fork pull requests; "
                "use the unprivileged workflow-job result or a separately designed GitHub App"
            ),
        )
    if (
        not isinstance(token, str)
        or not token
        or token != token.strip()
        or len(token) > 8192
        or any(ord(character) < 33 or ord(character) == 127 for character in token)
    ):
        raise GitHubCheckRunPublishError("token_invalid", "expected a non-empty bearer token")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < float(timeout_seconds) <= MAX_GITHUB_CHECK_RUN_TIMEOUT_SECONDS
    ):
        raise GitHubCheckRunPublishError(
            "timeout_invalid",
            f"timeout must be greater than zero and at most {MAX_GITHUB_CHECK_RUN_TIMEOUT_SECONDS}",
        )
    try:
        publication_time = _timestamp(
            published_at,
            "$.published_at",
            "GitHub Check Run receipt",
        )
    except GitHubCheckRunValidationError as exc:
        raise GitHubCheckRunPublishError("published_at_invalid", str(exc)) from exc
    gap_seconds = (
        _timestamp_value(publication_time) - _timestamp_value(request.created_at)
    ).total_seconds()
    if gap_seconds < -1 or gap_seconds > MAX_CHECK_REQUEST_TO_PUBLICATION_SECONDS:
        raise GitHubCheckRunPublishError(
            "request_stale",
            (
                "publication time must be within one second before and "
                f"{MAX_CHECK_REQUEST_TO_PUBLICATION_SECONDS} seconds after request creation"
            ),
        )
    api_body = github_check_run_api_body(request)
    response = (transport or UrllibGitHubCheckRunTransport()).post(
        _github_api_endpoint(request.repository),
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json; charset=utf-8",
            "User-Agent": "Causure",
            "X-GitHub-Api-Version": GITHUB_REST_API_VERSION,
        },
        body=api_body,
        timeout_seconds=float(timeout_seconds),
    )
    if response.status_code != 201:
        raise GitHubCheckRunPublishError(
            "http_status",
            f"GitHub Checks API returned HTTP {response.status_code}",
        )
    content_type = next(
        (value for key, value in response.headers.items() if key.casefold() == "content-type"),
        "",
    )
    if content_type.split(";", 1)[0].strip().casefold() not in {
        "application/json",
        "application/vnd.github+json",
    }:
        raise GitHubCheckRunPublishError(
            "response_content_type",
            "GitHub Checks API did not return JSON",
        )
    try:
        response_document = _parse_json_bytes(
            response.body,
            description="GitHub Check Run response",
            maximum=MAX_GITHUB_CHECK_RUN_RESPONSE_BYTES,
        )
    except GitHubCheckRunValidationError as exc:
        raise GitHubCheckRunPublishError("response_invalid", str(exc)) from exc
    root = _response_object(response_document, "$")
    check_run_id = _response_integer(root.get("id"), "$.id")
    response_name = _response_string(root.get("name"), "$.name", maximum=128)
    response_head_sha = _response_string(root.get("head_sha"), "$.head_sha", maximum=64)
    response_status = _response_string(root.get("status"), "$.status", maximum=32)
    response_conclusion = _response_string(root.get("conclusion"), "$.conclusion", maximum=32)
    response_external_id = _response_string(root.get("external_id"), "$.external_id", maximum=255)
    html_url = _response_string(root.get("html_url"), "$.html_url", maximum=2048)
    expected_html_prefix = f"https://github.com/{request.repository.full_name}/runs/"
    if (
        response_name != request.name
        or response_head_sha != request.head_sha
        or response_status != "completed"
        or response_conclusion != request.conclusion
        or response_external_id != request.external_id
        or not html_url.startswith(expected_html_prefix)
        or not html_url[len(expected_html_prefix) :].isdigit()
    ):
        raise GitHubCheckRunPublishError(
            "response_mismatch",
            "GitHub Check Run response does not match the submitted request",
        )
    request_subject = ArtifactIntegrity(
        media_type=GITHUB_CHECK_RUN_REQUEST_MEDIA_TYPE,
        sha256=hashlib.sha256(request_bytes).hexdigest(),
        byte_count=len(request_bytes),
    )
    receipt = GitHubCheckRunReceipt(
        schema_version=GITHUB_CHECK_RUN_RECEIPT_SCHEMA_VERSION,
        status="published",
        published_at=publication_time,
        repository=request.repository,
        pull_request_number=request.pull_request_number,
        head_sha=request.head_sha,
        workflow_run_id=request.workflow_run_id,
        run_attempt=request.run_attempt,
        check_run_id=check_run_id,
        name=request.name,
        conclusion=request.conclusion,
        external_id=request.external_id,
        html_url=html_url,
        annotation_count=len(request.findings),
        request=request_subject,
        verification=request.verification,
    )
    return parse_github_check_run_receipt(to_jsonable(receipt))


def parse_github_check_run_receipt(document: Any) -> GitHubCheckRunReceipt:
    """Strictly parse a minimized successful Check Run receipt."""

    name = "GitHub Check Run receipt"
    root = _object(
        document,
        "$",
        name,
        required={
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
        },
    )
    schema_version = _string(root["schema_version"], "$.schema_version", name, maximum=16)
    if schema_version != GITHUB_CHECK_RUN_RECEIPT_SCHEMA_VERSION:
        raise GitHubCheckRunValidationError(
            name,
            "$.schema_version",
            f"expected {GITHUB_CHECK_RUN_RECEIPT_SCHEMA_VERSION!r}",
        )
    status = _string(root["status"], "$.status", name, maximum=32)
    if status != "published":
        raise GitHubCheckRunValidationError(name, "$.status", "expected 'published'")
    receipt = GitHubCheckRunReceipt(
        schema_version=schema_version,
        status=status,
        published_at=_timestamp(root["published_at"], "$.published_at", name),
        repository=_parse_repository(root["repository"], "$.repository", name),
        pull_request_number=_integer(root["pull_request_number"], "$.pull_request_number", name),
        head_sha=_string(
            root["head_sha"],
            "$.head_sha",
            name,
            maximum=64,
            pattern=_GIT_COMMIT_PATTERN,
        ),
        workflow_run_id=_integer(root["workflow_run_id"], "$.workflow_run_id", name),
        run_attempt=_integer(root["run_attempt"], "$.run_attempt", name),
        check_run_id=_integer(root["check_run_id"], "$.check_run_id", name),
        name=_string(root["name"], "$.name", name, maximum=128),
        conclusion=_string(root["conclusion"], "$.conclusion", name, maximum=32),
        external_id=_string(root["external_id"], "$.external_id", name, maximum=255),
        html_url=_string(root["html_url"], "$.html_url", name, maximum=2048),
        annotation_count=_integer(
            root["annotation_count"],
            "$.annotation_count",
            name,
            minimum=0,
            maximum=MAX_GITHUB_CHECK_RUN_ANNOTATIONS,
        ),
        request=_parse_artifact(
            root["request"],
            "$.request",
            name,
            expected_media_type=GITHUB_CHECK_RUN_REQUEST_MEDIA_TYPE,
            maximum_bytes=MAX_GITHUB_CHECK_RUN_REQUEST_BYTES,
        ),
        verification=_parse_artifact(
            root["verification"],
            "$.verification",
            name,
            expected_media_type=GITHUB_REVIEW_VERIFICATION_MEDIA_TYPE,
            maximum_bytes=MAX_GITHUB_VERIFICATION_BYTES,
        ),
    )
    expected_html_prefix = f"https://github.com/{receipt.repository.full_name}/runs/"
    expected_external = _external_id(
        receipt.repository,
        receipt.pull_request_number,
        receipt.workflow_run_id,
        receipt.run_attempt,
        receipt.verification.sha256,
    )
    html_identifier = receipt.html_url[len(expected_html_prefix) :]
    if (
        receipt.name != GITHUB_CHECK_RUN_NAME
        or receipt.conclusion not in {"success", "failure", "action_required"}
        or receipt.external_id != expected_external
        or not receipt.html_url.startswith(expected_html_prefix)
        or not html_identifier.isdigit()
        or int(html_identifier) != receipt.check_run_id
    ):
        raise GitHubCheckRunValidationError(name, "$", "receipt identity is inconsistent")
    return receipt


def parse_github_check_run_receipt_bytes(raw_bytes: bytes) -> GitHubCheckRunReceipt:
    """Parse bounded exact successful Check Run receipt bytes."""

    return parse_github_check_run_receipt(
        _parse_json_bytes(
            raw_bytes,
            description="GitHub Check Run receipt",
            maximum=MAX_GITHUB_CHECK_RUN_RECEIPT_BYTES,
        )
    )


def render_github_check_run_receipt(receipt: GitHubCheckRunReceipt) -> str:
    """Render a stable successful Check Run receipt."""

    validated = parse_github_check_run_receipt(to_jsonable(receipt))
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


def verify_github_check_run_receipt(
    request_bytes: bytes,
    receipt_bytes: bytes,
) -> GitHubCheckRunReceipt:
    """Bind a successful API receipt back to the exact token-free request bytes."""

    request = parse_github_check_run_request_bytes(request_bytes)
    receipt = parse_github_check_run_receipt_bytes(receipt_bytes)
    expected_request = ArtifactIntegrity(
        media_type=GITHUB_CHECK_RUN_REQUEST_MEDIA_TYPE,
        sha256=hashlib.sha256(request_bytes).hexdigest(),
        byte_count=len(request_bytes),
    )
    expected = (
        receipt.repository == request.repository
        and receipt.pull_request_number == request.pull_request_number
        and receipt.head_sha == request.head_sha
        and receipt.workflow_run_id == request.workflow_run_id
        and receipt.run_attempt == request.run_attempt
        and receipt.name == request.name
        and receipt.conclusion == request.conclusion
        and receipt.external_id == request.external_id
        and receipt.annotation_count == len(request.findings)
        and receipt.request == expected_request
        and receipt.verification == request.verification
    )
    if not expected:
        raise GitHubCheckRunPublishError(
            "receipt_mismatch",
            "Check Run receipt does not correspond to the exact request",
        )
    gap_seconds = (
        _timestamp_value(receipt.published_at) - _timestamp_value(request.created_at)
    ).total_seconds()
    if gap_seconds < -1 or gap_seconds > MAX_CHECK_REQUEST_TO_PUBLICATION_SECONDS:
        raise GitHubCheckRunPublishError(
            "receipt_time_invalid",
            "Check Run receipt publication time is outside the request window",
        )
    return receipt
