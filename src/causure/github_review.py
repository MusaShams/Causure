"""Tamper-evident GitHub pull-request review publication records."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from causure.azure_devops import ArtifactIntegrity, PublicationSubject, ReviewBinding
from causure.constants import (
    GITHUB_REVIEW_PUBLICATION_SCHEMA_VERSION,
    GITHUB_REVIEW_VERIFICATION_SCHEMA_VERSION,
    RESULT_SCHEMA_VERSION,
    Component,
    Decision,
    RecommendedAction,
)
from causure.errors import DocumentValidationError
from causure.io import InputDocumentError, parse_json_text
from causure.models import document_sha256, parse_change_case, to_jsonable

MAX_GITHUB_CHANGE_CASE_BYTES = 5 * 1024 * 1024
MAX_GITHUB_REVIEW_RESULT_BYTES = 5 * 1024 * 1024
MAX_GITHUB_REVIEW_REPORT_BYTES = 2 * 1024 * 1024
MAX_GITHUB_EVENT_BYTES = 25 * 1024 * 1024
MAX_GITHUB_PUBLICATION_BYTES = 1024 * 1024
MAX_GITHUB_VERIFICATION_BYTES = 1024 * 1024
DEFAULT_MAX_GITHUB_PUBLICATION_AGE_SECONDS = 3600
MAX_GITHUB_PUBLICATION_AGE_SECONDS = 24 * 60 * 60
MAX_REVIEW_TO_GITHUB_PUBLICATION_SECONDS = 300

GITHUB_CHANGE_CASE_MEDIA_TYPE = "application/vnd.causure.change-case+json"
GITHUB_REVIEW_RESULT_MEDIA_TYPE = "application/vnd.causure.review-result+json"
GITHUB_REVIEW_REPORT_MEDIA_TYPE = "text/markdown; charset=utf-8"
GITHUB_EVENT_MEDIA_TYPE = "application/json"
GITHUB_REVIEW_PUBLICATION_MEDIA_TYPE = "application/vnd.causure.github-review-publication+json"
GITHUB_REVIEW_VERIFICATION_MEDIA_TYPE = "application/vnd.causure.github-review-verification+json"

_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_GIT_COMMIT_PATTERN = re.compile(r"^(?:[a-f0-9]{40}|[a-f0-9]{64})$")
_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_UTC_TIMESTAMP_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_REVIEW_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T"
    r"[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?Z$"
)
_NO_CONTROL_PATTERN = re.compile(r"^[^\x00-\x1f\x7f]+$")
_SUPPORTED_PULL_REQUEST_ACTIONS = frozenset(
    {"opened", "ready_for_review", "reopened", "synchronize"}
)


class GitHubReviewValidationError(ValueError):
    """Raised when a GitHub review boundary document is structurally invalid."""

    def __init__(self, document_name: str, path: str, message: str) -> None:
        self.document_name = document_name
        self.path = path
        self.message = message
        super().__init__(f"Invalid {document_name} at {path}: {message}")


class GitHubReviewVerificationError(ValueError):
    """Raised when a GitHub publication fails closed during verification."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


@dataclass(frozen=True, slots=True)
class GitHubRepositoryIdentity:
    """Stable and human-readable identity for one GitHub repository."""

    repository_id: int
    owner_id: int
    full_name: str


@dataclass(frozen=True, slots=True)
class GitHubPullRequestContext:
    """The exact base and candidate identities from one pull-request event."""

    number: int
    base_repository: GitHubRepositoryIdentity
    base_ref: str
    base_sha: str
    head_repository: GitHubRepositoryIdentity
    head_ref: str
    head_sha: str
    is_fork: bool
    draft: bool


@dataclass(frozen=True, slots=True)
class GitHubWorkflowRunContext:
    """GitHub-hosted workflow identity used to create or verify a publication."""

    server_url: str
    event_name: str
    event_action: str
    event_sha: str
    ref: str
    workflow_ref: str
    workflow_sha: str
    run_id: int
    run_number: int
    run_attempt: int
    job: str
    event_payload: ArtifactIntegrity


@dataclass(frozen=True, slots=True)
class GitHubReviewArtifacts:
    """Exact portable artifacts attached to the GitHub review decision."""

    change_case: ArtifactIntegrity
    review_result: ArtifactIntegrity
    review_report: ArtifactIntegrity


@dataclass(frozen=True, slots=True)
class GitHubReviewPublication:
    """Closed binding between a review and one GitHub pull-request head."""

    schema_version: str
    created_at: str
    review: ReviewBinding
    pull_request: GitHubPullRequestContext
    workflow: GitHubWorkflowRunContext
    artifacts: GitHubReviewArtifacts


@dataclass(frozen=True, slots=True)
class GitHubReviewVerification:
    """Successful re-verification of a GitHub review publication."""

    schema_version: str
    status: str
    verified_at: str
    maximum_age_seconds: int
    publication_age_seconds: int
    publication: PublicationSubject
    review: ReviewBinding
    pull_request: GitHubPullRequestContext
    workflow: GitHubWorkflowRunContext
    artifacts: GitHubReviewArtifacts


def _object(
    value: Any,
    path: str,
    document_name: str,
    *,
    required: set[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubReviewValidationError(document_name, path, "expected an object")
    missing = sorted(required - value.keys())
    if missing:
        raise GitHubReviewValidationError(
            document_name,
            f"{path}.{missing[0]}",
            "required property is missing",
        )
    unknown = sorted(value.keys() - required)
    if unknown:
        raise GitHubReviewValidationError(
            document_name,
            f"{path}.{unknown[0]}",
            "property is not allowed",
        )
    return value


def _source_object(value: Any, path: str, document_name: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubReviewValidationError(document_name, path, "expected an object")
    return value


def _string(
    value: Any,
    path: str,
    document_name: str,
    *,
    maximum: int,
    pattern: re.Pattern[str] | None = _NO_CONTROL_PATTERN,
) -> str:
    if not isinstance(value, str):
        raise GitHubReviewValidationError(document_name, path, "expected a string")
    if not value or value != value.strip():
        raise GitHubReviewValidationError(
            document_name,
            path,
            "expected a non-empty string without surrounding whitespace",
        )
    if len(value) > maximum:
        raise GitHubReviewValidationError(
            document_name,
            path,
            f"expected at most {maximum} characters",
        )
    if pattern is not None and pattern.fullmatch(value) is None:
        raise GitHubReviewValidationError(document_name, path, "value has an invalid format")
    return value


def _integer(
    value: Any,
    path: str,
    document_name: str,
    *,
    minimum: int = 1,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise GitHubReviewValidationError(
            document_name,
            path,
            f"expected an integer of at least {minimum}",
        )
    return value


def _boolean(value: Any, path: str, document_name: str) -> bool:
    if not isinstance(value, bool):
        raise GitHubReviewValidationError(document_name, path, "expected a boolean")
    return value


def _enum(value: Any, path: str, document_name: str, enum_type: type) -> Any:
    candidate = _string(value, path, document_name, maximum=128)
    try:
        return enum_type(candidate)
    except ValueError as exc:
        choices = ", ".join(item.value for item in enum_type)
        raise GitHubReviewValidationError(
            document_name,
            path,
            f"expected one of: {choices}",
        ) from exc


def _timestamp(
    value: Any,
    path: str,
    document_name: str,
    *,
    whole_seconds: bool,
) -> str:
    pattern = _UTC_TIMESTAMP_PATTERN if whole_seconds else _REVIEW_TIMESTAMP_PATTERN
    timestamp = _string(value, path, document_name, maximum=32, pattern=pattern)
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise GitHubReviewValidationError(
            document_name,
            path,
            "expected a valid UTC timestamp",
        ) from exc
    return timestamp


def _timestamp_value(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _parse_json_bytes(raw_bytes: bytes, *, description: str, maximum: int) -> Any:
    if not raw_bytes or len(raw_bytes) > maximum:
        raise GitHubReviewValidationError(
            description,
            "$",
            f"expected from 1 to {maximum} bytes",
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GitHubReviewValidationError(description, "$", "expected UTF-8 JSON") from exc
    try:
        return parse_json_text(text, source=description)
    except InputDocumentError as exc:
        raise GitHubReviewValidationError(description, "$", str(exc)) from exc


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
        raise GitHubReviewValidationError(
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
            maximum=64,
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
        reviewed_at=_timestamp(
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


def _artifact_integrity(raw_bytes: bytes, media_type: str) -> ArtifactIntegrity:
    return ArtifactIntegrity(
        media_type=media_type,
        sha256=hashlib.sha256(raw_bytes).hexdigest(),
        byte_count=len(raw_bytes),
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
    media_type = _string(
        obj["media_type"],
        f"{path}.media_type",
        document_name,
        maximum=255,
    )
    if media_type != expected_media_type:
        raise GitHubReviewValidationError(
            document_name,
            f"{path}.media_type",
            f"expected {expected_media_type!r}",
        )
    byte_count = _integer(obj["byte_count"], f"{path}.byte_count", document_name)
    if byte_count > maximum_bytes:
        raise GitHubReviewValidationError(
            document_name,
            f"{path}.byte_count",
            f"expected at most {maximum_bytes}",
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
        byte_count=byte_count,
    )


def _parse_repository(
    value: Any,
    path: str,
    document_name: str,
) -> GitHubRepositoryIdentity:
    obj = _object(
        value,
        path,
        document_name,
        required={"repository_id", "owner_id", "full_name"},
    )
    return GitHubRepositoryIdentity(
        repository_id=_integer(
            obj["repository_id"],
            f"{path}.repository_id",
            document_name,
        ),
        owner_id=_integer(obj["owner_id"], f"{path}.owner_id", document_name),
        full_name=_string(
            obj["full_name"],
            f"{path}.full_name",
            document_name,
            maximum=255,
            pattern=_REPOSITORY_PATTERN,
        ),
    )


def _parse_pull_request(
    value: Any,
    path: str,
    document_name: str,
) -> GitHubPullRequestContext:
    obj = _object(
        value,
        path,
        document_name,
        required={
            "number",
            "base_repository",
            "base_ref",
            "base_sha",
            "head_repository",
            "head_ref",
            "head_sha",
            "is_fork",
            "draft",
        },
    )
    pull_request = GitHubPullRequestContext(
        number=_integer(obj["number"], f"{path}.number", document_name),
        base_repository=_parse_repository(
            obj["base_repository"],
            f"{path}.base_repository",
            document_name,
        ),
        base_ref=_string(
            obj["base_ref"],
            f"{path}.base_ref",
            document_name,
            maximum=255,
        ),
        base_sha=_string(
            obj["base_sha"],
            f"{path}.base_sha",
            document_name,
            maximum=64,
            pattern=_GIT_COMMIT_PATTERN,
        ),
        head_repository=_parse_repository(
            obj["head_repository"],
            f"{path}.head_repository",
            document_name,
        ),
        head_ref=_string(
            obj["head_ref"],
            f"{path}.head_ref",
            document_name,
            maximum=255,
        ),
        head_sha=_string(
            obj["head_sha"],
            f"{path}.head_sha",
            document_name,
            maximum=64,
            pattern=_GIT_COMMIT_PATTERN,
        ),
        is_fork=_boolean(obj["is_fork"], f"{path}.is_fork", document_name),
        draft=_boolean(obj["draft"], f"{path}.draft", document_name),
    )
    expected_fork = (
        pull_request.head_repository.repository_id != pull_request.base_repository.repository_id
    )
    if pull_request.is_fork != expected_fork:
        raise GitHubReviewValidationError(
            document_name,
            f"{path}.is_fork",
            "must agree with the base and head repository IDs",
        )
    return pull_request


def _parse_workflow(
    value: Any,
    path: str,
    document_name: str,
) -> GitHubWorkflowRunContext:
    obj = _object(
        value,
        path,
        document_name,
        required={
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
        },
    )
    event_name = _string(
        obj["event_name"],
        f"{path}.event_name",
        document_name,
        maximum=64,
    )
    if event_name != "pull_request":
        raise GitHubReviewValidationError(
            document_name,
            f"{path}.event_name",
            "expected 'pull_request'",
        )
    event_action = _string(
        obj["event_action"],
        f"{path}.event_action",
        document_name,
        maximum=64,
    )
    if event_action not in _SUPPORTED_PULL_REQUEST_ACTIONS:
        raise GitHubReviewValidationError(
            document_name,
            f"{path}.event_action",
            "unsupported pull-request action",
        )
    return GitHubWorkflowRunContext(
        server_url=_https_server_url(
            obj["server_url"],
            f"{path}.server_url",
            document_name,
        ),
        event_name=event_name,
        event_action=event_action,
        event_sha=_string(
            obj["event_sha"],
            f"{path}.event_sha",
            document_name,
            maximum=64,
            pattern=_GIT_COMMIT_PATTERN,
        ),
        ref=_string(obj["ref"], f"{path}.ref", document_name, maximum=512),
        workflow_ref=_string(
            obj["workflow_ref"],
            f"{path}.workflow_ref",
            document_name,
            maximum=1024,
        ),
        workflow_sha=_string(
            obj["workflow_sha"],
            f"{path}.workflow_sha",
            document_name,
            maximum=64,
            pattern=_GIT_COMMIT_PATTERN,
        ),
        run_id=_integer(obj["run_id"], f"{path}.run_id", document_name),
        run_number=_integer(
            obj["run_number"],
            f"{path}.run_number",
            document_name,
        ),
        run_attempt=_integer(
            obj["run_attempt"],
            f"{path}.run_attempt",
            document_name,
        ),
        job=_string(obj["job"], f"{path}.job", document_name, maximum=255),
        event_payload=_parse_artifact(
            obj["event_payload"],
            f"{path}.event_payload",
            document_name,
            expected_media_type=GITHUB_EVENT_MEDIA_TYPE,
            maximum_bytes=MAX_GITHUB_EVENT_BYTES,
        ),
    )


def _validate_context_consistency(
    pull_request: GitHubPullRequestContext,
    workflow: GitHubWorkflowRunContext,
    *,
    document_name: str,
) -> None:
    expected_ref = f"refs/pull/{pull_request.number}/merge"
    if workflow.ref != expected_ref:
        raise GitHubReviewValidationError(
            document_name,
            "$.workflow.ref",
            f"expected {expected_ref!r} for the pull-request merge ref",
        )
    workflow_path, separator, workflow_source = workflow.workflow_ref.rpartition("@")
    expected_prefix = f"{pull_request.base_repository.full_name}/.github/workflows/"
    if (
        not separator
        or not workflow_source
        or not workflow_path.casefold().startswith(expected_prefix.casefold())
        or workflow_path.casefold() == expected_prefix.casefold()
        or "\\" in workflow_path
        or "/../" in workflow_path
    ):
        raise GitHubReviewValidationError(
            document_name,
            "$.workflow.workflow_ref",
            "must identify a workflow under the base repository's .github/workflows directory",
        )


def _parse_artifacts(
    value: Any,
    path: str,
    document_name: str,
) -> GitHubReviewArtifacts:
    obj = _object(
        value,
        path,
        document_name,
        required={"change_case", "review_result", "review_report"},
    )
    return GitHubReviewArtifacts(
        change_case=_parse_artifact(
            obj["change_case"],
            f"{path}.change_case",
            document_name,
            expected_media_type=GITHUB_CHANGE_CASE_MEDIA_TYPE,
            maximum_bytes=MAX_GITHUB_CHANGE_CASE_BYTES,
        ),
        review_result=_parse_artifact(
            obj["review_result"],
            f"{path}.review_result",
            document_name,
            expected_media_type=GITHUB_REVIEW_RESULT_MEDIA_TYPE,
            maximum_bytes=MAX_GITHUB_REVIEW_RESULT_BYTES,
        ),
        review_report=_parse_artifact(
            obj["review_report"],
            f"{path}.review_report",
            document_name,
            expected_media_type=GITHUB_REVIEW_REPORT_MEDIA_TYPE,
            maximum_bytes=MAX_GITHUB_REVIEW_REPORT_BYTES,
        ),
    )


def _https_server_url(value: Any, path: str, document_name: str) -> str:
    candidate = _string(value, path, document_name, maximum=2048)
    parsed = urlsplit(candidate)
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise GitHubReviewValidationError(
            document_name,
            path,
            "expected an HTTPS server origin without credentials, path, query, or fragment",
        )
    return urlunsplit(("https", parsed.netloc.lower(), "", "", ""))


def _required_environment(
    environment: Mapping[str, str],
    name: str,
    *,
    maximum: int = 2048,
) -> str:
    value = environment.get(name)
    if value is None:
        raise GitHubReviewValidationError(
            "GitHub Actions environment",
            name,
            "required variable is missing or empty",
        )
    return _string(value, name, "GitHub Actions environment", maximum=maximum)


def _environment_integer(environment: Mapping[str, str], name: str) -> int:
    value = _required_environment(environment, name, maximum=32)
    try:
        parsed = int(value)
    except ValueError as exc:
        raise GitHubReviewValidationError(
            "GitHub Actions environment",
            name,
            "expected a positive integer",
        ) from exc
    return _integer(parsed, name, "GitHub Actions environment")


def _event_repository(value: Any, path: str) -> GitHubRepositoryIdentity:
    document_name = "GitHub pull-request event"
    obj = _source_object(value, path, document_name)
    owner = _source_object(obj.get("owner"), f"{path}.owner", document_name)
    return GitHubRepositoryIdentity(
        repository_id=_integer(obj.get("id"), f"{path}.id", document_name),
        owner_id=_integer(owner.get("id"), f"{path}.owner.id", document_name),
        full_name=_string(
            obj.get("full_name"),
            f"{path}.full_name",
            document_name,
            maximum=255,
            pattern=_REPOSITORY_PATTERN,
        ),
    )


def _event_commit_side(
    value: Any,
    path: str,
) -> tuple[str, str, GitHubRepositoryIdentity]:
    document_name = "GitHub pull-request event"
    obj = _source_object(value, path, document_name)
    return (
        _string(obj.get("ref"), f"{path}.ref", document_name, maximum=255),
        _string(
            obj.get("sha"),
            f"{path}.sha",
            document_name,
            maximum=64,
            pattern=_GIT_COMMIT_PATTERN,
        ),
        _event_repository(obj.get("repo"), f"{path}.repo"),
    )


def _event_bytes_from_environment(environment: Mapping[str, str]) -> bytes:
    event_path = Path(_required_environment(environment, "GITHUB_EVENT_PATH", maximum=32767))
    try:
        size = event_path.stat().st_size
        if not event_path.is_file() or not 1 <= size <= MAX_GITHUB_EVENT_BYTES:
            raise GitHubReviewValidationError(
                "GitHub Actions environment",
                "GITHUB_EVENT_PATH",
                f"expected a regular event file from 1 to {MAX_GITHUB_EVENT_BYTES} bytes",
            )
        raw_bytes = event_path.read_bytes()
    except GitHubReviewValidationError:
        raise
    except OSError as exc:
        raise GitHubReviewValidationError(
            "GitHub Actions environment",
            "GITHUB_EVENT_PATH",
            f"could not read the event file: {exc}",
        ) from exc
    if len(raw_bytes) != size:
        raise GitHubReviewValidationError(
            "GitHub Actions environment",
            "GITHUB_EVENT_PATH",
            "event file changed while it was being read",
        )
    return raw_bytes


def github_context_from_environment(
    environment: Mapping[str, str],
    *,
    event_bytes: bytes | None = None,
) -> tuple[GitHubPullRequestContext, GitHubWorkflowRunContext]:
    """Read and validate one unprivileged pull-request workflow identity."""

    if _required_environment(environment, "GITHUB_ACTIONS", maximum=8).lower() != "true":
        raise GitHubReviewValidationError(
            "GitHub Actions environment",
            "GITHUB_ACTIONS",
            "expected 'true' on a GitHub Actions runner",
        )
    event_name = _required_environment(environment, "GITHUB_EVENT_NAME", maximum=64)
    if event_name != "pull_request":
        raise GitHubReviewValidationError(
            "GitHub Actions environment",
            "GITHUB_EVENT_NAME",
            "expected 'pull_request'; pull_request_target is deliberately unsupported",
        )
    raw_event = (
        event_bytes if event_bytes is not None else _event_bytes_from_environment(environment)
    )
    event = _source_object(
        _parse_json_bytes(
            raw_event,
            description="GitHub pull-request event",
            maximum=MAX_GITHUB_EVENT_BYTES,
        ),
        "$",
        "GitHub pull-request event",
    )
    action = _string(
        event.get("action"),
        "$.action",
        "GitHub pull-request event",
        maximum=64,
    )
    if action not in _SUPPORTED_PULL_REQUEST_ACTIONS:
        raise GitHubReviewValidationError(
            "GitHub pull-request event",
            "$.action",
            "unsupported pull-request action",
        )
    number = _integer(event.get("number"), "$.number", "GitHub pull-request event")
    event_repository = _event_repository(event.get("repository"), "$.repository")
    pull_request_obj = _source_object(
        event.get("pull_request"),
        "$.pull_request",
        "GitHub pull-request event",
    )
    pull_request_number = _integer(
        pull_request_obj.get("number"),
        "$.pull_request.number",
        "GitHub pull-request event",
    )
    if pull_request_number != number:
        raise GitHubReviewValidationError(
            "GitHub pull-request event",
            "$.pull_request.number",
            "does not match the root pull-request number",
        )
    base_ref, base_sha, base_repository = _event_commit_side(
        pull_request_obj.get("base"),
        "$.pull_request.base",
    )
    head_ref, head_sha, head_repository = _event_commit_side(
        pull_request_obj.get("head"),
        "$.pull_request.head",
    )
    if base_repository != event_repository:
        raise GitHubReviewValidationError(
            "GitHub pull-request event",
            "$.pull_request.base.repo",
            "does not match the event repository",
        )
    pull_request = GitHubPullRequestContext(
        number=number,
        base_repository=base_repository,
        base_ref=base_ref,
        base_sha=base_sha,
        head_repository=head_repository,
        head_ref=head_ref,
        head_sha=head_sha,
        is_fork=head_repository.repository_id != base_repository.repository_id,
        draft=_boolean(
            pull_request_obj.get("draft"),
            "$.pull_request.draft",
            "GitHub pull-request event",
        ),
    )

    repository_name = _required_environment(environment, "GITHUB_REPOSITORY", maximum=255)
    if repository_name.casefold() != base_repository.full_name.casefold():
        raise GitHubReviewValidationError(
            "GitHub Actions environment",
            "GITHUB_REPOSITORY",
            "does not match the event base repository",
        )
    if _environment_integer(environment, "GITHUB_REPOSITORY_ID") != base_repository.repository_id:
        raise GitHubReviewValidationError(
            "GitHub Actions environment",
            "GITHUB_REPOSITORY_ID",
            "does not match the event base repository ID",
        )
    if _environment_integer(environment, "GITHUB_REPOSITORY_OWNER_ID") != base_repository.owner_id:
        raise GitHubReviewValidationError(
            "GitHub Actions environment",
            "GITHUB_REPOSITORY_OWNER_ID",
            "does not match the event base owner ID",
        )
    repository_owner = _required_environment(
        environment,
        "GITHUB_REPOSITORY_OWNER",
        maximum=128,
    )
    if repository_owner.casefold() != base_repository.full_name.split("/", 1)[0].casefold():
        raise GitHubReviewValidationError(
            "GitHub Actions environment",
            "GITHUB_REPOSITORY_OWNER",
            "does not match the event base repository owner",
        )
    if _required_environment(environment, "GITHUB_BASE_REF", maximum=255) != base_ref:
        raise GitHubReviewValidationError(
            "GitHub Actions environment",
            "GITHUB_BASE_REF",
            "does not match the event base ref",
        )
    if _required_environment(environment, "GITHUB_HEAD_REF", maximum=255) != head_ref:
        raise GitHubReviewValidationError(
            "GitHub Actions environment",
            "GITHUB_HEAD_REF",
            "does not match the event head ref",
        )

    workflow = GitHubWorkflowRunContext(
        server_url=_https_server_url(
            _required_environment(environment, "GITHUB_SERVER_URL"),
            "GITHUB_SERVER_URL",
            "GitHub Actions environment",
        ),
        event_name=event_name,
        event_action=action,
        event_sha=_string(
            _required_environment(environment, "GITHUB_SHA", maximum=64),
            "GITHUB_SHA",
            "GitHub Actions environment",
            maximum=64,
            pattern=_GIT_COMMIT_PATTERN,
        ),
        ref=_required_environment(environment, "GITHUB_REF", maximum=512),
        workflow_ref=_required_environment(environment, "GITHUB_WORKFLOW_REF", maximum=1024),
        workflow_sha=_string(
            _required_environment(environment, "GITHUB_WORKFLOW_SHA", maximum=64),
            "GITHUB_WORKFLOW_SHA",
            "GitHub Actions environment",
            maximum=64,
            pattern=_GIT_COMMIT_PATTERN,
        ),
        run_id=_environment_integer(environment, "GITHUB_RUN_ID"),
        run_number=_environment_integer(environment, "GITHUB_RUN_NUMBER"),
        run_attempt=_environment_integer(environment, "GITHUB_RUN_ATTEMPT"),
        job=_required_environment(environment, "GITHUB_JOB", maximum=255),
        event_payload=_artifact_integrity(raw_event, GITHUB_EVENT_MEDIA_TYPE),
    )
    _validate_context_consistency(
        pull_request,
        workflow,
        document_name="GitHub Actions environment",
    )
    return pull_request, workflow


def _parse_change_case_bytes(raw_bytes: bytes, review: ReviewBinding) -> None:
    document = _parse_json_bytes(
        raw_bytes,
        description="change case",
        maximum=MAX_GITHUB_CHANGE_CASE_BYTES,
    )
    try:
        case = parse_change_case(document)
    except DocumentValidationError as exc:
        raise GitHubReviewValidationError("change case", "$", str(exc)) from exc
    if case.case_id != review.case_id:
        raise GitHubReviewValidationError(
            "change case",
            "$.case_id",
            "does not match the review result",
        )
    if case.proposed_change.component is not review.component:
        raise GitHubReviewValidationError(
            "change case",
            "$.proposed_change.component",
            "does not match the review result",
        )
    if document_sha256(case) != review.input_sha256:
        raise GitHubReviewValidationError(
            "change case",
            "$",
            "canonical SHA-256 does not match the review result",
        )


def _validate_report(raw_bytes: bytes, review: ReviewBinding) -> None:
    if not raw_bytes or len(raw_bytes) > MAX_GITHUB_REVIEW_REPORT_BYTES:
        raise GitHubReviewValidationError(
            "review report",
            "$",
            f"expected from 1 to {MAX_GITHUB_REVIEW_REPORT_BYTES} bytes",
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GitHubReviewValidationError(
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
        raise GitHubReviewValidationError(
            "review report",
            "$",
            "Markdown does not correspond to the supplied review result",
        )


def _review_from_result(raw_bytes: bytes) -> ReviewBinding:
    if not raw_bytes or len(raw_bytes) > MAX_GITHUB_REVIEW_RESULT_BYTES:
        raise GitHubReviewValidationError(
            "review result",
            "$",
            f"expected from 1 to {MAX_GITHUB_REVIEW_RESULT_BYTES} bytes",
        )
    try:
        from causure.azure_devops import parse_review_result_bytes

        return parse_review_result_bytes(raw_bytes)
    except (InputDocumentError, ValueError) as exc:
        raise GitHubReviewValidationError("review result", "$", str(exc)) from exc


def parse_github_review_publication(document: Any) -> GitHubReviewPublication:
    """Strictly parse an untrusted GitHub review-publication document."""

    name = "GitHub review publication"
    root = _object(
        document,
        "$",
        name,
        required={
            "schema_version",
            "created_at",
            "review",
            "pull_request",
            "workflow",
            "artifacts",
        },
    )
    schema_version = _string(
        root["schema_version"],
        "$.schema_version",
        name,
        maximum=16,
    )
    if schema_version != GITHUB_REVIEW_PUBLICATION_SCHEMA_VERSION:
        raise GitHubReviewValidationError(
            name,
            "$.schema_version",
            f"expected {GITHUB_REVIEW_PUBLICATION_SCHEMA_VERSION!r}",
        )
    publication = GitHubReviewPublication(
        schema_version=schema_version,
        created_at=_timestamp(
            root["created_at"],
            "$.created_at",
            name,
            whole_seconds=True,
        ),
        review=_parse_review(root["review"], "$.review", name),
        pull_request=_parse_pull_request(root["pull_request"], "$.pull_request", name),
        workflow=_parse_workflow(root["workflow"], "$.workflow", name),
        artifacts=_parse_artifacts(root["artifacts"], "$.artifacts", name),
    )
    gap_seconds = (
        _timestamp_value(publication.created_at) - _timestamp_value(publication.review.reviewed_at)
    ).total_seconds()
    if gap_seconds < -1 or gap_seconds > MAX_REVIEW_TO_GITHUB_PUBLICATION_SECONDS:
        raise GitHubReviewValidationError(
            name,
            "$.created_at",
            (
                "must be within one second before and "
                f"{MAX_REVIEW_TO_GITHUB_PUBLICATION_SECONDS} seconds after review.reviewed_at"
            ),
        )
    _validate_context_consistency(
        publication.pull_request,
        publication.workflow,
        document_name=name,
    )
    return publication


def parse_github_review_publication_bytes(raw_bytes: bytes) -> GitHubReviewPublication:
    """Parse a bounded GitHub publication from its exact UTF-8 bytes."""

    return parse_github_review_publication(
        _parse_json_bytes(
            raw_bytes,
            description="GitHub review publication",
            maximum=MAX_GITHUB_PUBLICATION_BYTES,
        )
    )


def create_github_review_publication(
    change_case_bytes: bytes,
    review_result_bytes: bytes,
    review_report_bytes: bytes,
    *,
    pull_request: GitHubPullRequestContext,
    workflow: GitHubWorkflowRunContext,
    created_at: str,
) -> GitHubReviewPublication:
    """Bind exact gate artifacts to the current GitHub pull-request head and run."""

    review = _review_from_result(review_result_bytes)
    _parse_change_case_bytes(change_case_bytes, review)
    _validate_report(review_report_bytes, review)
    _validate_context_consistency(
        pull_request,
        workflow,
        document_name="GitHub review publication",
    )
    publication = GitHubReviewPublication(
        schema_version=GITHUB_REVIEW_PUBLICATION_SCHEMA_VERSION,
        created_at=_timestamp(
            created_at,
            "$.created_at",
            "GitHub review publication",
            whole_seconds=True,
        ),
        review=review,
        pull_request=pull_request,
        workflow=workflow,
        artifacts=GitHubReviewArtifacts(
            change_case=_artifact_integrity(
                change_case_bytes,
                GITHUB_CHANGE_CASE_MEDIA_TYPE,
            ),
            review_result=_artifact_integrity(
                review_result_bytes,
                GITHUB_REVIEW_RESULT_MEDIA_TYPE,
            ),
            review_report=_artifact_integrity(
                review_report_bytes,
                GITHUB_REVIEW_REPORT_MEDIA_TYPE,
            ),
        ),
    )
    return parse_github_review_publication(to_jsonable(publication))


def render_github_review_publication(publication: GitHubReviewPublication) -> str:
    """Render a stable GitHub review-publication document."""

    validated = parse_github_review_publication(to_jsonable(publication))
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
        raise GitHubReviewVerificationError(
            "artifact_too_large",
            f"{role} exceeds the {maximum_bytes}-byte verification limit",
        )
    if len(raw_bytes) != expected.byte_count:
        raise GitHubReviewVerificationError(
            "artifact_size_mismatch",
            f"{role} byte count does not match the publication",
        )
    if hashlib.sha256(raw_bytes).hexdigest() != expected.sha256:
        raise GitHubReviewVerificationError(
            "artifact_digest_mismatch",
            f"{role} SHA-256 does not match the publication",
        )


def verify_github_review_publication(
    publication_bytes: bytes,
    change_case_bytes: bytes,
    review_result_bytes: bytes,
    review_report_bytes: bytes,
    *,
    expected_pull_request: GitHubPullRequestContext,
    expected_workflow: GitHubWorkflowRunContext,
    verified_at: str,
    maximum_age_seconds: int = DEFAULT_MAX_GITHUB_PUBLICATION_AGE_SECONDS,
) -> GitHubReviewVerification:
    """Recheck exact artifacts and the current GitHub event/run before completion."""

    if (
        isinstance(maximum_age_seconds, bool)
        or not isinstance(maximum_age_seconds, int)
        or not 1 <= maximum_age_seconds <= MAX_GITHUB_PUBLICATION_AGE_SECONDS
    ):
        raise GitHubReviewVerificationError(
            "maximum_age_invalid",
            f"maximum age must be from 1 to {MAX_GITHUB_PUBLICATION_AGE_SECONDS} seconds",
        )
    try:
        publication = parse_github_review_publication_bytes(publication_bytes)
        checked_at = _timestamp(
            verified_at,
            "$.verified_at",
            "GitHub review verification",
            whole_seconds=True,
        )
    except GitHubReviewValidationError as exc:
        raise GitHubReviewVerificationError("publication_invalid", str(exc)) from exc

    if publication.pull_request != expected_pull_request:
        raise GitHubReviewVerificationError(
            "pull_request_context_mismatch",
            "publication pull-request identity does not match the current GitHub event",
        )
    if publication.workflow != expected_workflow:
        raise GitHubReviewVerificationError(
            "workflow_context_mismatch",
            "publication workflow identity does not match the current GitHub run",
        )

    created = _timestamp_value(publication.created_at)
    checked = _timestamp_value(checked_at)
    if checked < created:
        raise GitHubReviewVerificationError(
            "publication_from_future",
            "publication creation time is later than verification time",
        )
    age_seconds = int((checked - created).total_seconds())
    if age_seconds > maximum_age_seconds:
        raise GitHubReviewVerificationError(
            "publication_stale",
            "publication is older than the permitted completion window",
        )

    for raw_bytes, expected, role, maximum in (
        (
            change_case_bytes,
            publication.artifacts.change_case,
            "change case",
            MAX_GITHUB_CHANGE_CASE_BYTES,
        ),
        (
            review_result_bytes,
            publication.artifacts.review_result,
            "review result",
            MAX_GITHUB_REVIEW_RESULT_BYTES,
        ),
        (
            review_report_bytes,
            publication.artifacts.review_report,
            "review report",
            MAX_GITHUB_REVIEW_REPORT_BYTES,
        ),
    ):
        _verify_artifact(
            raw_bytes,
            expected,
            role=role,
            maximum_bytes=maximum,
        )
    try:
        current_review = _review_from_result(review_result_bytes)
        _parse_change_case_bytes(change_case_bytes, current_review)
        _validate_report(review_report_bytes, current_review)
    except GitHubReviewValidationError as exc:
        raise GitHubReviewVerificationError("review_artifact_invalid", str(exc)) from exc
    if current_review != publication.review:
        raise GitHubReviewVerificationError(
            "review_binding_mismatch",
            "review-result identity does not match the publication",
        )

    return GitHubReviewVerification(
        schema_version=GITHUB_REVIEW_VERIFICATION_SCHEMA_VERSION,
        status="verified",
        verified_at=checked_at,
        maximum_age_seconds=maximum_age_seconds,
        publication_age_seconds=age_seconds,
        publication=PublicationSubject(
            media_type=GITHUB_REVIEW_PUBLICATION_MEDIA_TYPE,
            sha256=hashlib.sha256(publication_bytes).hexdigest(),
            byte_count=len(publication_bytes),
        ),
        review=publication.review,
        pull_request=publication.pull_request,
        workflow=publication.workflow,
        artifacts=publication.artifacts,
    )


def parse_github_review_verification(document: Any) -> GitHubReviewVerification:
    """Strictly parse a successful GitHub publication-verification receipt."""

    name = "GitHub review verification"
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
            "pull_request",
            "workflow",
            "artifacts",
        },
    )
    schema_version = _string(
        root["schema_version"],
        "$.schema_version",
        name,
        maximum=16,
    )
    if schema_version != GITHUB_REVIEW_VERIFICATION_SCHEMA_VERSION:
        raise GitHubReviewValidationError(
            name,
            "$.schema_version",
            f"expected {GITHUB_REVIEW_VERIFICATION_SCHEMA_VERSION!r}",
        )
    status = _string(root["status"], "$.status", name, maximum=16)
    if status != "verified":
        raise GitHubReviewValidationError(name, "$.status", "expected 'verified'")
    maximum_age = _integer(
        root["maximum_age_seconds"],
        "$.maximum_age_seconds",
        name,
    )
    if maximum_age > MAX_GITHUB_PUBLICATION_AGE_SECONDS:
        raise GitHubReviewValidationError(
            name,
            "$.maximum_age_seconds",
            f"expected at most {MAX_GITHUB_PUBLICATION_AGE_SECONDS}",
        )
    publication_age = _integer(
        root["publication_age_seconds"],
        "$.publication_age_seconds",
        name,
        minimum=0,
    )
    if publication_age > maximum_age:
        raise GitHubReviewValidationError(
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
    if media_type != GITHUB_REVIEW_PUBLICATION_MEDIA_TYPE:
        raise GitHubReviewValidationError(
            name,
            "$.publication.media_type",
            f"expected {GITHUB_REVIEW_PUBLICATION_MEDIA_TYPE!r}",
        )
    publication_bytes = _integer(
        publication_obj["byte_count"],
        "$.publication.byte_count",
        name,
    )
    if publication_bytes > MAX_GITHUB_PUBLICATION_BYTES:
        raise GitHubReviewValidationError(
            name,
            "$.publication.byte_count",
            f"expected at most {MAX_GITHUB_PUBLICATION_BYTES}",
        )
    pull_request = _parse_pull_request(root["pull_request"], "$.pull_request", name)
    workflow = _parse_workflow(root["workflow"], "$.workflow", name)
    _validate_context_consistency(pull_request, workflow, document_name=name)
    return GitHubReviewVerification(
        schema_version=schema_version,
        status=status,
        verified_at=_timestamp(
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
            byte_count=publication_bytes,
        ),
        review=_parse_review(root["review"], "$.review", name),
        pull_request=pull_request,
        workflow=workflow,
        artifacts=_parse_artifacts(root["artifacts"], "$.artifacts", name),
    )


def parse_github_review_verification_bytes(raw_bytes: bytes) -> GitHubReviewVerification:
    """Parse bounded exact GitHub review-verification bytes."""

    return parse_github_review_verification(
        _parse_json_bytes(
            raw_bytes,
            description="GitHub review verification",
            maximum=MAX_GITHUB_VERIFICATION_BYTES,
        )
    )


def render_github_review_verification(verification: GitHubReviewVerification) -> str:
    """Render a stable successful GitHub verification receipt."""

    validated = parse_github_review_verification(to_jsonable(verification))
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
