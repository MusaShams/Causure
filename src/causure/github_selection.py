"""Bounded GitHub pull-request file discovery and deterministic project selection."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from functools import lru_cache
from pathlib import PurePosixPath
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener

from causure.constants import Component
from causure.github_checks import GITHUB_REST_API_VERSION, GitHubHTTPResponse
from causure.github_review import GitHubPullRequestContext
from causure.io import parse_json_text
from causure.onboarding import ProjectConfiguration

MAX_GITHUB_PULL_FILES = 500
MAX_GITHUB_PULL_RESPONSE_BYTES = 8 * 1024 * 1024
MAX_GITHUB_PULL_TIMEOUT_SECONDS = 60.0
DEFAULT_GITHUB_PULL_TIMEOUT_SECONDS = 15.0
GITHUB_PULL_FILES_PER_PAGE = 100


class GitHubSelectionError(ValueError):
    """Raised when automatic GitHub component selection cannot be trusted."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"[{code}] {message}")


@dataclass(frozen=True, slots=True)
class GitHubChangedFile:
    """One normalized current path and optional previous path from a PR diff."""

    path: str
    previous_path: str | None


@dataclass(frozen=True, slots=True)
class GitHubChangeSelection:
    """The unique configured case selected from one pull request's changed paths."""

    component_id: str
    component: Component
    component_path: str
    matched_paths: tuple[str, ...]
    case_file: str
    policy_file: str
    artifact_retention_days: int


class GitHubPullFilesTransport(Protocol):
    """Injectable HTTPS transport used only for read-only PR discovery."""

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> GitHubHTTPResponse: ...


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


class UrllibGitHubPullFilesTransport:
    """Standard-library HTTPS GET transport with redirects and large bodies denied."""

    def get(
        self,
        url: str,
        *,
        headers: Mapping[str, str],
        timeout_seconds: float,
    ) -> GitHubHTTPResponse:
        request = Request(url, headers=dict(headers), method="GET")
        opener = build_opener(_NoRedirectHandler(), HTTPSHandler())
        try:
            with opener.open(request, timeout=timeout_seconds) as response:
                body = response.read(MAX_GITHUB_PULL_RESPONSE_BYTES + 1)
                status_code = response.status
                response_headers = {key.lower(): value for key, value in response.headers.items()}
        except HTTPError as exc:
            body = exc.read(MAX_GITHUB_PULL_RESPONSE_BYTES + 1)
            status_code = exc.code
            response_headers = {key.lower(): value for key, value in exc.headers.items()}
        except (OSError, URLError) as exc:
            raise GitHubSelectionError(
                "network_error",
                f"GitHub pull-request discovery failed: {type(exc).__name__}",
            ) from exc
        if len(body) > MAX_GITHUB_PULL_RESPONSE_BYTES:
            raise GitHubSelectionError(
                "response_too_large",
                "GitHub pull-request response exceeded the bounded response limit",
            )
        return GitHubHTTPResponse(
            status_code=status_code,
            headers=response_headers,
            body=body,
        )


def _validated_token(token: str) -> str:
    if (
        not isinstance(token, str)
        or not token
        or token != token.strip()
        or len(token) > 8192
        or any(ord(character) < 33 or ord(character) == 127 for character in token)
    ):
        raise GitHubSelectionError(
            "token_invalid",
            "automatic component selection requires the job's short-lived github-token",
        )
    return token


def _validated_timeout(timeout_seconds: float) -> float:
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not 0 < float(timeout_seconds) <= MAX_GITHUB_PULL_TIMEOUT_SECONDS
    ):
        raise GitHubSelectionError(
            "timeout_invalid",
            f"discovery timeout must be greater than zero and at most "
            f"{MAX_GITHUB_PULL_TIMEOUT_SECONDS}",
        )
    return float(timeout_seconds)


def _json_response(
    response: GitHubHTTPResponse,
    *,
    description: str,
) -> Any:
    if response.status_code != 200:
        raise GitHubSelectionError(
            "http_status",
            f"GitHub {description} endpoint returned HTTP {response.status_code}",
        )
    content_type = next(
        (value for key, value in response.headers.items() if key.casefold() == "content-type"),
        "",
    )
    if content_type.split(";", 1)[0].strip().casefold() not in {
        "application/json",
        "application/vnd.github+json",
    }:
        raise GitHubSelectionError(
            "response_content_type",
            f"GitHub {description} endpoint did not return JSON",
        )
    try:
        text = response.body.decode("utf-8")
        return parse_json_text(
            text,
            source=f"<GitHub {description} response>",
            max_bytes=MAX_GITHUB_PULL_RESPONSE_BYTES,
        )
    except (UnicodeDecodeError, ValueError) as exc:
        raise GitHubSelectionError(
            "response_invalid",
            f"GitHub {description} response was not valid bounded JSON",
        ) from exc


def _response_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GitHubSelectionError("response_invalid", f"expected an object at {path}")
    return value


def _response_integer(value: Any, path: str, *, allow_zero: bool = False) -> int:
    minimum = 0 if allow_zero else 1
    if type(value) is not int or value < minimum:
        raise GitHubSelectionError(
            "response_invalid",
            f"expected an integer of at least {minimum} at {path}",
        )
    return value


def _response_string(value: Any, path: str, *, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise GitHubSelectionError(
            "response_invalid",
            f"expected a bounded non-empty string at {path}",
        )
    return value


def _repository_file_path(value: Any, path: str) -> str:
    filename = _response_string(value, path, maximum=4096)
    if "\\" in filename:
        raise GitHubSelectionError("response_invalid", f"expected forward slashes at {path}")
    parsed = PurePosixPath(filename)
    if (
        parsed.is_absolute()
        or parsed.as_posix() != filename
        or any(part in {"", ".", ".."} for part in parsed.parts)
    ):
        raise GitHubSelectionError(
            "response_invalid",
            f"expected a contained repository path at {path}",
        )
    return filename


def _repository_identity(value: Any, path: str) -> tuple[int, str]:
    repository = _response_object(value, path)
    return (
        _response_integer(repository.get("id"), f"{path}.id"),
        _response_string(repository.get("full_name"), f"{path}.full_name", maximum=255),
    )


def _pull_request_snapshot(
    document: Any,
    expected: GitHubPullRequestContext,
) -> tuple[int, str, str, int, str, int]:
    root = _response_object(document, "$")
    number = _response_integer(root.get("number"), "$.number")
    base = _response_object(root.get("base"), "$.base")
    head = _response_object(root.get("head"), "$.head")
    base_repository_id, base_repository_name = _repository_identity(
        base.get("repo"),
        "$.base.repo",
    )
    head_repository_id, head_repository_name = _repository_identity(
        head.get("repo"),
        "$.head.repo",
    )
    base_sha = _response_string(base.get("sha"), "$.base.sha", maximum=64)
    head_sha = _response_string(head.get("sha"), "$.head.sha", maximum=64)
    changed_file_count = _response_integer(
        root.get("changed_files"),
        "$.changed_files",
        allow_zero=True,
    )
    expected_values = (
        expected.number,
        expected.base_repository.repository_id,
        expected.base_repository.full_name.casefold(),
        expected.base_sha,
        expected.head_repository.repository_id,
        expected.head_repository.full_name.casefold(),
        expected.head_sha,
    )
    observed_values = (
        number,
        base_repository_id,
        base_repository_name.casefold(),
        base_sha,
        head_repository_id,
        head_repository_name.casefold(),
        head_sha,
    )
    if observed_values != expected_values:
        raise GitHubSelectionError(
            "pull_request_changed",
            "GitHub's current pull request does not match the event-bound base and head",
        )
    if changed_file_count > MAX_GITHUB_PULL_FILES:
        raise GitHubSelectionError(
            "too_many_files",
            f"automatic selection accepts at most {MAX_GITHUB_PULL_FILES} changed files; "
            "split the pull request or use explicit Action inputs",
        )
    return (
        number,
        base_sha,
        head_sha,
        changed_file_count,
        base_repository_name,
        head_repository_id,
    )


def _parse_file_page(document: Any, *, page: int) -> tuple[GitHubChangedFile, ...]:
    if not isinstance(document, list):
        raise GitHubSelectionError(
            "response_invalid",
            f"expected an array in GitHub pull-request files page {page}",
        )
    files: list[GitHubChangedFile] = []
    for index, item in enumerate(document):
        root = _response_object(item, f"$[{index}]")
        path = _repository_file_path(root.get("filename"), f"$[{index}].filename")
        previous_value = root.get("previous_filename")
        previous_path = (
            _repository_file_path(previous_value, f"$[{index}].previous_filename")
            if previous_value is not None
            else None
        )
        files.append(GitHubChangedFile(path=path, previous_path=previous_path))
    return tuple(files)


def discover_github_pull_request_files(
    pull_request: GitHubPullRequestContext,
    *,
    token: str,
    timeout_seconds: float = DEFAULT_GITHUB_PULL_TIMEOUT_SECONDS,
    transport: GitHubPullFilesTransport | None = None,
) -> tuple[GitHubChangedFile, ...]:
    """Fetch exact current PR filenames while rejecting event/API identity races."""

    bearer_token = _validated_token(token)
    timeout = _validated_timeout(timeout_seconds)
    client = transport or UrllibGitHubPullFilesTransport()
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {bearer_token}",
        "User-Agent": "Causure",
        "X-GitHub-Api-Version": GITHUB_REST_API_VERSION,
    }
    base_url = (
        "https://api.github.com/repos/"
        f"{pull_request.base_repository.full_name}/pulls/{pull_request.number}"
    )

    def get_json(url: str, description: str) -> Any:
        return _json_response(
            client.get(url, headers=headers, timeout_seconds=timeout),
            description=description,
        )

    before = _pull_request_snapshot(
        get_json(base_url, "pull request"),
        pull_request,
    )
    expected_count = before[3]
    pages = (expected_count + GITHUB_PULL_FILES_PER_PAGE - 1) // GITHUB_PULL_FILES_PER_PAGE
    files: list[GitHubChangedFile] = []
    for page in range(1, pages + 1):
        page_document = get_json(
            f"{base_url}/files?per_page={GITHUB_PULL_FILES_PER_PAGE}&page={page}",
            "pull-request files",
        )
        page_files = _parse_file_page(page_document, page=page)
        expected_page_count = min(
            GITHUB_PULL_FILES_PER_PAGE,
            expected_count - len(files),
        )
        if len(page_files) != expected_page_count:
            raise GitHubSelectionError(
                "response_incomplete",
                "GitHub pull-request file pagination did not match changed_files",
            )
        files.extend(page_files)
    after = _pull_request_snapshot(
        get_json(base_url, "pull request"),
        pull_request,
    )
    if after != before:
        raise GitHubSelectionError(
            "pull_request_changed",
            "the pull request changed while its files were being discovered; rerun the job",
        )
    if len(files) != expected_count or len({item.path for item in files}) != len(files):
        raise GitHubSelectionError(
            "response_incomplete",
            "GitHub pull-request files were missing or duplicated",
        )
    return tuple(sorted(files, key=lambda item: (item.path, item.previous_path or "")))


@lru_cache(maxsize=4096)
def _path_pattern_regex(pattern: str) -> re.Pattern[str]:
    pieces = ["^"]
    index = 0
    while index < len(pattern):
        if pattern.startswith("**/", index) and (index == 0 or pattern[index - 1] == "/"):
            pieces.append("(?:[^/]+/)*")
            index += 3
        elif pattern.startswith("**", index):
            pieces.append(".*")
            index += 2
        elif pattern[index] == "*":
            pieces.append("[^/]*")
            index += 1
        else:
            pieces.append(re.escape(pattern[index]))
            index += 1
    pieces.append("$")
    return re.compile("".join(pieces))


def _matches(patterns: tuple[str, ...], changed_file: GitHubChangedFile) -> bool:
    candidates = (
        (changed_file.path,)
        if changed_file.previous_path is None
        else (changed_file.path, changed_file.previous_path)
    )
    return any(
        _path_pattern_regex(pattern).fullmatch(candidate) is not None
        for pattern in patterns
        for candidate in candidates
    )


def ensure_unchanged_github_paths(
    changed_files: tuple[GitHubChangedFile, ...],
    paths: tuple[str, ...],
) -> None:
    """Reject candidate changes to trusted configuration or policy paths."""

    protected = tuple(
        _repository_file_path(value, f"protected_paths[{index}]")
        for index, value in enumerate(paths)
    )
    changed_names = {
        candidate.casefold()
        for item in changed_files
        for candidate in (item.path, item.previous_path)
        if candidate is not None
    }
    changed_governance = next(
        (path for path in protected if path.casefold() in changed_names),
        None,
    )
    if changed_governance is not None:
        raise GitHubSelectionError(
            "governance_changed",
            "automatic selection will not trust a configuration or policy changed by the "
            f"same pull request: {changed_governance}; use a separately reviewed governance "
            "change or explicit Action inputs",
        )


def select_configured_github_change(
    configuration: ProjectConfiguration,
    changed_files: tuple[GitHubChangedFile, ...],
    *,
    config_repository_path: str,
) -> GitHubChangeSelection | None:
    """Select exactly one configured component, or return None when none changed."""

    config_path = _repository_file_path(config_repository_path, "config_repository_path")
    policy_path = (
        PurePosixPath(config_path)
        .parent.joinpath(*PurePosixPath(configuration.policy_file).parts)
        .as_posix()
    )
    ensure_unchanged_github_paths(changed_files, (config_path, policy_path))
    matches: list[tuple[Any, tuple[str, ...]]] = []
    for component in configuration.github.components:
        matched_paths = tuple(
            sorted(item.path for item in changed_files if _matches(component.paths, item))
        )
        if matched_paths:
            matches.append((component, matched_paths))
    if not matches:
        return None
    if len(matches) > 1:
        component_ids = ", ".join(component.component_id for component, _ in matches)
        raise GitHubSelectionError(
            "ambiguous_components",
            "one Action run accepts exactly one configured harness component; matched: "
            f"{component_ids}",
        )
    component, matched_paths = matches[0]
    return GitHubChangeSelection(
        component_id=component.component_id,
        component=component.component,
        component_path=matched_paths[0],
        matched_paths=matched_paths,
        case_file=component.case_file,
        policy_file=policy_path,
        artifact_retention_days=configuration.github.artifact_retention_days,
    )
