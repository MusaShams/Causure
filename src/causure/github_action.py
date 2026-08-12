"""One-step GitHub Actions orchestration over the closed review and Check Run contracts."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import Path

from causure.attestations import utc_timestamp
from causure.constants import Decision, RecommendedAction
from causure.engine import review_case
from causure.github_checks import (
    DEFAULT_GITHUB_CHECK_RUN_TIMEOUT_SECONDS,
    GitHubCheckRunReceipt,
    GitHubCheckRunTransport,
    create_github_check_run_request,
    publish_github_check_run,
    render_github_check_run_receipt,
    render_github_check_run_request,
    render_github_check_run_summary,
)
from causure.github_review import (
    DEFAULT_MAX_GITHUB_PUBLICATION_AGE_SECONDS,
    MAX_GITHUB_CHANGE_CASE_BYTES,
    create_github_review_publication,
    github_context_from_environment,
    render_github_review_publication,
    render_github_review_verification,
    verify_github_review_publication,
)
from causure.io import atomic_write_text, load_change_case, load_policy
from causure.report import render_json, render_markdown

GITHUB_ACTION_PUBLISH_MODES = frozenset({"auto", "required", "disabled"})


@dataclass(frozen=True, slots=True)
class GitHubActionArtifacts:
    """Paths produced by one GitHub Actions review run."""

    result: Path
    report: Path
    publication: Path
    verification: Path
    check_request: Path
    check_summary: Path
    check_receipt: Path | None


@dataclass(frozen=True, slots=True)
class GitHubActionRun:
    """Outcome and publication state for one one-step Action execution."""

    decision: Decision
    recommended_action: RecommendedAction
    check_published: bool
    check_publication_status: str
    check_run_id: int | None
    artifacts: GitHubActionArtifacts


def _read_bounded_bytes(path: Path, *, maximum: int, description: str) -> bytes:
    try:
        size = path.stat().st_size
        if not 1 <= size <= maximum:
            raise ValueError(f"{description} must contain from 1 to {maximum} bytes")
        raw_bytes = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"could not read {description} {path}: {exc}") from exc
    if len(raw_bytes) != size:
        raise ValueError(f"{description} changed while it was being read")
    return raw_bytes


def _artifact_paths(output_directory: Path) -> GitHubActionArtifacts:
    return GitHubActionArtifacts(
        result=output_directory / "review-result.json",
        report=output_directory / "review-report.md",
        publication=output_directory / "github-review-publication.json",
        verification=output_directory / "github-review-verification.json",
        check_request=output_directory / "github-check-run-request.json",
        check_summary=output_directory / "github-check-run-summary.md",
        check_receipt=None,
    )


def _prepare_output_directory(output_directory: Path, artifacts: GitHubActionArtifacts) -> None:
    targets = (
        artifacts.result,
        artifacts.report,
        artifacts.publication,
        artifacts.verification,
        artifacts.check_request,
        artifacts.check_summary,
        output_directory / "github-check-run-receipt.json",
    )
    existing = [path for path in targets if path.exists()]
    if existing:
        raise ValueError(f"refusing to overwrite existing Action artifact: {existing[0]}")
    try:
        output_directory.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ValueError(
            f"could not create Action output directory {output_directory}: {exc}"
        ) from exc
    if not output_directory.is_dir():
        raise ValueError(f"Action output path is not a directory: {output_directory}")


def _append_step_summary(path: Path, summary: str) -> None:
    try:
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(summary)
            if not summary.endswith("\n"):
                stream.write("\n")
    except OSError as exc:
        raise ValueError(f"could not append the GitHub step summary: {exc}") from exc


def run_github_action(
    case_path: str | Path,
    *,
    policy_path: str | Path | None,
    component_path: str,
    output_directory: str | Path,
    environment: Mapping[str, str],
    publish_mode: str = "auto",
    token: str = "",
    allow_conditional: bool = False,
    maximum_age_seconds: int = DEFAULT_MAX_GITHUB_PUBLICATION_AGE_SECONDS,
    timeout_seconds: float = DEFAULT_GITHUB_CHECK_RUN_TIMEOUT_SECONDS,
    step_summary_path: str | Path | None = None,
    run_at: datetime | None = None,
    transport: GitHubCheckRunTransport | None = None,
    publisher: Callable[..., GitHubCheckRunReceipt] = publish_github_check_run,
) -> GitHubActionRun:
    """Review, bind, verify, summarize, and optionally publish one pull-request decision."""

    if publish_mode not in GITHUB_ACTION_PUBLISH_MODES:
        raise ValueError(
            "publish_mode must be one of: " + ", ".join(sorted(GITHUB_ACTION_PUBLISH_MODES))
        )
    if not isinstance(allow_conditional, bool):
        raise ValueError("allow_conditional must be a boolean")
    instant = run_at or datetime.now(UTC)
    if instant.tzinfo is None or instant.utcoffset() is None:
        raise ValueError("run_at must include a timezone")
    instant = instant.astimezone(UTC)
    timestamp = utc_timestamp(instant)

    source = Path(case_path)
    destination = Path(output_directory)
    artifacts = _artifact_paths(destination)
    _prepare_output_directory(destination, artifacts)
    case_bytes = _read_bounded_bytes(
        source,
        maximum=MAX_GITHUB_CHANGE_CASE_BYTES,
        description="change case",
    )
    case = load_change_case(source)
    policy = load_policy(policy_path)
    result = review_case(case, policy, reviewed_at=instant.replace(microsecond=0))
    result_content = render_json(result)
    report_content = render_markdown(case, result)
    result_bytes = result_content.encode("utf-8")
    report_bytes = report_content.encode("utf-8")
    atomic_write_text(artifacts.result, result_content)
    atomic_write_text(artifacts.report, report_content)

    pull_request, workflow = github_context_from_environment(environment)
    publication = create_github_review_publication(
        case_bytes,
        result_bytes,
        report_bytes,
        pull_request=pull_request,
        workflow=workflow,
        created_at=timestamp,
    )
    publication_content = render_github_review_publication(publication)
    publication_bytes = publication_content.encode("utf-8")
    atomic_write_text(artifacts.publication, publication_content)
    verification = verify_github_review_publication(
        publication_bytes,
        case_bytes,
        result_bytes,
        report_bytes,
        expected_pull_request=pull_request,
        expected_workflow=workflow,
        verified_at=timestamp,
        maximum_age_seconds=maximum_age_seconds,
    )
    verification_content = render_github_review_verification(verification)
    verification_bytes = verification_content.encode("utf-8")
    atomic_write_text(artifacts.verification, verification_content)
    check_request = create_github_check_run_request(
        publication_bytes,
        verification_bytes,
        case_bytes,
        result_bytes,
        report_bytes,
        expected_pull_request=pull_request,
        expected_workflow=workflow,
        component_path=component_path,
        created_at=timestamp,
        allow_conditional=allow_conditional,
    )
    request_content = render_github_check_run_request(check_request)
    summary_content = render_github_check_run_summary(check_request)
    atomic_write_text(artifacts.check_request, request_content)
    atomic_write_text(artifacts.check_summary, summary_content)
    if step_summary_path is not None:
        _append_step_summary(Path(step_summary_path), summary_content)

    should_publish = publish_mode == "required" or (
        publish_mode == "auto" and not pull_request.is_fork
    )
    if publish_mode == "required" and pull_request.is_fork:
        raise ValueError(
            "required direct Check Run publication is unavailable for fork pull requests"
        )
    receipt: GitHubCheckRunReceipt | None = None
    if should_publish:
        if not token:
            raise ValueError("same-repository Check Run publication requires github-token")
        publish_arguments = {
            "token": token,
            "published_at": timestamp,
            "timeout_seconds": timeout_seconds,
        }
        if transport is not None:
            publish_arguments["transport"] = transport
        receipt = publisher(
            request_content.encode("utf-8"),
            **publish_arguments,
        )
        receipt_path = destination / "github-check-run-receipt.json"
        atomic_write_text(receipt_path, render_github_check_run_receipt(receipt))
        artifacts = replace(artifacts, check_receipt=receipt_path)

    publication_status = (
        "published"
        if receipt is not None
        else "fork_skipped"
        if pull_request.is_fork and publish_mode == "auto"
        else "disabled"
    )
    return GitHubActionRun(
        decision=result.decision,
        recommended_action=result.recommended_action,
        check_published=receipt is not None,
        check_publication_status=publication_status,
        check_run_id=receipt.check_run_id if receipt is not None else None,
        artifacts=artifacts,
    )
