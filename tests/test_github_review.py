"""GitHub pull-request publication and completion-verification contracts."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from causure.cli import main
from causure.engine import review_case
from causure.github_review import (
    GitHubReviewValidationError,
    GitHubReviewVerificationError,
    create_github_review_publication,
    github_context_from_environment,
    parse_github_review_publication,
    parse_github_review_publication_bytes,
    parse_github_review_verification,
    render_github_review_publication,
    render_github_review_verification,
    verify_github_review_publication,
)
from causure.io import load_change_case
from causure.models import to_jsonable
from causure.report import render_json, render_markdown
from tests.helpers import PROJECT_ROOT


def _repository(repository_id: int, owner_id: int, full_name: str) -> dict[str, object]:
    return {
        "id": repository_id,
        "full_name": full_name,
        "owner": {"id": owner_id},
    }


def _event(*, fork: bool = False, head_sha: str = "c" * 40) -> dict[str, object]:
    base_repository = _repository(1001, 501, "acme/agent-harness")
    head_repository = (
        _repository(2002, 777, "contributor/agent-harness") if fork else base_repository
    )
    return {
        "action": "synchronize",
        "number": 17,
        "repository": base_repository,
        "pull_request": {
            "number": 17,
            "draft": False,
            "base": {
                "ref": "main",
                "sha": "b" * 40,
                "repo": base_repository,
            },
            "head": {
                "ref": "fix/refund-tool-description",
                "sha": head_sha,
                "repo": head_repository,
            },
        },
    }


def _event_bytes(*, fork: bool = False, head_sha: str = "c" * 40) -> bytes:
    return json.dumps(_event(fork=fork, head_sha=head_sha), sort_keys=True).encode("utf-8")


def _environment() -> dict[str, str]:
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_EVENT_PATH": "event.json",
        "GITHUB_REPOSITORY": "acme/agent-harness",
        "GITHUB_REPOSITORY_ID": "1001",
        "GITHUB_REPOSITORY_OWNER": "acme",
        "GITHUB_REPOSITORY_OWNER_ID": "501",
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_SHA": "d" * 40,
        "GITHUB_REF": "refs/pull/17/merge",
        "GITHUB_BASE_REF": "main",
        "GITHUB_HEAD_REF": "fix/refund-tool-description",
        "GITHUB_WORKFLOW_REF": ("acme/agent-harness/.github/workflows/causure.yml@refs/heads/main"),
        "GITHUB_WORKFLOW_SHA": "e" * 40,
        "GITHUB_RUN_ID": "90001",
        "GITHUB_RUN_NUMBER": "41",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_JOB": "causure",
    }


class GitHubReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.case_path = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        cls.case_bytes = cls.case_path.read_bytes()
        case = load_change_case(cls.case_path)
        result = replace(
            review_case(case),
            reviewed_at="2026-08-10T20:59:30Z",
        )
        cls.result_bytes = render_json(result).encode("utf-8")
        cls.report_bytes = render_markdown(case, result).encode("utf-8")

    def _context(
        self,
        *,
        environment: dict[str, str] | None = None,
        event_bytes: bytes | None = None,
    ):
        return github_context_from_environment(
            environment or _environment(),
            event_bytes=event_bytes or _event_bytes(),
        )

    def _publication(
        self,
        *,
        environment: dict[str, str] | None = None,
        event_bytes: bytes | None = None,
        created_at: str = "2026-08-10T21:00:00Z",
    ):
        pull_request, workflow = self._context(
            environment=environment,
            event_bytes=event_bytes,
        )
        return create_github_review_publication(
            self.case_bytes,
            self.result_bytes,
            self.report_bytes,
            pull_request=pull_request,
            workflow=workflow,
            created_at=created_at,
        )

    def test_context_binds_pull_request_head_not_merge_sha(self) -> None:
        raw_event = _event_bytes()
        pull_request, workflow = self._context(event_bytes=raw_event)

        self.assertEqual("c" * 40, pull_request.head_sha)
        self.assertEqual("d" * 40, workflow.event_sha)
        self.assertEqual(1001, pull_request.base_repository.repository_id)
        self.assertFalse(pull_request.is_fork)
        self.assertEqual(hashlib.sha256(raw_event).hexdigest(), workflow.event_payload.sha256)

    def test_fork_identity_is_explicit_and_privileged_event_is_rejected(self) -> None:
        pull_request, _ = self._context(event_bytes=_event_bytes(fork=True))

        self.assertTrue(pull_request.is_fork)
        self.assertEqual(2002, pull_request.head_repository.repository_id)
        self.assertEqual("contributor/agent-harness", pull_request.head_repository.full_name)

        environment = _environment()
        environment["GITHUB_EVENT_NAME"] = "pull_request_target"
        with self.assertRaisesRegex(GitHubReviewValidationError, "deliberately unsupported"):
            self._context(environment=environment)

    def test_environment_and_event_repository_must_agree(self) -> None:
        for variable, value in (
            ("GITHUB_REPOSITORY", "other/agent-harness"),
            ("GITHUB_REPOSITORY_ID", "1002"),
            ("GITHUB_REPOSITORY_OWNER_ID", "502"),
            ("GITHUB_HEAD_REF", "different-head"),
        ):
            with self.subTest(variable=variable):
                environment = _environment()
                environment[variable] = value
                with self.assertRaisesRegex(GitHubReviewValidationError, variable):
                    self._context(environment=environment)

    def test_publication_binds_case_result_report_candidate_and_run(self) -> None:
        publication = self._publication()

        self.assertEqual("tool_description", publication.review.component.value)
        self.assertEqual("c" * 40, publication.pull_request.head_sha)
        self.assertEqual(90001, publication.workflow.run_id)
        self.assertEqual(len(self.case_bytes), publication.artifacts.change_case.byte_count)
        self.assertEqual(
            len(self.result_bytes),
            publication.artifacts.review_result.byte_count,
        )
        self.assertEqual(
            len(self.report_bytes),
            publication.artifacts.review_report.byte_count,
        )

        rendered = render_github_review_publication(publication)
        reparsed = parse_github_review_publication_bytes(rendered.encode("utf-8"))
        self.assertEqual(publication, reparsed)
        self.assertEqual(rendered, render_github_review_publication(reparsed))

    def test_publication_rejects_mismatched_case_or_report(self) -> None:
        pull_request, workflow = self._context()
        different_case = (
            PROJECT_ROOT / "examples" / "change-cases" / "reject-overbroad-prompt.json"
        ).read_bytes()

        with self.assertRaisesRegex(GitHubReviewValidationError, "review result"):
            create_github_review_publication(
                different_case,
                self.result_bytes,
                self.report_bytes,
                pull_request=pull_request,
                workflow=workflow,
                created_at="2026-08-10T21:00:00Z",
            )

        changed_report = self.report_bytes.replace(
            b"| Case | `refund-tool-description-001` |",
            b"| Case | `different-case-id` |",
        )
        with self.assertRaisesRegex(GitHubReviewValidationError, "does not correspond"):
            create_github_review_publication(
                self.case_bytes,
                self.result_bytes,
                changed_report,
                pull_request=pull_request,
                workflow=workflow,
                created_at="2026-08-10T21:00:00Z",
            )

    def test_verification_rechecks_exact_artifacts_event_and_run(self) -> None:
        publication_bytes = render_github_review_publication(self._publication()).encode("utf-8")
        pull_request, workflow = self._context()

        verification = verify_github_review_publication(
            publication_bytes,
            self.case_bytes,
            self.result_bytes,
            self.report_bytes,
            expected_pull_request=pull_request,
            expected_workflow=workflow,
            verified_at="2026-08-10T21:00:30Z",
            maximum_age_seconds=60,
        )

        self.assertEqual("verified", verification.status)
        self.assertEqual(30, verification.publication_age_seconds)
        self.assertEqual("c" * 40, verification.pull_request.head_sha)
        rendered = render_github_review_verification(verification)
        self.assertEqual(
            verification,
            parse_github_review_verification(json.loads(rendered)),
        )

    def test_changed_artifact_head_event_or_attempt_fails_closed(self) -> None:
        publication_bytes = render_github_review_publication(self._publication()).encode("utf-8")
        pull_request, workflow = self._context()
        changed_case = self.case_bytes.replace(b"refund-tool", b"refund-fool", 1)

        with self.assertRaisesRegex(
            GitHubReviewVerificationError,
            r"\[artifact_digest_mismatch\]",
        ):
            verify_github_review_publication(
                publication_bytes,
                changed_case,
                self.result_bytes,
                self.report_bytes,
                expected_pull_request=pull_request,
                expected_workflow=workflow,
                verified_at="2026-08-10T21:00:30Z",
            )

        changed_pull_request, changed_head_workflow = self._context(
            event_bytes=_event_bytes(head_sha="f" * 40)
        )
        with self.assertRaisesRegex(
            GitHubReviewVerificationError,
            r"\[pull_request_context_mismatch\]",
        ):
            verify_github_review_publication(
                publication_bytes,
                self.case_bytes,
                self.result_bytes,
                self.report_bytes,
                expected_pull_request=changed_pull_request,
                expected_workflow=changed_head_workflow,
                verified_at="2026-08-10T21:00:30Z",
            )

        changed_environment = _environment()
        changed_environment["GITHUB_RUN_ATTEMPT"] = "2"
        same_pull_request, changed_workflow = self._context(environment=changed_environment)
        with self.assertRaisesRegex(
            GitHubReviewVerificationError,
            r"\[workflow_context_mismatch\]",
        ):
            verify_github_review_publication(
                publication_bytes,
                self.case_bytes,
                self.result_bytes,
                self.report_bytes,
                expected_pull_request=same_pull_request,
                expected_workflow=changed_workflow,
                verified_at="2026-08-10T21:00:30Z",
            )

    def test_irrelevant_event_payload_change_is_detected_by_subject_hash(self) -> None:
        publication_bytes = render_github_review_publication(self._publication()).encode("utf-8")
        changed_event = _event()
        changed_event["sender"] = {"id": 888}
        pull_request, workflow = self._context(
            event_bytes=json.dumps(changed_event, sort_keys=True).encode("utf-8")
        )

        with self.assertRaisesRegex(
            GitHubReviewVerificationError,
            r"\[workflow_context_mismatch\]",
        ):
            verify_github_review_publication(
                publication_bytes,
                self.case_bytes,
                self.result_bytes,
                self.report_bytes,
                expected_pull_request=pull_request,
                expected_workflow=workflow,
                verified_at="2026-08-10T21:00:30Z",
            )

    def test_parser_is_closed_and_cross_checks_fork_ref_and_time(self) -> None:
        document = to_jsonable(self._publication())
        document["unexpected"] = True
        with self.assertRaisesRegex(GitHubReviewValidationError, "is not allowed"):
            parse_github_review_publication(document)

        wrong_fork = deepcopy(to_jsonable(self._publication()))
        wrong_fork["pull_request"]["is_fork"] = True
        with self.assertRaisesRegex(GitHubReviewValidationError, "repository IDs"):
            parse_github_review_publication(wrong_fork)

        wrong_ref = deepcopy(to_jsonable(self._publication()))
        wrong_ref["workflow"]["ref"] = "refs/heads/main"
        with self.assertRaisesRegex(GitHubReviewValidationError, "merge ref"):
            parse_github_review_publication(wrong_ref)

        stale_review = deepcopy(to_jsonable(self._publication()))
        stale_review["created_at"] = "2026-08-10T22:00:00Z"
        with self.assertRaisesRegex(GitHubReviewValidationError, "after review.reviewed_at"):
            parse_github_review_publication(stale_review)

    def test_verification_rejects_stale_or_future_publication(self) -> None:
        publication_bytes = render_github_review_publication(self._publication()).encode("utf-8")
        pull_request, workflow = self._context()

        for verified_at, code in (
            ("2026-08-10T22:00:01Z", "publication_stale"),
            ("2026-08-10T20:59:59Z", "publication_from_future"),
        ):
            with self.subTest(code=code):
                with self.assertRaisesRegex(
                    GitHubReviewVerificationError,
                    rf"\[{code}\]",
                ):
                    verify_github_review_publication(
                        publication_bytes,
                        self.case_bytes,
                        self.result_bytes,
                        self.report_bytes,
                        expected_pull_request=pull_request,
                        expected_workflow=workflow,
                        verified_at=verified_at,
                        maximum_age_seconds=3600,
                    )


class GitHubReviewCliTests(unittest.TestCase):
    def test_cli_publishes_and_verifies_current_pull_request(self) -> None:
        case_path = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result_path = root / "result.json"
            report_path = root / "report.md"
            event_path = root / "event.json"
            publication_path = root / "publication.json"
            verification_path = root / "verification.json"
            event_path.write_bytes(_event_bytes())
            environment = _environment()
            environment["GITHUB_EVENT_PATH"] = str(event_path)

            with contextlib.redirect_stdout(io.StringIO()):
                review_exit = main(
                    [
                        "review",
                        str(case_path),
                        "--output",
                        str(report_path),
                        "--result-output",
                        str(result_path),
                        "--quiet",
                    ]
                )

            with (
                patch.dict(os.environ, environment, clear=True),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                publication_exit = main(
                    [
                        "github-publish",
                        str(case_path),
                        str(result_path),
                        str(report_path),
                        "--output",
                        str(publication_path),
                        "--quiet",
                    ]
                )
                verification_exit = main(
                    [
                        "github-verify",
                        str(publication_path),
                        str(case_path),
                        str(result_path),
                        str(report_path),
                        "--output",
                        str(verification_path),
                        "--quiet",
                    ]
                )

            self.assertEqual(0, review_exit)
            self.assertEqual(0, publication_exit)
            self.assertEqual(0, verification_exit)
            publication = parse_github_review_publication(
                json.loads(publication_path.read_text(encoding="utf-8"))
            )
            verification = parse_github_review_verification(
                json.loads(verification_path.read_text(encoding="utf-8"))
            )
            self.assertEqual(17, publication.pull_request.number)
            self.assertEqual(publication.pull_request, verification.pull_request)
            self.assertEqual(publication.workflow, verification.workflow)


if __name__ == "__main__":
    unittest.main()
