"""Closed GitHub Check Run request, publication, and receipt tests."""

from __future__ import annotations

import hashlib
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
from causure.github_checks import (
    GITHUB_CHECK_RUN_NAME,
    GITHUB_CHECK_RUN_REQUEST_MEDIA_TYPE,
    GitHubCheckRunPublishError,
    GitHubCheckRunValidationError,
    GitHubHTTPResponse,
    create_github_check_run_request,
    github_check_run_api_body,
    parse_github_check_run_receipt,
    parse_github_check_run_request,
    parse_github_check_run_request_bytes,
    publish_github_check_run,
    render_github_check_run_receipt,
    render_github_check_run_request,
    render_github_check_run_summary,
    verify_github_check_run_receipt,
)
from causure.github_review import (
    create_github_review_publication,
    github_context_from_environment,
    render_github_review_publication,
    render_github_review_verification,
    verify_github_review_publication,
)
from causure.io import load_change_case
from causure.report import render_json, render_markdown
from tests.helpers import PROJECT_ROOT


def _repository(repository_id: int, owner_id: int, full_name: str) -> dict[str, object]:
    return {
        "id": repository_id,
        "full_name": full_name,
        "owner": {"id": owner_id},
    }


def _event(*, fork: bool = False) -> bytes:
    base_repository = _repository(1001, 501, "acme/agent-harness")
    head_repository = (
        _repository(2002, 777, "contributor/agent-harness") if fork else base_repository
    )
    document = {
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
                "sha": "c" * 40,
                "repo": head_repository,
            },
        },
    }
    return json.dumps(document, sort_keys=True).encode("utf-8")


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


class RecordingTransport:
    def __init__(
        self,
        *,
        status_code: int = 201,
        content_type: str = "application/json; charset=utf-8",
        mutate_response=None,
    ) -> None:
        self.status_code = status_code
        self.content_type = content_type
        self.mutate_response = mutate_response
        self.url: str | None = None
        self.headers: dict[str, str] = {}
        self.body = b""
        self.timeout_seconds = 0.0

    def post(self, url, *, headers, body, timeout_seconds):
        self.url = url
        self.headers = dict(headers)
        self.body = body
        self.timeout_seconds = timeout_seconds
        request = json.loads(body)
        response = {
            "id": 70001,
            "name": request["name"],
            "head_sha": request["head_sha"],
            "status": request["status"],
            "conclusion": request["conclusion"],
            "external_id": request["external_id"],
            "html_url": "https://github.com/acme/agent-harness/runs/70001",
        }
        if self.mutate_response is not None:
            self.mutate_response(response)
        return GitHubHTTPResponse(
            status_code=self.status_code,
            headers={"content-type": self.content_type},
            body=json.dumps(response).encode("utf-8"),
        )


class GitHubCheckRunTests(unittest.TestCase):
    def _chain(self, case_name: str = "approve-refund-tool-description.json"):
        case_path = PROJECT_ROOT / "examples" / "change-cases" / case_name
        case_bytes = case_path.read_bytes()
        case = load_change_case(case_path)
        result = replace(review_case(case), reviewed_at="2026-08-10T21:00:00Z")
        result_bytes = render_json(result).encode("utf-8")
        report_bytes = render_markdown(case, result).encode("utf-8")
        pull_request, workflow = github_context_from_environment(
            _environment(),
            event_bytes=_event(),
        )
        publication = create_github_review_publication(
            case_bytes,
            result_bytes,
            report_bytes,
            pull_request=pull_request,
            workflow=workflow,
            created_at="2026-08-10T21:00:01Z",
        )
        publication_bytes = render_github_review_publication(publication).encode("utf-8")
        verification = verify_github_review_publication(
            publication_bytes,
            case_bytes,
            result_bytes,
            report_bytes,
            expected_pull_request=pull_request,
            expected_workflow=workflow,
            verified_at="2026-08-10T21:00:30Z",
        )
        verification_bytes = render_github_review_verification(verification).encode("utf-8")
        return (
            case_bytes,
            result_bytes,
            report_bytes,
            pull_request,
            workflow,
            publication_bytes,
            verification_bytes,
        )

    def _request(self, case_name: str = "approve-refund-tool-description.json"):
        chain = self._chain(case_name)
        request = create_github_check_run_request(
            chain[5],
            chain[6],
            chain[0],
            chain[1],
            chain[2],
            expected_pull_request=chain[3],
            expected_workflow=chain[4],
            component_path="agent/tools/refund.py",
            created_at="2026-08-10T21:00:31Z",
        )
        return chain, request

    def test_approved_request_is_closed_stable_and_minimized(self) -> None:
        chain, request = self._request()
        rendered = render_github_check_run_request(request)
        parsed = parse_github_check_run_request_bytes(rendered.encode("utf-8"))

        self.assertEqual(request, parsed)
        self.assertEqual(GITHUB_CHECK_RUN_NAME, request.name)
        self.assertEqual("success", request.conclusion)
        self.assertEqual("c" * 40, request.head_sha)
        self.assertEqual(17, request.pull_request_number)
        self.assertEqual(90001, request.workflow_run_id)
        self.assertEqual(1, request.run_attempt)
        self.assertEqual(hashlib.sha256(chain[6]).hexdigest(), request.verification.sha256)
        self.assertEqual((), request.findings)
        self.assertNotIn("test-token", rendered)
        self.assertNotIn("event_payload", rendered)
        self.assertNotIn("head_repository", rendered)
        self.assertNotIn("pull_request_title", rendered)

        document = json.loads(rendered)
        document["unexpected"] = True
        with self.assertRaisesRegex(GitHubCheckRunValidationError, "property is not allowed"):
            parse_github_check_run_request(document)

    def test_rejected_request_maps_all_decision_findings_to_failure_annotations(self) -> None:
        _, request = self._request("reject-overbroad-prompt.json")
        body = json.loads(github_check_run_api_body(request))
        summary = render_github_check_run_summary(request)

        self.assertEqual("reject", request.review.decision.value)
        self.assertEqual("failure", request.conclusion)
        self.assertGreater(len(request.findings), 0)
        self.assertEqual(len(request.findings), len(body["output"]["annotations"]))
        self.assertTrue(
            all(finding.path == "agent/tools/refund.py" for finding in request.findings)
        )
        self.assertTrue(
            all(
                item["annotation_level"] in {"failure", "warning"}
                for item in body["output"]["annotations"]
            )
        )
        self.assertIn("### Required resolution", summary)
        self.assertIn("`failure`", summary)

    def test_request_reproduces_receipt_artifacts_context_and_time(self) -> None:
        chain = list(self._chain())
        tampered_verification = json.loads(chain[6])
        tampered_verification["publication_age_seconds"] += 1
        chain[6] = json.dumps(tampered_verification).encode("utf-8")
        with self.assertRaisesRegex(GitHubCheckRunValidationError, "does not reproduce"):
            create_github_check_run_request(
                chain[5],
                chain[6],
                chain[0],
                chain[1],
                chain[2],
                expected_pull_request=chain[3],
                expected_workflow=chain[4],
                component_path="agent/tools/refund.py",
                created_at="2026-08-10T21:00:31Z",
            )

        chain = self._chain()
        with self.assertRaisesRegex(GitHubCheckRunValidationError, "within one second"):
            create_github_check_run_request(
                chain[5],
                chain[6],
                chain[0],
                chain[1],
                chain[2],
                expected_pull_request=chain[3],
                expected_workflow=chain[4],
                component_path="agent/tools/refund.py",
                created_at="2026-08-10T21:10:31Z",
            )

    def test_request_rejects_unsafe_paths_and_too_many_annotations(self) -> None:
        chain = self._chain()
        with self.assertRaisesRegex(GitHubCheckRunValidationError, "repository-relative"):
            create_github_check_run_request(
                chain[5],
                chain[6],
                chain[0],
                chain[1],
                chain[2],
                expected_pull_request=chain[3],
                expected_workflow=chain[4],
                component_path="../outside.py",
                created_at="2026-08-10T21:00:31Z",
            )

        _, rejected = self._request("reject-overbroad-prompt.json")
        document = json.loads(render_github_check_run_request(rejected))
        template = document["findings"][0]
        document["findings"] = []
        for index in range(51):
            finding = deepcopy(template)
            finding["code"] = f"synthetic.finding.{index}"
            document["findings"].append(finding)
        with self.assertRaisesRegex(GitHubCheckRunValidationError, "at most 50"):
            parse_github_check_run_request(document)

    def test_fork_request_can_render_but_direct_publisher_fails_closed(self) -> None:
        chain = self._chain()
        fork_pull_request, fork_workflow = github_context_from_environment(
            _environment(),
            event_bytes=_event(fork=True),
        )
        publication = create_github_review_publication(
            chain[0],
            chain[1],
            chain[2],
            pull_request=fork_pull_request,
            workflow=fork_workflow,
            created_at="2026-08-10T21:00:01Z",
        )
        publication_bytes = render_github_review_publication(publication).encode("utf-8")
        verification = verify_github_review_publication(
            publication_bytes,
            chain[0],
            chain[1],
            chain[2],
            expected_pull_request=fork_pull_request,
            expected_workflow=fork_workflow,
            verified_at="2026-08-10T21:00:30Z",
        )
        verification_bytes = render_github_review_verification(verification).encode("utf-8")
        request = create_github_check_run_request(
            publication_bytes,
            verification_bytes,
            chain[0],
            chain[1],
            chain[2],
            expected_pull_request=fork_pull_request,
            expected_workflow=fork_workflow,
            component_path="agent/tools/refund.py",
            created_at="2026-08-10T21:00:31Z",
        )
        request_bytes = render_github_check_run_request(request).encode("utf-8")

        self.assertTrue(request.is_fork)
        self.assertIn("Causure evidence gate", render_github_check_run_summary(request))
        with self.assertRaisesRegex(GitHubCheckRunPublishError, "fork pull requests"):
            publish_github_check_run(
                request_bytes,
                token="test-token",
                published_at="2026-08-10T21:00:32Z",
                transport=RecordingTransport(),
            )

    def test_request_parser_rechecks_conclusion_findings_and_external_identity(self) -> None:
        _, request = self._request("reject-overbroad-prompt.json")
        original = json.loads(render_github_check_run_request(request))
        mutations = (
            ("conclusion", lambda doc: doc.__setitem__("conclusion", "success")),
            ("decision", lambda doc: doc["review"].__setitem__("decision", "approve")),
            ("external", lambda doc: doc.__setitem__("external_id", doc["external_id"] + "x")),
            ("path", lambda doc: doc["findings"][0].__setitem__("path", "../escape")),
            ("duplicate", lambda doc: doc["findings"].append(deepcopy(doc["findings"][0]))),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                changed = deepcopy(original)
                mutate(changed)
                with self.assertRaises(GitHubCheckRunValidationError):
                    parse_github_check_run_request(changed)

    def test_publisher_sends_exact_bounded_request_and_returns_bound_receipt(self) -> None:
        chain, request = self._request("reject-overbroad-prompt.json")
        request_bytes = render_github_check_run_request(request).encode("utf-8")
        transport = RecordingTransport()
        receipt = publish_github_check_run(
            request_bytes,
            token="test-token",
            published_at="2026-08-10T21:00:32Z",
            timeout_seconds=7.5,
            transport=transport,
        )
        receipt_bytes = render_github_check_run_receipt(receipt).encode("utf-8")

        self.assertEqual(
            "https://api.github.com/repos/acme/agent-harness/check-runs",
            transport.url,
        )
        self.assertEqual("Bearer test-token", transport.headers["Authorization"])
        self.assertEqual("2022-11-28", transport.headers["X-GitHub-Api-Version"])
        self.assertEqual(7.5, transport.timeout_seconds)
        self.assertEqual(github_check_run_api_body(request), transport.body)
        self.assertEqual(70001, receipt.check_run_id)
        self.assertEqual("failure", receipt.conclusion)
        self.assertEqual(len(request.findings), receipt.annotation_count)
        self.assertEqual(
            GITHUB_CHECK_RUN_REQUEST_MEDIA_TYPE,
            receipt.request.media_type,
        )
        self.assertEqual(hashlib.sha256(request_bytes).hexdigest(), receipt.request.sha256)
        self.assertEqual(request.verification, receipt.verification)
        self.assertEqual(receipt, verify_github_check_run_receipt(request_bytes, receipt_bytes))
        self.assertEqual(chain[3].head_sha, receipt.head_sha)

    def test_publisher_fails_closed_without_disclosing_token_or_response_body(self) -> None:
        _, request = self._request()
        request_bytes = render_github_check_run_request(request).encode("utf-8")
        with self.assertRaisesRegex(GitHubCheckRunPublishError, "non-empty bearer token") as caught:
            publish_github_check_run(
                request_bytes,
                token=" bad token ",
                published_at="2026-08-10T21:00:32Z",
                transport=RecordingTransport(),
            )
        self.assertNotIn("bad token", str(caught.exception))

        with self.assertRaisesRegex(GitHubCheckRunPublishError, "HTTP 403") as caught:
            publish_github_check_run(
                request_bytes,
                token="test-token",
                published_at="2026-08-10T21:00:32Z",
                transport=RecordingTransport(status_code=403),
            )
        self.assertNotIn("test-token", str(caught.exception))
        self.assertNotIn("external_id", str(caught.exception))

        with self.assertRaisesRegex(GitHubCheckRunPublishError, "did not return JSON"):
            publish_github_check_run(
                request_bytes,
                token="test-token",
                published_at="2026-08-10T21:00:32Z",
                transport=RecordingTransport(content_type="text/html"),
            )

    def test_publisher_rejects_mismatched_response_stale_request_and_receipt_tampering(
        self,
    ) -> None:
        _, request = self._request()
        request_bytes = render_github_check_run_request(request).encode("utf-8")
        with self.assertRaisesRegex(GitHubCheckRunPublishError, "response does not match"):
            publish_github_check_run(
                request_bytes,
                token="test-token",
                published_at="2026-08-10T21:00:32Z",
                transport=RecordingTransport(
                    mutate_response=lambda response: response.__setitem__("head_sha", "f" * 40)
                ),
            )
        with self.assertRaisesRegex(GitHubCheckRunPublishError, "publication time"):
            publish_github_check_run(
                request_bytes,
                token="test-token",
                published_at="2026-08-10T21:10:32Z",
                transport=RecordingTransport(),
            )

        receipt = publish_github_check_run(
            request_bytes,
            token="test-token",
            published_at="2026-08-10T21:00:32Z",
            transport=RecordingTransport(),
        )
        receipt_document = json.loads(render_github_check_run_receipt(receipt))
        receipt_document["annotation_count"] += 1
        with self.assertRaisesRegex(GitHubCheckRunPublishError, "does not correspond"):
            verify_github_check_run_receipt(
                request_bytes,
                json.dumps(receipt_document).encode("utf-8"),
            )

    def test_receipt_parser_is_closed_and_cross_checks_identity(self) -> None:
        _, request = self._request()
        request_bytes = render_github_check_run_request(request).encode("utf-8")
        receipt = publish_github_check_run(
            request_bytes,
            token="test-token",
            published_at="2026-08-10T21:00:32Z",
            transport=RecordingTransport(),
        )
        original = json.loads(render_github_check_run_receipt(receipt))
        mutations = (
            ("unknown", lambda doc: doc.__setitem__("unexpected", True)),
            ("url", lambda doc: doc.__setitem__("html_url", "https://example.com/runs/70001")),
            ("id", lambda doc: doc.__setitem__("check_run_id", 70002)),
            ("external", lambda doc: doc.__setitem__("external_id", "different")),
        )
        for label, mutate in mutations:
            with self.subTest(label=label):
                changed = deepcopy(original)
                mutate(changed)
                with self.assertRaises(GitHubCheckRunValidationError):
                    parse_github_check_run_receipt(changed)

    def test_cli_writes_plan_summary_and_bound_receipt_without_persisting_token(self) -> None:
        chain = self._chain("reject-overbroad-prompt.json")
        transport = RecordingTransport()

        def fake_publish(request_bytes, *, token, published_at, timeout_seconds):
            return publish_github_check_run(
                request_bytes,
                token=token,
                published_at=published_at,
                timeout_seconds=timeout_seconds,
                transport=transport,
            )

        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            paths = {
                "case": root / "case.json",
                "result": root / "result.json",
                "report": root / "report.md",
                "publication": root / "publication.json",
                "verification": root / "verification.json",
                "request": root / "check-request.json",
                "summary": root / "check-summary.md",
                "receipt": root / "check-receipt.json",
                "event": root / "event.json",
            }
            for name, content in zip(
                ("case", "result", "report", "publication", "verification"),
                (chain[0], chain[1], chain[2], chain[5], chain[6]),
                strict=True,
            ):
                paths[name].write_bytes(content)
            paths["event"].write_bytes(_event())
            environment = {
                **_environment(),
                "GITHUB_EVENT_PATH": str(paths["event"]),
                "CAUSURE_GITHUB_TOKEN": "test-token",
            }

            with (
                patch.dict(os.environ, environment, clear=True),
                patch(
                    "causure.cli.utc_timestamp",
                    side_effect=["2026-08-10T21:00:31Z", "2026-08-10T21:00:32Z"],
                ),
                patch(
                    "causure.cli.publish_github_check_run",
                    side_effect=fake_publish,
                ),
            ):
                exit_code = main(
                    [
                        "github-check-run",
                        str(paths["publication"]),
                        str(paths["verification"]),
                        str(paths["case"]),
                        str(paths["result"]),
                        str(paths["report"]),
                        "--component-path",
                        "agent/tools/refund.py",
                        "--request-output",
                        str(paths["request"]),
                        "--summary-output",
                        str(paths["summary"]),
                        "--output",
                        str(paths["receipt"]),
                        "--quiet",
                    ]
                )

            self.assertEqual(1, exit_code)
            request_bytes = paths["request"].read_bytes()
            receipt_bytes = paths["receipt"].read_bytes()
            self.assertEqual(
                parse_github_check_run_request_bytes(request_bytes).review.decision.value,
                "reject",
            )
            self.assertEqual(
                70001,
                verify_github_check_run_receipt(request_bytes, receipt_bytes).check_run_id,
            )
            self.assertIn("Required resolution", paths["summary"].read_text(encoding="utf-8"))
            for path in (paths["request"], paths["summary"], paths["receipt"]):
                self.assertNotIn("test-token", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
