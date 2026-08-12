"""Azure DevOps/TFVC publication and pre-approval verification contracts."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from causure.azure_devops import (
    AzureReviewValidationError,
    AzureReviewVerificationError,
    TfvcChangesetTarget,
    TfvcShelvesetTarget,
    azure_context_from_environment,
    create_azure_review_publication,
    parse_azure_review_publication,
    parse_azure_review_publication_bytes,
    parse_azure_review_verification,
    render_azure_build_summary,
    render_azure_review_publication,
    render_azure_review_verification,
    verify_azure_review_publication,
)
from causure.cli import main
from causure.engine import review_case
from causure.io import load_change_case
from causure.models import to_jsonable
from causure.report import render_json, render_markdown
from tests.helpers import PROJECT_ROOT, load_needs_evidence_example


def _changeset_environment() -> dict[str, str]:
    return {
        "TF_BUILD": "True",
        "BUILD_REPOSITORY_PROVIDER": "TfsVersionControl",
        "SYSTEM_COLLECTIONURI": "https://dev.azure.com/example/",
        "SYSTEM_TEAMPROJECTID": "11111111-1111-4111-8111-111111111111",
        "SYSTEM_TEAMPROJECT": "Causure",
        "BUILD_BUILDID": "42",
        "BUILD_BUILDNUMBER": "20260728.1",
        "SYSTEM_DEFINITIONID": "7",
        "BUILD_DEFINITIONNAME": "Causure gate",
        "BUILD_REASON": "IndividualCI",
        "BUILD_SOURCEVERSION": "122",
        "BUILD_SOURCEBRANCH": "$/ProofBeforePatch",
        "BUILD_REQUESTEDFORID": "22222222-2222-4222-8222-222222222222",
    }


class AzureReviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        case = load_change_case(
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        result = replace(
            review_case(case),
            reviewed_at="2026-07-28T20:59:30Z",
        )
        cls.result_bytes = render_json(result).encode("utf-8")
        cls.report_bytes = render_markdown(case, result).encode("utf-8")

    def _publication(
        self,
        environment: dict[str, str] | None = None,
        *,
        created_at: str = "2026-07-28T21:00:00Z",
    ):
        tfvc, build = azure_context_from_environment(
            environment or _changeset_environment(),
            tfvc_server_path="$/ProofBeforePatch",
        )
        return create_azure_review_publication(
            self.result_bytes,
            self.report_bytes,
            tfvc=tfvc,
            build=build,
            work_item_ids=[93, 17],
            created_at=created_at,
        )

    def test_changeset_publication_binds_exact_artifacts_and_associations(self) -> None:
        publication = self._publication()

        self.assertIsInstance(publication.tfvc.target, TfvcChangesetTarget)
        self.assertEqual(122, publication.tfvc.target.changeset_id)
        self.assertEqual((17, 93), publication.work_item_ids)
        self.assertEqual("approve", publication.review.decision.value)
        self.assertEqual(len(self.result_bytes), publication.artifacts.review_result.byte_count)
        self.assertEqual(len(self.report_bytes), publication.artifacts.review_report.byte_count)

        rendered = render_azure_review_publication(publication)
        reparsed = parse_azure_review_publication_bytes(rendered.encode("utf-8"))
        self.assertEqual(publication, reparsed)
        self.assertEqual(rendered, render_azure_review_publication(reparsed))

    def test_shelveset_publication_records_gated_identity(self) -> None:
        environment = _changeset_environment()
        environment.update(
            {
                "BUILD_REASON": "CheckInShelveset",
                "BUILD_SOURCEVERSION": "121",
                "BUILD_SOURCEBRANCH": "Gated_2026-07-28_21.00.00;user@example.com",
                "BUILD_SOURCETFVCSHELVESET": ("Gated_2026-07-28_21.00.00;user@example.com"),
            }
        )

        publication = self._publication(environment)

        self.assertIsInstance(publication.tfvc.target, TfvcShelvesetTarget)
        self.assertEqual("Gated_2026-07-28_21.00.00", publication.tfvc.target.shelveset_name)
        self.assertEqual("user@example.com", publication.tfvc.target.owner)
        self.assertEqual(
            "Gated_2026-07-28_21.00.00;user@example.com",
            publication.build.source_tfvc_shelveset,
        )

    def test_environment_must_be_an_azure_tfvc_build(self) -> None:
        environment = _changeset_environment()
        environment["BUILD_REPOSITORY_PROVIDER"] = "TfsGit"

        with self.assertRaisesRegex(
            AzureReviewValidationError,
            "BUILD_REPOSITORY_PROVIDER",
        ):
            azure_context_from_environment(
                environment,
                tfvc_server_path="$/ProofBeforePatch",
            )

        environment = _changeset_environment()
        del environment["BUILD_BUILDID"]
        with self.assertRaisesRegex(AzureReviewValidationError, "BUILD_BUILDID"):
            azure_context_from_environment(
                environment,
                tfvc_server_path="$/ProofBeforePatch",
            )

    def test_collection_uri_rejects_query_or_credentials(self) -> None:
        for collection_uri in (
            "https://dev.azure.com/example/?token=not-allowed",
            "https://user:password@dev.azure.com/example/",
        ):
            with self.subTest(collection_uri=collection_uri):
                environment = _changeset_environment()
                environment["SYSTEM_COLLECTIONURI"] = collection_uri
                with self.assertRaisesRegex(
                    AzureReviewValidationError,
                    "without credentials, query, or fragment",
                ):
                    azure_context_from_environment(
                        environment,
                        tfvc_server_path="$/ProofBeforePatch",
                    )

    def test_nil_build_identity_uuid_is_rejected(self) -> None:
        environment = _changeset_environment()
        environment["BUILD_REQUESTEDFORID"] = "00000000-0000-0000-0000-000000000000"

        with self.assertRaisesRegex(AzureReviewValidationError, "nil UUID"):
            azure_context_from_environment(
                environment,
                tfvc_server_path="$/ProofBeforePatch",
            )

    def test_changeset_source_must_match_protected_tfvc_path(self) -> None:
        environment = _changeset_environment()
        environment["BUILD_SOURCEBRANCH"] = "$/AnotherProject"

        with self.assertRaisesRegex(AzureReviewValidationError, "TFVC server path"):
            azure_context_from_environment(
                environment,
                tfvc_server_path="$/ProofBeforePatch",
            )

    def test_shelveset_reason_and_reference_must_agree(self) -> None:
        environment = _changeset_environment()
        environment.update(
            {
                "BUILD_REASON": "CheckInShelveset",
                "BUILD_SOURCEBRANCH": "shelf-one;user@example.com",
            }
        )

        with self.assertRaisesRegex(
            AzureReviewValidationError,
            "BUILD_SOURCETFVCSHELVESET",
        ):
            azure_context_from_environment(
                environment,
                tfvc_server_path="$/ProofBeforePatch",
            )

    def test_report_must_correspond_to_review_result(self) -> None:
        tfvc, build = azure_context_from_environment(
            _changeset_environment(),
            tfvc_server_path="$/ProofBeforePatch",
        )
        unrelated = self.report_bytes.replace(
            b"| Case | `refund-tool-description-001` |",
            b"| Case | `different-case-id` |",
        )

        with self.assertRaisesRegex(
            AzureReviewValidationError,
            "does not correspond",
        ):
            create_azure_review_publication(
                self.result_bytes,
                unrelated,
                tfvc=tfvc,
                build=build,
                work_item_ids=[],
                created_at="2026-07-28T21:00:00Z",
            )

    def test_multiword_needs_evidence_report_corresponds_to_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            case_path = Path(directory) / "needs-evidence.case.json"
            case_path.write_text(
                json.dumps(load_needs_evidence_example(), indent=2) + "\n",
                encoding="utf-8",
            )
            case = load_change_case(case_path)
            result = replace(
                review_case(case),
                reviewed_at="2026-07-28T20:59:30Z",
            )
            tfvc, build = azure_context_from_environment(
                _changeset_environment(),
                tfvc_server_path="$/ProofBeforePatch",
            )

            publication = create_azure_review_publication(
                render_json(result).encode("utf-8"),
                render_markdown(case, result).encode("utf-8"),
                tfvc=tfvc,
                build=build,
                work_item_ids=[],
                created_at="2026-07-28T21:00:00Z",
            )

        self.assertEqual("needs_evidence", publication.review.decision.value)

    def test_verification_rechecks_exact_bytes_and_current_build(self) -> None:
        publication = self._publication()
        publication_bytes = render_azure_review_publication(publication).encode("utf-8")
        tfvc, build = azure_context_from_environment(
            _changeset_environment(),
            tfvc_server_path="$/ProofBeforePatch",
        )

        verification = verify_azure_review_publication(
            publication_bytes,
            self.result_bytes,
            self.report_bytes,
            expected_tfvc=tfvc,
            expected_build=build,
            verified_at="2026-07-28T21:00:30Z",
            maximum_age_seconds=60,
        )

        self.assertEqual("verified", verification.status)
        self.assertEqual(30, verification.publication_age_seconds)
        self.assertEqual(42, verification.build_id)
        rendered = render_azure_review_verification(verification)
        self.assertEqual(
            verification,
            parse_azure_review_verification(json.loads(rendered)),
        )
        summary = render_azure_build_summary(publication_bytes, verification)
        self.assertIn("**APPROVE**", summary)
        self.assertIn("changeset 122", summary)
        self.assertIn("[#17]", summary)
        self.assertIn(verification.publication.sha256, summary)
        self.assertIn("does not authenticate an approver", summary)

    def test_build_summary_escapes_untrusted_markdown_fields(self) -> None:
        environment = _changeset_environment()
        environment["BUILD_BUILDNUMBER"] = "42](https://malicious.invalid)"
        publication = self._publication(environment)
        publication_bytes = render_azure_review_publication(publication).encode("utf-8")
        tfvc, build = azure_context_from_environment(
            environment,
            tfvc_server_path="$/ProofBeforePatch",
        )
        verification = verify_azure_review_publication(
            publication_bytes,
            self.result_bytes,
            self.report_bytes,
            expected_tfvc=tfvc,
            expected_build=build,
            verified_at="2026-07-28T21:00:30Z",
        )

        summary = render_azure_build_summary(publication_bytes, verification)

        self.assertNotIn("42](https://malicious.invalid)", summary)
        self.assertIn("42&#93;&#40;https://malicious.invalid&#41;", summary)

    def test_build_summary_requires_the_exact_verified_publication(self) -> None:
        publication = self._publication()
        publication_bytes = render_azure_review_publication(publication).encode("utf-8")
        tfvc, build = azure_context_from_environment(
            _changeset_environment(),
            tfvc_server_path="$/ProofBeforePatch",
        )
        verification = verify_azure_review_publication(
            publication_bytes,
            self.result_bytes,
            self.report_bytes,
            expected_tfvc=tfvc,
            expected_build=build,
            verified_at="2026-07-28T21:00:30Z",
        )
        changed_document = json.loads(publication_bytes)
        changed_document["work_item_ids"].append(101)
        changed_bytes = (
            json.dumps(changed_document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")

        with self.assertRaisesRegex(ValueError, "does not correspond"):
            render_azure_build_summary(changed_bytes, verification)

    def test_changed_artifact_fails_before_approval(self) -> None:
        publication = self._publication()
        publication_bytes = render_azure_review_publication(publication).encode("utf-8")
        tfvc, build = azure_context_from_environment(
            _changeset_environment(),
            tfvc_server_path="$/ProofBeforePatch",
        )
        changed_result = self.result_bytes.replace(b'"approve"', b'"rejectx"', 1)

        with self.assertRaisesRegex(
            AzureReviewVerificationError,
            r"\[artifact_digest_mismatch\]",
        ):
            verify_azure_review_publication(
                publication_bytes,
                changed_result,
                self.report_bytes,
                expected_tfvc=tfvc,
                expected_build=build,
                verified_at="2026-07-28T21:00:30Z",
            )

    def test_verification_rejects_a_different_build(self) -> None:
        publication = self._publication()
        publication_bytes = render_azure_review_publication(publication).encode("utf-8")
        environment = _changeset_environment()
        environment["BUILD_BUILDID"] = "43"
        tfvc, build = azure_context_from_environment(
            environment,
            tfvc_server_path="$/ProofBeforePatch",
        )

        with self.assertRaisesRegex(
            AzureReviewVerificationError,
            r"\[build_context_mismatch\]",
        ):
            verify_azure_review_publication(
                publication_bytes,
                self.result_bytes,
                self.report_bytes,
                expected_tfvc=tfvc,
                expected_build=build,
                verified_at="2026-07-28T21:00:30Z",
            )

    def test_verification_rejects_stale_or_future_publication(self) -> None:
        tfvc, build = azure_context_from_environment(
            _changeset_environment(),
            tfvc_server_path="$/ProofBeforePatch",
        )
        publication = self._publication()
        publication_bytes = render_azure_review_publication(publication).encode("utf-8")

        with self.assertRaisesRegex(
            AzureReviewVerificationError,
            r"\[publication_stale\]",
        ):
            verify_azure_review_publication(
                publication_bytes,
                self.result_bytes,
                self.report_bytes,
                expected_tfvc=tfvc,
                expected_build=build,
                verified_at="2026-07-28T22:00:01Z",
                maximum_age_seconds=3600,
            )

        with self.assertRaisesRegex(
            AzureReviewVerificationError,
            r"\[publication_from_future\]",
        ):
            verify_azure_review_publication(
                publication_bytes,
                self.result_bytes,
                self.report_bytes,
                expected_tfvc=tfvc,
                expected_build=build,
                verified_at="2026-07-28T20:59:59Z",
            )

    def test_publication_parser_is_closed_and_cross_checks_target(self) -> None:
        document = to_jsonable(self._publication())
        document["unexpected"] = True
        with self.assertRaisesRegex(AzureReviewValidationError, "is not allowed"):
            parse_azure_review_publication(document)

        mismatched = deepcopy(to_jsonable(self._publication()))
        mismatched["build"]["source_version"] = "123"
        with self.assertRaisesRegex(AzureReviewValidationError, "changeset target"):
            parse_azure_review_publication(mismatched)

        stale_review = deepcopy(to_jsonable(self._publication()))
        stale_review["created_at"] = "2026-07-28T22:00:00Z"
        with self.assertRaisesRegex(AzureReviewValidationError, "after review.reviewed_at"):
            parse_azure_review_publication(stale_review)

    def test_work_item_ids_must_be_unique_positive_integers(self) -> None:
        tfvc, build = azure_context_from_environment(
            _changeset_environment(),
            tfvc_server_path="$/ProofBeforePatch",
        )

        with self.assertRaisesRegex(AzureReviewValidationError, "positive integer"):
            create_azure_review_publication(
                self.result_bytes,
                self.report_bytes,
                tfvc=tfvc,
                build=build,
                work_item_ids=[17, 17],
                created_at="2026-07-28T21:00:00Z",
            )


class AzureReviewCliTests(unittest.TestCase):
    def test_cli_publishes_verifies_and_writes_build_summary(self) -> None:
        case_path = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result_path = root / "result.json"
            report_path = root / "report.md"
            publication_path = root / "publication.json"
            verification_path = root / "verification.json"
            summary_path = root / "summary.md"
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
                patch.dict(os.environ, _changeset_environment(), clear=True),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                publication_exit = main(
                    [
                        "azure-publish",
                        str(result_path),
                        str(report_path),
                        "--tfvc-server-path",
                        "$/ProofBeforePatch",
                        "--work-item-id",
                        "17",
                        "--output",
                        str(publication_path),
                        "--quiet",
                    ]
                )
                verification_exit = main(
                    [
                        "azure-verify",
                        str(publication_path),
                        str(result_path),
                        str(report_path),
                        "--tfvc-server-path",
                        "$/ProofBeforePatch",
                        "--maximum-age-seconds",
                        "60",
                        "--output",
                        str(verification_path),
                        "--summary-output",
                        str(summary_path),
                        "--quiet",
                    ]
                )

            self.assertEqual(0, review_exit)
            self.assertEqual(0, publication_exit)
            self.assertEqual(0, verification_exit)
            self.assertEqual(
                "changeset",
                json.loads(publication_path.read_text(encoding="utf-8"))["tfvc"]["target"]["kind"],
            )
            self.assertEqual(
                "verified",
                json.loads(verification_path.read_text(encoding="utf-8"))["status"],
            )
            self.assertIn("Exact artifact integrity", summary_path.read_text(encoding="utf-8"))


class AzureGateScriptTests(unittest.TestCase):
    def test_script_publishes_verified_artifacts_before_returning_gate_status(self) -> None:
        script = (PROJECT_ROOT / "scripts" / "azure_review_gate.ps1").read_text(encoding="utf-8")

        self.assertIn('$env:TF_BUILD -ne "True"', script)
        self.assertIn("azure-publish", script)
        self.assertIn("azure-verify", script)
        self.assertIn("##vso[task.uploadsummary]", script)
        self.assertIn("##vso[artifact.upload", script)
        self.assertNotIn("SYSTEM_ACCESSTOKEN", script)
        self.assertLess(script.index("azure-verify"), script.index("task.uploadsummary"))
        self.assertLess(script.index("artifact.upload"), script.rindex("exit $reviewExitCode"))


if __name__ == "__main__":
    unittest.main()
