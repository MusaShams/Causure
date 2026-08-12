"""Exact-chain, privacy, and append-only tests for Team dashboard case records."""

from __future__ import annotations

import json
import unittest
from copy import deepcopy
from dataclasses import replace
from pathlib import Path

from causure.approvals import (
    render_approval_assertion,
    render_approval_verification,
)
from causure.azure_devops import (
    azure_context_from_environment,
    create_azure_review_publication,
    parse_review_result_findings_bytes,
    render_azure_review_publication,
    render_azure_review_verification,
    verify_azure_review_publication,
)
from causure.canary import render_canary_result
from causure.constants import Consequence
from causure.engine import review_case
from causure.io import load_change_case
from causure.models import to_jsonable
from causure.report import render_json, render_markdown
from causure.team_cases import (
    TeamCaseValidationError,
    create_team_case_record,
    parse_team_case_record,
    parse_team_case_record_bytes,
    render_team_case_record,
    validate_team_case_successor,
)
from tests import test_approvals
from tests.helpers import PROJECT_ROOT
from tests.test_approvals import _changeset_environment
from tests.test_canary import _artifacts as _canary_artifacts
from tests.test_canary import _compare as _compare_canary


def _base_artifacts(
    case_name: str = "approve-refund-tool-description.json",
) -> tuple[bytes, bytes, bytes]:
    case_path = PROJECT_ROOT / "examples" / "change-cases" / case_name
    case = load_change_case(case_path)
    result = replace(
        review_case(case),
        reviewed_at="2026-07-28T20:59:30Z",
    )
    return (
        case_path.read_bytes(),
        render_json(result).encode("utf-8"),
        render_markdown(case, result).encode("utf-8"),
    )


def _azure_artifacts() -> tuple[bytes, bytes, bytes, bytes, bytes]:
    case_bytes, review_bytes, report_bytes = _base_artifacts()
    tfvc, build = azure_context_from_environment(
        _changeset_environment(),
        tfvc_server_path="$/ProofBeforePatch",
    )
    publication = create_azure_review_publication(
        review_bytes,
        report_bytes,
        tfvc=tfvc,
        build=build,
        work_item_ids=[17, 93],
        created_at="2026-07-28T21:00:00Z",
    )
    publication_bytes = render_azure_review_publication(publication).encode("utf-8")
    verification = verify_azure_review_publication(
        publication_bytes,
        review_bytes,
        report_bytes,
        expected_tfvc=tfvc,
        expected_build=build,
        verified_at="2026-07-28T21:01:00Z",
    )
    return (
        case_bytes,
        review_bytes,
        report_bytes,
        publication_bytes,
        render_azure_review_verification(verification).encode("utf-8"),
    )


def _approval_artifacts() -> tuple[bytes, bytes, bytes, bytes, bytes, bytes]:
    fixture = test_approvals.ApprovalTests(
        methodName="test_approve_assertion_authenticates_identity_and_exact_chain"
    )
    fixture.setUp()
    assertion_bytes = render_approval_assertion(fixture._assertion()).encode("utf-8")
    receipt = fixture._verify(assertion_bytes)
    case_bytes = (
        PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
    ).read_bytes()
    return (
        case_bytes,
        fixture.approve_result,
        fixture.approve_report,
        fixture.approve_publication,
        fixture.approve_verification,
        render_approval_verification(receipt).encode("utf-8"),
    )


class TeamCaseRecordTests(unittest.TestCase):
    def test_base_record_is_deterministic_minimized_and_round_trips(self) -> None:
        case_bytes, review_bytes, _ = _base_artifacts()

        record = create_team_case_record(
            case_bytes,
            review_bytes,
            tenant_id="tenant-acme",
            revision=1,
            published_at="2026-08-03T12:00:00Z",
        )
        rendered = render_team_case_record(record)

        self.assertEqual(record, parse_team_case_record_bytes(rendered.encode("utf-8")))
        self.assertEqual(
            rendered, render_team_case_record(parse_team_case_record(json.loads(rendered)))
        )
        self.assertEqual("refund-tool-description-001", record.case_id)
        self.assertIsNone(record.delivery)
        self.assertIsNone(record.approval)
        self.assertIsNone(record.canary)
        source_ref = json.loads(case_bytes)["incident"]["source_refs"][0]
        self.assertNotIn(source_ref, rendered)
        self.assertNotIn("evidence_refs", rendered)
        self.assertNotIn("observed_behavior", rendered)

    def test_full_delivery_and_approval_chain_is_cross_bound(self) -> None:
        case, review, _, publication, verification, approval = _approval_artifacts()

        record = create_team_case_record(
            case,
            review,
            tenant_id="tenant-acme",
            revision=1,
            published_at="2026-08-03T12:00:00Z",
            azure_publication_bytes=publication,
            azure_verification_bytes=verification,
            approval_verification_bytes=approval,
        )

        self.assertEqual(123, record.delivery.changeset_id)
        self.assertEqual("approve", record.approval.action.value)
        self.assertEqual("record_only", record.approval.gate_effect.value)
        self.assertEqual(64, len(record.sources.approval_verification.sha256))
        self.assertEqual(
            record, parse_team_case_record_bytes(render_team_case_record(record).encode())
        )

        changed = json.loads(approval)
        changed["build_id"] += 1
        with self.assertRaisesRegex(TeamCaseValidationError, "Azure artifacts"):
            create_team_case_record(
                case,
                review,
                tenant_id="tenant-acme",
                revision=1,
                published_at="2026-08-03T12:00:00Z",
                azure_publication_bytes=publication,
                azure_verification_bytes=verification,
                approval_verification_bytes=(json.dumps(changed) + "\n").encode(),
            )

    def test_canary_result_is_bound_and_parser_rechecks_semantics(self) -> None:
        observation, policy, case, review, _ = _canary_artifacts()
        result = _compare_canary(observation, policy, case, review)
        canary_bytes = render_canary_result(result).encode("utf-8")
        record = create_team_case_record(
            case,
            review,
            tenant_id="tenant-acme",
            revision=1,
            published_at="2026-08-03T12:00:00Z",
            canary_result_bytes=canary_bytes,
        )

        self.assertEqual("promote", record.canary.decision.value)
        document = to_jsonable(record)
        document["canary"]["candidate_deployment_ref"] = document["canary"][
            "baseline_deployment_ref"
        ]
        with self.assertRaisesRegex(TeamCaseValidationError, "must differ"):
            parse_team_case_record(document)

        substituted = json.loads(canary_bytes)
        substituted["review_result_sha256"] = "0" * 64
        with self.assertRaisesRegex(TeamCaseValidationError, "does not bind"):
            create_team_case_record(
                case,
                review,
                tenant_id="tenant-acme",
                revision=1,
                published_at="2026-08-03T12:00:00Z",
                canary_result_bytes=(json.dumps(substituted) + "\n").encode(),
            )

    def test_successors_are_additive_and_exact_subjects_are_immutable(self) -> None:
        case, review, _, publication, verification = _azure_artifacts()
        base = create_team_case_record(
            case,
            review,
            tenant_id="tenant-acme",
            revision=1,
            published_at="2026-08-03T12:00:00Z",
        )
        delivered = create_team_case_record(
            case,
            review,
            tenant_id="tenant-acme",
            revision=2,
            published_at="2026-08-03T12:01:00Z",
            azure_publication_bytes=publication,
            azure_verification_bytes=verification,
        )
        self.assertEqual(delivered, validate_team_case_successor(base, delivered))

        swapped = replace(
            delivered,
            revision=3,
            published_at="2026-08-03T12:02:00Z",
            sources=replace(
                delivered.sources,
                azure_publication=replace(
                    delivered.sources.azure_publication,
                    sha256="0" * 64,
                ),
            ),
        )
        with self.assertRaisesRegex(TeamCaseValidationError, "subjects are immutable"):
            validate_team_case_successor(delivered, swapped)

        removed = replace(
            delivered,
            revision=3,
            published_at="2026-08-03T12:02:00Z",
            delivery=None,
        )
        with self.assertRaisesRegex(TeamCaseValidationError, "cannot be removed"):
            validate_team_case_successor(delivered, removed)

    def test_stored_stage_time_order_is_revalidated(self) -> None:
        case, review, _, publication, verification, approval = _approval_artifacts()
        record = create_team_case_record(
            case,
            review,
            tenant_id="tenant-acme",
            revision=1,
            published_at="2026-08-03T12:00:00Z",
            azure_publication_bytes=publication,
            azure_verification_bytes=verification,
            approval_verification_bytes=approval,
        )
        document = to_jsonable(record)
        document["delivery"]["verified_at"] = "2026-07-28T20:59:59Z"
        with self.assertRaisesRegex(TeamCaseValidationError, "after published_at"):
            parse_team_case_record(document)

        document = to_jsonable(record)
        document["approval"]["checked_at"] = document["approval"]["expires_at"]
        with self.assertRaisesRegex(TeamCaseValidationError, "validity window"):
            parse_team_case_record(document)

    def test_parser_rejects_unknown_duplicate_and_nonfinite_documents(self) -> None:
        case, review, _ = _base_artifacts()
        record = create_team_case_record(
            case,
            review,
            tenant_id="tenant-acme",
            revision=1,
            published_at="2026-08-03T12:00:00Z",
        )
        document = to_jsonable(record)
        document["unknown"] = True
        with self.assertRaisesRegex(TeamCaseValidationError, "unknown field"):
            parse_team_case_record(document)

        rendered = render_team_case_record(record).rstrip()
        duplicate = rendered[:-1] + ',\n  "tenant_id": "tenant-other"\n}\n'
        with self.assertRaisesRegex(TeamCaseValidationError, "duplicate JSON key"):
            parse_team_case_record_bytes(duplicate.encode())

        nonfinite = deepcopy(to_jsonable(record))
        nonfinite["evidence"]["hypotheses"][0]["confidence"] = float("inf")
        with self.assertRaises(TeamCaseValidationError):
            parse_team_case_record_bytes(json.dumps(nonfinite, allow_nan=True).encode())

    def test_exception_justification_is_not_retained_in_dashboard_record(self) -> None:
        fixture = test_approvals.ApprovalTests(
            methodName="test_exception_must_cover_every_decision_affecting_finding"
        )
        fixture.setUp()
        result, report, publication, verification, tfvc, build = fixture._chain(
            "reject-overbroad-prompt.json"
        )
        codes = tuple(
            sorted(
                finding.code
                for finding in parse_review_result_findings_bytes(result)
                if finding.consequence is not Consequence.NONE
            )
        )
        secret = "Sensitive exception rationale that must remain outside the dashboard"
        assertion = fixture._assertion(
            result_bytes=result,
            publication_bytes=publication,
            verification_bytes=verification,
            action="exception",
            finding_codes=codes,
            justification=secret,
        )
        receipt = fixture._verify(
            render_approval_assertion(assertion).encode(),
            publication_bytes=publication,
            verification_bytes=verification,
            result_bytes=result,
            report_bytes=report,
            tfvc=tfvc,
            build=build,
        )
        receipt_bytes = render_approval_verification(receipt).encode()
        case = (
            Path(PROJECT_ROOT) / "examples" / "change-cases" / "reject-overbroad-prompt.json"
        ).read_bytes()
        record = create_team_case_record(
            case,
            result,
            tenant_id="tenant-acme",
            revision=1,
            published_at="2026-08-03T12:00:00Z",
            azure_publication_bytes=publication,
            azure_verification_bytes=verification,
            approval_verification_bytes=receipt_bytes,
        )

        rendered = render_team_case_record(record)
        self.assertNotIn(secret, rendered)
        self.assertEqual(codes, record.approval.exception_finding_codes)

        changed = json.loads(receipt_bytes)
        changed["exception"]["finding_codes"] = ["fabricated-finding"]
        with self.assertRaisesRegex(TeamCaseValidationError, "must exactly cover"):
            create_team_case_record(
                case,
                result,
                tenant_id="tenant-acme",
                revision=1,
                published_at="2026-08-03T12:00:00Z",
                azure_publication_bytes=publication,
                azure_verification_bytes=verification,
                approval_verification_bytes=(json.dumps(changed) + "\n").encode(),
            )


if __name__ == "__main__":
    unittest.main()
