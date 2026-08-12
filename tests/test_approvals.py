"""Authenticated approval assertions and explicit policy-exception tests."""

from __future__ import annotations

import unittest
from dataclasses import replace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from causure.approvals import (
    ApprovalKeyRevocation,
    ApprovalValidationError,
    ApprovalVerificationError,
    create_approval_assertion,
    parse_approval_assertion,
    parse_approval_revocation_list,
    parse_approval_trust_store,
    render_approval_assertion,
    verify_approval_assertion,
)
from causure.attestations import public_key_base64url_from_pem
from causure.azure_devops import (
    azure_context_from_environment,
    create_azure_review_publication,
    parse_review_result_findings_bytes,
    render_azure_review_publication,
    render_azure_review_verification,
    verify_azure_review_publication,
)
from causure.constants import (
    ApprovalAction,
    ApprovalGateEffect,
    Consequence,
    Decision,
    RevocationMode,
)
from causure.engine import review_case
from causure.io import load_change_case
from causure.models import to_jsonable
from causure.report import render_json, render_markdown
from tests.helpers import PROJECT_ROOT


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
        "BUILD_SOURCEVERSION": "123",
        "BUILD_SOURCEBRANCH": "$/ProofBeforePatch",
        "BUILD_REQUESTEDFORID": "22222222-2222-4222-8222-222222222222",
    }


class ApprovalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.trust_store = parse_approval_trust_store(
            {
                "schema_version": "1.0",
                "store_id": "approval-trust-prod",
                "revocation_list_id": "approval-revocations-prod",
                "keys": [
                    {
                        "key_id": "approval-key-2026-q3",
                        "authority_id": "corporate-approval-service",
                        "algorithm": "ed25519",
                        "public_key_base64url": public_key_base64url_from_pem(public_pem),
                        "valid_from": "2026-07-01T00:00:00Z",
                        "valid_until": "2027-01-01T00:00:00Z",
                        "allowed_actions": ["approve", "exception"],
                    }
                ],
            }
        )
        self.revocations = parse_approval_revocation_list(
            {
                "schema_version": "1.0",
                "list_id": "approval-revocations-prod",
                "updated_at": "2026-07-28T21:03:00Z",
                "revoked_keys": [],
            }
        )
        (
            self.approve_result,
            self.approve_report,
            self.approve_publication,
            self.approve_verification,
            self.tfvc,
            self.build,
        ) = self._chain("approve-refund-tool-description.json")

    @staticmethod
    def _chain(
        case_name: str,
    ) -> tuple[bytes, bytes, bytes, bytes, object, object]:
        case = load_change_case(PROJECT_ROOT / "examples" / "change-cases" / case_name)
        result = replace(
            review_case(case),
            reviewed_at="2026-07-28T20:59:30Z",
        )
        result_bytes = render_json(result).encode("utf-8")
        report_bytes = render_markdown(case, result).encode("utf-8")
        tfvc, build = azure_context_from_environment(
            _changeset_environment(),
            tfvc_server_path="$/ProofBeforePatch",
        )
        publication = create_azure_review_publication(
            result_bytes,
            report_bytes,
            tfvc=tfvc,
            build=build,
            work_item_ids=[17],
            created_at="2026-07-28T21:00:00Z",
        )
        publication_bytes = render_azure_review_publication(publication).encode("utf-8")
        verification = verify_azure_review_publication(
            publication_bytes,
            result_bytes,
            report_bytes,
            expected_tfvc=tfvc,
            expected_build=build,
            verified_at="2026-07-28T21:01:00Z",
        )
        verification_bytes = render_azure_review_verification(verification).encode("utf-8")
        return (
            result_bytes,
            report_bytes,
            publication_bytes,
            verification_bytes,
            tfvc,
            build,
        )

    def _assertion(
        self,
        *,
        result_bytes: bytes | None = None,
        publication_bytes: bytes | None = None,
        verification_bytes: bytes | None = None,
        action: str = "approve",
        finding_codes: tuple[str, ...] = (),
        justification: str | None = None,
        authenticated_at: str = "2026-07-28T21:02:00Z",
        issued_at: str = "2026-07-28T21:03:00Z",
        expires_at: str = "2026-07-29T21:01:00Z",
    ):
        return create_approval_assertion(
            publication_bytes or self.approve_publication,
            verification_bytes or self.approve_verification,
            result_bytes or self.approve_result,
            assertion_id="approval-event-001",
            authority_id="corporate-approval-service",
            key_id="approval-key-2026-q3",
            approver_id="33333333-3333-4333-8333-333333333333",
            identity_provider="azure-devops:example",
            authentication_method="azure_devops_approval",
            authentication_event_id="44444444-4444-4444-8444-444444444444",
            authenticated_at=authenticated_at,
            action=action,
            finding_codes=finding_codes,
            justification=justification,
            issued_at=issued_at,
            expires_at=expires_at,
            revocation_list_id="approval-revocations-prod",
            private_key_pem=self.private_pem,
        )

    def _verify(
        self,
        assertion_bytes: bytes,
        *,
        publication_bytes: bytes | None = None,
        verification_bytes: bytes | None = None,
        result_bytes: bytes | None = None,
        report_bytes: bytes | None = None,
        trust_store=None,
        revocations=None,
        tfvc=None,
        build=None,
        checked_at: str = "2026-07-28T21:04:00Z",
        max_revocation_age_seconds: int = 86400,
    ):
        return verify_approval_assertion(
            assertion_bytes,
            publication_bytes or self.approve_publication,
            verification_bytes or self.approve_verification,
            result_bytes or self.approve_result,
            report_bytes or self.approve_report,
            trust_store or self.trust_store,
            revocations or self.revocations,
            expected_tfvc=tfvc or self.tfvc,
            expected_build=build or self.build,
            checked_at=checked_at,
            max_revocation_age_seconds=max_revocation_age_seconds,
        )

    def test_approve_assertion_authenticates_identity_and_exact_chain(self) -> None:
        assertion = self._assertion()
        assertion_bytes = render_approval_assertion(assertion).encode("utf-8")

        receipt = self._verify(assertion_bytes)

        self.assertEqual("verified", receipt.status)
        self.assertEqual(ApprovalAction.APPROVE, receipt.action)
        self.assertEqual(ApprovalGateEffect.RECORD_ONLY, receipt.gate_effect)
        self.assertEqual(
            "33333333-3333-4333-8333-333333333333",
            receipt.approver.subject_id,
        )
        self.assertEqual(Decision.APPROVE, receipt.review.decision)
        self.assertIsNone(receipt.exception)
        self.assertEqual(assertion, parse_approval_assertion(to_jsonable(assertion)))

    def test_signed_identity_tampering_fails_signature_verification(self) -> None:
        assertion = self._assertion()
        tampered = replace(
            assertion,
            approver=replace(
                assertion.approver,
                subject_id="55555555-5555-4555-8555-555555555555",
            ),
        )

        with self.assertRaisesRegex(
            ApprovalVerificationError,
            r"\[invalid_signature\]",
        ):
            self._verify(render_approval_assertion(tampered).encode("utf-8"))

    def test_every_exact_artifact_boundary_fails_closed_on_mutation(self) -> None:
        assertion_bytes = render_approval_assertion(self._assertion()).encode("utf-8")
        cases = (
            (
                {"publication_bytes": self.approve_publication + b" "},
                "publication_size_mismatch",
            ),
            (
                {"verification_bytes": self.approve_verification + b" "},
                "verification_size_mismatch",
            ),
            (
                {
                    "result_bytes": self.approve_result.replace(
                        b'"policy_name": "default-v1"',
                        b'"policy_name": "changed---"',
                    )
                },
                "approval_chain_invalid",
            ),
            (
                {"report_bytes": self.approve_report + b"changed"},
                "approval_chain_invalid",
            ),
        )
        for arguments, code in cases:
            with (
                self.subTest(code=code),
                self.assertRaisesRegex(ApprovalVerificationError, rf"\[{code}\]"),
            ):
                self._verify(assertion_bytes, **arguments)

    def test_authority_action_permission_and_revocation_fail_closed(self) -> None:
        assertion_bytes = render_approval_assertion(self._assertion()).encode("utf-8")
        exception_only = replace(
            self.trust_store,
            keys=(
                replace(
                    self.trust_store.keys[0],
                    allowed_actions=(ApprovalAction.EXCEPTION,),
                ),
            ),
        )
        with self.assertRaisesRegex(
            ApprovalVerificationError,
            r"\[action_not_authorized\]",
        ):
            self._verify(assertion_bytes, trust_store=exception_only)

        revoked = replace(
            self.revocations,
            revoked_keys=(
                ApprovalKeyRevocation(
                    key_id="approval-key-2026-q3",
                    revoked_at="2026-07-28T21:02:30Z",
                    mode=RevocationMode.ALL_SIGNATURES,
                    reason="authority key compromise",
                ),
            ),
        )
        with self.assertRaisesRegex(
            ApprovalVerificationError,
            r"\[key_revoked\]",
        ):
            self._verify(assertion_bytes, revocations=revoked)

    def test_expiration_and_revocation_freshness_are_checked_at_use_time(self) -> None:
        assertion_bytes = render_approval_assertion(self._assertion()).encode("utf-8")
        with self.assertRaisesRegex(
            ApprovalVerificationError,
            r"\[approval_expired\]",
        ):
            self._verify(assertion_bytes, checked_at="2026-07-29T21:03:00Z")

        with self.assertRaisesRegex(
            ApprovalVerificationError,
            r"\[revocation_list_stale\]",
        ):
            self._verify(
                assertion_bytes,
                checked_at="2026-07-29T20:00:00Z",
                max_revocation_age_seconds=60,
            )

    def test_duplicate_keys_and_unknown_fields_are_rejected(self) -> None:
        document = to_jsonable(self._assertion())
        document["unexpected"] = True
        with self.assertRaisesRegex(ApprovalValidationError, "unknown field"):
            parse_approval_assertion(document)

        assertion_text = render_approval_assertion(self._assertion()).rstrip()
        duplicate = assertion_text[:-1] + ',"action":"approve"}'
        with self.assertRaisesRegex(
            ApprovalVerificationError,
            r"\[assertion_invalid\].*duplicate JSON key",
        ):
            self._verify(duplicate.encode("utf-8"))

    def test_exception_must_cover_every_decision_affecting_finding(self) -> None:
        (
            reject_result,
            reject_report,
            reject_publication,
            reject_verification,
            tfvc,
            build,
        ) = self._chain("reject-overbroad-prompt.json")
        consequential = tuple(
            sorted(
                finding.code
                for finding in parse_review_result_findings_bytes(reject_result)
                if finding.consequence is not Consequence.NONE
            )
        )
        with self.assertRaisesRegex(
            ApprovalValidationError,
            "exactly cover every decision-affecting finding",
        ):
            self._assertion(
                result_bytes=reject_result,
                publication_bytes=reject_publication,
                verification_bytes=reject_verification,
                action="exception",
                finding_codes=consequential[:-1],
                justification="Temporary, risk-accepted emergency deployment.",
            )

        assertion = self._assertion(
            result_bytes=reject_result,
            publication_bytes=reject_publication,
            verification_bytes=reject_verification,
            action="exception",
            finding_codes=consequential,
            justification="Temporary, risk-accepted emergency deployment.",
        )
        receipt = self._verify(
            render_approval_assertion(assertion).encode("utf-8"),
            publication_bytes=reject_publication,
            verification_bytes=reject_verification,
            result_bytes=reject_result,
            report_bytes=reject_report,
            tfvc=tfvc,
            build=build,
        )

        self.assertEqual(ApprovalAction.EXCEPTION, receipt.action)
        self.assertEqual(Decision.REJECT, receipt.review.decision)
        self.assertEqual(ApprovalGateEffect.RECORD_ONLY, receipt.gate_effect)
        self.assertEqual(consequential, receipt.exception.finding_codes)

    def test_action_cannot_relabel_the_deterministic_gate_decision(self) -> None:
        (
            reject_result,
            _,
            reject_publication,
            reject_verification,
            _,
            _,
        ) = self._chain("reject-overbroad-prompt.json")
        with self.assertRaisesRegex(
            ApprovalValidationError,
            "approve is valid only for an approve gate decision",
        ):
            self._assertion(
                result_bytes=reject_result,
                publication_bytes=reject_publication,
                verification_bytes=reject_verification,
            )
        with self.assertRaisesRegex(
            ApprovalValidationError,
            "exception is valid only for a non-approve gate decision",
        ):
            self._assertion(
                action="exception",
                finding_codes=("CAUSURE-MET-001",),
                justification="Not a valid exception target.",
            )

    def test_approval_event_order_and_lifetime_are_bounded(self) -> None:
        with self.assertRaisesRegex(
            ApprovalValidationError,
            "at or after the bound pre-approval verification",
        ):
            self._assertion(authenticated_at="2026-07-28T21:00:59Z")

        with self.assertRaisesRegex(
            ApprovalValidationError,
            "within 15 minutes",
        ):
            self._assertion(
                authenticated_at="2026-07-28T21:02:00Z",
                issued_at="2026-07-28T21:17:01Z",
                expires_at="2026-07-29T21:17:01Z",
            )

        with self.assertRaisesRegex(
            ApprovalValidationError,
            "must not exceed 24 hours",
        ):
            self._assertion(expires_at="2026-07-29T21:03:01Z")

        with self.assertRaisesRegex(
            ApprovalValidationError,
            "within 24 hours of the bound pre-approval verification",
        ):
            self._assertion(expires_at="2026-07-29T21:01:01Z")

    def test_current_azure_build_is_rechecked_after_approval(self) -> None:
        assertion_bytes = render_approval_assertion(self._assertion()).encode("utf-8")
        wrong_build = replace(self.build, build_id=43)

        with self.assertRaisesRegex(
            ApprovalVerificationError,
            r"\[approval_chain_invalid\]",
        ):
            self._verify(assertion_bytes, build=wrong_build)


if __name__ == "__main__":
    unittest.main()
