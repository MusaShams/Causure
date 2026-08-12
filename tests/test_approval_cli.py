"""CLI integration for signed approval assertions."""

from __future__ import annotations

import contextlib
import io
import json
import os
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from causure.attestations import public_key_base64url_from_pem, utc_timestamp
from causure.cli import main
from causure.constants import ApprovalAction, Decision
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


class ApprovalCliTests(unittest.TestCase):
    def test_issue_and_verify_approval_emit_separate_record_only_receipt(self) -> None:
        now = datetime.now(UTC).replace(microsecond=0)
        private_key = Ed25519PrivateKey.generate()
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        case_path = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            result_path = root / "result.json"
            report_path = root / "report.md"
            publication_path = root / "publication.json"
            azure_verification_path = root / "azure-verification.json"
            key_path = root / "authority-private.pem"
            assertion_path = root / "approval.json"
            trust_path = root / "approval-trust.json"
            revocations_path = root / "approval-revocations.json"
            receipt_path = root / "approval-verification.json"
            key_path.write_bytes(private_pem)
            trust_path.write_text(
                json.dumps(
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
                                "valid_from": utc_timestamp(now - timedelta(days=1)),
                                "valid_until": utc_timestamp(now + timedelta(days=30)),
                                "allowed_actions": ["approve", "exception"],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            revocations_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "list_id": "approval-revocations-prod",
                        "updated_at": utc_timestamp(now),
                        "revoked_keys": [],
                    }
                ),
                encoding="utf-8",
            )

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
                        "--output",
                        str(publication_path),
                        "--quiet",
                    ]
                )
                azure_verify_exit = main(
                    [
                        "azure-verify",
                        str(publication_path),
                        str(result_path),
                        str(report_path),
                        "--tfvc-server-path",
                        "$/ProofBeforePatch",
                        "--output",
                        str(azure_verification_path),
                        "--quiet",
                    ]
                )
                approval_time = datetime.now(UTC).replace(microsecond=0)
                issue_exit = main(
                    [
                        "issue-approval",
                        str(publication_path),
                        str(azure_verification_path),
                        str(result_path),
                        "--assertion-id",
                        "approval-event-001",
                        "--authority-id",
                        "corporate-approval-service",
                        "--key-id",
                        "approval-key-2026-q3",
                        "--approver-id",
                        "33333333-3333-4333-8333-333333333333",
                        "--identity-provider",
                        "azure-devops:example",
                        "--authentication-method",
                        "azure_devops_approval",
                        "--authentication-event-id",
                        "44444444-4444-4444-8444-444444444444",
                        "--authenticated-at",
                        utc_timestamp(approval_time),
                        "--action",
                        "approve",
                        "--issued-at",
                        utc_timestamp(approval_time),
                        "--expires-at",
                        utc_timestamp(approval_time + timedelta(hours=1)),
                        "--revocation-list-id",
                        "approval-revocations-prod",
                        "--private-key",
                        str(key_path),
                        "--output",
                        str(assertion_path),
                        "--quiet",
                    ]
                )
                verify_exit = main(
                    [
                        "verify-approval",
                        str(assertion_path),
                        str(publication_path),
                        str(azure_verification_path),
                        str(result_path),
                        str(report_path),
                        "--trust-store",
                        str(trust_path),
                        "--revocations",
                        str(revocations_path),
                        "--tfvc-server-path",
                        "$/ProofBeforePatch",
                        "--output",
                        str(receipt_path),
                        "--quiet",
                    ]
                )

            assertion = json.loads(assertion_path.read_text(encoding="utf-8"))
            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(
                (0, 0, 0, 0, 0),
                (
                    review_exit,
                    publication_exit,
                    azure_verify_exit,
                    issue_exit,
                    verify_exit,
                ),
            )
            self.assertEqual(
                "33333333-3333-4333-8333-333333333333",
                assertion["approver"]["subject_id"],
            )
            self.assertEqual("record_only", assertion["gate_effect"])
            self.assertEqual("verified", receipt["status"])
            self.assertEqual("approve", receipt["action"])
            self.assertEqual("record_only", receipt["gate_effect"])
            self.assertEqual("approve", receipt["review"]["decision"])

    def test_verified_exception_writes_receipt_but_keeps_nonapproval_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = {
                name: root / name
                for name in (
                    "assertion.json",
                    "publication.json",
                    "azure-verification.json",
                    "result.json",
                    "report.md",
                    "trust.json",
                    "revocations.json",
                )
            }
            for path in paths.values():
                path.write_text("{}\n", encoding="utf-8")
            output = root / "approval-verification.json"
            verified_exception = SimpleNamespace(
                action=ApprovalAction.EXCEPTION,
                approver=SimpleNamespace(subject_id="approver-subject-001"),
                review=SimpleNamespace(decision=Decision.REJECT),
            )

            with (
                patch(
                    "causure.cli.parse_approval_trust_store",
                    return_value=object(),
                ),
                patch(
                    "causure.cli.parse_approval_revocation_list",
                    return_value=object(),
                ),
                patch(
                    "causure.cli.azure_context_from_environment",
                    return_value=(object(), object()),
                ),
                patch(
                    "causure.cli.verify_approval_assertion",
                    return_value=verified_exception,
                ),
                patch(
                    "causure.cli.render_approval_verification",
                    return_value='{"status":"verified"}\n',
                ),
                contextlib.redirect_stdout(io.StringIO()),
            ):
                exit_code = main(
                    [
                        "verify-approval",
                        str(paths["assertion.json"]),
                        str(paths["publication.json"]),
                        str(paths["azure-verification.json"]),
                        str(paths["result.json"]),
                        str(paths["report.md"]),
                        "--trust-store",
                        str(paths["trust.json"]),
                        "--revocations",
                        str(paths["revocations.json"]),
                        "--tfvc-server-path",
                        "$/ProofBeforePatch",
                        "--output",
                        str(output),
                        "--quiet",
                    ]
                )

            self.assertEqual(1, exit_code)
            self.assertEqual(
                {"status": "verified"},
                json.loads(output.read_text(encoding="utf-8")),
            )


if __name__ == "__main__":
    unittest.main()
