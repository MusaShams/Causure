"""Detached producer attestation contract and verification tests."""

from __future__ import annotations

import copy
import json
import unittest
from dataclasses import replace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from causure.attestations import (
    AttestationValidationError,
    AttestationVerificationError,
    KeyRevocation,
    attestation_payload_bytes,
    create_artifact_attestation,
    parse_artifact_attestation,
    parse_attestation_revocation_list,
    parse_attestation_trust_store,
    public_key_base64url_from_pem,
    render_artifact_attestation,
    verify_artifact_attestation,
)
from causure.constants import RevocationMode
from causure.models import to_jsonable


class AttestationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.generate()
        self.private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        self.public_pem = self.private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.artifact = b'{"case_id":"refund-001","decision":"approve"}\n'
        self.attestation = create_artifact_attestation(
            self.artifact,
            artifact_id="refund-case-001",
            media_type="application/json",
            producer_id="replay-service-prod",
            key_id="replay-signing-2026-q3",
            private_key_pem=self.private_pem,
            issued_at="2026-07-28T11:50:00Z",
            expires_at="2026-07-30T12:00:00Z",
            retention_class="incident-evidence-90d",
            retain_until="2026-10-26T12:00:00Z",
            revocation_list_id="producer-keys-prod",
        )
        public_key = public_key_base64url_from_pem(self.public_pem)
        self.trust_store = parse_attestation_trust_store(
            {
                "schema_version": "1.0",
                "store_id": "evidence-producers-prod",
                "revocation_list_id": "producer-keys-prod",
                "keys": [
                    {
                        "key_id": "replay-signing-2026-q3",
                        "producer_id": "replay-service-prod",
                        "algorithm": "ed25519",
                        "public_key_base64url": public_key,
                        "valid_from": "2026-07-01T00:00:00Z",
                        "valid_until": "2027-01-01T00:00:00Z",
                    }
                ],
            }
        )
        self.revocations = parse_attestation_revocation_list(
            {
                "schema_version": "1.0",
                "list_id": "producer-keys-prod",
                "updated_at": "2026-07-28T12:00:00Z",
                "revoked_keys": [],
            }
        )

    def test_valid_attestation_verifies_exact_artifact(self) -> None:
        verification = verify_artifact_attestation(
            self.artifact,
            self.attestation,
            self.trust_store,
            self.revocations,
            checked_at="2026-07-28T12:01:00Z",
        )

        self.assertEqual("verified", verification.status)
        self.assertEqual("refund-case-001", verification.artifact.artifact_id)
        self.assertEqual("replay-service-prod", verification.producer.producer_id)
        self.assertEqual("incident-evidence-90d", verification.retention.class_id)

    def test_same_length_artifact_change_fails_digest_check(self) -> None:
        changed = self.artifact.replace(b"approve", b"rejeeee")

        with self.assertRaisesRegex(
            AttestationVerificationError,
            r"\[artifact_digest_mismatch\]",
        ):
            verify_artifact_attestation(
                changed,
                self.attestation,
                self.trust_store,
                self.revocations,
                checked_at="2026-07-28T12:01:00Z",
            )

    def test_different_length_artifact_fails_size_check(self) -> None:
        with self.assertRaisesRegex(
            AttestationVerificationError,
            r"\[artifact_size_mismatch\]",
        ):
            verify_artifact_attestation(
                self.artifact + b" ",
                self.attestation,
                self.trust_store,
                self.revocations,
                checked_at="2026-07-28T12:01:00Z",
            )

    def test_signed_metadata_tampering_fails_signature_check(self) -> None:
        tampered = replace(
            self.attestation,
            retention=replace(
                self.attestation.retention,
                class_id="incident-evidence-7d",
            ),
        )

        with self.assertRaisesRegex(
            AttestationVerificationError,
            r"\[invalid_signature\]",
        ):
            verify_artifact_attestation(
                self.artifact,
                tampered,
                self.trust_store,
                self.revocations,
                checked_at="2026-07-28T12:01:00Z",
            )

    def test_compromise_revocation_invalidates_all_signatures(self) -> None:
        revoked = replace(
            self.revocations,
            revoked_keys=(
                KeyRevocation(
                    key_id="replay-signing-2026-q3",
                    revoked_at="2026-07-28T11:55:00Z",
                    mode=RevocationMode.ALL_SIGNATURES,
                    reason="key compromise",
                ),
            ),
        )

        with self.assertRaisesRegex(
            AttestationVerificationError,
            r"\[key_revoked\]",
        ):
            verify_artifact_attestation(
                self.artifact,
                self.attestation,
                self.trust_store,
                revoked,
                checked_at="2026-07-28T12:01:00Z",
            )

    def test_retirement_revocation_preserves_prior_signatures(self) -> None:
        retired = replace(
            self.revocations,
            revoked_keys=(
                KeyRevocation(
                    key_id="replay-signing-2026-q3",
                    revoked_at="2026-07-28T11:55:00Z",
                    mode=RevocationMode.ISSUED_AT_OR_AFTER,
                    reason="scheduled rotation",
                ),
            ),
        )

        verification = verify_artifact_attestation(
            self.artifact,
            self.attestation,
            self.trust_store,
            retired,
            checked_at="2026-07-28T12:01:00Z",
        )

        self.assertEqual("verified", verification.status)

    def test_retirement_rejects_signatures_issued_after_cutoff(self) -> None:
        later_attestation = create_artifact_attestation(
            self.artifact,
            artifact_id="refund-case-001",
            media_type="application/json",
            producer_id="replay-service-prod",
            key_id="replay-signing-2026-q3",
            private_key_pem=self.private_pem,
            issued_at="2026-07-28T11:56:00Z",
            expires_at="2026-07-30T12:00:00Z",
            retention_class="incident-evidence-90d",
            retain_until="2026-10-26T12:00:00Z",
            revocation_list_id="producer-keys-prod",
        )
        retired = replace(
            self.revocations,
            revoked_keys=(
                KeyRevocation(
                    key_id="replay-signing-2026-q3",
                    revoked_at="2026-07-28T11:55:00Z",
                    mode=RevocationMode.ISSUED_AT_OR_AFTER,
                    reason="scheduled rotation",
                ),
            ),
        )

        with self.assertRaisesRegex(
            AttestationVerificationError,
            r"\[key_revoked\]",
        ):
            verify_artifact_attestation(
                self.artifact,
                later_attestation,
                self.trust_store,
                retired,
                checked_at="2026-07-28T12:01:00Z",
            )

    def test_expired_attestation_fails_closed(self) -> None:
        with self.assertRaisesRegex(
            AttestationVerificationError,
            r"\[attestation_expired\]",
        ):
            verify_artifact_attestation(
                self.artifact,
                self.attestation,
                self.trust_store,
                self.revocations,
                checked_at="2026-07-30T12:00:00Z",
            )

    def test_stale_revocation_list_fails_closed(self) -> None:
        stale = replace(
            self.revocations,
            updated_at="2026-07-27T10:00:00Z",
        )

        with self.assertRaisesRegex(
            AttestationVerificationError,
            r"\[revocation_list_stale\]",
        ):
            verify_artifact_attestation(
                self.artifact,
                self.attestation,
                self.trust_store,
                stale,
                checked_at="2026-07-28T12:01:00Z",
            )

    def test_untrusted_producer_binding_fails_closed(self) -> None:
        mismatched_key = replace(
            self.trust_store.keys[0],
            producer_id="different-producer",
        )
        trust_store = replace(self.trust_store, keys=(mismatched_key,))

        with self.assertRaisesRegex(
            AttestationVerificationError,
            r"\[producer_mismatch\]",
        ):
            verify_artifact_attestation(
                self.artifact,
                self.attestation,
                trust_store,
                self.revocations,
                checked_at="2026-07-28T12:01:00Z",
            )

    def test_attestation_window_must_fit_inside_key_window(self) -> None:
        short_lived_key = replace(
            self.trust_store.keys[0],
            valid_until="2026-07-29T12:00:00Z",
        )
        trust_store = replace(self.trust_store, keys=(short_lived_key,))

        with self.assertRaisesRegex(
            AttestationVerificationError,
            r"\[key_validity_exceeded\]",
        ):
            verify_artifact_attestation(
                self.artifact,
                self.attestation,
                trust_store,
                self.revocations,
                checked_at="2026-07-28T12:01:00Z",
            )

    def test_revocation_list_identity_must_match_trust_policy(self) -> None:
        wrong_list = replace(self.revocations, list_id="different-revocations")

        with self.assertRaisesRegex(
            AttestationVerificationError,
            r"\[revocation_list_mismatch\]",
        ):
            verify_artifact_attestation(
                self.artifact,
                self.attestation,
                self.trust_store,
                wrong_list,
                checked_at="2026-07-28T12:01:00Z",
            )

    def test_retention_must_cover_full_attestation_validity(self) -> None:
        document = to_jsonable(self.attestation)
        document["retention"]["retain_until"] = "2026-07-29T12:00:00Z"

        with self.assertRaisesRegex(
            AttestationValidationError,
            "must be at or after expires_at",
        ):
            parse_artifact_attestation(document)

    def test_unknown_attestation_fields_are_rejected(self) -> None:
        document = to_jsonable(self.attestation)
        document["storage_url"] = "https://example.invalid/secret"

        with self.assertRaisesRegex(
            AttestationValidationError,
            "unknown field",
        ):
            parse_artifact_attestation(document)

    def test_invalid_unicode_scalar_is_rejected_before_canonicalization(self) -> None:
        document = to_jsonable(self.revocations)
        document["revoked_keys"] = [
            {
                "key_id": "replay-signing-2026-q3",
                "revoked_at": "2026-07-28T11:55:00Z",
                "mode": "all_signatures",
                "reason": "\ud800",
            }
        ]

        with self.assertRaisesRegex(
            AttestationValidationError,
            "valid Unicode scalar values",
        ):
            parse_attestation_revocation_list(document)

    def test_duplicate_trust_and_revocation_key_ids_are_rejected(self) -> None:
        trust_document = to_jsonable(self.trust_store)
        trust_document["keys"].append(copy.deepcopy(trust_document["keys"][0]))
        with self.assertRaisesRegex(
            AttestationValidationError,
            "key IDs must be unique",
        ):
            parse_attestation_trust_store(trust_document)

        revocation_document = to_jsonable(self.revocations)
        entry = {
            "key_id": "replay-signing-2026-q3",
            "revoked_at": "2026-07-28T11:55:00Z",
            "mode": "all_signatures",
            "reason": "compromise",
        }
        revocation_document["revoked_keys"] = [entry, copy.deepcopy(entry)]
        with self.assertRaisesRegex(
            AttestationValidationError,
            "key IDs must be unique",
        ):
            parse_attestation_revocation_list(revocation_document)

    def test_payload_and_rendering_are_deterministic(self) -> None:
        rendered = render_artifact_attestation(self.attestation)
        reparsed = parse_artifact_attestation(json.loads(rendered))

        self.assertEqual(
            attestation_payload_bytes(self.attestation),
            attestation_payload_bytes(reparsed),
        )
        self.assertEqual(rendered, render_artifact_attestation(reparsed))

    def test_public_key_export_accepts_public_private_and_encrypted_pem(self) -> None:
        encrypted = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(b"test-password"),
        )

        expected = public_key_base64url_from_pem(self.public_pem)
        self.assertEqual(expected, public_key_base64url_from_pem(self.private_pem))
        self.assertEqual(
            expected,
            public_key_base64url_from_pem(
                encrypted,
                password=b"test-password",
            ),
        )


if __name__ == "__main__":
    unittest.main()
