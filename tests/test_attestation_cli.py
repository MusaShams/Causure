"""CLI integration tests for detached producer attestations."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from causure.attestations import public_key_base64url_from_pem, utc_timestamp
from causure.cli import main


class AttestationCliTests(unittest.TestCase):
    def test_public_key_command_exports_trust_store_value(self) -> None:
        private_key = Ed25519PrivateKey.generate()
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "producer-public.pem"
            key_path.write_bytes(public_pem)
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(["public-key", str(key_path)])

        self.assertEqual(0, exit_code)
        self.assertEqual(
            public_key_base64url_from_pem(public_pem),
            stdout.getvalue().strip(),
        )

    def test_attest_and_verify_emit_machine_readable_receipt(self) -> None:
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

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact_path = root / "change-case.json"
            key_path = root / "producer-private.pem"
            attestation_path = root / "change-case.attestation.json"
            trust_path = root / "trust-store.json"
            revocation_path = root / "revocations.json"
            receipt_path = root / "verification.json"
            artifact_path.write_text('{"case_id":"refund-001"}\n', encoding="utf-8")
            key_path.write_bytes(private_pem)
            trust_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "store_id": "evidence-producers-prod",
                        "revocation_list_id": "producer-keys-prod",
                        "keys": [
                            {
                                "key_id": "replay-signing-2026-q3",
                                "producer_id": "replay-service-prod",
                                "algorithm": "ed25519",
                                "public_key_base64url": public_key_base64url_from_pem(public_pem),
                                "valid_from": utc_timestamp(now - timedelta(days=1)),
                                "valid_until": utc_timestamp(now + timedelta(days=365)),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            revocation_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "list_id": "producer-keys-prod",
                        "updated_at": utc_timestamp(now),
                        "revoked_keys": [],
                    }
                ),
                encoding="utf-8",
            )

            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                attest_exit = main(
                    [
                        "attest",
                        str(artifact_path),
                        "--artifact-id",
                        "refund-case-001",
                        "--media-type",
                        "application/json",
                        "--producer-id",
                        "replay-service-prod",
                        "--key-id",
                        "replay-signing-2026-q3",
                        "--private-key",
                        str(key_path),
                        "--issued-at",
                        utc_timestamp(now - timedelta(minutes=1)),
                        "--expires-at",
                        utc_timestamp(now + timedelta(days=1)),
                        "--retention-class",
                        "incident-evidence-90d",
                        "--retain-until",
                        utc_timestamp(now + timedelta(days=90)),
                        "--revocation-list-id",
                        "producer-keys-prod",
                        "--output",
                        str(attestation_path),
                        "--quiet",
                    ]
                )
                verify_exit = main(
                    [
                        "verify-attestation",
                        str(artifact_path),
                        str(attestation_path),
                        "--trust-store",
                        str(trust_path),
                        "--revocations",
                        str(revocation_path),
                        "--output",
                        str(receipt_path),
                        "--quiet",
                    ]
                )

            receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
            self.assertEqual(0, attest_exit)
            self.assertEqual(0, verify_exit)
            self.assertEqual("", stdout.getvalue())
            self.assertEqual("verified", receipt["status"])
            self.assertEqual("refund-case-001", receipt["artifact"]["artifact_id"])
            self.assertEqual("replay-service-prod", receipt["producer"]["producer_id"])

    def test_verify_returns_configuration_error_for_changed_artifact(self) -> None:
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

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            artifact_path = root / "artifact.json"
            key_path = root / "private.pem"
            attestation_path = root / "attestation.json"
            trust_path = root / "trust.json"
            revocation_path = root / "revocations.json"
            artifact_path.write_text('{"value":1}\n', encoding="utf-8")
            key_path.write_bytes(private_pem)
            trust_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "store_id": "producer-trust-prod",
                        "revocation_list_id": "producer-revocations-prod",
                        "keys": [
                            {
                                "key_id": "producer-key-001",
                                "producer_id": "producer-service",
                                "algorithm": "ed25519",
                                "public_key_base64url": public_key_base64url_from_pem(public_pem),
                                "valid_from": utc_timestamp(now - timedelta(days=1)),
                                "valid_until": utc_timestamp(now + timedelta(days=30)),
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            revocation_path.write_text(
                json.dumps(
                    {
                        "schema_version": "1.0",
                        "list_id": "producer-revocations-prod",
                        "updated_at": utc_timestamp(now),
                        "revoked_keys": [],
                    }
                ),
                encoding="utf-8",
            )
            attest_exit = main(
                [
                    "attest",
                    str(artifact_path),
                    "--artifact-id",
                    "artifact-001",
                    "--media-type",
                    "application/json",
                    "--producer-id",
                    "producer-service",
                    "--key-id",
                    "producer-key-001",
                    "--private-key",
                    str(key_path),
                    "--issued-at",
                    utc_timestamp(now - timedelta(minutes=1)),
                    "--expires-at",
                    utc_timestamp(now + timedelta(days=1)),
                    "--retention-class",
                    "evidence-30d",
                    "--retain-until",
                    utc_timestamp(now + timedelta(days=30)),
                    "--revocation-list-id",
                    "producer-revocations-prod",
                    "--output",
                    str(attestation_path),
                    "--quiet",
                ]
            )
            artifact_path.write_text('{"value":2}\n', encoding="utf-8")

            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                verify_exit = main(
                    [
                        "verify-attestation",
                        str(artifact_path),
                        str(attestation_path),
                        "--trust-store",
                        str(trust_path),
                        "--revocations",
                        str(revocation_path),
                    ]
                )

            self.assertEqual(0, attest_exit)
            self.assertEqual(2, verify_exit)
            self.assertIn("[artifact_digest_mismatch]", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
