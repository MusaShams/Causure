"""Tests for protected OpenAI quota pilot-state preparation."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

from causure.openai_quota_host import parse_openai_quota_host_configuration_bytes
from causure.openai_quota_pilot import (
    OpenAIQuotaPilotDependencyError,
    OpenAIQuotaPilotError,
    prepare_openai_quota_pilot_state,
)
from tests.helpers import PROJECT_ROOT

_NOW = datetime(2026, 8, 9, 20, 0, tzinfo=UTC)
_PROVIDER_KEY = "provider-pilot-key-that-is-long-enough-12345"


def _quota_bytes() -> bytes:
    document = {
        "schema_version": "1.0",
        "service_id": "openai-quota-company-pilot",
        "upstream_responses_url": "https://api.example.test/v1/responses",
        "worker_proxy_url": "https://openai-quota:8443/v1",
        "proxy_container_name": "openai-quota",
        "network_name": "causure-quota",
        "lease_cleanup_seconds": 30,
        "upstream_timeout_seconds": 20.0,
        "max_request_bytes": 65_536,
        "max_response_bytes": 65_536,
        "models": [
            {
                "model": "company-qualified-model-2026-08-01",
                "input_usd_per_million_tokens": "1.000000",
                "cached_input_usd_per_million_tokens": "1.000000",
                "output_usd_per_million_tokens": "2.000000",
                "max_input_tokens": 10_000,
                "max_output_tokens": 1_000,
            }
        ],
    }
    return (json.dumps(document, indent=2) + "\n").encode()


class OpenAIQuotaPilotPreparationTests(unittest.TestCase):
    def test_preparation_creates_new_closed_state_without_retaining_ca_key_or_secret_hashes(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            quota_path = root / "input-quota.json"
            provider_path = root / "provider-key"
            output = root / "pilot-state"
            quota_bytes = _quota_bytes()
            quota_path.write_bytes(quota_bytes)
            provider_path.write_text(_PROVIDER_KEY, encoding="ascii")

            state = prepare_openai_quota_pilot_state(
                quota_path,
                provider_path,
                output,
                valid_days=30,
                now=_NOW,
            )
            manifest_text = Path(state.manifest_path).read_text(encoding="utf-8")
            manifest = json.loads(manifest_text)
            host_bytes = Path(state.host_configuration_path).read_bytes()
            host = parse_openai_quota_host_configuration_bytes(host_bytes)
            copied_provider = output / "secrets" / "openai-provider-api-key"
            admin_token = output / "secrets" / "openai-quota-admin-token"

            self.assertEqual(_PROVIDER_KEY.encode(), copied_provider.read_bytes())
            self.assertGreaterEqual(len(admin_token.read_bytes()), 32)
            self.assertNotEqual(copied_provider.read_bytes(), admin_token.read_bytes())
            self.assertNotIn(_PROVIDER_KEY, manifest_text)
            self.assertNotIn(admin_token.read_text(encoding="ascii"), manifest_text)
            self.assertFalse(manifest["tls"]["ca_private_key_retained"])
            self.assertFalse(manifest["secret_delivery"]["secret_hashes_recorded"])
            self.assertFalse((output / "tls" / "ca.key").exists())
            self.assertEqual(
                hashlib.sha256(quota_bytes).hexdigest(),
                host.quota_configuration.sha256,
            )
            self.assertEqual("0.0.0.0", host.server.listen_host)
            self.assertEqual("https", host.server.trusted_external_scheme)
            self.assertNotIn(_PROVIDER_KEY, repr(state))

    def test_generated_certificate_has_only_the_pilot_names_and_short_lifetime(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            quota_path = root / "input-quota.json"
            provider_path = root / "provider-key"
            output = root / "pilot-state"
            quota_path.write_bytes(_quota_bytes())
            provider_path.write_text(_PROVIDER_KEY, encoding="ascii")

            prepare_openai_quota_pilot_state(
                quota_path,
                provider_path,
                output,
                valid_days=7,
                now=_NOW,
            )
            certificate = x509.load_pem_x509_certificate(
                (output / "tls" / "quota-server.crt").read_bytes()
            )
            names = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_ALTERNATIVE_NAME
            ).value
            authority_key = certificate.extensions.get_extension_for_oid(
                ExtensionOID.AUTHORITY_KEY_IDENTIFIER
            ).value
            subject_key = certificate.extensions.get_extension_for_oid(
                ExtensionOID.SUBJECT_KEY_IDENTIFIER
            ).value

        self.assertEqual(
            {"localhost", "openai-quota", "openai-quota-admin"},
            set(names.get_values_for_type(x509.DNSName)),
        )
        self.assertEqual(
            {"127.0.0.1", "::1"},
            {str(value) for value in names.get_values_for_type(x509.IPAddress)},
        )
        self.assertEqual(
            7 * 24 * 60 * 60,
            int((certificate.not_valid_after_utc - _NOW).total_seconds()),
        )
        self.assertIsNotNone(authority_key.key_identifier)
        self.assertIsNotNone(subject_key.digest)

    def test_preparation_rejects_reference_config_bad_secret_existing_state_and_bad_lifetime(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            provider_path = root / "provider-key"
            provider_path.write_text(_PROVIDER_KEY, encoding="ascii")
            reference = PROJECT_ROOT / "examples" / "quota" / "openai-compatible-reference.json"
            with self.assertRaisesRegex(OpenAIQuotaPilotError, "non-operational"):
                prepare_openai_quota_pilot_state(
                    reference,
                    provider_path,
                    root / "reference-state",
                    now=_NOW,
                )

            quota_path = root / "input-quota.json"
            quota_path.write_bytes(_quota_bytes())
            provider_path.write_text(f"{_PROVIDER_KEY}\nsecond-line", encoding="ascii")
            with self.assertRaisesRegex(OpenAIQuotaPilotError, "trailing source newline"):
                prepare_openai_quota_pilot_state(
                    quota_path,
                    provider_path,
                    root / "bad-secret-state",
                    now=_NOW,
                )

            provider_path.write_text(f"{_PROVIDER_KEY}\n", encoding="ascii")
            newline_state = root / "one-newline-state"
            prepare_openai_quota_pilot_state(
                quota_path,
                provider_path,
                newline_state,
                now=_NOW,
            )
            self.assertEqual(
                _PROVIDER_KEY.encode(),
                (newline_state / "secrets" / "openai-provider-api-key").read_bytes(),
            )

            provider_path.write_text(_PROVIDER_KEY, encoding="ascii")
            existing = root / "existing"
            existing.mkdir()
            with self.assertRaisesRegex(OpenAIQuotaPilotError, "will not be overwritten"):
                prepare_openai_quota_pilot_state(
                    quota_path,
                    provider_path,
                    existing,
                    now=_NOW,
                )
            with self.assertRaisesRegex(OpenAIQuotaPilotError, "valid_days"):
                prepare_openai_quota_pilot_state(
                    quota_path,
                    provider_path,
                    root / "lifetime-state",
                    valid_days=91,
                    now=_NOW,
                )

    def test_cryptography_version_drift_fails_before_state_is_created(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            quota_path = root / "input-quota.json"
            provider_path = root / "provider-key"
            output = root / "pilot-state"
            quota_path.write_bytes(_quota_bytes())
            provider_path.write_text(_PROVIDER_KEY, encoding="ascii")

            with patch(
                "causure.openai_quota_pilot.metadata.version",
                return_value="48.0.0",
            ):
                with self.assertRaises(OpenAIQuotaPilotDependencyError):
                    prepare_openai_quota_pilot_state(
                        quota_path,
                        provider_path,
                        output,
                        now=_NOW,
                    )

            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
