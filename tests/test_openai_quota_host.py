"""Tests for the closed OpenAI-compatible quota service host."""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from waitress.adjustments import Adjustments

import causure.openai_quota_host as quota_host
from causure.openai_quota_host import (
    OpenAIQuotaHostConfigurationError,
    OpenAIQuotaHostRuntimeError,
    create_openai_quota_host_runtime,
    load_openai_quota_host_configuration_subject,
    openai_quota_host_runtime_summary,
    parse_openai_quota_host_configuration,
    parse_openai_quota_host_configuration_bytes,
    render_openai_quota_host_configuration,
    validate_openai_quota_host_dependencies,
)
from tests.helpers import PROJECT_ROOT

_ADMIN_TOKEN = "admin-pilot-token-that-is-long-enough-123456"
_PROVIDER_KEY = "provider-pilot-key-that-is-long-enough-12345"


def _quota_document(*, upstream_timeout_seconds: float = 20.0) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "service_id": "openai-quota-pilot",
        "upstream_responses_url": "https://api.example.test/v1/responses",
        "worker_proxy_url": "https://openai-quota:8443/v1",
        "proxy_container_name": "openai-quota",
        "network_name": "causure-quota",
        "lease_cleanup_seconds": 30,
        "upstream_timeout_seconds": upstream_timeout_seconds,
        "max_request_bytes": 65_536,
        "max_response_bytes": 65_536,
        "models": [
            {
                "model": "model-exact-2026-08-01",
                "input_usd_per_million_tokens": "1.000000",
                "cached_input_usd_per_million_tokens": "0.500000",
                "output_usd_per_million_tokens": "2.000000",
                "max_input_tokens": 10_000,
                "max_output_tokens": 1_000,
            }
        ],
    }


def _json_bytes(document: dict[str, object]) -> bytes:
    return (json.dumps(document, indent=2) + "\n").encode()


def _host_document(
    directory: str,
    quota_bytes: bytes,
    **server_overrides: object,
) -> dict[str, object]:
    root = Path(directory)
    server: dict[str, object] = {
        "implementation": "waitress",
        "version": "3.0.2",
        "listen_host": "127.0.0.1",
        "listen_port": 18443,
        "trusted_external_scheme": "https",
        "threads": 4,
        "connection_limit": 32,
        "backlog": 16,
        "channel_timeout_seconds": 30,
        "max_request_header_bytes": 8192,
    }
    server.update(server_overrides)
    return {
        "schema_version": "1.0",
        "quota_configuration": {
            "path": str(root / "config" / "openai-quota.json"),
            "sha256": hashlib.sha256(quota_bytes).hexdigest(),
            "byte_count": len(quota_bytes),
        },
        "database": {
            "path": str(root / "data" / "quota.sqlite3"),
            "busy_timeout_ms": 5000,
        },
        "secrets": {
            "admin_token_path": str(root / "secrets" / "admin-token"),
            "provider_api_key_path": str(root / "secrets" / "provider-api-key"),
        },
        "server": server,
    }


def _write_runtime_files(
    directory: str,
    *,
    quota_bytes: bytes | None = None,
    admin_token: bytes = _ADMIN_TOKEN.encode(),
    provider_key: bytes = _PROVIDER_KEY.encode(),
) -> tuple[bytes, dict[str, object]]:
    root = Path(directory)
    for name in ("config", "data", "secrets"):
        (root / name).mkdir()
    selected_quota_bytes = quota_bytes or _json_bytes(_quota_document())
    (root / "config" / "openai-quota.json").write_bytes(selected_quota_bytes)
    (root / "secrets" / "admin-token").write_bytes(admin_token)
    (root / "secrets" / "provider-api-key").write_bytes(provider_key)
    return selected_quota_bytes, _host_document(directory, selected_quota_bytes)


class OpenAIQuotaHostConfigurationTests(unittest.TestCase):
    def test_configuration_round_trips_without_secret_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            quota_bytes = _json_bytes(_quota_document())
            configuration = parse_openai_quota_host_configuration(
                _host_document(directory, quota_bytes)
            )

        rendered = render_openai_quota_host_configuration(configuration)
        reparsed = parse_openai_quota_host_configuration_bytes(rendered.encode())

        self.assertEqual(configuration, reparsed)
        self.assertNotIn(_ADMIN_TOKEN, rendered)
        self.assertNotIn(_PROVIDER_KEY, rendered)

    def test_configuration_rejects_unknown_relative_colliding_and_writable_secret_paths(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            quota_bytes = _json_bytes(_quota_document())
            base = _host_document(directory, quota_bytes)

            unknown = json.loads(json.dumps(base))
            unknown["unknown"] = True
            with self.assertRaises(OpenAIQuotaHostConfigurationError):
                parse_openai_quota_host_configuration(unknown)

            relative = json.loads(json.dumps(base))
            relative["database"]["path"] = "quota.sqlite3"
            with self.assertRaises(OpenAIQuotaHostConfigurationError):
                parse_openai_quota_host_configuration(relative)

            collision = json.loads(json.dumps(base))
            collision["secrets"]["provider_api_key_path"] = collision["secrets"]["admin_token_path"]
            with self.assertRaises(OpenAIQuotaHostConfigurationError):
                parse_openai_quota_host_configuration(collision)

            writable = json.loads(json.dumps(base))
            writable["secrets"]["admin_token_path"] = str(Path(directory) / "data" / "admin-token")
            with self.assertRaises(OpenAIQuotaHostConfigurationError):
                parse_openai_quota_host_configuration(writable)

    def test_configuration_requires_closed_server_security_settings(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            quota_bytes = _json_bytes(_quota_document())
            for field, value in (
                ("implementation", "gunicorn"),
                ("version", "latest"),
                ("listen_host", "quota-core"),
                ("trusted_external_scheme", "http"),
                ("connection_limit", 5),
            ):
                with self.subTest(field=field):
                    document = _host_document(directory, quota_bytes, **{field: value})
                    with self.assertRaises(OpenAIQuotaHostConfigurationError):
                        parse_openai_quota_host_configuration(document)

    def test_committed_container_example_is_closed_and_hash_bound(self) -> None:
        example = PROJECT_ROOT / "examples" / "quota" / "openai-compatible-pilot-host.json"
        configuration = parse_openai_quota_host_configuration_bytes(example.read_bytes())

        self.assertEqual("0.0.0.0", configuration.server.listen_host)
        self.assertEqual("https", configuration.server.trusted_external_scheme)
        self.assertEqual(
            "20fb49a7e06aba42a5c440c27d87f910f77c454e9831aa6b51ce5621a94ca6c4",
            configuration.quota_configuration.sha256,
        )
        self.assertNotIn("token", example.read_text(encoding="utf-8").lower().split("path")[0])


class OpenAIQuotaHostRuntimeTests(unittest.TestCase):
    def test_runtime_loads_exact_inputs_initializes_store_and_keeps_secrets_out_of_summary(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            quota_bytes, document = _write_runtime_files(directory)
            configuration = parse_openai_quota_host_configuration(document)
            runtime = create_openai_quota_host_runtime(configuration)
            summary = openai_quota_host_runtime_summary(configuration)

            self.assertTrue(Path(configuration.database.path).is_file())
            self.assertEqual(
                hashlib.sha256(quota_bytes).hexdigest(),
                summary["quota_configuration"]["sha256"],
            )
            self.assertNotIn(_ADMIN_TOKEN, repr(runtime) + json.dumps(summary))
            self.assertNotIn(_PROVIDER_KEY, repr(runtime) + json.dumps(summary))
            runtime.close()
            self.assertTrue(runtime.closed)

    def test_runtime_rejects_quota_drift_bad_secret_and_insufficient_server_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, document = _write_runtime_files(directory)
            quota_path = Path(document["quota_configuration"]["path"])
            quota_path.write_bytes(_json_bytes(_quota_document(upstream_timeout_seconds=21.0)))
            with self.assertRaisesRegex(OpenAIQuotaHostRuntimeError, "do not match"):
                create_openai_quota_host_runtime(parse_openai_quota_host_configuration(document))

        with tempfile.TemporaryDirectory() as directory:
            _, document = _write_runtime_files(directory, admin_token=b"short")
            with self.assertRaisesRegex(OpenAIQuotaHostRuntimeError, "32 through"):
                create_openai_quota_host_runtime(parse_openai_quota_host_configuration(document))

        with tempfile.TemporaryDirectory() as directory:
            quota_bytes, _ = _write_runtime_files(
                directory,
                quota_bytes=_json_bytes(_quota_document(upstream_timeout_seconds=30.0)),
            )
            document = _host_document(
                directory,
                quota_bytes,
                channel_timeout_seconds=34,
            )
            with self.assertRaisesRegex(OpenAIQuotaHostRuntimeError, "at least five"):
                create_openai_quota_host_runtime(parse_openai_quota_host_configuration(document))

    def test_runtime_rejects_symbolic_linked_secret_when_supported(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, document = _write_runtime_files(directory)
            secret_path = Path(document["secrets"]["admin_token_path"])
            target = secret_path.with_name("admin-token-target")
            target.write_bytes(_ADMIN_TOKEN.encode())
            secret_path.unlink()
            try:
                secret_path.symlink_to(target)
            except OSError:
                self.skipTest("symbolic links are unavailable to this test identity")
            with self.assertRaisesRegex(OpenAIQuotaHostRuntimeError, "symbolic link"):
                create_openai_quota_host_runtime(parse_openai_quota_host_configuration(document))

    def test_host_configuration_subject_binds_exact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            quota_bytes = _json_bytes(_quota_document())
            configuration = parse_openai_quota_host_configuration(
                _host_document(directory, quota_bytes)
            )
            host_bytes = render_openai_quota_host_configuration(configuration).encode()
            host_path = Path(directory) / "host.json"
            host_path.write_bytes(host_bytes)

            subject = load_openai_quota_host_configuration_subject(host_path)

        self.assertEqual(len(host_bytes), subject.byte_count)
        self.assertEqual(hashlib.sha256(host_bytes).hexdigest(), subject.sha256)
        self.assertEqual(configuration, subject.configuration)


class OpenAIQuotaHostWaitressTests(unittest.TestCase):
    def test_exact_waitress_settings_fix_https_and_trust_no_proxy_headers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            quota_bytes = _json_bytes(_quota_document())
            configuration = parse_openai_quota_host_configuration(
                _host_document(directory, quota_bytes)
            )

        validate_openai_quota_host_dependencies(configuration)
        arguments = quota_host._waitress_arguments(configuration)
        adjustments = Adjustments(**arguments)

        self.assertEqual("https", adjustments.url_scheme)
        self.assertIsNone(adjustments.trusted_proxy)
        self.assertEqual(set(), adjustments.trusted_proxy_headers)
        self.assertTrue(adjustments.clear_untrusted_proxy_headers)
        self.assertFalse(adjustments.expose_tracebacks)

    def test_dependency_version_drift_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            quota_bytes = _json_bytes(_quota_document())
            configuration = parse_openai_quota_host_configuration(
                _host_document(directory, quota_bytes)
            )

        with patch("causure.openai_quota_host.metadata.version", return_value="3.0.1"):
            with self.assertRaisesRegex(Exception, "exact Waitress version"):
                validate_openai_quota_host_dependencies(configuration)


if __name__ == "__main__":
    unittest.main()
