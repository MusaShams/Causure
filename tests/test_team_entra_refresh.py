"""Adversarial tests for Entra discovery/JWKS refresh and atomic reload."""

from __future__ import annotations

import base64
import json
import os
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime
from email.message import Message
from pathlib import Path
from typing import Any
from unittest.mock import patch
from urllib.error import HTTPError

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa

from causure.io import atomic_write_text
from causure.team_entra import (
    EntraAccessTokenError,
    EntraTeamIdentityMiddleware,
    EntraTrustUnavailableError,
    parse_entra_trust_store_bytes,
    render_entra_trust_store,
)
from causure.team_entra_refresh import (
    MAX_ENTRA_DISCOVERY_BYTES,
    MAX_ENTRA_JWKS_BYTES,
    MAX_ENTRA_REFRESH_CONFIG_BYTES,
    CoordinatedEntraAccessTokenVerifier,
    EntraHTTPSJSONClient,
    EntraRefreshConfigurationError,
    EntraRefreshCoordinationError,
    EntraRefreshError,
    EntraSnapshotInstallError,
    LocalFileEntraRefreshCoordinator,
    ManagedEntraAccessTokenVerifier,
    ReloadingEntraAccessTokenVerifier,
    install_entra_trust_store,
    load_entra_refresh_configuration,
    parse_entra_refresh_configuration,
    parse_entra_refresh_configuration_bytes,
    refresh_entra_trust_file,
    refresh_entra_trust_store,
)
from tests.helpers import PROJECT_ROOT

NOW = int(datetime(2026, 7, 29, 12, 0, tzinfo=UTC).timestamp())
TENANT_ID = "11111111-1111-4111-8111-111111111111"
OTHER_TENANT_ID = "22222222-2222-4222-8222-222222222222"
AUDIENCE = "33333333-3333-4333-8333-333333333333"
CLIENT_ID = "44444444-4444-4444-8444-444444444444"
OBJECT_ID = "55555555-5555-4555-8555-555555555555"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"
JWKS_URI = f"https://login.microsoftonline.com/{TENANT_ID}/discovery/v2.0/keys"
DISCOVERY_URL = f"{ISSUER}/.well-known/openid-configuration"


def _wait_until(predicate: Any, *, timeout_seconds: float = 3.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.01)
    return bool(predicate())


def _base64url_integer(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


class _FakeRefreshClient:
    def __init__(self, responses: dict[str, bytes | Exception]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, int, float, frozenset[str]]] = []

    def fetch(
        self,
        url: str,
        *,
        maximum_bytes: int,
        timeout_seconds: float,
        media_types: frozenset[str],
    ) -> bytes:
        self.calls.append((url, maximum_bytes, timeout_seconds, media_types))
        response = self.responses[url]
        if isinstance(response, Exception):
            raise response
        return response


class _BlockingRefreshClient(_FakeRefreshClient):
    def __init__(self, responses: dict[str, bytes | Exception]) -> None:
        super().__init__(responses)
        self.block_started = threading.Event()
        self.release = threading.Event()
        self._block_lock = threading.Lock()
        self._block_once = False

    def arm_one_block(self) -> None:
        with self._block_lock:
            self._block_once = True
            self.block_started.clear()
            self.release.clear()

    def fetch(
        self,
        url: str,
        *,
        maximum_bytes: int,
        timeout_seconds: float,
        media_types: frozenset[str],
    ) -> bytes:
        with self._block_lock:
            should_block = self._block_once
            self._block_once = False
        if should_block:
            self.block_started.set()
            if not self.release.wait(timeout=2):
                raise EntraRefreshError("fetch_failed", "test refresh was not released")
        return super().fetch(
            url,
            maximum_bytes=maximum_bytes,
            timeout_seconds=timeout_seconds,
            media_types=media_types,
        )


class _SequenceClock:
    def __init__(self, *values: str) -> None:
        self._values = list(values)
        self._lock = threading.Lock()

    def __call__(self) -> str:
        with self._lock:
            if not self._values:
                raise RuntimeError("test snapshot clock was exhausted")
            return self._values.pop(0)


class _FakeResponse:
    def __init__(
        self,
        body: bytes,
        *,
        url: str = DISCOVERY_URL,
        status: int = 200,
        content_type: str = "application/json",
        content_length: str | None = None,
        content_encoding: str | None = None,
    ) -> None:
        self._body = body
        self._url = url
        self.status = status
        self.headers = Message()
        self.headers["Content-Type"] = content_type
        if content_length is not None:
            self.headers["Content-Length"] = content_length
        if content_encoding is not None:
            self.headers["Content-Encoding"] = content_encoding
        self.closed = False

    def geturl(self) -> str:
        return self._url

    def read(self, amount: int) -> bytes:
        return self._body[:amount]

    def close(self) -> None:
        self.closed = True


class _FakeOpener:
    def __init__(self, result: _FakeResponse | Exception) -> None:
        self.result = result
        self.request: Any | None = None
        self.timeout: float | None = None

    def open(self, request: Any, *, timeout: float) -> _FakeResponse:
        self.request = request
        self.timeout = timeout
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class EntraRefreshTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.next_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    @staticmethod
    def _jwk(private_key: Any, *, kid: str) -> dict[str, Any]:
        numbers = private_key.public_key().public_numbers()
        return {
            "kid": kid,
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": _base64url_integer(numbers.n),
            "e": _base64url_integer(numbers.e),
            "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0",
            "x5c": ["ignored-public-certificate-representation"],
        }

    def _configuration_document(
        self,
        *,
        store_id: str = "entra-production",
    ) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "store_id": store_id,
            "snapshot_ttl_seconds": 43200,
            "tenants": [
                {
                    "entra_tenant_id": TENANT_ID,
                    "team_tenant_id": "tenant-acme",
                    "issuer": ISSUER,
                    "jwks_uri": JWKS_URI,
                    "audience": AUDIENCE,
                    "allowed_client_ids": [CLIENT_ID],
                    "accepted_delegated_scopes": ["Causure.Access"],
                    "accepted_application_roles": ["Causure.Service"],
                    "max_token_lifetime_seconds": 7200,
                }
            ],
        }

    def _configuration(self, *, store_id: str = "entra-production") -> Any:
        return parse_entra_refresh_configuration(self._configuration_document(store_id=store_id))

    @staticmethod
    def _discovery(
        *,
        issuer: str = ISSUER,
        jwks_uri: str = JWKS_URI,
        algorithms: Any = ("RS256",),
    ) -> bytes:
        return _json_bytes(
            {
                "issuer": issuer,
                "jwks_uri": jwks_uri,
                "id_token_signing_alg_values_supported": list(algorithms),
                "unknown_extension": "ignored",
            }
        )

    def _jwks(
        self,
        *,
        private_key: Any | None = None,
        kid: str = "key-one",
        extra_keys: list[dict[str, Any]] | None = None,
    ) -> bytes:
        keys = [
            {
                "kid": "ignored-ec",
                "kty": "EC",
                "crv": "P-256",
                "x": "AA",
                "y": "AA",
            },
            {
                **self._jwk(self.private_key, kid="ignored-encryption"),
                "use": "enc",
            },
            self._jwk(private_key or self.private_key, kid=kid),
        ]
        if extra_keys:
            keys.extend(extra_keys)
        return _json_bytes({"keys": keys, "unknown_extension": True})

    def _client(
        self,
        *,
        discovery: bytes | Exception | None = None,
        jwks: bytes | Exception | None = None,
    ) -> _FakeRefreshClient:
        return _FakeRefreshClient(
            {
                DISCOVERY_URL: discovery if discovery is not None else self._discovery(),
                JWKS_URI: jwks if jwks is not None else self._jwks(),
            }
        )

    def _refreshed_store(
        self,
        *,
        instant: str = "2026-07-29T12:00:00Z",
        private_key: Any | None = None,
        kid: str = "key-one",
        store_id: str = "entra-production",
    ) -> Any:
        return refresh_entra_trust_store(
            self._configuration(store_id=store_id),
            client=self._client(jwks=self._jwks(private_key=private_key, kid=kid)),
            clock=lambda: instant,
        )

    @staticmethod
    def _token(
        private_key: Any,
        *,
        kid: str,
        now: int,
        tenant_id: str = TENANT_ID,
        issuer: str = ISSUER,
    ) -> str:
        return jwt.encode(
            {
                "ver": "2.0",
                "iss": issuer,
                "aud": AUDIENCE,
                "tid": tenant_id,
                "oid": OBJECT_ID,
                "azp": CLIENT_ID,
                "iat": now - 60,
                "nbf": now - 60,
                "exp": now + 600,
                "scp": "Causure.Access",
            },
            private_key,
            algorithm="RS256",
            headers={"kid": kid, "typ": "JWT"},
        )

    def test_refresh_configuration_is_closed_tenant_specific_and_same_origin(self) -> None:
        configuration = self._configuration()

        self.assertEqual("entra-production", configuration.store_id)
        self.assertEqual(DISCOVERY_URL, configuration.tenants[0].discovery_url)
        self.assertEqual(JWKS_URI, configuration.tenants[0].jwks_uri)

        cases: list[dict[str, Any]] = []
        common = self._configuration_document()
        common["tenants"][0]["issuer"] = "https://login.microsoftonline.com/common/v2.0"
        cases.append(common)
        cross_origin = self._configuration_document()
        cross_origin["tenants"][0]["jwks_uri"] = "https://attacker.test/keys"
        cases.append(cross_origin)
        insecure = self._configuration_document()
        insecure["tenants"][0]["jwks_uri"] = JWKS_URI.replace("https:", "http:")
        cases.append(insecure)
        trailing_dot = self._configuration_document()
        trailing_dot["tenants"][0]["issuer"] = ISSUER.replace(
            "login.microsoftonline.com",
            "login.microsoftonline.com.",
        )
        cases.append(trailing_dot)
        unknown = self._configuration_document()
        unknown["unexpected"] = True
        cases.append(unknown)
        no_grant = self._configuration_document()
        no_grant["tenants"][0]["accepted_delegated_scopes"] = []
        no_grant["tenants"][0]["accepted_application_roles"] = []
        cases.append(no_grant)
        bad_ttl = self._configuration_document()
        bad_ttl["snapshot_ttl_seconds"] = 3599
        cases.append(bad_ttl)

        for document in cases:
            with self.subTest(document=document), self.assertRaises(EntraRefreshConfigurationError):
                parse_entra_refresh_configuration(document)

    def test_refresh_configuration_bytes_reject_duplicates_and_oversize(self) -> None:
        raw = _json_bytes(self._configuration_document())
        duplicate = raw.replace(
            b'{"schema_version"',
            b'{"store_id":"duplicate","schema_version"',
            1,
        )
        with self.assertRaises(EntraRefreshConfigurationError):
            parse_entra_refresh_configuration_bytes(duplicate)
        with self.assertRaises(EntraRefreshConfigurationError):
            parse_entra_refresh_configuration_bytes(b" " * (MAX_ENTRA_REFRESH_CONFIG_BYTES + 1))

    def test_committed_refresh_example_matches_the_runtime_contract(self) -> None:
        configuration = load_entra_refresh_configuration(
            PROJECT_ROOT / "examples" / "team" / "acme-entra-refresh.json"
        )

        self.assertEqual("entra-production", configuration.store_id)
        self.assertEqual(TENANT_ID, configuration.tenants[0].entra_tenant_id)
        self.assertEqual(86400, configuration.snapshot_ttl_seconds)

    def test_refresh_fetches_exact_urls_and_reduces_eligible_keys(self) -> None:
        key_two = self._jwk(self.next_private_key, kid="key-two")
        client = self._client(jwks=self._jwks(extra_keys=[key_two]))

        store = refresh_entra_trust_store(
            self._configuration(),
            client=client,
            clock=lambda: "2026-07-29T12:00:00Z",
            timeout_seconds=7,
        )

        self.assertEqual("2026-07-29T12:00:00Z", store.refreshed_at)
        self.assertEqual("2026-07-30T00:00:00Z", store.expires_at)
        self.assertEqual(["key-one", "key-two"], [key.kid for key in store.tenants[0].keys])
        self.assertEqual(
            [
                (DISCOVERY_URL, MAX_ENTRA_DISCOVERY_BYTES),
                (JWKS_URI, MAX_ENTRA_JWKS_BYTES),
            ],
            [(url, maximum) for url, maximum, _, _ in client.calls],
        )
        self.assertEqual(
            store,
            parse_entra_trust_store_bytes(render_entra_trust_store(store).encode("utf-8")),
        )

    def test_refresh_scopes_each_signing_key_to_the_configured_issuer(self) -> None:
        exact = self._jwk(self.next_private_key, kid="exact")
        exact["issuer"] = ISSUER
        other = self._jwk(self.next_private_key, kid="other-tenant")
        other["issuer"] = f"https://login.microsoftonline.com/{OTHER_TENANT_ID}/v2.0"

        store = refresh_entra_trust_store(
            self._configuration(),
            client=self._client(jwks=self._jwks(extra_keys=[exact, other])),
            clock=lambda: "2026-07-29T12:00:00Z",
        )

        self.assertEqual(
            ["exact", "key-one"],
            [key.kid for key in store.tenants[0].keys],
        )

        missing = self._jwk(self.private_key, kid="missing")
        missing.pop("issuer")
        with self.assertRaises(EntraRefreshError) as context:
            refresh_entra_trust_store(
                self._configuration(),
                client=self._client(jwks=_json_bytes({"keys": [missing]})),
                clock=lambda: "2026-07-29T12:00:00Z",
            )
        self.assertEqual("jwk_issuer_invalid", context.exception.code)

    def test_discovery_must_match_protected_issuer_jwks_and_algorithm(self) -> None:
        cases = [
            self._discovery(issuer=f"https://login.microsoftonline.com/{OTHER_TENANT_ID}/v2.0"),
            self._discovery(jwks_uri="https://login.microsoftonline.com/other/keys"),
            self._discovery(algorithms=("ES256",)),
        ]
        for discovery in cases:
            with self.subTest(discovery=discovery), self.assertRaises(EntraRefreshError):
                refresh_entra_trust_store(
                    self._configuration(),
                    client=self._client(discovery=discovery),
                    clock=lambda: "2026-07-29T12:00:00Z",
                )

    def test_jwks_rejects_private_duplicate_malformed_and_weak_keys(self) -> None:
        private = self._jwk(self.private_key, kid="private")
        private["d"] = "secret"
        duplicate = self._jwk(self.next_private_key, kid="key-one")
        malformed = self._jwk(self.private_key, kid="bad")
        malformed.pop("n")
        weak = self._jwk(self.private_key, kid="weak")
        weak["n"] = _base64url_integer((1 << 1023) + 1)
        cases = [
            self._jwks(extra_keys=[private]),
            self._jwks(extra_keys=[duplicate]),
            self._jwks(extra_keys=[malformed]),
            _json_bytes({"keys": [weak]}),
            _json_bytes({"keys": [{"kty": "EC", "kid": "only-ec"}]}),
        ]

        for jwks in cases:
            with self.subTest(jwks=jwks[:80]), self.assertRaises(EntraRefreshError):
                refresh_entra_trust_store(
                    self._configuration(),
                    client=self._client(jwks=jwks),
                    clock=lambda: "2026-07-29T12:00:00Z",
                )

    def test_remote_json_duplicates_and_invalid_clock_fail_closed(self) -> None:
        duplicate_discovery = (
            b'{"issuer":"'
            + ISSUER.encode()
            + b'","issuer":"'
            + ISSUER.encode()
            + b'","jwks_uri":"'
            + JWKS_URI.encode()
            + b'"}'
        )
        with self.assertRaises(EntraRefreshError):
            refresh_entra_trust_store(
                self._configuration(),
                client=self._client(discovery=duplicate_discovery),
                clock=lambda: "2026-07-29T12:00:00Z",
            )
        with self.assertRaises(EntraRefreshError):
            refresh_entra_trust_store(
                self._configuration(),
                client=self._client(),
                clock=lambda: "not-a-time",
            )

    def test_https_client_bounds_type_length_encoding_and_redirects(self) -> None:
        body = self._discovery()
        valid_response = _FakeResponse(body, content_length=str(len(body)))
        opener = _FakeOpener(valid_response)
        client = EntraHTTPSJSONClient(opener=opener)

        result = client.fetch(
            DISCOVERY_URL,
            maximum_bytes=MAX_ENTRA_DISCOVERY_BYTES,
            timeout_seconds=5,
            media_types=frozenset({"application/json"}),
        )

        self.assertEqual(body, result)
        self.assertEqual(5.0, opener.timeout)
        self.assertEqual("GET", opener.request.get_method())
        self.assertTrue(valid_response.closed)

        failures = [
            _FakeResponse(body, status=201),
            _FakeResponse(body, url="https://attacker.test/metadata"),
            _FakeResponse(body, content_type="text/html"),
            _FakeResponse(body, content_encoding="gzip"),
            _FakeResponse(body, content_length=str(len(body) + 1)),
            _FakeResponse(body, content_length="1, 1"),
            _FakeResponse(b"x" * 11),
        ]
        for response in failures:
            maximum = 10 if len(response._body) == 11 else MAX_ENTRA_DISCOVERY_BYTES
            with self.subTest(response=response), self.assertRaises(EntraRefreshError):
                EntraHTTPSJSONClient(opener=_FakeOpener(response)).fetch(
                    DISCOVERY_URL,
                    maximum_bytes=maximum,
                    timeout_seconds=5,
                    media_types=frozenset({"application/json"}),
                )
            self.assertTrue(response.closed)

        redirect = HTTPError(DISCOVERY_URL, 302, "Found", Message(), None)
        with self.assertRaises(EntraRefreshError) as context:
            EntraHTTPSJSONClient(opener=_FakeOpener(redirect)).fetch(
                DISCOVERY_URL,
                maximum_bytes=100,
                timeout_seconds=5,
                media_types=frozenset({"application/json"}),
            )
        self.assertEqual("redirect_rejected", context.exception.code)

        insecure_context = ssl._create_unverified_context()
        with self.assertRaises(ValueError):
            EntraHTTPSJSONClient(ssl_context=insecure_context)

    def test_refresh_failure_never_overwrites_last_known_good_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "entra-trust.json"
            original = self._refreshed_store()
            install_entra_trust_store(output, original)
            original_bytes = output.read_bytes()

            with self.assertRaises(EntraRefreshError):
                refresh_entra_trust_file(
                    self._configuration(),
                    output,
                    client=self._client(jwks=EntraRefreshError("fetch_failed", "simulated")),
                    clock=lambda: "2026-07-29T13:00:00Z",
                )

            self.assertEqual(original_bytes, output.read_bytes())

    def test_atomic_install_requires_same_store_and_monotonic_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "entra-trust.json"
            original = self._refreshed_store()
            newer = self._refreshed_store(
                instant="2026-07-29T13:00:00Z",
                private_key=self.next_private_key,
                kid="key-two",
            )
            install_entra_trust_store(output, original)
            install_entra_trust_store(output, newer)
            newer_bytes = output.read_bytes()
            self.assertEqual(
                "key-two",
                parse_entra_trust_store_bytes(newer_bytes).tenants[0].keys[0].kid,
            )

            cases = [
                original,
                self._refreshed_store(
                    instant="2026-07-29T14:00:00Z",
                    store_id="other-store",
                ),
            ]
            for store in cases:
                with (
                    self.subTest(store=store.store_id),
                    self.assertRaises(EntraSnapshotInstallError),
                ):
                    install_entra_trust_store(output, store)
                self.assertEqual(newer_bytes, output.read_bytes())

    def test_atomic_install_refuses_to_replace_invalid_existing_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "entra-trust.json"
            output.write_bytes(b"not-json")

            with self.assertRaises(EntraSnapshotInstallError):
                install_entra_trust_store(output, self._refreshed_store())

            self.assertEqual(b"not-json", output.read_bytes())

    def test_atomic_install_revalidates_hand_constructed_snapshot_objects(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "entra-trust.json"
            valid = self._refreshed_store()
            invalid = replace(valid, expires_at=valid.refreshed_at)

            with self.assertRaises(EntraSnapshotInstallError) as context:
                install_entra_trust_store(output, invalid)

            self.assertEqual("snapshot_invalid", context.exception.code)
            self.assertFalse(output.exists())

    def test_reloader_swaps_newer_snapshot_and_keeps_fresh_last_known_good(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "entra-trust.json"
            initial = self._refreshed_store()
            install_entra_trust_store(output, initial)
            current_time = [NOW]
            reloader = ReloadingEntraAccessTokenVerifier(
                output,
                clock=lambda: current_time[0],
            )
            first_token = self._token(self.private_key, kid="key-one", now=NOW)
            self.assertEqual(OBJECT_ID, reloader.verify(first_token).object_id)
            first_digest = reloader.snapshot_sha256

            next_time = NOW + 3600
            newer = self._refreshed_store(
                instant="2026-07-29T13:00:00Z",
                private_key=self.next_private_key,
                kid="key-two",
            )
            install_entra_trust_store(output, newer)
            current_time[0] = next_time
            second_token = self._token(
                self.next_private_key,
                kid="key-two",
                now=next_time,
            )
            self.assertEqual(OBJECT_ID, reloader.verify(second_token).object_id)
            self.assertNotEqual(first_digest, reloader.snapshot_sha256)
            self.assertIsNone(reloader.last_reload_error_code)

            atomic_write_text(output, "not-json\n")
            self.assertEqual(OBJECT_ID, reloader.verify(second_token).object_id)
            self.assertEqual("snapshot_reload_rejected", reloader.last_reload_error_code)

            current_time[0] = int(datetime(2026, 7, 30, 2, 0, tzinfo=UTC).timestamp())
            with self.assertRaises(EntraTrustUnavailableError):
                reloader.check_ready()

    def test_reloader_rejects_rollback_and_is_accepted_by_wsgi_middleware(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "entra-trust.json"
            original = self._refreshed_store()
            install_entra_trust_store(output, original)
            reloader = ReloadingEntraAccessTokenVerifier(
                output,
                clock=lambda: NOW,
            )
            self.assertIsInstance(
                EntraTeamIdentityMiddleware(lambda _environ, _start: [], reloader),
                EntraTeamIdentityMiddleware,
            )

            rollback_document = json.loads(render_entra_trust_store(original))
            rollback_document["refreshed_at"] = "2026-07-29T11:00:00Z"
            rollback_document["expires_at"] = "2026-07-29T23:00:00Z"
            atomic_write_text(output, json.dumps(rollback_document) + "\n")
            token = self._token(self.private_key, kid="key-one", now=NOW)

            self.assertEqual(OBJECT_ID, reloader.verify(token).object_id)
            self.assertEqual("snapshot_reload_rejected", reloader.last_reload_error_code)

    def test_local_file_coordinator_elects_one_owner_and_coalesces_requests(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            owner_path = Path(directory) / "entra-owner.lock"
            request_path = Path(directory) / "entra-request"
            first = LocalFileEntraRefreshCoordinator(owner_path, request_path)
            second = LocalFileEntraRefreshCoordinator(owner_path, request_path)
            try:
                self.assertTrue(first.try_acquire())
                self.assertTrue(first.is_owner)
                self.assertFalse(second.try_acquire())
                self.assertTrue(second.signal_refresh())
                self.assertFalse(second.signal_refresh())
                self.assertTrue(first.refresh_requested)
                with self.assertRaises(EntraRefreshCoordinationError) as context:
                    second.consume_refresh_request()
                self.assertEqual("refresh_owner_required", context.exception.code)
                self.assertTrue(first.consume_refresh_request())
                self.assertFalse(first.refresh_requested)

                first.release()
                self.assertTrue(second.try_acquire())
                self.assertTrue(second.ownership_valid)
            finally:
                first.close()
                second.close()

            with self.assertRaises(ValueError):
                LocalFileEntraRefreshCoordinator(owner_path, owner_path)

            process_bound = LocalFileEntraRefreshCoordinator(Path(directory) / "process-bound.lock")
            current_process = os.getpid()
            with (
                patch(
                    "causure.team_entra_refresh.os.getpid",
                    return_value=current_process + 1,
                ),
                self.assertRaises(EntraRefreshCoordinationError) as context,
            ):
                process_bound.try_acquire()
            self.assertEqual("coordination_process_changed", context.exception.code)
            process_bound.close()

    def test_local_file_coordinator_recovers_ownership_after_process_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            owner_path = Path(directory) / "entra-owner.lock"
            request_path = Path(directory) / "entra-request"
            script = "\n".join(
                (
                    "import sys, time",
                    ("from causure.team_entra_refresh import LocalFileEntraRefreshCoordinator"),
                    "coordinator = LocalFileEntraRefreshCoordinator(sys.argv[1], sys.argv[2])",
                    "print('ACQUIRED' if coordinator.try_acquire() else 'BUSY', flush=True)",
                    "time.sleep(60)",
                )
            )
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-c",
                    script,
                    str(owner_path),
                    str(request_path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            peer = LocalFileEntraRefreshCoordinator(owner_path, request_path)
            try:
                if process.stdout is None:
                    self.fail("coordinator subprocess stdout was unavailable")
                self.assertEqual("ACQUIRED", process.stdout.readline().strip())
                self.assertFalse(peer.try_acquire())
                process.terminate()
                process.wait(timeout=5)
                self.assertTrue(_wait_until(peer.try_acquire))
                self.assertTrue(peer.ownership_valid)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=5)
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
                peer.close()

    def test_managed_refresh_guard_blocks_install_after_ownership_loss(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "entra-trust.json"
            install_entra_trust_store(output, self._refreshed_store())
            original = output.read_bytes()
            guard_values = iter((True, False))
            manager = ManagedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=self._client(),
                snapshot_clock=_SequenceClock("2026-07-29T13:00:00Z"),
                verifier_clock=lambda: NOW + 3600,
                refresh_guard=lambda: next(guard_values),
            )
            manager.start()
            try:
                self.assertEqual("refresh_ownership_lost", manager.status.last_error_code)
                self.assertEqual(original, output.read_bytes())
            finally:
                manager.close()

    def test_coordinated_verifiers_relay_unknown_key_only_to_owner(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "causure.team_entra_refresh.MIN_ENTRA_COORDINATION_POLL_SECONDS",
                0.001,
            ),
        ):
            output = Path(directory) / "entra-trust.json"
            owner_client = self._client()
            follower_client = self._client()
            monotonic = [0.0]
            owner = CoordinatedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=owner_client,
                snapshot_clock=_SequenceClock(
                    "2026-07-29T12:00:00Z",
                    "2026-07-29T13:00:00Z",
                ),
                verifier_clock=lambda: NOW + 3600,
                monotonic_clock=lambda: monotonic[0],
                coordination_poll_seconds=0.01,
            )
            follower = CoordinatedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=follower_client,
                snapshot_clock=_SequenceClock("2026-07-29T14:00:00Z"),
                verifier_clock=lambda: NOW + 3600,
                monotonic_clock=lambda: monotonic[0],
                coordination_poll_seconds=0.01,
            )
            owner.start()
            follower.start()
            try:
                self.assertTrue(owner.status.is_refresh_owner)
                self.assertFalse(follower.status.is_refresh_owner)
                self.assertEqual([], follower_client.calls)

                owner_client.responses[JWKS_URI] = self._jwks(
                    private_key=self.next_private_key,
                    kid="key-two",
                )
                monotonic[0] = 301.0
                rolled = self._token(
                    self.next_private_key,
                    kid="key-two",
                    now=NOW + 3600,
                )
                request_path = Path(f"{output}.refresh-request")
                real_unlink = os.unlink
                deny_first_request_unlink = [True]

                def temporarily_locked_request(path: Any) -> None:
                    if Path(path) == request_path and deny_first_request_unlink[0]:
                        deny_first_request_unlink[0] = False
                        raise PermissionError("simulated open Windows request marker")
                    real_unlink(path)

                with patch(
                    "causure.team_entra_refresh.os.unlink",
                    side_effect=temporarily_locked_request,
                ):
                    with self.assertRaises(EntraAccessTokenError) as context:
                        follower.verify(rolled)
                    self.assertEqual("signing_key_unknown", context.exception.code)
                    self.assertTrue(
                        owner.wait_for_refresh_attempt(
                            after_completed_count=1,
                            timeout_seconds=3,
                        )
                    )
                    self.assertTrue(
                        _wait_until(lambda: not owner.status.refresh_request_pending),
                        owner.status,
                    )
                self.assertEqual(OBJECT_ID, follower.verify(rolled).object_id)
                self.assertEqual([], follower_client.calls)
                managed = owner.status.managed_refresh
                self.assertIsNotNone(managed)
                self.assertEqual(2, managed.completed_attempt_count if managed else -1)
                self.assertIsNone(owner.status.last_error_code)
            finally:
                follower.close()
                owner.close()

    def test_concurrent_coordinated_startup_runs_one_network_refresh(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "causure.team_entra_refresh.MIN_ENTRA_COORDINATION_POLL_SECONDS",
                0.001,
            ),
        ):
            output = Path(directory) / "entra-trust.json"
            first_client = self._client()
            second_client = self._client()
            first = CoordinatedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=first_client,
                snapshot_clock=_SequenceClock("2026-07-29T12:00:00Z"),
                verifier_clock=lambda: NOW,
                coordination_poll_seconds=0.01,
            )
            second = CoordinatedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=second_client,
                snapshot_clock=_SequenceClock("2026-07-29T12:00:00Z"),
                verifier_clock=lambda: NOW,
                coordination_poll_seconds=0.01,
            )
            instances = (first, second)
            try:
                with ThreadPoolExecutor(max_workers=2) as executor:
                    futures = [executor.submit(instance.start) for instance in instances]
                    for future in futures:
                        future.result(timeout=3)
                self.assertEqual(
                    1,
                    sum(instance.status.is_refresh_owner for instance in instances),
                )
                self.assertEqual(2, len(first_client.calls) + len(second_client.calls))
                token = self._token(self.private_key, kid="key-one", now=NOW)
                for instance in instances:
                    self.assertEqual(OBJECT_ID, instance.verify(token).object_id)
            finally:
                for instance in sorted(
                    instances,
                    key=lambda value: value.status.is_refresh_owner,
                ):
                    instance.close()

    def test_coordinated_follower_promotes_after_owner_shutdown(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "causure.team_entra_refresh.MIN_ENTRA_COORDINATION_POLL_SECONDS",
                0.001,
            ),
        ):
            output = Path(directory) / "entra-trust.json"
            owner = CoordinatedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=self._client(),
                snapshot_clock=_SequenceClock("2026-07-29T12:00:00Z"),
                verifier_clock=lambda: NOW + 3600,
                coordination_poll_seconds=0.01,
            )
            follower_client = self._client()
            follower = CoordinatedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=follower_client,
                snapshot_clock=_SequenceClock("2026-07-29T13:00:00Z"),
                verifier_clock=lambda: NOW + 3600,
                coordination_poll_seconds=0.01,
            )
            owner.start()
            follower.start()
            try:
                self.assertFalse(follower.status.is_refresh_owner)
                owner.close()
                self.assertTrue(
                    _wait_until(lambda: follower.status.is_refresh_owner),
                    follower.status,
                )
                status = follower.status
                self.assertTrue(status.running)
                self.assertEqual(1, status.ownership_acquisition_count)
                self.assertIsNotNone(status.managed_refresh)
                self.assertEqual(2, len(follower_client.calls))
                token = self._token(self.private_key, kid="key-one", now=NOW + 3600)
                self.assertEqual(OBJECT_ID, follower.verify(token).object_id)
            finally:
                owner.close()
                follower.close()

    def test_coordinated_untrusted_tenant_does_not_publish_refresh_request(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "causure.team_entra_refresh.MIN_ENTRA_COORDINATION_POLL_SECONDS",
                0.001,
            ),
        ):
            output = Path(directory) / "entra-trust.json"
            verifier = CoordinatedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=self._client(),
                snapshot_clock=_SequenceClock("2026-07-29T12:00:00Z"),
                verifier_clock=lambda: NOW,
                coordination_poll_seconds=0.01,
            )
            verifier.start()
            try:
                token = self._token(
                    self.private_key,
                    kid="untrusted-key",
                    now=NOW,
                    tenant_id=OTHER_TENANT_ID,
                    issuer=(f"https://login.microsoftonline.com/{OTHER_TENANT_ID}/v2.0"),
                )
                with self.assertRaises(EntraAccessTokenError) as context:
                    verifier.verify(token)
                self.assertEqual("tenant_untrusted", context.exception.code)
                self.assertFalse(verifier.status.refresh_request_pending)
            finally:
                verifier.close()

    def test_coordinated_follower_does_not_fetch_without_published_trust(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "causure.team_entra_refresh.MIN_ENTRA_COORDINATION_POLL_SECONDS",
                0.001,
            ),
        ):
            output = Path(directory) / "entra-trust.json"
            lock = LocalFileEntraRefreshCoordinator(f"{output}.refresh-owner.lock")
            self.assertTrue(lock.try_acquire())
            client = self._client()
            follower = CoordinatedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=client,
                coordination_poll_seconds=0.01,
                startup_wait_seconds=0.05,
            )
            try:
                with self.assertRaises(EntraTrustUnavailableError) as context:
                    follower.start()
                self.assertEqual("coordinated_refresh_unavailable", context.exception.code)
                self.assertEqual([], client.calls)
            finally:
                follower.close()
                lock.close()

    def test_managed_refresh_bootstraps_runs_and_stops_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "entra-trust.json"
            manager = ManagedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=self._client(),
                snapshot_clock=_SequenceClock("2026-07-29T12:00:00Z"),
                verifier_clock=lambda: NOW,
            )

            with manager as running:
                token = self._token(self.private_key, kid="key-one", now=NOW)
                self.assertEqual(OBJECT_ID, running.verify(token).object_id)
                self.assertTrue(running.status.running)
                self.assertEqual(1, running.status.completed_attempt_count)
                self.assertEqual("startup", running.status.last_reason)
                self.assertIsNone(running.status.last_error_code)

            self.assertFalse(manager.status.running)
            with self.assertRaises(EntraTrustUnavailableError):
                manager.check_ready()

    def test_managed_refresh_intervals_and_monotonic_clock_are_bounded(self) -> None:
        cases = [
            {"refresh_interval_seconds": 59},
            {"failure_retry_seconds": 29},
            {"failure_retry_seconds": 7200},
            {"unknown_key_refresh_seconds": 299},
            {"refresh_interval_seconds": float("nan")},
        ]
        for options in cases:
            with self.subTest(options=options), self.assertRaises(ValueError):
                ManagedEntraAccessTokenVerifier(
                    self._configuration(),
                    "unused.json",
                    **options,
                )
        with self.assertRaises(EntraTrustUnavailableError):
            ManagedEntraAccessTokenVerifier(
                self._configuration(),
                "unused.json",
                monotonic_clock=lambda: True,
            )

    def test_managed_startup_failure_uses_only_fresh_same_store_last_known_good(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "entra-trust.json"
            install_entra_trust_store(output, self._refreshed_store())
            manager = ManagedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=self._client(discovery=EntraRefreshError("fetch_failed", "simulated")),
                snapshot_clock=_SequenceClock("2026-07-29T13:00:00Z"),
                verifier_clock=lambda: NOW,
            )
            manager.start()
            try:
                token = self._token(self.private_key, kid="key-one", now=NOW)
                self.assertEqual(OBJECT_ID, manager.verify(token).object_id)
                self.assertEqual("fetch_failed", manager.status.last_error_code)
                self.assertEqual("2026-07-29T12:00:00Z", manager.status.last_successful_refresh_at)
            finally:
                manager.close()

            wrong_store = Path(directory) / "wrong-store.json"
            install_entra_trust_store(
                wrong_store,
                self._refreshed_store(store_id="other-store"),
            )
            mismatched = ManagedEntraAccessTokenVerifier(
                self._configuration(),
                wrong_store,
                client=self._client(discovery=EntraRefreshError("fetch_failed", "simulated")),
                snapshot_clock=_SequenceClock("2026-07-29T13:00:00Z"),
                verifier_clock=lambda: NOW,
            )
            with self.assertRaises(EntraTrustUnavailableError):
                mismatched.start()
            mismatched.close()

            future_output = Path(directory) / "future-candidate.json"
            original = self._refreshed_store()
            install_entra_trust_store(future_output, original)
            original_bytes = future_output.read_bytes()
            future = ManagedEntraAccessTokenVerifier(
                self._configuration(),
                future_output,
                client=self._client(),
                snapshot_clock=_SequenceClock("2026-07-29T14:00:00Z"),
                verifier_clock=lambda: NOW,
            )
            future.start()
            try:
                self.assertEqual("trust_not_yet_valid", future.status.last_error_code)
                self.assertEqual(original_bytes, future_output.read_bytes())
            finally:
                future.close()

    def test_managed_periodic_refresh_installs_and_reloads_new_keys(self) -> None:
        with (
            tempfile.TemporaryDirectory() as directory,
            patch(
                "causure.team_entra_refresh.MIN_ENTRA_MANAGED_REFRESH_INTERVAL_SECONDS",
                0.01,
            ),
            patch(
                "causure.team_entra_refresh.MIN_ENTRA_REFRESH_FAILURE_RETRY_SECONDS",
                0.01,
            ),
        ):
            output = Path(directory) / "entra-trust.json"
            client = self._client()
            manager = ManagedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=client,
                snapshot_clock=_SequenceClock(
                    "2026-07-29T12:00:00Z",
                    "2026-07-29T13:00:00Z",
                ),
                verifier_clock=lambda: NOW + 3600,
                refresh_interval_seconds=0.5,
                failure_retry_seconds=0.05,
            )
            manager.start()
            try:
                client.responses[JWKS_URI] = self._jwks(
                    private_key=self.next_private_key,
                    kid="key-two",
                )
                self.assertTrue(
                    manager.wait_for_refresh_attempt(
                        after_completed_count=1,
                        timeout_seconds=2,
                    )
                )
                token = self._token(
                    self.next_private_key,
                    kid="key-two",
                    now=NOW + 3600,
                )
                self.assertEqual(OBJECT_ID, manager.verify(token).object_id)
                self.assertEqual("periodic", manager.status.last_reason)
                self.assertIsNone(manager.status.last_error_code)
            finally:
                manager.close()

    def test_unknown_key_refresh_is_async_singleflight_and_rate_limited(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "entra-trust.json"
            base_client = self._client()
            client = _BlockingRefreshClient(base_client.responses)
            monotonic = [0.0]
            manager = ManagedEntraAccessTokenVerifier(
                self._configuration(),
                output,
                client=client,
                snapshot_clock=_SequenceClock(
                    "2026-07-29T12:00:00Z",
                    "2026-07-29T13:00:00Z",
                ),
                verifier_clock=lambda: NOW + 3600,
                monotonic_clock=lambda: monotonic[0],
            )
            manager.start()
            try:
                client.responses[JWKS_URI] = self._jwks(
                    private_key=self.next_private_key,
                    kid="key-two",
                )
                client.arm_one_block()
                monotonic[0] = 301.0
                rolled = self._token(
                    self.next_private_key,
                    kid="key-two",
                    now=NOW + 3600,
                )

                def verify_rolled() -> str:
                    try:
                        manager.verify(rolled)
                    except EntraAccessTokenError as exc:
                        return exc.code
                    return "unexpected_success"

                with ThreadPoolExecutor(max_workers=12) as executor:
                    futures = [executor.submit(verify_rolled) for _ in range(24)]
                    self.assertTrue(client.block_started.wait(timeout=1))
                    results = [future.result(timeout=1) for future in futures]
                self.assertEqual({"signing_key_unknown"}, set(results))
                self.assertEqual(1, manager.status.completed_attempt_count)

                client.release.set()
                self.assertTrue(
                    manager.wait_for_refresh_attempt(
                        after_completed_count=1,
                        timeout_seconds=2,
                    )
                )
                self.assertEqual(OBJECT_ID, manager.verify(rolled).object_id)
                self.assertEqual(2, manager.status.completed_attempt_count)
                self.assertEqual("unknown_key", manager.status.last_reason)

                unknown_again = self._token(
                    self.private_key,
                    kid="key-three",
                    now=NOW + 3600,
                )
                with self.assertRaises(EntraAccessTokenError):
                    manager.verify(unknown_again)
                self.assertFalse(
                    manager.wait_for_refresh_attempt(
                        after_completed_count=2,
                        timeout_seconds=0.1,
                    )
                )
            finally:
                client.release.set()
                manager.close()

    def test_untrusted_tenant_never_schedules_unknown_key_refresh(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            monotonic = [0.0]
            manager = ManagedEntraAccessTokenVerifier(
                self._configuration(),
                Path(directory) / "entra-trust.json",
                client=self._client(),
                snapshot_clock=_SequenceClock("2026-07-29T12:00:00Z"),
                verifier_clock=lambda: NOW,
                monotonic_clock=lambda: monotonic[0],
            )
            manager.start()
            try:
                monotonic[0] = 301.0
                token = self._token(
                    self.private_key,
                    kid="untrusted-key",
                    now=NOW,
                    tenant_id=OTHER_TENANT_ID,
                    issuer=(f"https://login.microsoftonline.com/{OTHER_TENANT_ID}/v2.0"),
                )
                with self.assertRaises(EntraAccessTokenError) as context:
                    manager.verify(token)
                self.assertEqual("tenant_untrusted", context.exception.code)
                self.assertFalse(
                    manager.wait_for_refresh_attempt(
                        after_completed_count=1,
                        timeout_seconds=0.1,
                    )
                )
            finally:
                manager.close()


if __name__ == "__main__":
    unittest.main()
