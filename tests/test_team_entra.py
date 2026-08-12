"""Adversarial tests for the Microsoft Entra Team identity adapter."""

from __future__ import annotations

import base64
import json
import unittest
from datetime import UTC, datetime
from typing import Any

import jwt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from causure.team_application import AuthenticatedTeamIdentity
from causure.team_entra import (
    ENTRA_CLOCK_SKEW_SECONDS,
    MAX_ENTRA_TRUST_STORE_BYTES,
    EntraAccessDeniedError,
    EntraAccessTokenError,
    EntraAccessTokenVerifier,
    EntraTeamIdentityMiddleware,
    EntraTrustStoreError,
    EntraTrustUnavailableError,
    parse_entra_trust_store,
    parse_entra_trust_store_bytes,
)
from causure.team_http import (
    TEAM_IDENTITY_ENVIRON_KEY,
    TEAM_REQUEST_INTEGRITY_ENVIRON_KEY,
)

NOW = int(datetime(2026, 7, 29, 12, 0, tzinfo=UTC).timestamp())
TENANT_ID = "11111111-1111-4111-8111-111111111111"
OTHER_TENANT_ID = "22222222-2222-4222-8222-222222222222"
AUDIENCE = "33333333-3333-4333-8333-333333333333"
CLIENT_ID = "44444444-4444-4444-8444-444444444444"
OTHER_CLIENT_ID = "55555555-5555-4555-8555-555555555555"
OBJECT_ID = "66666666-6666-4666-8666-666666666666"
OTHER_AUDIENCE = "77777777-7777-4777-8777-777777777777"
ISSUER = f"https://login.microsoftonline.com/{TENANT_ID}/v2.0"


def _base64url_integer(value: int) -> str:
    raw = value.to_bytes((value.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _compact_json(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _segment(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


class _CaptureApplication:
    def __init__(self) -> None:
        self.environ: dict[str, Any] | None = None

    def __call__(self, environ: dict[str, Any], start_response: Any) -> list[bytes]:
        self.environ = dict(environ)
        body = b"ok"
        start_response(
            "200 OK",
            [
                ("Content-Type", "text/plain"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]


class EntraAdapterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cls.other_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def _jwk(self, *, kid: str = "key-one", private_key: Any | None = None) -> dict[str, str]:
        selected = private_key or self.private_key
        numbers = selected.public_key().public_numbers()
        return {
            "kid": kid,
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "n": _base64url_integer(numbers.n),
            "e": _base64url_integer(numbers.e),
        }

    def _trust_document(
        self,
        *,
        refreshed_at: str = "2026-07-29T11:00:00Z",
        expires_at: str = "2026-07-29T23:00:00Z",
    ) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "store_id": "entra-production",
            "refreshed_at": refreshed_at,
            "expires_at": expires_at,
            "tenants": [
                {
                    "entra_tenant_id": TENANT_ID,
                    "team_tenant_id": "tenant-acme",
                    "issuer": ISSUER,
                    "audience": AUDIENCE,
                    "allowed_client_ids": [CLIENT_ID],
                    "accepted_delegated_scopes": ["Causure.Access"],
                    "accepted_application_roles": ["Causure.Service"],
                    "max_token_lifetime_seconds": 7200,
                    "keys": [self._jwk()],
                }
            ],
        }

    def _trust_store(self, **changes: str) -> Any:
        return parse_entra_trust_store(self._trust_document(**changes))

    def _claims(self, **changes: Any) -> dict[str, Any]:
        claims: dict[str, Any] = {
            "ver": "2.0",
            "iss": ISSUER,
            "aud": AUDIENCE,
            "tid": TENANT_ID,
            "oid": OBJECT_ID,
            "azp": CLIENT_ID,
            "iat": NOW - 60,
            "nbf": NOW - 60,
            "exp": NOW + 600,
            "scp": "Causure.Access",
        }
        claims.update(changes)
        return claims

    def _token(
        self,
        claims: dict[str, Any] | None = None,
        *,
        headers: dict[str, Any] | None = None,
        private_key: Any | None = None,
        algorithm: str = "RS256",
    ) -> str:
        selected_headers = {"kid": "key-one", "typ": "JWT"}
        if headers:
            selected_headers.update(headers)
        key: Any = private_key or self.private_key
        if algorithm == "HS256":
            key = b"not-an-rsa-key-not-an-rsa-key-1234"
        return jwt.encode(
            claims or self._claims(),
            key,
            algorithm=algorithm,
            headers=selected_headers,
        )

    def _raw_token(self, header: bytes, claims: bytes) -> str:
        header_segment = _segment(header)
        claims_segment = _segment(claims)
        signing_input = f"{header_segment}.{claims_segment}".encode("ascii")
        signature = self.private_key.sign(
            signing_input,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        return f"{header_segment}.{claims_segment}.{_segment(signature)}"

    def _verifier(self, store: Any | None = None) -> EntraAccessTokenVerifier:
        return EntraAccessTokenVerifier(
            store or self._trust_store(),
            clock=lambda: NOW,
        )

    @staticmethod
    def _request(
        middleware: EntraTeamIdentityMiddleware,
        *,
        path: str = "/v1/team/summary",
        scheme: str = "https",
        authorization: str | None = None,
        method: str = "GET",
        extra: dict[str, Any] | None = None,
    ) -> tuple[str, dict[str, str], bytes]:
        environ: dict[str, Any] = {
            "PATH_INFO": path,
            "REQUEST_METHOD": method,
            "wsgi.url_scheme": scheme,
        }
        if authorization is not None:
            environ["HTTP_AUTHORIZATION"] = authorization
        if extra:
            environ.update(extra)
        response: dict[str, Any] = {}

        def start_response(status: str, headers: list[tuple[str, str]]) -> None:
            response["status"] = status
            response["headers"] = dict(headers)

        body = b"".join(middleware(environ, start_response))
        return response["status"], response["headers"], body

    def test_parser_accepts_closed_tenant_specific_rollover_snapshot(self) -> None:
        store = self._trust_store()

        self.assertEqual("entra-production", store.store_id)
        self.assertEqual(TENANT_ID, store.tenants[0].entra_tenant_id)
        self.assertEqual(("Causure.Access",), store.tenants[0].accepted_delegated_scopes)
        self.assertEqual("RS256", store.tenants[0].keys[0].alg)

    def test_bytes_parser_rejects_duplicate_json_members_and_oversize(self) -> None:
        raw = _compact_json(self._trust_document())
        duplicate = raw.replace(
            b'{"expires_at"',
            b'{"schema_version":"1.0","expires_at"',
            1,
        )
        with self.assertRaises(EntraTrustStoreError):
            parse_entra_trust_store_bytes(duplicate)
        with self.assertRaises(EntraTrustStoreError):
            parse_entra_trust_store_bytes(b" " * (MAX_ENTRA_TRUST_STORE_BYTES + 1))

    def test_parser_rejects_open_or_ambiguous_trust_configuration(self) -> None:
        cases: list[tuple[str, Any]] = []
        unknown = self._trust_document()
        unknown["unexpected"] = True
        cases.append(("unknown property", unknown))
        common_issuer = self._trust_document()
        common_issuer["tenants"][0]["issuer"] = "https://login.microsoftonline.com/common/v2.0"
        cases.append(("common issuer", common_issuer))
        malformed_issuer = self._trust_document()
        malformed_issuer["tenants"][0]["issuer"] = f"https://[invalid/{TENANT_ID}/v2.0"
        cases.append(("malformed issuer", malformed_issuer))
        duplicate_client = self._trust_document()
        duplicate_client["tenants"][0]["allowed_client_ids"] *= 2
        cases.append(("duplicate client", duplicate_client))
        no_grant = self._trust_document()
        no_grant["tenants"][0]["accepted_delegated_scopes"] = []
        no_grant["tenants"][0]["accepted_application_roles"] = []
        cases.append(("no accepted grant", no_grant))
        too_long = self._trust_document(expires_at="2026-07-30T12:00:01Z")
        cases.append(("trust window", too_long))
        weak_key = self._trust_document()
        weak_key["tenants"][0]["keys"][0]["n"] = _base64url_integer((1 << 1023) + 1)
        cases.append(("weak RSA key", weak_key))

        for label, document in cases:
            with self.subTest(label=label), self.assertRaises(EntraTrustStoreError):
                parse_entra_trust_store(document)

    def test_delegated_token_maps_only_immutable_tenant_and_object_ids(self) -> None:
        claims = self._claims(
            email="attacker-controlled@example.test",
            preferred_username="mutable@example.test",
        )
        principal = self._verifier().verify(self._token(claims))

        self.assertEqual("delegated", principal.grant_type)
        self.assertEqual(("Causure.Access",), principal.permissions)
        self.assertEqual(
            AuthenticatedTeamIdentity(
                tenant_id="tenant-acme",
                identity_provider=f"entra:{TENANT_ID}",
                subject_id=OBJECT_ID,
            ),
            principal.identity,
        )
        self.assertNotIn("example.test", repr(principal))

    def test_app_only_token_requires_idtyp_and_application_role(self) -> None:
        claims = self._claims()
        claims.pop("scp")
        claims.update(
            {
                "idtyp": "app",
                "roles": ["Causure.Service"],
            }
        )

        principal = self._verifier().verify(self._token(claims))

        self.assertEqual("application", principal.grant_type)
        self.assertEqual(("Causure.Service",), principal.permissions)

    def test_signature_and_jose_confusion_attacks_are_rejected(self) -> None:
        valid = self._token()
        parts = valid.split(".")
        replacement = "A" if parts[2][0] != "A" else "B"
        tampered = ".".join([parts[0], parts[1], replacement + parts[2][1:]])
        cases = {
            "tampered signature": tampered,
            "wrong RSA key": self._token(private_key=self.other_private_key),
            "HS/RS confusion": self._token(algorithm="HS256"),
            "embedded JWK URL": self._token(headers={"jku": "https://attacker.test/keys"}),
            "critical extension": self._token(headers={"crit": ["exp"]}),
        }

        for label, token in cases.items():
            with self.subTest(label=label), self.assertRaises(EntraAccessTokenError):
                self._verifier().verify(token)

    def test_duplicate_claims_and_noncanonical_segments_are_rejected(self) -> None:
        header = _compact_json({"alg": "RS256", "kid": "key-one", "typ": "JWT"})
        claims_text = _compact_json(self._claims())
        duplicate_claims = claims_text.replace(
            b'{"aud"',
            f'{{"aud":"{AUDIENCE}","aud"'.encode(),
            1,
        )
        duplicate_token = self._raw_token(header, duplicate_claims)
        valid_parts = self._token().split(".")
        padded = f"{valid_parts[0]}=.{valid_parts[1]}.{valid_parts[2]}"

        for token in (duplicate_token, padded):
            with self.subTest(token=token[:24]), self.assertRaises(EntraAccessTokenError):
                self._verifier().verify(token)

    def test_tenant_issuer_audience_and_key_must_match_trust(self) -> None:
        cases = {
            "tenant": self._claims(tid=OTHER_TENANT_ID),
            "issuer": self._claims(iss=f"https://login.microsoftonline.com/{OTHER_TENANT_ID}/v2.0"),
            "audience": self._claims(aud=OTHER_CLIENT_ID),
        }
        for label, claims in cases.items():
            with self.subTest(label=label), self.assertRaises(EntraAccessTokenError):
                self._verifier().verify(self._token(claims))
        with self.assertRaises(EntraAccessTokenError):
            self._verifier().verify(self._token(headers={"kid": "rolled-key"}))

    def test_same_kid_is_resolved_inside_the_verified_tenant_partition(self) -> None:
        document = self._trust_document()
        other_issuer = f"https://login.microsoftonline.com/{OTHER_TENANT_ID}/v2.0"
        document["tenants"].append(
            {
                "entra_tenant_id": OTHER_TENANT_ID,
                "team_tenant_id": "tenant-beta",
                "issuer": other_issuer,
                "audience": OTHER_AUDIENCE,
                "allowed_client_ids": [CLIENT_ID],
                "accepted_delegated_scopes": ["Causure.Access"],
                "accepted_application_roles": [],
                "max_token_lifetime_seconds": 7200,
                "keys": [self._jwk(private_key=self.other_private_key)],
            }
        )
        verifier = self._verifier(parse_entra_trust_store(document))
        claims = self._claims(
            tid=OTHER_TENANT_ID,
            iss=other_issuer,
            aud=OTHER_AUDIENCE,
        )

        principal = verifier.verify(self._token(claims, private_key=self.other_private_key))

        self.assertEqual("tenant-beta", principal.identity.tenant_id)
        with self.assertRaises(EntraAccessTokenError):
            verifier.verify(self._token(claims))

    def test_time_claims_are_typed_bounded_and_fresh(self) -> None:
        cases = {
            "expired": self._claims(exp=NOW - ENTRA_CLOCK_SKEW_SECONDS - 1),
            "future nbf": self._claims(nbf=NOW + ENTRA_CLOCK_SKEW_SECONDS + 1),
            "future iat": self._claims(iat=NOW + ENTRA_CLOCK_SKEW_SECONDS + 1),
            "boolean timestamp": self._claims(iat=True),
            "inconsistent": self._claims(exp=NOW - 60),
            "overlong": self._claims(iat=NOW - 8000, nbf=NOW - 8000),
        }
        for label, claims in cases.items():
            with self.subTest(label=label), self.assertRaises(EntraAccessTokenError):
                self._verifier().verify(self._token(claims))

    def test_actor_and_grant_fail_after_authentication(self) -> None:
        cases = {
            "client": self._claims(azp=OTHER_CLIENT_ID),
            "scope": self._claims(scp="Other.Scope"),
        }
        app_without_type = self._claims(roles=["Causure.Service"])
        app_without_type.pop("scp")
        for label, claims in cases.items():
            with self.subTest(label=label), self.assertRaises(EntraAccessDeniedError):
                self._verifier().verify(self._token(claims))
        with self.assertRaises(EntraAccessTokenError):
            self._verifier().verify(self._token(app_without_type))
        with self.assertRaises(EntraAccessTokenError):
            self._verifier().verify(self._token(self._claims(idtyp="unexpected")))

    def test_stale_or_future_trust_snapshot_is_unavailable(self) -> None:
        stores = [
            self._trust_store(
                refreshed_at="2026-07-28T10:00:00Z",
                expires_at="2026-07-28T22:00:00Z",
            ),
            self._trust_store(
                refreshed_at="2026-07-29T12:01:01Z",
                expires_at="2026-07-29T23:00:00Z",
            ),
        ]
        for store in stores:
            with (
                self.subTest(store=store.refreshed_at),
                self.assertRaises(EntraTrustUnavailableError),
            ):
                self._verifier(store).check_ready()

    def test_middleware_injects_typed_identity_and_removes_bearer(self) -> None:
        capture = _CaptureApplication()
        middleware = EntraTeamIdentityMiddleware(capture, self._verifier())
        spoofed = AuthenticatedTeamIdentity(
            tenant_id="attacker-tenant",
            identity_provider="attacker",
            subject_id="attacker",
        )

        status, headers, body = self._request(
            middleware,
            authorization=f"Bearer {self._token()}",
            method="POST",
            extra={
                TEAM_IDENTITY_ENVIRON_KEY: spoofed,
                TEAM_REQUEST_INTEGRITY_ENVIRON_KEY: False,
                "HTTP_X_TENANT_ID": "attacker-tenant",
            },
        )

        self.assertEqual("200 OK", status)
        self.assertEqual(b"ok", body)
        self.assertEqual("max-age=31536000", headers["Strict-Transport-Security"])
        assert capture.environ is not None
        self.assertEqual("tenant-acme", capture.environ[TEAM_IDENTITY_ENVIRON_KEY].tenant_id)
        self.assertIs(True, capture.environ[TEAM_REQUEST_INTEGRITY_ENVIRON_KEY])
        self.assertNotIn("HTTP_AUTHORIZATION", capture.environ)
        self.assertEqual("attacker-tenant", capture.environ["HTTP_X_TENANT_ID"])

    def test_middleware_emits_bearer_challenges_without_token_details(self) -> None:
        capture = _CaptureApplication()
        middleware = EntraTeamIdentityMiddleware(capture, self._verifier())
        invalid_token = self._token(self._claims(aud=OTHER_CLIENT_ID))
        cases = [
            (None, "401 Unauthorized", 'Bearer realm="causure-team"'),
            (
                f"Bearer {invalid_token}",
                "401 Unauthorized",
                'error="invalid_token"',
            ),
            (
                f"Bearer {self._token(self._claims(scp='Other.Scope'))}",
                "403 Forbidden",
                'error="insufficient_scope"',
            ),
        ]

        for authorization, expected_status, challenge_part in cases:
            with self.subTest(expected_status=expected_status):
                status, headers, body = self._request(
                    middleware,
                    authorization=authorization,
                )
                self.assertEqual(expected_status, status)
                self.assertIn(challenge_part, headers["WWW-Authenticate"])
                self.assertNotIn(invalid_token.encode(), body)
                self.assertEqual("no-store", headers["Cache-Control"])

    def test_middleware_rejects_plain_http_and_malformed_authorization(self) -> None:
        middleware = EntraTeamIdentityMiddleware(_CaptureApplication(), self._verifier())

        status, _, _ = self._request(
            middleware,
            scheme="http",
            authorization=f"Bearer {self._token()}",
        )
        self.assertEqual("400 Bad Request", status)
        for value in ("Basic abc", "Bearer  token", "Bearer", "Bearer token extra"):
            with self.subTest(value=value):
                status, headers, _ = self._request(middleware, authorization=value)
                self.assertEqual("401 Unauthorized", status)
                self.assertIn('error="invalid_token"', headers["WWW-Authenticate"])

    def test_public_routes_strip_untrusted_identity_and_readiness_checks_trust(self) -> None:
        capture = _CaptureApplication()
        middleware = EntraTeamIdentityMiddleware(capture, self._verifier())
        status, _, _ = self._request(
            middleware,
            path="/healthz",
            scheme="http",
            authorization="Bearer attacker-value",
            extra={
                TEAM_IDENTITY_ENVIRON_KEY: AuthenticatedTeamIdentity(
                    tenant_id="attacker",
                    identity_provider="attacker",
                    subject_id="attacker",
                )
            },
        )
        self.assertEqual("200 OK", status)
        assert capture.environ is not None
        self.assertNotIn(TEAM_IDENTITY_ENVIRON_KEY, capture.environ)
        self.assertNotIn("HTTP_AUTHORIZATION", capture.environ)

        stale = self._trust_store(
            refreshed_at="2026-07-28T10:00:00Z",
            expires_at="2026-07-28T22:00:00Z",
        )
        unavailable = EntraTeamIdentityMiddleware(_CaptureApplication(), self._verifier(stale))
        status, headers, body = self._request(
            unavailable,
            path="/readyz",
            scheme="http",
        )
        self.assertEqual("503 Service Unavailable", status)
        self.assertEqual("60", headers["Retry-After"])
        self.assertIn(b"identity_provider_unavailable", body)


if __name__ == "__main__":
    unittest.main()
