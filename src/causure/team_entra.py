"""Microsoft Entra bearer-token adapter for the trusted Team WSGI boundary."""

from __future__ import annotations

import base64
import binascii
import json
import math
import re
import time
import uuid
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

from causure.constants import ENTRA_TRUST_STORE_SCHEMA_VERSION
from causure.io import InputDocumentError, parse_json_text
from causure.team_application import AuthenticatedTeamIdentity
from causure.team_http import (
    TEAM_IDENTITY_ENVIRON_KEY,
    TEAM_REQUEST_INTEGRITY_ENVIRON_KEY,
)

MAX_ENTRA_TRUST_STORE_BYTES = 1024 * 1024
MAX_ENTRA_ACCESS_TOKEN_BYTES = 32 * 1024
MAX_ENTRA_AUTHORIZATION_BYTES = MAX_ENTRA_ACCESS_TOKEN_BYTES + 16
ENTRA_CLOCK_SKEW_SECONDS = 60
MAX_ENTRA_TRUST_WINDOW_SECONDS = 24 * 60 * 60

_TEAM_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$")
_STORE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{2,127}$")
_PERMISSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")
_KID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_JWT_SEGMENT_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_UTC_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_PUBLIC_PATHS = frozenset({"/healthz", "/readyz", "/team.css"})
_DANGEROUS_JOSE_HEADERS = frozenset({"crit", "jku", "jwk", "x5u", "x5c", "b64"})
_StartResponse = Callable[..., Any]
_Clock = Callable[[], int]


class EntraTrustStoreError(ValueError):
    """Raised when protected Entra trust configuration violates its contract."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"Invalid Entra trust store at {path}: {message}")


class EntraDependencyError(RuntimeError):
    """Raised when the optional Entra cryptography dependencies are unavailable."""


class EntraTrustUnavailableError(RuntimeError):
    """Raised when configured Entra trust cannot safely validate requests."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Entra trust unavailable [{code}]: {message}")


class EntraAccessTokenError(ValueError):
    """Raised with a stable, non-sensitive access-token rejection code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Entra access token rejected [{code}]: {message}")


class EntraAccessDeniedError(PermissionError):
    """Raised after authentication when the actor or grant is not accepted."""

    def __init__(
        self,
        code: str,
        message: str,
        *,
        accepted_scopes: tuple[str, ...] = (),
    ) -> None:
        self.code = code
        self.message = message
        self.accepted_scopes = accepted_scopes
        super().__init__(f"Entra access denied [{code}]: {message}")


@dataclass(frozen=True, slots=True)
class EntraRSAKey:
    kid: str
    kty: str
    use: str
    alg: str
    n: str
    e: str


@dataclass(frozen=True, slots=True)
class EntraTenantTrust:
    entra_tenant_id: str
    team_tenant_id: str
    issuer: str
    audience: str
    allowed_client_ids: tuple[str, ...]
    accepted_delegated_scopes: tuple[str, ...]
    accepted_application_roles: tuple[str, ...]
    max_token_lifetime_seconds: int
    keys: tuple[EntraRSAKey, ...]


@dataclass(frozen=True, slots=True)
class EntraTrustStore:
    schema_version: str
    store_id: str
    refreshed_at: str
    expires_at: str
    tenants: tuple[EntraTenantTrust, ...]


@dataclass(frozen=True, slots=True)
class EntraVerifiedPrincipal:
    """A verified Entra principal and the bounded authorization facts used."""

    identity: AuthenticatedTeamIdentity
    entra_tenant_id: str
    object_id: str
    client_id: str
    grant_type: str
    permissions: tuple[str, ...]
    issued_at: int
    expires_at: int


def _closed_object(
    value: Any,
    *,
    path: str,
    required: set[str],
) -> Mapping[str, Any]:
    if type(value) is not dict:
        raise EntraTrustStoreError(path, "must be an object")
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required)
    if missing:
        raise EntraTrustStoreError(path, f"missing required properties: {', '.join(missing)}")
    if unknown:
        raise EntraTrustStoreError(path, f"unknown properties: {', '.join(unknown)}")
    return value


def _string(
    value: Any,
    *,
    path: str,
    pattern: re.Pattern[str] | None = None,
    maximum: int = 256,
) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise EntraTrustStoreError(
            path,
            f"must be a non-empty string of at most {maximum} characters",
        )
    if pattern is not None and pattern.fullmatch(value) is None:
        raise EntraTrustStoreError(path, "has an invalid format")
    return value


def _canonical_uuid(value: Any, *, path: str) -> str:
    text = _string(value, path=path, maximum=36)
    try:
        parsed = uuid.UUID(text)
    except (ValueError, AttributeError) as exc:
        raise EntraTrustStoreError(path, "must be a canonical UUID") from exc
    if str(parsed) != text:
        raise EntraTrustStoreError(path, "must be a lowercase canonical UUID")
    return text


def _timestamp(value: Any, *, path: str) -> tuple[str, int]:
    text = _string(value, path=path, maximum=20)
    try:
        parsed = datetime.strptime(text, _UTC_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError as exc:
        raise EntraTrustStoreError(path, "must be a whole-second UTC timestamp") from exc
    if parsed.strftime(_UTC_TIMESTAMP_FORMAT) != text:
        raise EntraTrustStoreError(path, "must be a whole-second UTC timestamp")
    return text, int(parsed.timestamp())


def _string_set(
    value: Any,
    *,
    path: str,
    item_parser: Callable[[Any], str],
    minimum: int,
    maximum: int,
) -> tuple[str, ...]:
    if type(value) is not list or not minimum <= len(value) <= maximum:
        raise EntraTrustStoreError(
            path,
            f"must be an array with between {minimum} and {maximum} items",
        )
    parsed = tuple(item_parser(item) for item in value)
    if len(set(parsed)) != len(parsed):
        raise EntraTrustStoreError(path, "must not contain duplicate values")
    return parsed


def _decode_base64url_integer(value: Any, *, path: str) -> tuple[str, int]:
    text = _string(value, path=path, pattern=_BASE64URL_PATTERN, maximum=1366)
    try:
        raw = base64.urlsafe_b64decode(text + ("=" * (-len(text) % 4)))
    except (binascii.Error, ValueError) as exc:
        raise EntraTrustStoreError(path, "must be canonical unpadded base64url") from exc
    if not raw or raw[0] == 0 or base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != text:
        raise EntraTrustStoreError(path, "must be a canonical unsigned base64url integer")
    return text, int.from_bytes(raw, "big")


def _parse_key(value: Any, *, path: str) -> EntraRSAKey:
    document = _closed_object(
        value,
        path=path,
        required={"kid", "kty", "use", "alg", "n", "e"},
    )
    kid = _string(document["kid"], path=f"{path}.kid", pattern=_KID_PATTERN)
    for name, expected in (("kty", "RSA"), ("use", "sig"), ("alg", "RS256")):
        if document[name] != expected:
            raise EntraTrustStoreError(f"{path}.{name}", f"must be {expected!r}")
    n, modulus = _decode_base64url_integer(document["n"], path=f"{path}.n")
    e, exponent = _decode_base64url_integer(document["e"], path=f"{path}.e")
    if not 2048 <= modulus.bit_length() <= 8192 or modulus % 2 == 0:
        raise EntraTrustStoreError(f"{path}.n", "RSA modulus must be between 2048 and 8192 bits")
    if exponent < 3 or exponent > 0xFFFFFFFF or exponent % 2 == 0:
        raise EntraTrustStoreError(
            f"{path}.e",
            "RSA exponent must be an odd integer from 3 to 2^32-1",
        )
    if math.gcd(modulus, exponent) != 1:
        raise EntraTrustStoreError(f"{path}.e", "RSA exponent must be coprime to the modulus")
    return EntraRSAKey(kid=kid, kty="RSA", use="sig", alg="RS256", n=n, e=e)


def _validate_issuer(value: Any, *, path: str, tenant_id: str) -> str:
    issuer = _string(value, path=path, maximum=256)
    try:
        parsed = urlsplit(issuer)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise EntraTrustStoreError(
            path,
            "must be an exact tenant-specific HTTPS v2.0 issuer",
        ) from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or parsed.query
        or parsed.fragment
        or parsed.path != f"/{tenant_id}/v2.0"
    ):
        raise EntraTrustStoreError(
            path,
            "must be an exact tenant-specific HTTPS v2.0 issuer",
        )
    return issuer


def _parse_tenant(value: Any, *, path: str) -> EntraTenantTrust:
    document = _closed_object(
        value,
        path=path,
        required={
            "entra_tenant_id",
            "team_tenant_id",
            "issuer",
            "audience",
            "allowed_client_ids",
            "accepted_delegated_scopes",
            "accepted_application_roles",
            "max_token_lifetime_seconds",
            "keys",
        },
    )
    entra_tenant_id = _canonical_uuid(
        document["entra_tenant_id"],
        path=f"{path}.entra_tenant_id",
    )
    team_tenant_id = _string(
        document["team_tenant_id"],
        path=f"{path}.team_tenant_id",
        pattern=_TEAM_ID_PATTERN,
        maximum=128,
    )
    issuer = _validate_issuer(
        document["issuer"],
        path=f"{path}.issuer",
        tenant_id=entra_tenant_id,
    )
    audience = _canonical_uuid(document["audience"], path=f"{path}.audience")
    allowed_client_ids = _string_set(
        document["allowed_client_ids"],
        path=f"{path}.allowed_client_ids",
        item_parser=lambda item: _canonical_uuid(item, path=f"{path}.allowed_client_ids[]"),
        minimum=1,
        maximum=100,
    )
    delegated = _string_set(
        document["accepted_delegated_scopes"],
        path=f"{path}.accepted_delegated_scopes",
        item_parser=lambda item: _string(
            item,
            path=f"{path}.accepted_delegated_scopes[]",
            pattern=_PERMISSION_PATTERN,
            maximum=128,
        ),
        minimum=0,
        maximum=100,
    )
    application = _string_set(
        document["accepted_application_roles"],
        path=f"{path}.accepted_application_roles",
        item_parser=lambda item: _string(
            item,
            path=f"{path}.accepted_application_roles[]",
            pattern=_PERMISSION_PATTERN,
            maximum=128,
        ),
        minimum=0,
        maximum=100,
    )
    if not delegated and not application:
        raise EntraTrustStoreError(
            path,
            "must accept at least one delegated scope or application role",
        )
    lifetime = document["max_token_lifetime_seconds"]
    if type(lifetime) is not int or not 300 <= lifetime <= 86400:
        raise EntraTrustStoreError(
            f"{path}.max_token_lifetime_seconds",
            "must be an integer from 300 through 86400",
        )
    keys_value = document["keys"]
    if type(keys_value) is not list or not 1 <= len(keys_value) <= 100:
        raise EntraTrustStoreError(f"{path}.keys", "must contain between 1 and 100 keys")
    keys = tuple(
        _parse_key(item, path=f"{path}.keys[{index}]") for index, item in enumerate(keys_value)
    )
    if len({key.kid for key in keys}) != len(keys):
        raise EntraTrustStoreError(f"{path}.keys", "must not contain duplicate kid values")
    return EntraTenantTrust(
        entra_tenant_id=entra_tenant_id,
        team_tenant_id=team_tenant_id,
        issuer=issuer,
        audience=audience,
        allowed_client_ids=allowed_client_ids,
        accepted_delegated_scopes=delegated,
        accepted_application_roles=application,
        max_token_lifetime_seconds=lifetime,
        keys=keys,
    )


def parse_entra_trust_store(document: Any) -> EntraTrustStore:
    """Parse a closed, tenant-specific Entra trust snapshot."""

    value = _closed_object(
        document,
        path="$",
        required={"schema_version", "store_id", "refreshed_at", "expires_at", "tenants"},
    )
    if value["schema_version"] != ENTRA_TRUST_STORE_SCHEMA_VERSION:
        raise EntraTrustStoreError(
            "$.schema_version",
            f"must be {ENTRA_TRUST_STORE_SCHEMA_VERSION!r}",
        )
    store_id = _string(
        value["store_id"],
        path="$.store_id",
        pattern=_STORE_ID_PATTERN,
        maximum=128,
    )
    refreshed_at, refreshed_epoch = _timestamp(value["refreshed_at"], path="$.refreshed_at")
    expires_at, expires_epoch = _timestamp(value["expires_at"], path="$.expires_at")
    if not 0 < expires_epoch - refreshed_epoch <= MAX_ENTRA_TRUST_WINDOW_SECONDS:
        raise EntraTrustStoreError(
            "$.expires_at",
            "must be after refreshed_at and no more than 24 hours later",
        )
    tenants_value = value["tenants"]
    if type(tenants_value) is not list or not 1 <= len(tenants_value) <= 100:
        raise EntraTrustStoreError("$.tenants", "must contain between 1 and 100 tenants")
    tenants = tuple(
        _parse_tenant(item, path=f"$.tenants[{index}]") for index, item in enumerate(tenants_value)
    )
    if len({tenant.entra_tenant_id for tenant in tenants}) != len(tenants):
        raise EntraTrustStoreError("$.tenants", "must not contain duplicate Entra tenant IDs")
    return EntraTrustStore(
        schema_version=ENTRA_TRUST_STORE_SCHEMA_VERSION,
        store_id=store_id,
        refreshed_at=refreshed_at,
        expires_at=expires_at,
        tenants=tenants,
    )


def parse_entra_trust_store_bytes(data: bytes) -> EntraTrustStore:
    """Decode a bounded UTF-8 Entra trust snapshot and parse its contract."""

    if not isinstance(data, bytes):
        raise EntraTrustStoreError("$", "trust-store input must be bytes")
    if len(data) > MAX_ENTRA_TRUST_STORE_BYTES:
        raise EntraTrustStoreError(
            "$",
            f"trust-store input exceeds {MAX_ENTRA_TRUST_STORE_BYTES} bytes",
        )
    try:
        text = data.decode("utf-8")
        document = parse_json_text(
            text,
            source="Entra trust store",
            max_bytes=MAX_ENTRA_TRUST_STORE_BYTES,
        )
    except (UnicodeDecodeError, InputDocumentError) as exc:
        raise EntraTrustStoreError("$", f"must be strict UTF-8 JSON: {exc}") from exc
    return parse_entra_trust_store(document)


def render_entra_trust_store(store: EntraTrustStore) -> str:
    """Render one parsed Entra trust snapshot as deterministic UTF-8 JSON text."""

    if type(store) is not EntraTrustStore:
        raise TypeError("store must be an EntraTrustStore")
    document = {
        "schema_version": store.schema_version,
        "store_id": store.store_id,
        "refreshed_at": store.refreshed_at,
        "expires_at": store.expires_at,
        "tenants": [
            {
                "entra_tenant_id": tenant.entra_tenant_id,
                "team_tenant_id": tenant.team_tenant_id,
                "issuer": tenant.issuer,
                "audience": tenant.audience,
                "allowed_client_ids": list(tenant.allowed_client_ids),
                "accepted_delegated_scopes": list(tenant.accepted_delegated_scopes),
                "accepted_application_roles": list(tenant.accepted_application_roles),
                "max_token_lifetime_seconds": tenant.max_token_lifetime_seconds,
                "keys": [
                    {
                        "kid": key.kid,
                        "kty": key.kty,
                        "use": key.use,
                        "alg": key.alg,
                        "n": key.n,
                        "e": key.e,
                    }
                    for key in tenant.keys
                ],
            }
            for tenant in store.tenants
        ],
    }
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )


def _epoch(timestamp: str) -> int:
    return int(datetime.strptime(timestamp, _UTC_TIMESTAMP_FORMAT).replace(tzinfo=UTC).timestamp())


def _jwt_types() -> tuple[Any, type[Exception], Any]:
    try:
        import jwt
        from cryptography.hazmat.primitives.asymmetric import rsa
        from jwt.exceptions import InvalidTokenError
    except ImportError as exc:
        raise EntraDependencyError(
            'Entra bearer support requires: pip install "causure[entra]"'
        ) from exc
    return jwt, InvalidTokenError, rsa


def _token_error(code: str, message: str) -> EntraAccessTokenError:
    return EntraAccessTokenError(code, message)


def _decode_jwt_segment(segment: str, *, name: str, maximum: int) -> bytes:
    if not segment or len(segment) > maximum or _JWT_SEGMENT_PATTERN.fullmatch(segment) is None:
        raise _token_error("token_malformed", f"{name} is not canonical base64url")
    try:
        raw = base64.urlsafe_b64decode(segment + ("=" * (-len(segment) % 4)))
    except (binascii.Error, ValueError) as exc:
        raise _token_error("token_malformed", f"{name} is not canonical base64url") from exc
    if base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=") != segment:
        raise _token_error("token_malformed", f"{name} is not canonical base64url")
    return raw


def _jwt_object(raw: bytes, *, name: str) -> Mapping[str, Any]:
    try:
        text = raw.decode("utf-8")
        value = parse_json_text(text, source=name, max_bytes=len(raw))
    except (UnicodeDecodeError, InputDocumentError) as exc:
        raise _token_error("token_malformed", f"{name} is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise _token_error("token_malformed", f"{name} must be a JSON object")
    return value


def _compact_jwt(token: str) -> tuple[Mapping[str, Any], Mapping[str, Any]]:
    if not isinstance(token, str):
        raise _token_error("token_malformed", "access token must be text")
    try:
        token_bytes = token.encode("ascii")
    except UnicodeEncodeError as exc:
        raise _token_error("token_malformed", "access token must be ASCII") from exc
    if not token_bytes or len(token_bytes) > MAX_ENTRA_ACCESS_TOKEN_BYTES:
        raise _token_error("token_malformed", "access token is empty or exceeds its size limit")
    segments = token.split(".")
    if len(segments) != 3:
        raise _token_error("token_malformed", "access token must have three compact segments")
    header_raw = _decode_jwt_segment(segments[0], name="JWT header", maximum=4096)
    claims_raw = _decode_jwt_segment(
        segments[1],
        name="JWT claims",
        maximum=MAX_ENTRA_ACCESS_TOKEN_BYTES,
    )
    signature = _decode_jwt_segment(
        segments[2],
        name="JWT signature",
        maximum=4096,
    )
    if not signature:
        raise _token_error("token_malformed", "JWT signature must not be empty")
    return _jwt_object(header_raw, name="JWT header"), _jwt_object(
        claims_raw,
        name="JWT claims",
    )


def _claim_string(claims: Mapping[str, Any], name: str) -> str:
    value = claims.get(name)
    if not isinstance(value, str) or not value:
        raise _token_error("claims_invalid", f"required {name} claim is invalid")
    return value


def _claim_uuid(claims: Mapping[str, Any], name: str) -> str:
    value = _claim_string(claims, name)
    try:
        parsed = uuid.UUID(value)
    except ValueError as exc:
        raise _token_error("claims_invalid", f"required {name} claim is invalid") from exc
    if str(parsed) != value:
        raise _token_error("claims_invalid", f"required {name} claim is not canonical")
    return value


def _claim_time(claims: Mapping[str, Any], name: str) -> int:
    value = claims.get(name)
    if type(value) is not int or value < 0 or value > 253402300799:
        raise _token_error("claims_invalid", f"required {name} claim is invalid")
    return value


def _permissions(value: Any, *, claim: str) -> tuple[str, ...]:
    if claim == "scp":
        if not isinstance(value, str) or not value or value.strip() != value:
            raise _token_error("claims_invalid", "scp claim is invalid")
        items = tuple(value.split(" "))
    else:
        if type(value) is not list or not value:
            raise _token_error("claims_invalid", "roles claim is invalid")
        items = tuple(value)
    if (
        not items
        or any(
            not isinstance(item, str) or _PERMISSION_PATTERN.fullmatch(item) is None
            for item in items
        )
        or len(set(items)) != len(items)
    ):
        raise _token_error("claims_invalid", f"{claim} claim is invalid")
    return items


class EntraTokenVerifier(ABC):
    """Interface implemented by fixed and atomically reloading Entra verifiers."""

    @abstractmethod
    def check_ready(self) -> None:
        """Fail unless the verifier currently has usable, fresh trust."""

    @abstractmethod
    def verify(self, token: str) -> EntraVerifiedPrincipal:
        """Verify one bearer access token and return its typed principal."""


class EntraAccessTokenVerifier(EntraTokenVerifier):
    """Verify a strict Microsoft Entra v2.0 access-token profile offline."""

    def __init__(
        self,
        trust_store: EntraTrustStore,
        *,
        clock: _Clock = lambda: int(time.time()),
        clock_skew_seconds: int = ENTRA_CLOCK_SKEW_SECONDS,
    ) -> None:
        if type(trust_store) is not EntraTrustStore:
            raise TypeError("trust_store must be an EntraTrustStore")
        if not callable(clock):
            raise TypeError("clock must be callable")
        if type(clock_skew_seconds) is not int or not 0 <= clock_skew_seconds <= 300:
            raise ValueError("clock_skew_seconds must be an integer from 0 through 300")
        self._trust_store = trust_store
        self._clock = clock
        self._clock_skew_seconds = clock_skew_seconds
        self._tenants = {tenant.entra_tenant_id: tenant for tenant in trust_store.tenants}
        self._public_keys: dict[tuple[str, str], Any] = {}
        self._all_keys_loaded = False

    @property
    def trust_store(self) -> EntraTrustStore:
        return self._trust_store

    def _now(self) -> int:
        value = self._clock()
        if type(value) is not int or value < 0:
            raise EntraTrustUnavailableError(
                "clock_invalid",
                "the verifier clock did not return a non-negative integer epoch",
            )
        return value

    def check_ready(self) -> None:
        """Fail unless trust freshness and optional crypto dependencies are usable."""

        now = self._now()
        if now + self._clock_skew_seconds < _epoch(self._trust_store.refreshed_at):
            raise EntraTrustUnavailableError(
                "trust_not_yet_valid",
                "the Entra trust snapshot is dated in the future",
            )
        if now >= _epoch(self._trust_store.expires_at):
            raise EntraTrustUnavailableError(
                "trust_stale",
                "the Entra trust snapshot has expired",
            )
        try:
            _jwt_types()
        except EntraDependencyError as exc:
            raise EntraTrustUnavailableError(
                "dependency_unavailable",
                "the Entra verifier dependencies are unavailable",
            ) from exc
        if not self._all_keys_loaded:
            for tenant in self._trust_store.tenants:
                for key in tenant.keys:
                    self._trusted_public_key(tenant, key)
            self._all_keys_loaded = True

    def _tenant(self, claims: Mapping[str, Any]) -> EntraTenantTrust:
        tenant_id = _claim_uuid(claims, "tid")
        tenant = self._tenants.get(tenant_id)
        if tenant is None:
            raise _token_error("tenant_untrusted", "token tenant is not trusted")
        return tenant

    @staticmethod
    def _key(tenant: EntraTenantTrust, header: Mapping[str, Any]) -> EntraRSAKey:
        if header.get("typ") != "JWT" or header.get("alg") != "RS256":
            raise _token_error("header_invalid", "JWT type or algorithm is not accepted")
        if any(name in header for name in _DANGEROUS_JOSE_HEADERS):
            raise _token_error("header_invalid", "JWT contains an unsupported JOSE header")
        kid = header.get("kid")
        if not isinstance(kid, str) or _KID_PATTERN.fullmatch(kid) is None:
            raise _token_error("header_invalid", "JWT kid is invalid")
        for key in tenant.keys:
            if key.kid == kid:
                return key
        raise _token_error("signing_key_unknown", "JWT signing key is not trusted")

    @staticmethod
    def _load_public_key(key: EntraRSAKey) -> Any:
        _, _, rsa = _jwt_types()
        modulus_raw = base64.urlsafe_b64decode(key.n + ("=" * (-len(key.n) % 4)))
        exponent_raw = base64.urlsafe_b64decode(key.e + ("=" * (-len(key.e) % 4)))
        modulus = int.from_bytes(modulus_raw, "big")
        exponent = int.from_bytes(exponent_raw, "big")
        try:
            return rsa.RSAPublicNumbers(exponent, modulus).public_key()
        except (TypeError, ValueError) as exc:
            raise EntraTrustUnavailableError(
                "signing_key_invalid",
                "configured Entra RSA key cannot be loaded",
            ) from exc

    def _trusted_public_key(
        self,
        tenant: EntraTenantTrust,
        key: EntraRSAKey,
    ) -> Any:
        cache_key = (tenant.entra_tenant_id, key.kid)
        public_key = self._public_keys.get(cache_key)
        if public_key is None:
            public_key = self._load_public_key(key)
            self._public_keys[cache_key] = public_key
        return public_key

    def _verify_signature(
        self,
        token: str,
        header: Mapping[str, Any],
        claims: Mapping[str, Any],
        tenant: EntraTenantTrust,
        key: EntraRSAKey,
    ) -> None:
        jwt, invalid_token, _ = _jwt_types()
        try:
            decoded = jwt.decode(
                token,
                self._trusted_public_key(tenant, key),
                algorithms=["RS256"],
                options={
                    "verify_signature": True,
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                    "verify_aud": False,
                    "verify_iss": False,
                    "verify_sub": False,
                    "verify_jti": False,
                },
            )
        except invalid_token as exc:
            raise _token_error("signature_invalid", "JWT signature is invalid") from exc
        if type(decoded) is not dict or decoded != claims or header.get("alg") != "RS256":
            raise _token_error("token_malformed", "JWT decoding was inconsistent")

    def _validate_claims(
        self,
        claims: Mapping[str, Any],
        tenant: EntraTenantTrust,
        *,
        now: int,
    ) -> EntraVerifiedPrincipal:
        if _claim_string(claims, "ver") != "2.0":
            raise _token_error(
                "token_version_invalid",
                "only Entra v2.0 access tokens are accepted",
            )
        if _claim_string(claims, "iss") != tenant.issuer:
            raise _token_error("issuer_invalid", "token issuer does not match trusted metadata")
        if _claim_string(claims, "aud") != tenant.audience:
            raise _token_error("audience_invalid", "token audience does not identify this API")
        if _claim_uuid(claims, "tid") != tenant.entra_tenant_id:
            raise _token_error("tenant_invalid", "token tenant does not match trusted metadata")
        object_id = _claim_uuid(claims, "oid")
        client_id = _claim_uuid(claims, "azp")
        issued_at = _claim_time(claims, "iat")
        not_before = _claim_time(claims, "nbf")
        expires_at = _claim_time(claims, "exp")
        if expires_at <= max(issued_at, not_before):
            raise _token_error("lifetime_invalid", "token time claims are inconsistent")
        if expires_at - issued_at > tenant.max_token_lifetime_seconds:
            raise _token_error("lifetime_invalid", "token lifetime exceeds trusted policy")
        skew = self._clock_skew_seconds
        if issued_at > now + skew or not_before > now + skew:
            raise _token_error("token_not_yet_valid", "token is not yet valid")
        if expires_at <= now - skew:
            raise _token_error("token_expired", "token has expired")
        if client_id not in tenant.allowed_client_ids:
            raise EntraAccessDeniedError(
                "actor_not_authorized",
                "the client application is not allowed for this tenant",
            )

        if "scp" in claims:
            permissions = _permissions(claims["scp"], claim="scp")
            if "idtyp" in claims and claims["idtyp"] != "user":
                raise _token_error(
                    "claims_invalid",
                    "delegated token idtyp must be user when present",
                )
            if not tenant.accepted_delegated_scopes or not set(permissions).intersection(
                tenant.accepted_delegated_scopes
            ):
                raise EntraAccessDeniedError(
                    "insufficient_scope",
                    "the delegated token lacks an accepted API scope",
                    accepted_scopes=tenant.accepted_delegated_scopes,
                )
            grant_type = "delegated"
        else:
            if claims.get("idtyp") != "app":
                raise _token_error(
                    "claims_invalid",
                    "app-only tokens must carry the idtyp=app claim",
                )
            permissions = _permissions(claims.get("roles"), claim="roles")
            if not tenant.accepted_application_roles or not set(permissions).intersection(
                tenant.accepted_application_roles
            ):
                raise EntraAccessDeniedError(
                    "insufficient_scope",
                    "the app-only token lacks an accepted API role",
                )
            grant_type = "application"

        return EntraVerifiedPrincipal(
            identity=AuthenticatedTeamIdentity(
                tenant_id=tenant.team_tenant_id,
                identity_provider=f"entra:{tenant.entra_tenant_id}",
                subject_id=object_id,
            ),
            entra_tenant_id=tenant.entra_tenant_id,
            object_id=object_id,
            client_id=client_id,
            grant_type=grant_type,
            permissions=permissions,
            issued_at=issued_at,
            expires_at=expires_at,
        )

    def verify(self, token: str) -> EntraVerifiedPrincipal:
        """Verify signature, tenant, audience, actor, lifetime, and API grant."""

        self.check_ready()
        now = self._now()
        header, claims = _compact_jwt(token)
        tenant = self._tenant(claims)
        key = self._key(tenant, header)
        self._verify_signature(token, header, claims, tenant, key)
        return self._validate_claims(claims, tenant, now=now)


def _json_error(code: str, message: str) -> bytes:
    return (
        json.dumps(
            {"error": {"code": code, "message": message}},
            ensure_ascii=False,
            separators=(",", ":"),
        )
        + "\n"
    ).encode("utf-8")


def _challenge(
    *,
    error: str | None = None,
    scopes: Iterable[str] = (),
) -> str:
    parts = ['Bearer realm="causure-team"']
    if error is not None:
        parts.append(f'error="{error}"')
    scope_values = tuple(scopes)
    if scope_values:
        parts.append(f'scope="{" ".join(scope_values)}"')
    return ", ".join(parts)


class EntraTeamIdentityMiddleware:
    """Authenticate Entra bearer tokens and inject only a typed Team identity."""

    def __init__(
        self,
        application: Callable[[Mapping[str, Any], _StartResponse], list[bytes]],
        verifier: EntraTokenVerifier,
        *,
        require_https: bool = True,
    ) -> None:
        if not callable(application):
            raise TypeError("application must be callable")
        if not isinstance(verifier, EntraTokenVerifier):
            raise TypeError("verifier must be an EntraTokenVerifier")
        if type(require_https) is not bool:
            raise TypeError("require_https must be a bool")
        self._application = application
        self._verifier = verifier
        self._require_https = require_https

    @staticmethod
    def _status_reason(status: int) -> str:
        return {
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            503: "Service Unavailable",
        }[status]

    @classmethod
    def _error(
        cls,
        start_response: _StartResponse,
        status: int,
        code: str,
        message: str,
        *,
        scheme: str,
        challenge: str | None = None,
        retry_after: str | None = None,
    ) -> list[bytes]:
        body = _json_error(code, message)
        headers = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
        ]
        if scheme == "https":
            headers.append(("Strict-Transport-Security", "max-age=31536000"))
        if challenge is not None:
            headers.append(("WWW-Authenticate", challenge))
        if retry_after is not None:
            headers.append(("Retry-After", retry_after))
        start_response(f"{status} {cls._status_reason(status)}", headers)
        return [body]

    @staticmethod
    def _with_hsts(
        start_response: _StartResponse,
        *,
        enabled: bool,
    ) -> _StartResponse:
        if not enabled:
            return start_response

        def wrapped(
            status: str,
            headers: list[tuple[str, str]],
            exc_info: Any = None,
        ) -> Any:
            if not any(name.lower() == "strict-transport-security" for name, _ in headers):
                headers = [*headers, ("Strict-Transport-Security", "max-age=31536000")]
            if exc_info is None:
                return start_response(status, headers)
            return start_response(status, headers, exc_info)

        return wrapped

    @staticmethod
    def _bearer(environ: Mapping[str, Any]) -> str | None:
        raw = environ.get("HTTP_AUTHORIZATION")
        if raw is None:
            return None
        if not isinstance(raw, str) or len(raw.encode("utf-8")) > MAX_ENTRA_AUTHORIZATION_BYTES:
            raise _token_error("authorization_malformed", "Authorization header is invalid")
        parts = raw.split(" ")
        if (
            len(parts) != 2
            or parts[0].casefold() != "bearer"
            or not parts[1]
            or any(character.isspace() for character in parts[1])
        ):
            raise _token_error("authorization_malformed", "Authorization header is invalid")
        return parts[1]

    def __call__(
        self,
        environ: Mapping[str, Any],
        start_response: _StartResponse,
    ) -> list[bytes]:
        trusted_environ = dict(environ)
        trusted_environ.pop(TEAM_IDENTITY_ENVIRON_KEY, None)
        trusted_environ.pop(TEAM_REQUEST_INTEGRITY_ENVIRON_KEY, None)
        path = str(trusted_environ.get("PATH_INFO", "") or "/")
        scheme = str(trusted_environ.get("wsgi.url_scheme", "")).lower()
        secure_start = self._with_hsts(start_response, enabled=scheme == "https")

        if path in _PUBLIC_PATHS:
            trusted_environ.pop("HTTP_AUTHORIZATION", None)
            if path == "/readyz":
                try:
                    self._verifier.check_ready()
                except EntraTrustUnavailableError:
                    return self._error(
                        start_response,
                        503,
                        "identity_provider_unavailable",
                        "the identity trust snapshot is unavailable",
                        scheme=scheme,
                        retry_after="60",
                    )
            return self._application(trusted_environ, secure_start)

        if self._require_https and scheme != "https":
            return self._error(
                start_response,
                400,
                "https_required",
                "protected Team endpoints require HTTPS",
                scheme=scheme,
            )
        try:
            token = self._bearer(trusted_environ)
            if token is None:
                return self._error(
                    start_response,
                    401,
                    "authentication_required",
                    "a bearer access token is required",
                    scheme=scheme,
                    challenge=_challenge(),
                )
            principal = self._verifier.verify(token)
        except EntraAccessDeniedError as exc:
            return self._error(
                start_response,
                403,
                "insufficient_scope",
                "the access token does not grant this API",
                scheme=scheme,
                challenge=_challenge(
                    error="insufficient_scope",
                    scopes=exc.accepted_scopes,
                ),
            )
        except EntraAccessTokenError:
            return self._error(
                start_response,
                401,
                "invalid_token",
                "the bearer access token is invalid",
                scheme=scheme,
                challenge=_challenge(error="invalid_token"),
            )
        except (EntraTrustUnavailableError, EntraDependencyError):
            return self._error(
                start_response,
                503,
                "identity_provider_unavailable",
                "the identity trust snapshot is unavailable",
                scheme=scheme,
                retry_after="60",
            )

        trusted_environ.pop("HTTP_AUTHORIZATION", None)
        trusted_environ[TEAM_IDENTITY_ENVIRON_KEY] = principal.identity
        trusted_environ[TEAM_REQUEST_INTEGRITY_ENVIRON_KEY] = True
        return self._application(trusted_environ, secure_start)
