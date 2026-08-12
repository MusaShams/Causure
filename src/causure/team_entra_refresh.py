"""Bounded Microsoft Entra discovery/JWKS refresh and atomic trust reload."""

from __future__ import annotations

import errno
import hashlib
import math
import os
import re
import ssl
import stat
import threading
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO
from urllib.error import HTTPError, URLError
from urllib.parse import SplitResult, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from causure.attestations import utc_timestamp
from causure.constants import (
    ENTRA_REFRESH_CONFIG_SCHEMA_VERSION,
    ENTRA_TRUST_STORE_SCHEMA_VERSION,
    PACKAGE_VERSION,
)
from causure.io import InputDocumentError, atomic_write_text, parse_json_text
from causure.team_entra import (
    ENTRA_CLOCK_SKEW_SECONDS,
    MAX_ENTRA_TRUST_STORE_BYTES,
    EntraAccessTokenError,
    EntraAccessTokenVerifier,
    EntraTokenVerifier,
    EntraTrustStore,
    EntraTrustStoreError,
    EntraTrustUnavailableError,
    EntraVerifiedPrincipal,
    parse_entra_trust_store,
    parse_entra_trust_store_bytes,
    render_entra_trust_store,
)

MAX_ENTRA_REFRESH_CONFIG_BYTES = 512 * 1024
MAX_ENTRA_DISCOVERY_BYTES = 256 * 1024
MAX_ENTRA_JWKS_BYTES = 1024 * 1024
MAX_ENTRA_REMOTE_JWKS_KEYS = 1000
DEFAULT_ENTRA_REFRESH_TIMEOUT_SECONDS = 10.0
DEFAULT_ENTRA_MANAGED_REFRESH_INTERVAL_SECONDS = 3600.0
DEFAULT_ENTRA_REFRESH_FAILURE_RETRY_SECONDS = 300.0
DEFAULT_ENTRA_UNKNOWN_KEY_REFRESH_SECONDS = 300.0
DEFAULT_ENTRA_COORDINATION_POLL_SECONDS = 1.0
DEFAULT_ENTRA_COORDINATED_STARTUP_WAIT_SECONDS = 30.0
MIN_ENTRA_MANAGED_REFRESH_INTERVAL_SECONDS = 60.0
MIN_ENTRA_REFRESH_FAILURE_RETRY_SECONDS = 30.0
MIN_ENTRA_UNKNOWN_KEY_REFRESH_SECONDS = 300.0
MIN_ENTRA_COORDINATION_POLL_SECONDS = 0.1

_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$")
_STORE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{2,127}$")
_PERMISSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$")
_KID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{1,256}$")
_BASE64URL_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")
_UTC_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_PRIVATE_JWK_MEMBERS = frozenset({"d", "p", "q", "dp", "dq", "qi", "oth", "k"})
_Clock = Callable[[], str]


class EntraRefreshConfigurationError(ValueError):
    """Raised when a protected Entra refresh configuration is invalid."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"Invalid Entra refresh configuration at {path}: {message}")


class EntraRefreshError(ValueError):
    """Raised with a stable code when discovery/JWKS refresh fails closed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Entra trust refresh failed [{code}]: {message}")


class EntraSnapshotInstallError(ValueError):
    """Raised when an atomic snapshot install would violate local continuity."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Entra snapshot install failed [{code}]: {message}")


class EntraRefreshCoordinationError(ValueError):
    """Raised with a stable code when local refresh coordination fails closed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Entra refresh coordination failed [{code}]: {message}")


@dataclass(frozen=True, slots=True)
class EntraRefreshTenant:
    entra_tenant_id: str
    team_tenant_id: str
    issuer: str
    jwks_uri: str
    audience: str
    allowed_client_ids: tuple[str, ...]
    accepted_delegated_scopes: tuple[str, ...]
    accepted_application_roles: tuple[str, ...]
    max_token_lifetime_seconds: int

    @property
    def discovery_url(self) -> str:
        return f"{self.issuer}/.well-known/openid-configuration"


@dataclass(frozen=True, slots=True)
class EntraRefreshConfiguration:
    schema_version: str
    store_id: str
    snapshot_ttl_seconds: int
    tenants: tuple[EntraRefreshTenant, ...]


@dataclass(frozen=True, slots=True)
class EntraManagedRefreshStatus:
    running: bool
    refresh_in_progress: bool
    completed_attempt_count: int
    last_reason: str | None
    last_error_code: str | None
    last_successful_refresh_at: str | None


@dataclass(frozen=True, slots=True)
class EntraCoordinatedRefreshStatus:
    running: bool
    is_refresh_owner: bool
    ownership_acquisition_count: int
    refresh_request_pending: bool
    last_error_code: str | None
    managed_refresh: EntraManagedRefreshStatus | None


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(
        self,
        req: Any,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def _closed_object(
    value: Any,
    *,
    path: str,
    required: set[str],
) -> Mapping[str, Any]:
    if type(value) is not dict:
        raise EntraRefreshConfigurationError(path, "must be an object")
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required)
    if missing:
        raise EntraRefreshConfigurationError(
            path,
            f"missing required properties: {', '.join(missing)}",
        )
    if unknown:
        raise EntraRefreshConfigurationError(
            path,
            f"unknown properties: {', '.join(unknown)}",
        )
    return value


def _text(
    value: Any,
    *,
    path: str,
    pattern: re.Pattern[str] | None = None,
    maximum: int = 256,
) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise EntraRefreshConfigurationError(
            path,
            f"must be a non-empty string of at most {maximum} characters",
        )
    if pattern is not None and pattern.fullmatch(value) is None:
        raise EntraRefreshConfigurationError(path, "has an invalid format")
    return value


def _canonical_uuid(value: Any, *, path: str) -> str:
    text = _text(value, path=path, maximum=36)
    try:
        parsed = uuid.UUID(text)
    except (AttributeError, ValueError) as exc:
        raise EntraRefreshConfigurationError(path, "must be a canonical UUID") from exc
    if str(parsed) != text:
        raise EntraRefreshConfigurationError(path, "must be a lowercase canonical UUID")
    return text


def _string_set(
    value: Any,
    *,
    path: str,
    item_parser: Callable[[Any], str],
    minimum: int,
    maximum: int,
) -> tuple[str, ...]:
    if type(value) is not list or not minimum <= len(value) <= maximum:
        raise EntraRefreshConfigurationError(
            path,
            f"must be an array with between {minimum} and {maximum} items",
        )
    parsed = tuple(item_parser(item) for item in value)
    if len(set(parsed)) != len(parsed):
        raise EntraRefreshConfigurationError(path, "must not contain duplicate values")
    return parsed


def _https_endpoint(
    value: Any,
    *,
    path: str,
    query_allowed: bool,
    maximum: int = 512,
) -> tuple[str, SplitResult]:
    text = _text(value, path=path, maximum=maximum)
    try:
        text.encode("ascii")
        parsed = urlsplit(text)
        hostname = parsed.hostname
        port = parsed.port
    except (UnicodeEncodeError, ValueError) as exc:
        raise EntraRefreshConfigurationError(path, "must be a canonical HTTPS URL") from exc
    if (
        parsed.scheme != "https"
        or not hostname
        or hostname != hostname.lower()
        or parsed.netloc != hostname
        or hostname.endswith(".")
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
        or not parsed.path.startswith("/")
        or parsed.fragment
        or (parsed.query and not query_allowed)
        or "\\" in text
        or any(ord(character) < 0x20 for character in text)
    ):
        raise EntraRefreshConfigurationError(path, "must be a canonical HTTPS URL")
    return text, parsed


def _issuer(value: Any, *, path: str, tenant_id: str) -> tuple[str, SplitResult]:
    text, parsed = _https_endpoint(
        value,
        path=path,
        query_allowed=False,
        maximum=256,
    )
    if parsed.path != f"/{tenant_id}/v2.0":
        raise EntraRefreshConfigurationError(
            path,
            "must be an exact tenant-specific v2.0 issuer",
        )
    return text, parsed


def _same_origin(left: SplitResult, right: SplitResult) -> bool:
    return (
        left.scheme == right.scheme and left.hostname == right.hostname and left.port == right.port
    )


def _parse_refresh_tenant(value: Any, *, path: str) -> EntraRefreshTenant:
    document = _closed_object(
        value,
        path=path,
        required={
            "entra_tenant_id",
            "team_tenant_id",
            "issuer",
            "jwks_uri",
            "audience",
            "allowed_client_ids",
            "accepted_delegated_scopes",
            "accepted_application_roles",
            "max_token_lifetime_seconds",
        },
    )
    tenant_id = _canonical_uuid(
        document["entra_tenant_id"],
        path=f"{path}.entra_tenant_id",
    )
    team_tenant_id = _text(
        document["team_tenant_id"],
        path=f"{path}.team_tenant_id",
        pattern=_SAFE_ID_PATTERN,
        maximum=128,
    )
    issuer, issuer_url = _issuer(
        document["issuer"],
        path=f"{path}.issuer",
        tenant_id=tenant_id,
    )
    jwks_uri, jwks_url = _https_endpoint(
        document["jwks_uri"],
        path=f"{path}.jwks_uri",
        query_allowed=True,
    )
    if not _same_origin(issuer_url, jwks_url):
        raise EntraRefreshConfigurationError(
            f"{path}.jwks_uri",
            "must use the same trusted origin as the issuer",
        )
    audience = _canonical_uuid(document["audience"], path=f"{path}.audience")
    clients = _string_set(
        document["allowed_client_ids"],
        path=f"{path}.allowed_client_ids",
        item_parser=lambda item: _canonical_uuid(
            item,
            path=f"{path}.allowed_client_ids[]",
        ),
        minimum=1,
        maximum=100,
    )
    delegated = _string_set(
        document["accepted_delegated_scopes"],
        path=f"{path}.accepted_delegated_scopes",
        item_parser=lambda item: _text(
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
        item_parser=lambda item: _text(
            item,
            path=f"{path}.accepted_application_roles[]",
            pattern=_PERMISSION_PATTERN,
            maximum=128,
        ),
        minimum=0,
        maximum=100,
    )
    if not delegated and not application:
        raise EntraRefreshConfigurationError(
            path,
            "must accept at least one delegated scope or application role",
        )
    lifetime = document["max_token_lifetime_seconds"]
    if type(lifetime) is not int or not 300 <= lifetime <= 86400:
        raise EntraRefreshConfigurationError(
            f"{path}.max_token_lifetime_seconds",
            "must be an integer from 300 through 86400",
        )
    return EntraRefreshTenant(
        entra_tenant_id=tenant_id,
        team_tenant_id=team_tenant_id,
        issuer=issuer,
        jwks_uri=jwks_uri,
        audience=audience,
        allowed_client_ids=clients,
        accepted_delegated_scopes=delegated,
        accepted_application_roles=application,
        max_token_lifetime_seconds=lifetime,
    )


def parse_entra_refresh_configuration(document: Any) -> EntraRefreshConfiguration:
    """Parse the closed protected inputs allowed to select discovery/JWKS URLs."""

    value = _closed_object(
        document,
        path="$",
        required={"schema_version", "store_id", "snapshot_ttl_seconds", "tenants"},
    )
    if value["schema_version"] != ENTRA_REFRESH_CONFIG_SCHEMA_VERSION:
        raise EntraRefreshConfigurationError(
            "$.schema_version",
            f"must be {ENTRA_REFRESH_CONFIG_SCHEMA_VERSION!r}",
        )
    store_id = _text(
        value["store_id"],
        path="$.store_id",
        pattern=_STORE_ID_PATTERN,
        maximum=128,
    )
    ttl = value["snapshot_ttl_seconds"]
    if type(ttl) is not int or not 3600 <= ttl <= 86400:
        raise EntraRefreshConfigurationError(
            "$.snapshot_ttl_seconds",
            "must be an integer from 3600 through 86400",
        )
    tenants_value = value["tenants"]
    if type(tenants_value) is not list or not 1 <= len(tenants_value) <= 100:
        raise EntraRefreshConfigurationError("$.tenants", "must contain 1 through 100 tenants")
    tenants = tuple(
        _parse_refresh_tenant(item, path=f"$.tenants[{index}]")
        for index, item in enumerate(tenants_value)
    )
    if len({tenant.entra_tenant_id for tenant in tenants}) != len(tenants):
        raise EntraRefreshConfigurationError(
            "$.tenants",
            "must not contain duplicate Entra tenant IDs",
        )
    return EntraRefreshConfiguration(
        schema_version=ENTRA_REFRESH_CONFIG_SCHEMA_VERSION,
        store_id=store_id,
        snapshot_ttl_seconds=ttl,
        tenants=tenants,
    )


def parse_entra_refresh_configuration_bytes(data: bytes) -> EntraRefreshConfiguration:
    """Decode bounded strict UTF-8 JSON refresh configuration."""

    if not isinstance(data, bytes):
        raise EntraRefreshConfigurationError("$", "refresh configuration must be bytes")
    if len(data) > MAX_ENTRA_REFRESH_CONFIG_BYTES:
        raise EntraRefreshConfigurationError(
            "$",
            f"refresh configuration exceeds {MAX_ENTRA_REFRESH_CONFIG_BYTES} bytes",
        )
    try:
        document = parse_json_text(
            data.decode("utf-8"),
            source="Entra refresh configuration",
            max_bytes=MAX_ENTRA_REFRESH_CONFIG_BYTES,
        )
    except (InputDocumentError, UnicodeDecodeError) as exc:
        raise EntraRefreshConfigurationError("$", f"must be strict UTF-8 JSON: {exc}") from exc
    return parse_entra_refresh_configuration(document)


def load_entra_refresh_configuration(path: str | Path) -> EntraRefreshConfiguration:
    """Read one protected refresh configuration with the runtime byte bound."""

    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_ENTRA_REFRESH_CONFIG_BYTES + 1)
    except OSError as exc:
        raise EntraRefreshConfigurationError(
            "$",
            "refresh configuration could not be read",
        ) from exc
    return parse_entra_refresh_configuration_bytes(data)


def _header_values(headers: Any, name: str) -> list[str]:
    if hasattr(headers, "get_all"):
        values = headers.get_all(name, [])
        return [str(value) for value in values]
    value = headers.get(name) if hasattr(headers, "get") else None
    return [] if value is None else [str(value)]


class EntraHTTPSJSONClient:
    """Direct HTTPS JSON client with certificate checks, no proxy, and no redirects."""

    def __init__(
        self,
        *,
        opener: Any | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if opener is not None and not hasattr(opener, "open"):
            raise TypeError("opener must provide open()")
        if ssl_context is not None and not isinstance(ssl_context, ssl.SSLContext):
            raise TypeError("ssl_context must be an SSLContext")
        if opener is not None and ssl_context is not None:
            raise ValueError("ssl_context cannot be combined with a custom opener")
        if opener is None:
            context = ssl_context or ssl.create_default_context()
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError("ssl_context must require certificate and hostname verification")
            opener = build_opener(
                ProxyHandler({}),
                _NoRedirectHandler(),
                HTTPSHandler(context=context),
            )
        self._opener = opener

    def fetch(
        self,
        url: str,
        *,
        maximum_bytes: int,
        timeout_seconds: float,
        media_types: frozenset[str],
    ) -> bytes:
        try:
            checked_url, _ = _https_endpoint(url, path="$url", query_allowed=True)
        except EntraRefreshConfigurationError as exc:
            raise EntraRefreshError("url_invalid", "configured refresh URL is invalid") from exc
        if (
            type(maximum_bytes) is not int
            or maximum_bytes < 1
            or isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 1.0 <= float(timeout_seconds) <= 30.0
        ):
            raise ValueError("fetch bounds are invalid")
        request = Request(
            checked_url,
            headers={
                "Accept": ", ".join(sorted(media_types)),
                "User-Agent": f"causure/{PACKAGE_VERSION}",
            },
            method="GET",
        )
        response: Any | None = None
        try:
            response = self._opener.open(request, timeout=float(timeout_seconds))
            status = getattr(response, "status", None)
            final_url = response.geturl()
            headers = response.headers
            if status != 200:
                raise EntraRefreshError(
                    "http_status_invalid",
                    "metadata endpoint did not return 200",
                )
            if final_url != checked_url:
                raise EntraRefreshError("redirect_rejected", "metadata endpoint redirected")
            content_types = _header_values(headers, "Content-Type")
            if len(content_types) != 1:
                raise EntraRefreshError(
                    "content_type_invalid",
                    "metadata response must have one JSON content type",
                )
            media_type = content_types[0].split(";", maxsplit=1)[0].strip().lower()
            if media_type not in media_types:
                raise EntraRefreshError(
                    "content_type_invalid",
                    "metadata response content type is not accepted",
                )
            encodings = _header_values(headers, "Content-Encoding")
            if encodings and (
                len(encodings) != 1 or encodings[0].strip().lower() not in {"", "identity"}
            ):
                raise EntraRefreshError(
                    "content_encoding_invalid",
                    "compressed metadata responses are not accepted",
                )
            lengths = _header_values(headers, "Content-Length")
            if lengths:
                if (
                    len(lengths) != 1
                    or not lengths[0].isdigit()
                    or not 1 <= int(lengths[0], 10) <= maximum_bytes
                ):
                    raise EntraRefreshError(
                        "content_length_invalid",
                        "metadata response length is invalid",
                    )
            body = response.read(maximum_bytes + 1)
            if not isinstance(body, bytes) or not 1 <= len(body) <= maximum_bytes:
                raise EntraRefreshError(
                    "response_size_invalid",
                    "metadata response is empty or exceeds its size limit",
                )
            if lengths and len(body) != int(lengths[0], 10):
                raise EntraRefreshError(
                    "content_length_mismatch",
                    "metadata response length changed during transfer",
                )
            return body
        except EntraRefreshError:
            raise
        except HTTPError as exc:
            try:
                code = getattr(exc, "code", 0)
                if 300 <= code < 400:
                    raise EntraRefreshError(
                        "redirect_rejected",
                        "metadata endpoint redirected",
                    ) from exc
                raise EntraRefreshError(
                    "fetch_failed",
                    "metadata endpoint could not be fetched securely",
                ) from exc
            finally:
                exc.close()
        except (TimeoutError, URLError, OSError) as exc:
            raise EntraRefreshError(
                "fetch_failed",
                "metadata endpoint could not be fetched securely",
            ) from exc
        finally:
            if response is not None:
                response.close()


def _remote_object(data: bytes, *, name: str, maximum_bytes: int) -> Mapping[str, Any]:
    try:
        value = parse_json_text(
            data.decode("utf-8"),
            source=name,
            max_bytes=maximum_bytes,
        )
    except (InputDocumentError, UnicodeDecodeError) as exc:
        raise EntraRefreshError("remote_json_invalid", f"{name} is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise EntraRefreshError("remote_json_invalid", f"{name} must be a JSON object")
    return value


def _validate_discovery(
    data: bytes,
    *,
    tenant: EntraRefreshTenant,
) -> None:
    metadata = _remote_object(
        data,
        name="Entra discovery metadata",
        maximum_bytes=MAX_ENTRA_DISCOVERY_BYTES,
    )
    if metadata.get("issuer") != tenant.issuer:
        raise EntraRefreshError(
            "discovery_issuer_mismatch",
            "discovery issuer does not match protected configuration",
        )
    if metadata.get("jwks_uri") != tenant.jwks_uri:
        raise EntraRefreshError(
            "discovery_jwks_mismatch",
            "discovery JWKS URI does not match protected configuration",
        )
    algorithms = metadata.get("id_token_signing_alg_values_supported")
    if algorithms is not None and (
        type(algorithms) is not list
        or any(not isinstance(item, str) for item in algorithms)
        or "RS256" not in algorithms
    ):
        raise EntraRefreshError(
            "discovery_algorithm_invalid",
            "discovery metadata does not advertise RS256",
        )


def _signing_key_issuer_matches(value: Any, *, tenant: EntraRefreshTenant) -> bool:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise EntraRefreshError(
            "jwk_issuer_invalid",
            "eligible RSA signing JWK issuer must be bounded text",
        )
    scoped = re.sub(
        r"\{tenantid\}",
        tenant.entra_tenant_id,
        value,
        flags=re.IGNORECASE,
    )
    return scoped == tenant.issuer


def _reduce_jwks(
    data: bytes,
    *,
    tenant: EntraRefreshTenant,
) -> list[dict[str, str]]:
    document = _remote_object(
        data,
        name="Entra JWKS",
        maximum_bytes=MAX_ENTRA_JWKS_BYTES,
    )
    keys = document.get("keys")
    if type(keys) is not list or not 1 <= len(keys) <= MAX_ENTRA_REMOTE_JWKS_KEYS:
        raise EntraRefreshError(
            "jwks_keys_invalid",
            f"JWKS must contain 1 through {MAX_ENTRA_REMOTE_JWKS_KEYS} keys",
        )
    reduced: list[dict[str, str]] = []
    for key in keys:
        if type(key) is not dict:
            raise EntraRefreshError("jwk_invalid", "every JWKS key must be an object")
        if _PRIVATE_JWK_MEMBERS.intersection(key):
            raise EntraRefreshError("jwk_private_material", "JWKS contains private key material")
        if key.get("kty") != "RSA":
            continue
        use = key.get("use")
        algorithm = key.get("alg")
        if use is not None and not isinstance(use, str):
            raise EntraRefreshError("jwk_invalid", "RSA JWK use must be text")
        if algorithm is not None and not isinstance(algorithm, str):
            raise EntraRefreshError("jwk_invalid", "RSA JWK alg must be text")
        if use not in {None, "sig"} or algorithm not in {None, "RS256"}:
            continue
        operations = key.get("key_ops")
        if operations is not None:
            if (
                type(operations) is not list
                or not operations
                or any(not isinstance(item, str) for item in operations)
                or len(set(operations)) != len(operations)
            ):
                raise EntraRefreshError("jwk_invalid", "RSA JWK key_ops is invalid")
            if set(operations) != {"verify"}:
                continue
        if not _signing_key_issuer_matches(key.get("issuer"), tenant=tenant):
            continue
        kid = key.get("kid")
        modulus = key.get("n")
        exponent = key.get("e")
        if (
            not isinstance(kid, str)
            or _KID_PATTERN.fullmatch(kid) is None
            or not isinstance(modulus, str)
            or _BASE64URL_PATTERN.fullmatch(modulus) is None
            or not isinstance(exponent, str)
            or _BASE64URL_PATTERN.fullmatch(exponent) is None
        ):
            raise EntraRefreshError(
                "jwk_invalid",
                "eligible RSA signing JWK is missing canonical kid, n, or e",
            )
        reduced.append(
            {
                "kid": kid,
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": modulus,
                "e": exponent,
            }
        )
    if not 1 <= len(reduced) <= 100:
        raise EntraRefreshError(
            "jwks_signing_keys_invalid",
            "JWKS must contain 1 through 100 eligible RS256 signing keys",
        )
    if len({key["kid"] for key in reduced}) != len(reduced):
        raise EntraRefreshError(
            "jwks_kid_duplicate",
            "eligible RS256 signing keys must have distinct kid values",
        )
    return sorted(reduced, key=lambda key: key["kid"])


def _refresh_instant(clock: _Clock, ttl_seconds: int) -> tuple[str, str]:
    value = clock()
    if not isinstance(value, str):
        raise EntraRefreshError("clock_invalid", "refresh clock did not return UTC text")
    try:
        instant = datetime.strptime(value, _UTC_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except ValueError as exc:
        raise EntraRefreshError(
            "clock_invalid",
            "refresh clock did not return whole-second UTC text",
        ) from exc
    if instant.strftime(_UTC_TIMESTAMP_FORMAT) != value:
        raise EntraRefreshError(
            "clock_invalid",
            "refresh clock did not return whole-second UTC text",
        )
    expires = instant + timedelta(seconds=ttl_seconds)
    return value, expires.strftime(_UTC_TIMESTAMP_FORMAT)


def refresh_entra_trust_store(
    configuration: EntraRefreshConfiguration,
    *,
    client: EntraHTTPSJSONClient | None = None,
    clock: _Clock = utc_timestamp,
    timeout_seconds: float = DEFAULT_ENTRA_REFRESH_TIMEOUT_SECONDS,
) -> EntraTrustStore:
    """Fetch every configured tenant and return one all-or-nothing trust snapshot."""

    if type(configuration) is not EntraRefreshConfiguration:
        raise TypeError("configuration must be an EntraRefreshConfiguration")
    if not callable(clock):
        raise TypeError("clock must be callable")
    if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, (int, float)):
        raise TypeError("timeout_seconds must be numeric")
    if not 1.0 <= float(timeout_seconds) <= 30.0:
        raise ValueError("timeout_seconds must be from 1 through 30")
    selected_client = client or EntraHTTPSJSONClient()
    if not hasattr(selected_client, "fetch"):
        raise TypeError("client must provide fetch()")
    refreshed_at, expires_at = _refresh_instant(
        clock,
        configuration.snapshot_ttl_seconds,
    )
    tenant_documents: list[dict[str, Any]] = []
    for tenant in configuration.tenants:
        discovery_bytes = selected_client.fetch(
            tenant.discovery_url,
            maximum_bytes=MAX_ENTRA_DISCOVERY_BYTES,
            timeout_seconds=float(timeout_seconds),
            media_types=frozenset({"application/json"}),
        )
        _validate_discovery(discovery_bytes, tenant=tenant)
        jwks_bytes = selected_client.fetch(
            tenant.jwks_uri,
            maximum_bytes=MAX_ENTRA_JWKS_BYTES,
            timeout_seconds=float(timeout_seconds),
            media_types=frozenset({"application/json", "application/jwk-set+json"}),
        )
        tenant_documents.append(
            {
                "entra_tenant_id": tenant.entra_tenant_id,
                "team_tenant_id": tenant.team_tenant_id,
                "issuer": tenant.issuer,
                "audience": tenant.audience,
                "allowed_client_ids": list(tenant.allowed_client_ids),
                "accepted_delegated_scopes": list(tenant.accepted_delegated_scopes),
                "accepted_application_roles": list(tenant.accepted_application_roles),
                "max_token_lifetime_seconds": tenant.max_token_lifetime_seconds,
                "keys": _reduce_jwks(jwks_bytes, tenant=tenant),
            }
        )
    try:
        return parse_entra_trust_store(
            {
                "schema_version": ENTRA_TRUST_STORE_SCHEMA_VERSION,
                "store_id": configuration.store_id,
                "refreshed_at": refreshed_at,
                "expires_at": expires_at,
                "tenants": tenant_documents,
            }
        )
    except EntraTrustStoreError as exc:
        raise EntraRefreshError(
            "snapshot_invalid",
            "refreshed metadata could not form a valid trust snapshot",
        ) from exc


def _read_snapshot(path: Path) -> tuple[bytes, EntraTrustStore]:
    try:
        with path.open("rb") as stream:
            data = stream.read(MAX_ENTRA_TRUST_STORE_BYTES + 1)
    except OSError as exc:
        raise EntraSnapshotInstallError(
            "snapshot_unavailable",
            "existing trust snapshot could not be read",
        ) from exc
    if not 1 <= len(data) <= MAX_ENTRA_TRUST_STORE_BYTES:
        raise EntraSnapshotInstallError(
            "snapshot_invalid",
            "existing trust snapshot is empty or oversized",
        )
    try:
        return data, parse_entra_trust_store_bytes(data)
    except EntraTrustStoreError as exc:
        raise EntraSnapshotInstallError(
            "snapshot_invalid",
            "existing trust snapshot is invalid",
        ) from exc


def _timestamp_epoch(value: str) -> int:
    return int(datetime.strptime(value, _UTC_TIMESTAMP_FORMAT).replace(tzinfo=UTC).timestamp())


def install_entra_trust_store(
    path: str | Path,
    store: EntraTrustStore,
) -> Path:
    """Atomically install a newer same-store snapshot without overwriting on failure."""

    if type(store) is not EntraTrustStore:
        raise TypeError("store must be an EntraTrustStore")
    destination = Path(path)
    try:
        content = render_entra_trust_store(store)
        store = parse_entra_trust_store_bytes(content.encode("utf-8"))
        content = render_entra_trust_store(store)
    except (AttributeError, EntraTrustStoreError, OverflowError, TypeError, ValueError) as exc:
        raise EntraSnapshotInstallError(
            "snapshot_invalid",
            "new trust snapshot is invalid",
        ) from exc
    if destination.exists():
        current_bytes, current = _read_snapshot(destination)
        if current.store_id != store.store_id:
            raise EntraSnapshotInstallError(
                "store_id_mismatch",
                "new trust snapshot does not match the installed store ID",
            )
        if current_bytes == content.encode("utf-8"):
            return destination
        if _timestamp_epoch(store.refreshed_at) <= _timestamp_epoch(current.refreshed_at):
            raise EntraSnapshotInstallError(
                "snapshot_not_newer",
                "new trust snapshot does not advance refreshed_at",
            )
    try:
        atomic_write_text(destination, content)
    except OSError as exc:
        raise EntraSnapshotInstallError(
            "snapshot_write_failed",
            "trust snapshot could not be installed atomically",
        ) from exc
    return destination


def refresh_entra_trust_file(
    configuration: EntraRefreshConfiguration,
    path: str | Path,
    *,
    client: EntraHTTPSJSONClient | None = None,
    clock: _Clock = utc_timestamp,
    timeout_seconds: float = DEFAULT_ENTRA_REFRESH_TIMEOUT_SECONDS,
) -> EntraTrustStore:
    """Refresh all tenants, then atomically install only the complete valid snapshot."""

    store = refresh_entra_trust_store(
        configuration,
        client=client,
        clock=clock,
        timeout_seconds=timeout_seconds,
    )
    install_entra_trust_store(path, store)
    return store


class ReloadingEntraAccessTokenVerifier(EntraTokenVerifier):
    """Use atomically replaced trust files while retaining a still-fresh last known good."""

    def __init__(
        self,
        path: str | Path,
        *,
        clock: Callable[[], int] = lambda: int(time.time()),
        clock_skew_seconds: int = ENTRA_CLOCK_SKEW_SECONDS,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._path = Path(path)
        self._clock = clock
        self._clock_skew_seconds = clock_skew_seconds
        self._lock = threading.RLock()
        self._rejected_fingerprint: tuple[int, int, int, int] | None = None
        self._last_reload_error_code: str | None = None
        try:
            fingerprint = self._fingerprint()
            data, store = _read_snapshot(self._path)
            verifier = EntraAccessTokenVerifier(
                store,
                clock=clock,
                clock_skew_seconds=clock_skew_seconds,
            )
            verifier.check_ready()
        except (EntraSnapshotInstallError, EntraTrustUnavailableError, OSError) as exc:
            raise EntraTrustUnavailableError(
                "snapshot_unavailable",
                "initial Entra trust snapshot is unavailable",
            ) from exc
        self._fingerprint_value = fingerprint
        self._snapshot_sha256 = hashlib.sha256(data).hexdigest()
        self._store_id = store.store_id
        self._snapshot_refreshed_at = store.refreshed_at
        self._snapshot_expires_at = store.expires_at
        self._refreshed_epoch = _timestamp_epoch(store.refreshed_at)
        self._verifier = verifier

    @property
    def snapshot_sha256(self) -> str:
        with self._lock:
            return self._snapshot_sha256

    @property
    def last_reload_error_code(self) -> str | None:
        with self._lock:
            return self._last_reload_error_code

    @property
    def store_id(self) -> str:
        with self._lock:
            return self._store_id

    @property
    def snapshot_refreshed_at(self) -> str:
        with self._lock:
            return self._snapshot_refreshed_at

    @property
    def snapshot_expires_at(self) -> str:
        with self._lock:
            return self._snapshot_expires_at

    def _fingerprint(self) -> tuple[int, int, int, int]:
        status = self._path.stat()
        return (status.st_dev, status.st_ino, status.st_size, status.st_mtime_ns)

    def _maybe_reload(self) -> EntraAccessTokenVerifier:
        try:
            fingerprint = self._fingerprint()
        except OSError:
            with self._lock:
                self._last_reload_error_code = "snapshot_unavailable"
                return self._verifier
        with self._lock:
            if fingerprint == self._fingerprint_value:
                self._last_reload_error_code = None
                return self._verifier
            if fingerprint == self._rejected_fingerprint:
                return self._verifier
            try:
                data, store = _read_snapshot(self._path)
                digest = hashlib.sha256(data).hexdigest()
                if store.store_id != self._store_id:
                    raise EntraSnapshotInstallError(
                        "store_id_mismatch",
                        "reloaded snapshot store ID changed",
                    )
                if digest == self._snapshot_sha256:
                    self._fingerprint_value = fingerprint
                    self._rejected_fingerprint = None
                    self._last_reload_error_code = None
                    return self._verifier
                refreshed_epoch = _timestamp_epoch(store.refreshed_at)
                if refreshed_epoch <= self._refreshed_epoch:
                    raise EntraSnapshotInstallError(
                        "snapshot_not_newer",
                        "reloaded snapshot did not advance refreshed_at",
                    )
                candidate = EntraAccessTokenVerifier(
                    store,
                    clock=self._clock,
                    clock_skew_seconds=self._clock_skew_seconds,
                )
                candidate.check_ready()
            except (
                EntraSnapshotInstallError,
                EntraTrustStoreError,
                EntraTrustUnavailableError,
                OSError,
            ):
                self._rejected_fingerprint = fingerprint
                self._last_reload_error_code = "snapshot_reload_rejected"
                return self._verifier
            self._verifier = candidate
            self._fingerprint_value = fingerprint
            self._rejected_fingerprint = None
            self._last_reload_error_code = None
            self._snapshot_sha256 = digest
            self._snapshot_refreshed_at = store.refreshed_at
            self._snapshot_expires_at = store.expires_at
            self._refreshed_epoch = refreshed_epoch
            return self._verifier

    def check_ready(self) -> None:
        self._maybe_reload().check_ready()

    def verify(self, token: str) -> EntraVerifiedPrincipal:
        return self._maybe_reload().verify(token)


_ENTRA_OWNER_LOCK_CONTENT = b"causure-entra-refresh-owner-v1\n"
_ENTRA_REFRESH_REQUEST_CONTENT = b"causure-entra-refresh-request-v1\n"
_MAX_ENTRA_COORDINATION_FILE_BYTES = 128


def _coordination_path(value: str | Path) -> Path:
    return Path(os.path.abspath(os.fspath(value)))


def _coordination_path_key(value: Path) -> str:
    return os.path.normcase(os.fspath(value))


def _file_identity(value: os.stat_result) -> tuple[int, int]:
    return (value.st_dev, value.st_ino)


def _try_platform_file_lock(handle: BinaryIO) -> bool:
    handle.seek(0)
    try:
        if os.name == "nt":
            import msvcrt

            msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as exc:
        contention = exc.errno in {errno.EACCES, errno.EAGAIN}
        if os.name == "nt":
            contention = contention or getattr(exc, "winerror", None) in {33, 36}
        if contention:
            return False
        raise EntraRefreshCoordinationError(
            "coordination_lock_failed",
            "refresh ownership lock could not be acquired",
        ) from exc
    return True


def _unlock_platform_file(handle: BinaryIO) -> None:
    handle.seek(0)
    if os.name == "nt":
        import msvcrt

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


class LocalFileEntraRefreshCoordinator:
    """Coordinate one local-volume refresh owner and one coalesced refresh request."""

    def __init__(
        self,
        owner_lock_path: str | Path,
        refresh_request_path: str | Path | None = None,
    ) -> None:
        self._owner_lock_path = _coordination_path(owner_lock_path)
        self._refresh_request_path = _coordination_path(
            refresh_request_path
            if refresh_request_path is not None
            else f"{self._owner_lock_path}.request"
        )
        if _coordination_path_key(self._owner_lock_path) == _coordination_path_key(
            self._refresh_request_path
        ):
            raise ValueError("owner_lock_path and refresh_request_path must differ")
        self._lock = threading.RLock()
        self._handle: BinaryIO | None = None
        self._identity: tuple[int, int] | None = None
        self._process_id = os.getpid()
        self._closed = False

    @property
    def owner_lock_path(self) -> Path:
        return self._owner_lock_path

    @property
    def refresh_request_path(self) -> Path:
        return self._refresh_request_path

    def _check_open(self) -> None:
        if self._closed:
            raise RuntimeError("local Entra refresh coordinator is closed")
        if os.getpid() != self._process_id:
            raise EntraRefreshCoordinationError(
                "coordination_process_changed",
                "local Entra refresh coordination must be created after process fork",
            )

    def _open_owner_lock(self) -> tuple[BinaryIO, tuple[int, int]]:
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._owner_lock_path, flags, 0o600)
        except OSError as exc:
            raise EntraRefreshCoordinationError(
                "coordination_open_failed",
                "refresh ownership lock could not be opened",
            ) from exc
        handle: BinaryIO | None = None
        try:
            handle = os.fdopen(descriptor, "r+b", buffering=0)
            opened_status = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened_status.st_mode):
                raise EntraRefreshCoordinationError(
                    "coordination_path_invalid",
                    "refresh ownership lock must be a regular file",
                )
            if opened_status.st_size > _MAX_ENTRA_COORDINATION_FILE_BYTES:
                raise EntraRefreshCoordinationError(
                    "coordination_path_invalid",
                    "refresh ownership lock is unexpectedly large",
                )
            if opened_status.st_size == 0:
                handle.write(_ENTRA_OWNER_LOCK_CONTENT)
                handle.flush()
                os.fsync(handle.fileno())
                opened_status = os.fstat(handle.fileno())
            path_status = os.lstat(self._owner_lock_path)
            if not stat.S_ISREG(path_status.st_mode) or _file_identity(
                path_status
            ) != _file_identity(opened_status):
                raise EntraRefreshCoordinationError(
                    "coordination_path_invalid",
                    "refresh ownership lock was replaced while it was opened",
                )
            return handle, _file_identity(opened_status)
        except Exception:
            if handle is not None:
                handle.close()
            else:
                os.close(descriptor)
            raise

    def try_acquire(self) -> bool:
        """Try to become the sole refresh owner without blocking."""

        with self._lock:
            self._check_open()
            if self._handle is not None:
                return self.ownership_valid
            handle, identity = self._open_owner_lock()
            try:
                acquired = _try_platform_file_lock(handle)
            except Exception:
                handle.close()
                raise
            if not acquired:
                handle.close()
                return False
            try:
                path_status = os.lstat(self._owner_lock_path)
            except OSError as exc:
                try:
                    _unlock_platform_file(handle)
                finally:
                    handle.close()
                raise EntraRefreshCoordinationError(
                    "coordination_lock_replaced",
                    "refresh ownership lock disappeared during acquisition",
                ) from exc
            if not stat.S_ISREG(path_status.st_mode) or _file_identity(path_status) != identity:
                try:
                    _unlock_platform_file(handle)
                finally:
                    handle.close()
                raise EntraRefreshCoordinationError(
                    "coordination_lock_replaced",
                    "refresh ownership lock was replaced during acquisition",
                )
            self._handle = handle
            self._identity = identity
            return True

    @property
    def is_owner(self) -> bool:
        with self._lock:
            return os.getpid() == self._process_id and self._handle is not None

    @property
    def ownership_valid(self) -> bool:
        with self._lock:
            if os.getpid() != self._process_id:
                return False
            handle = self._handle
            identity = self._identity
            if handle is None or identity is None:
                return False
            try:
                opened_status = os.fstat(handle.fileno())
                path_status = os.lstat(self._owner_lock_path)
            except OSError:
                return False
            return (
                stat.S_ISREG(opened_status.st_mode)
                and stat.S_ISREG(path_status.st_mode)
                and _file_identity(opened_status) == identity
                and _file_identity(path_status) == identity
            )

    def signal_refresh(self) -> bool:
        """Create one bounded request marker; concurrent signals coalesce."""

        with self._lock:
            self._check_open()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self._refresh_request_path, flags, 0o600)
        except FileExistsError:
            return False
        except OSError as exc:
            raise EntraRefreshCoordinationError(
                "coordination_signal_failed",
                "refresh request marker could not be created",
            ) from exc
        installed = False
        try:
            with os.fdopen(descriptor, "wb", buffering=0) as handle:
                handle.write(_ENTRA_REFRESH_REQUEST_CONTENT)
                handle.flush()
                os.fsync(handle.fileno())
            installed = True
        except OSError as exc:
            raise EntraRefreshCoordinationError(
                "coordination_signal_failed",
                "refresh request marker could not be written",
            ) from exc
        finally:
            if not installed:
                try:
                    os.unlink(self._refresh_request_path)
                except OSError:
                    pass
        return True

    @property
    def refresh_requested(self) -> bool:
        with self._lock:
            self._check_open()
        try:
            status = os.lstat(self._refresh_request_path)
        except FileNotFoundError:
            return False
        except OSError as exc:
            raise EntraRefreshCoordinationError(
                "coordination_request_unavailable",
                "refresh request marker could not be inspected",
            ) from exc
        if not stat.S_ISREG(status.st_mode) or status.st_size > _MAX_ENTRA_COORDINATION_FILE_BYTES:
            raise EntraRefreshCoordinationError(
                "coordination_request_invalid",
                "refresh request marker must be a bounded regular file",
            )
        return True

    def consume_refresh_request(self) -> bool:
        """Remove a pending request only while this coordinator is the valid owner."""

        with self._lock:
            self._check_open()
            if not self.ownership_valid:
                raise EntraRefreshCoordinationError(
                    "refresh_owner_required",
                    "only the valid refresh owner may consume a request",
                )
            if not self.refresh_requested:
                return False
            try:
                os.unlink(self._refresh_request_path)
            except FileNotFoundError:
                return False
            except OSError as exc:
                raise EntraRefreshCoordinationError(
                    "coordination_request_unavailable",
                    "refresh request marker could not be consumed",
                ) from exc
            return True

    def release(self) -> None:
        """Release ownership while keeping the coordinator reusable."""

        with self._lock:
            handle = self._handle
            self._handle = None
            self._identity = None
            if handle is None:
                self._check_open()
                return
            if os.getpid() != self._process_id:
                handle.close()
                raise EntraRefreshCoordinationError(
                    "coordination_process_changed",
                    "inherited refresh ownership was closed without unlocking its parent",
                )
            unlock_error: OSError | None = None
            try:
                _unlock_platform_file(handle)
            except OSError as exc:
                unlock_error = exc
            finally:
                handle.close()
            if unlock_error is not None:
                raise EntraRefreshCoordinationError(
                    "coordination_unlock_failed",
                    "refresh ownership lock could not be released cleanly",
                ) from unlock_error

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            try:
                self.release()
            finally:
                self._closed = True

    def __enter__(self) -> LocalFileEntraRefreshCoordinator:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def _managed_seconds(
    value: Any,
    *,
    name: str,
    minimum: float,
    maximum: float,
) -> float:
    try:
        numeric = float(value)
    except (OverflowError, TypeError, ValueError):
        numeric = math.nan
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(numeric)
        or not minimum <= numeric <= maximum
    ):
        raise ValueError(f"{name} must be from {minimum:g} through {maximum:g} seconds")
    return numeric


class ManagedEntraAccessTokenVerifier(EntraTokenVerifier):
    """Own startup/periodic refresh and rate-limited asynchronous unknown-key recovery."""

    def __init__(
        self,
        configuration: EntraRefreshConfiguration,
        path: str | Path,
        *,
        client: EntraHTTPSJSONClient | None = None,
        snapshot_clock: _Clock = utc_timestamp,
        verifier_clock: Callable[[], int] = lambda: int(time.time()),
        monotonic_clock: Callable[[], float] = time.monotonic,
        refresh_guard: Callable[[], bool] | None = None,
        clock_skew_seconds: int = ENTRA_CLOCK_SKEW_SECONDS,
        timeout_seconds: float = DEFAULT_ENTRA_REFRESH_TIMEOUT_SECONDS,
        refresh_interval_seconds: float = DEFAULT_ENTRA_MANAGED_REFRESH_INTERVAL_SECONDS,
        failure_retry_seconds: float = DEFAULT_ENTRA_REFRESH_FAILURE_RETRY_SECONDS,
        unknown_key_refresh_seconds: float = DEFAULT_ENTRA_UNKNOWN_KEY_REFRESH_SECONDS,
    ) -> None:
        if type(configuration) is not EntraRefreshConfiguration:
            raise TypeError("configuration must be an EntraRefreshConfiguration")
        if client is not None and not hasattr(client, "fetch"):
            raise TypeError("client must provide fetch()")
        if not callable(snapshot_clock):
            raise TypeError("snapshot_clock must be callable")
        if not callable(verifier_clock):
            raise TypeError("verifier_clock must be callable")
        if not callable(monotonic_clock):
            raise TypeError("monotonic_clock must be callable")
        if refresh_guard is not None and not callable(refresh_guard):
            raise TypeError("refresh_guard must be callable")
        if type(clock_skew_seconds) is not int or not 0 <= clock_skew_seconds <= 300:
            raise ValueError("clock_skew_seconds must be an integer from 0 through 300")
        self._configuration = configuration
        self._path = Path(path)
        self._client = client
        self._snapshot_clock = snapshot_clock
        self._verifier_clock = verifier_clock
        self._monotonic_clock = monotonic_clock
        self._refresh_guard = refresh_guard
        self._clock_skew_seconds = clock_skew_seconds
        self._timeout_seconds = _managed_seconds(
            timeout_seconds,
            name="timeout_seconds",
            minimum=1.0,
            maximum=30.0,
        )
        self._refresh_interval_seconds = _managed_seconds(
            refresh_interval_seconds,
            name="refresh_interval_seconds",
            minimum=MIN_ENTRA_MANAGED_REFRESH_INTERVAL_SECONDS,
            maximum=86400.0,
        )
        self._failure_retry_seconds = _managed_seconds(
            failure_retry_seconds,
            name="failure_retry_seconds",
            minimum=MIN_ENTRA_REFRESH_FAILURE_RETRY_SECONDS,
            maximum=self._refresh_interval_seconds,
        )
        self._unknown_key_refresh_seconds = _managed_seconds(
            unknown_key_refresh_seconds,
            name="unknown_key_refresh_seconds",
            minimum=MIN_ENTRA_UNKNOWN_KEY_REFRESH_SECONDS,
            maximum=86400.0,
        )
        self._lifecycle_lock = threading.RLock()
        self._condition = threading.Condition(threading.RLock())
        self._reloader: ReloadingEntraAccessTokenVerifier | None = None
        self._thread: threading.Thread | None = None
        self._started = False
        self._closed = False
        self._stop_requested = False
        self._pending_unknown_key_refresh = False
        self._refresh_in_progress = False
        self._completed_attempt_count = 0
        self._last_attempt_monotonic: float | None = None
        self._next_periodic_monotonic: float | None = None
        self._last_reason: str | None = None
        self._last_error_code: str | None = None
        self._last_successful_refresh_at: str | None = None
        self._monotonic_now()

    def _monotonic_now(self) -> float:
        try:
            value = self._monotonic_clock()
            numeric = float(value)
        except (OverflowError, TypeError, ValueError) as exc:
            raise EntraTrustUnavailableError(
                "clock_invalid",
                "managed Entra monotonic clock is invalid",
            ) from exc
        if isinstance(value, bool) or not math.isfinite(numeric) or numeric < 0:
            raise EntraTrustUnavailableError(
                "clock_invalid",
                "managed Entra monotonic clock is invalid",
            )
        return numeric

    @property
    def status(self) -> EntraManagedRefreshStatus:
        with self._condition:
            thread = self._thread
            return EntraManagedRefreshStatus(
                running=(
                    self._started and not self._closed and thread is not None and thread.is_alive()
                ),
                refresh_in_progress=self._refresh_in_progress,
                completed_attempt_count=self._completed_attempt_count,
                last_reason=self._last_reason,
                last_error_code=self._last_error_code,
                last_successful_refresh_at=self._last_successful_refresh_at,
            )

    @staticmethod
    def _error_code(exc: Exception) -> str:
        if isinstance(
            exc,
            (
                EntraRefreshError,
                EntraSnapshotInstallError,
                EntraTrustUnavailableError,
            ),
        ):
            return exc.code
        return "refresh_failed"

    def _check_refresh_guard(self) -> None:
        guard = self._refresh_guard
        if guard is None:
            return
        try:
            permitted = guard()
        except Exception as exc:
            raise EntraTrustUnavailableError(
                "refresh_ownership_lost",
                "managed Entra refresh ownership could not be confirmed",
            ) from exc
        if permitted is not True:
            raise EntraTrustUnavailableError(
                "refresh_ownership_lost",
                "managed Entra refresh ownership could not be confirmed",
            )

    def _refresh_once(self, *, reason: str) -> bool:
        attempt_monotonic = self._monotonic_now()
        with self._condition:
            self._refresh_in_progress = True
            self._last_reason = reason
            self._last_attempt_monotonic = attempt_monotonic
            self._condition.notify_all()
        store: EntraTrustStore | None = None
        error_code: str | None = None
        try:
            self._check_refresh_guard()
            store = refresh_entra_trust_store(
                self._configuration,
                client=self._client,
                clock=self._snapshot_clock,
                timeout_seconds=self._timeout_seconds,
            )
            EntraAccessTokenVerifier(
                store,
                clock=self._verifier_clock,
                clock_skew_seconds=self._clock_skew_seconds,
            ).check_ready()
            self._check_refresh_guard()
            install_entra_trust_store(self._path, store)
            with self._condition:
                reloader = self._reloader
            if reloader is not None:
                reloader.check_ready()
                if reloader.snapshot_refreshed_at != store.refreshed_at:
                    raise EntraTrustUnavailableError(
                        "snapshot_reload_rejected",
                        "managed Entra verifier did not adopt the refreshed snapshot",
                    )
        except Exception as exc:
            error_code = self._error_code(exc)
            store = None
        with self._condition:
            self._completed_attempt_count += 1
            self._refresh_in_progress = False
            self._last_error_code = error_code
            if store is not None:
                self._last_successful_refresh_at = store.refreshed_at
            self._condition.notify_all()
        return store is not None

    def start(self) -> ManagedEntraAccessTokenVerifier:
        """Refresh synchronously, fall back to fresh same-store trust, then start one worker."""

        with self._lifecycle_lock:
            with self._condition:
                if self._closed:
                    raise RuntimeError("managed Entra verifier is closed")
                if self._started:
                    return self
            refreshed = self._refresh_once(reason="startup")
            try:
                reloader = ReloadingEntraAccessTokenVerifier(
                    self._path,
                    clock=self._verifier_clock,
                    clock_skew_seconds=self._clock_skew_seconds,
                )
                if reloader.store_id != self._configuration.store_id:
                    raise EntraTrustUnavailableError(
                        "store_id_mismatch",
                        "installed Entra trust does not match refresh configuration",
                    )
            except EntraTrustUnavailableError as exc:
                raise EntraTrustUnavailableError(
                    "managed_refresh_unavailable",
                    "managed Entra trust could not start with usable local trust",
                ) from exc
            delay = self._refresh_interval_seconds if refreshed else self._failure_retry_seconds
            next_periodic = self._monotonic_now() + delay
            with self._condition:
                self._reloader = reloader
                if self._last_successful_refresh_at is None:
                    self._last_successful_refresh_at = reloader.snapshot_refreshed_at
                self._stop_requested = False
                self._pending_unknown_key_refresh = False
                self._started = True
                self._next_periodic_monotonic = next_periodic
                thread = threading.Thread(
                    target=self._run,
                    name="causure-entra-refresh",
                    daemon=True,
                )
                self._thread = thread
            try:
                thread.start()
            except RuntimeError as exc:
                with self._condition:
                    self._started = False
                    self._thread = None
                    self._last_error_code = "refresh_worker_start_failed"
                raise EntraTrustUnavailableError(
                    "refresh_worker_start_failed",
                    "managed Entra refresh worker could not start",
                ) from exc
            return self

    def _run(self) -> None:
        while True:
            with self._condition:
                while True:
                    if self._stop_requested:
                        return
                    now = self._monotonic_now()
                    if self._pending_unknown_key_refresh:
                        self._pending_unknown_key_refresh = False
                        reason = "unknown_key"
                        break
                    next_periodic = self._next_periodic_monotonic
                    if next_periodic is None or now >= next_periodic:
                        reason = "periodic"
                        break
                    self._condition.wait(timeout=max(0.0, next_periodic - now))
            refreshed = self._refresh_once(reason=reason)
            with self._condition:
                delay = self._refresh_interval_seconds if refreshed else self._failure_retry_seconds
                self._next_periodic_monotonic = self._monotonic_now() + delay

    def _schedule_unknown_key_refresh(self) -> bool:
        with self._condition:
            if (
                not self._started
                or self._closed
                or self._stop_requested
                or self._pending_unknown_key_refresh
            ):
                return False
            try:
                now = self._monotonic_now()
            except EntraTrustUnavailableError:
                self._last_error_code = "clock_invalid"
                return False
            if (
                self._last_attempt_monotonic is not None
                and now < self._last_attempt_monotonic + self._unknown_key_refresh_seconds
            ):
                return False
            self._pending_unknown_key_refresh = True
            self._condition.notify_all()
            return True

    def wait_for_refresh_attempt(
        self,
        *,
        after_completed_count: int,
        timeout_seconds: float,
    ) -> bool:
        """Wait until a later refresh attempt completes; intended for lifecycle coordination."""

        if type(after_completed_count) is not int or after_completed_count < 0:
            raise ValueError("after_completed_count must be a non-negative integer")
        timeout = _managed_seconds(
            timeout_seconds,
            name="timeout_seconds",
            minimum=0.01,
            maximum=300.0,
        )
        deadline = time.monotonic() + timeout
        with self._condition:
            while self._completed_attempt_count <= after_completed_count:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(timeout=remaining)
            return True

    def _active_reloader(self) -> ReloadingEntraAccessTokenVerifier:
        with self._condition:
            if not self._started or self._closed or self._reloader is None:
                raise EntraTrustUnavailableError(
                    "managed_refresh_not_running",
                    "managed Entra refresh is not running",
                )
            if self._thread is None or not self._thread.is_alive():
                self._last_error_code = "refresh_worker_unavailable"
                raise EntraTrustUnavailableError(
                    "refresh_worker_unavailable",
                    "managed Entra refresh worker is unavailable",
                )
            return self._reloader

    def check_ready(self) -> None:
        self._active_reloader().check_ready()

    def verify(self, token: str) -> EntraVerifiedPrincipal:
        try:
            return self._active_reloader().verify(token)
        except EntraAccessTokenError as exc:
            if exc.code == "signing_key_unknown":
                self._schedule_unknown_key_refresh()
            raise

    def close(self, *, timeout_seconds: float = 30.0) -> None:
        """Stop scheduling new refreshes and wait a bounded time for the worker."""

        timeout = _managed_seconds(
            timeout_seconds,
            name="timeout_seconds",
            minimum=0.1,
            maximum=300.0,
        )
        with self._lifecycle_lock:
            with self._condition:
                thread = self._thread
                if not self._closed:
                    self._closed = True
                    self._stop_requested = True
                    self._pending_unknown_key_refresh = False
                    self._condition.notify_all()
                elif thread is None or not thread.is_alive():
                    return
            if thread is not None:
                thread.join(timeout=timeout)
                if thread.is_alive():
                    raise EntraTrustUnavailableError(
                        "refresh_worker_stop_timeout",
                        "managed Entra refresh worker did not stop within its deadline",
                    )
            with self._condition:
                self._started = False
                self._thread = None

    def __enter__(self) -> ManagedEntraAccessTokenVerifier:
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


class CoordinatedEntraAccessTokenVerifier(EntraTokenVerifier):
    """Elect one local-process refresh owner while every process reloads trust."""

    def __init__(
        self,
        configuration: EntraRefreshConfiguration,
        path: str | Path,
        *,
        owner_lock_path: str | Path | None = None,
        refresh_request_path: str | Path | None = None,
        client: EntraHTTPSJSONClient | None = None,
        snapshot_clock: _Clock = utc_timestamp,
        verifier_clock: Callable[[], int] = lambda: int(time.time()),
        monotonic_clock: Callable[[], float] = time.monotonic,
        clock_skew_seconds: int = ENTRA_CLOCK_SKEW_SECONDS,
        timeout_seconds: float = DEFAULT_ENTRA_REFRESH_TIMEOUT_SECONDS,
        refresh_interval_seconds: float = DEFAULT_ENTRA_MANAGED_REFRESH_INTERVAL_SECONDS,
        failure_retry_seconds: float = DEFAULT_ENTRA_REFRESH_FAILURE_RETRY_SECONDS,
        unknown_key_refresh_seconds: float = DEFAULT_ENTRA_UNKNOWN_KEY_REFRESH_SECONDS,
        coordination_poll_seconds: float = DEFAULT_ENTRA_COORDINATION_POLL_SECONDS,
        startup_wait_seconds: float = DEFAULT_ENTRA_COORDINATED_STARTUP_WAIT_SECONDS,
    ) -> None:
        if type(configuration) is not EntraRefreshConfiguration:
            raise TypeError("configuration must be an EntraRefreshConfiguration")
        if client is not None and not hasattr(client, "fetch"):
            raise TypeError("client must provide fetch()")
        if not callable(snapshot_clock):
            raise TypeError("snapshot_clock must be callable")
        if not callable(verifier_clock):
            raise TypeError("verifier_clock must be callable")
        if not callable(monotonic_clock):
            raise TypeError("monotonic_clock must be callable")
        if type(clock_skew_seconds) is not int or not 0 <= clock_skew_seconds <= 300:
            raise ValueError("clock_skew_seconds must be an integer from 0 through 300")
        self._configuration = configuration
        self._path = _coordination_path(path)
        resolved_owner_path = _coordination_path(
            owner_lock_path if owner_lock_path is not None else f"{self._path}.refresh-owner.lock"
        )
        resolved_request_path = _coordination_path(
            refresh_request_path
            if refresh_request_path is not None
            else f"{self._path}.refresh-request"
        )
        distinct_paths = {
            _coordination_path_key(self._path),
            _coordination_path_key(resolved_owner_path),
            _coordination_path_key(resolved_request_path),
        }
        if len(distinct_paths) != 3:
            raise ValueError("snapshot, owner lock, and refresh request paths must differ")
        self._client = client
        self._snapshot_clock = snapshot_clock
        self._verifier_clock = verifier_clock
        self._monotonic_clock = monotonic_clock
        self._clock_skew_seconds = clock_skew_seconds
        self._timeout_seconds = _managed_seconds(
            timeout_seconds,
            name="timeout_seconds",
            minimum=1.0,
            maximum=30.0,
        )
        self._refresh_interval_seconds = _managed_seconds(
            refresh_interval_seconds,
            name="refresh_interval_seconds",
            minimum=MIN_ENTRA_MANAGED_REFRESH_INTERVAL_SECONDS,
            maximum=86400.0,
        )
        self._failure_retry_seconds = _managed_seconds(
            failure_retry_seconds,
            name="failure_retry_seconds",
            minimum=MIN_ENTRA_REFRESH_FAILURE_RETRY_SECONDS,
            maximum=self._refresh_interval_seconds,
        )
        self._unknown_key_refresh_seconds = _managed_seconds(
            unknown_key_refresh_seconds,
            name="unknown_key_refresh_seconds",
            minimum=MIN_ENTRA_UNKNOWN_KEY_REFRESH_SECONDS,
            maximum=86400.0,
        )
        self._coordination_poll_seconds = _managed_seconds(
            coordination_poll_seconds,
            name="coordination_poll_seconds",
            minimum=MIN_ENTRA_COORDINATION_POLL_SECONDS,
            maximum=30.0,
        )
        self._startup_wait_seconds = _managed_seconds(
            startup_wait_seconds,
            name="startup_wait_seconds",
            minimum=0.0,
            maximum=300.0,
        )
        self._coordinator = LocalFileEntraRefreshCoordinator(
            resolved_owner_path,
            resolved_request_path,
        )
        self._lifecycle_lock = threading.RLock()
        self._condition = threading.Condition(threading.RLock())
        self._stop_event = threading.Event()
        self._reloader: ReloadingEntraAccessTokenVerifier | None = None
        self._manager: ManagedEntraAccessTokenVerifier | None = None
        self._thread: threading.Thread | None = None
        self._started = False
        self._closed = False
        self._is_refresh_owner = False
        self._ownership_acquisition_count = 0
        self._last_error_code: str | None = None
        self._refresh_request_consumption_pending = False
        self._next_ownership_attempt_monotonic = 0.0

    @staticmethod
    def _exception_code(exc: Exception) -> str:
        if isinstance(
            exc,
            (
                EntraRefreshCoordinationError,
                EntraRefreshError,
                EntraSnapshotInstallError,
                EntraTrustUnavailableError,
            ),
        ):
            return exc.code
        return "coordinated_refresh_failed"

    def _record_error(self, code: str | None) -> None:
        with self._condition:
            self._last_error_code = code
            self._condition.notify_all()

    def _new_manager(self) -> ManagedEntraAccessTokenVerifier:
        return ManagedEntraAccessTokenVerifier(
            self._configuration,
            self._path,
            client=self._client,
            snapshot_clock=self._snapshot_clock,
            verifier_clock=self._verifier_clock,
            monotonic_clock=self._monotonic_clock,
            refresh_guard=lambda: self._coordinator.ownership_valid,
            clock_skew_seconds=self._clock_skew_seconds,
            timeout_seconds=self._timeout_seconds,
            refresh_interval_seconds=self._refresh_interval_seconds,
            failure_retry_seconds=self._failure_retry_seconds,
            unknown_key_refresh_seconds=self._unknown_key_refresh_seconds,
        )

    def _ensure_reloader(self) -> ReloadingEntraAccessTokenVerifier:
        with self._condition:
            current = self._reloader
        if current is None:
            candidate = ReloadingEntraAccessTokenVerifier(
                self._path,
                clock=self._verifier_clock,
                clock_skew_seconds=self._clock_skew_seconds,
            )
            if candidate.store_id != self._configuration.store_id:
                raise EntraTrustUnavailableError(
                    "store_id_mismatch",
                    "installed Entra trust does not match refresh configuration",
                )
            with self._condition:
                if self._reloader is None:
                    self._reloader = candidate
                current = self._reloader
        if current is None:
            raise EntraTrustUnavailableError(
                "snapshot_unavailable",
                "coordinated Entra trust snapshot is unavailable",
            )
        if current.store_id != self._configuration.store_id:
            raise EntraTrustUnavailableError(
                "store_id_mismatch",
                "installed Entra trust does not match refresh configuration",
            )
        current.check_ready()
        return current

    def _release_after_failed_promotion(
        self,
        manager: ManagedEntraAccessTokenVerifier | None,
        error_code: str,
    ) -> bool:
        if manager is not None:
            try:
                manager.close()
            except EntraTrustUnavailableError as exc:
                with self._condition:
                    self._manager = manager
                    self._is_refresh_owner = False
                    self._last_error_code = exc.code
                    self._condition.notify_all()
                return False
        try:
            self._coordinator.release()
        except EntraRefreshCoordinationError as exc:
            error_code = exc.code
        with self._condition:
            self._manager = None
            self._is_refresh_owner = False
            self._last_error_code = error_code
            self._refresh_request_consumption_pending = False
            self._next_ownership_attempt_monotonic = time.monotonic() + self._failure_retry_seconds
            self._condition.notify_all()
        return True

    def _promote(self, *, startup: bool) -> bool:
        if not self._coordinator.ownership_valid:
            self._record_error("refresh_ownership_lost")
            return False
        manager: ManagedEntraAccessTokenVerifier | None = None
        try:
            manager = self._new_manager()
            manager.start()
            if not self._coordinator.ownership_valid:
                raise EntraTrustUnavailableError(
                    "refresh_ownership_lost",
                    "refresh ownership was lost during owner startup",
                )
            self._ensure_reloader()
        except Exception as exc:
            error_code = self._exception_code(exc)
            self._release_after_failed_promotion(manager, error_code)
            if startup:
                raise EntraTrustUnavailableError(
                    "coordinated_refresh_unavailable",
                    "coordinated Entra refresh owner could not start",
                ) from exc
            return False
        if manager is None:
            raise RuntimeError("coordinated refresh manager was not created")
        with self._condition:
            if self._closed or self._stop_event.is_set():
                stopping = True
            else:
                stopping = False
                self._manager = manager
                self._is_refresh_owner = True
                self._ownership_acquisition_count += 1
                self._last_error_code = None
                self._refresh_request_consumption_pending = False
                self._next_ownership_attempt_monotonic = 0.0
                self._condition.notify_all()
        if stopping:
            self._release_after_failed_promotion(manager, "coordinated_refresh_stopping")
            return False
        if manager.status.last_error_code is None:
            try:
                if self._coordinator.refresh_requested:
                    with self._condition:
                        self._refresh_request_consumption_pending = True
                    self._consume_satisfied_refresh_request()
            except EntraRefreshCoordinationError as exc:
                self._record_error(exc.code)
        return True

    def _demote(self, *, reason: str) -> bool:
        with self._condition:
            manager = self._manager
            self._is_refresh_owner = False
            self._last_error_code = reason
            self._refresh_request_consumption_pending = False
            self._condition.notify_all()
        if manager is not None:
            try:
                manager.close()
            except EntraTrustUnavailableError as exc:
                self._record_error(exc.code)
                return False
        try:
            self._coordinator.release()
        except EntraRefreshCoordinationError as exc:
            self._record_error(exc.code)
            return False
        with self._condition:
            self._manager = None
            self._next_ownership_attempt_monotonic = time.monotonic() + self._failure_retry_seconds
            self._condition.notify_all()
        return True

    def _consume_satisfied_refresh_request(self) -> None:
        try:
            self._coordinator.consume_refresh_request()
        except EntraRefreshCoordinationError as exc:
            self._record_error(exc.code)
            return
        with self._condition:
            self._refresh_request_consumption_pending = False
            if self._last_error_code == "coordination_request_unavailable":
                self._last_error_code = None
            self._condition.notify_all()

    def _process_refresh_request(
        self,
        manager: ManagedEntraAccessTokenVerifier,
    ) -> None:
        with self._condition:
            consumption_pending = self._refresh_request_consumption_pending
        if consumption_pending:
            self._consume_satisfied_refresh_request()
            return
        try:
            requested = self._coordinator.refresh_requested
        except EntraRefreshCoordinationError as exc:
            self._record_error(exc.code)
            return
        if requested and manager._schedule_unknown_key_refresh():
            with self._condition:
                self._refresh_request_consumption_pending = True
            self._consume_satisfied_refresh_request()

    def _run(self) -> None:
        try:
            while not self._stop_event.wait(self._coordination_poll_seconds):
                with self._condition:
                    is_owner = self._is_refresh_owner
                    manager = self._manager
                    next_attempt = self._next_ownership_attempt_monotonic
                if is_owner:
                    if not self._coordinator.ownership_valid:
                        self._demote(reason="refresh_ownership_lost")
                        continue
                    if manager is None or not manager.status.running:
                        self._demote(reason="refresh_worker_unavailable")
                        continue
                    self._process_refresh_request(manager)
                    continue
                if self._coordinator.is_owner:
                    self._demote(reason="refresh_owner_stopping")
                    continue
                if time.monotonic() < next_attempt:
                    continue
                try:
                    acquired = self._coordinator.try_acquire()
                except EntraRefreshCoordinationError as exc:
                    self._record_error(exc.code)
                    with self._condition:
                        self._next_ownership_attempt_monotonic = (
                            time.monotonic() + self._failure_retry_seconds
                        )
                    continue
                if acquired:
                    self._promote(startup=False)
        except Exception as exc:
            self._record_error(self._exception_code(exc))

    @property
    def status(self) -> EntraCoordinatedRefreshStatus:
        with self._condition:
            thread = self._thread
            manager = self._manager
            running = (
                self._started and not self._closed and thread is not None and thread.is_alive()
            )
            is_owner = self._is_refresh_owner
            acquisition_count = self._ownership_acquisition_count
            last_error_code = self._last_error_code
        try:
            request_pending = self._coordinator.refresh_requested
        except (EntraRefreshCoordinationError, RuntimeError):
            request_pending = False
        return EntraCoordinatedRefreshStatus(
            running=running,
            is_refresh_owner=is_owner,
            ownership_acquisition_count=acquisition_count,
            refresh_request_pending=request_pending,
            last_error_code=last_error_code,
            managed_refresh=manager.status if manager is not None else None,
        )

    def start(self) -> CoordinatedEntraAccessTokenVerifier:
        """Join local coordination, obtain usable trust, and start failover supervision."""

        with self._lifecycle_lock:
            with self._condition:
                if self._closed:
                    raise RuntimeError("coordinated Entra verifier is closed")
                if self._started:
                    return self
            deadline = time.monotonic() + self._startup_wait_seconds
            last_error: Exception | None = None
            while True:
                try:
                    if self._coordinator.try_acquire():
                        self._promote(startup=True)
                        break
                except EntraRefreshCoordinationError:
                    raise
                try:
                    self._ensure_reloader()
                    break
                except EntraTrustUnavailableError as exc:
                    last_error = exc
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise EntraTrustUnavailableError(
                        "coordinated_refresh_unavailable",
                        "no refresh owner published usable Entra trust before startup deadline",
                    ) from last_error
                time.sleep(min(self._coordination_poll_seconds, remaining))
            self._stop_event.clear()
            thread = threading.Thread(
                target=self._run,
                name="causure-entra-coordinator",
                daemon=True,
            )
            with self._condition:
                self._started = True
                self._thread = thread
            try:
                thread.start()
            except RuntimeError as exc:
                with self._condition:
                    self._started = False
                    self._thread = None
                    self._last_error_code = "coordination_worker_start_failed"
                manager = self._manager
                if manager is not None:
                    manager.close()
                self._coordinator.release()
                raise EntraTrustUnavailableError(
                    "coordination_worker_start_failed",
                    "coordinated Entra supervision worker could not start",
                ) from exc
            return self

    def _active_reloader(self) -> ReloadingEntraAccessTokenVerifier:
        with self._condition:
            thread = self._thread
            manager = self._manager
            if (
                not self._started
                or self._closed
                or self._reloader is None
                or thread is None
                or not thread.is_alive()
            ):
                raise EntraTrustUnavailableError(
                    "coordinated_refresh_not_running",
                    "coordinated Entra refresh is not running",
                )
            if self._is_refresh_owner and (manager is None or not manager.status.running):
                self._last_error_code = "refresh_worker_unavailable"
                raise EntraTrustUnavailableError(
                    "refresh_worker_unavailable",
                    "owned Entra refresh worker is unavailable",
                )
            return self._reloader

    def check_ready(self) -> None:
        self._active_reloader().check_ready()

    def verify(self, token: str) -> EntraVerifiedPrincipal:
        try:
            return self._active_reloader().verify(token)
        except EntraAccessTokenError as exc:
            if exc.code == "signing_key_unknown":
                try:
                    self._coordinator.signal_refresh()
                except (EntraRefreshCoordinationError, RuntimeError) as signal_error:
                    code = (
                        signal_error.code
                        if isinstance(signal_error, EntraRefreshCoordinationError)
                        else "coordination_signal_failed"
                    )
                    self._record_error(code)
            raise

    def wait_for_refresh_attempt(
        self,
        *,
        after_completed_count: int,
        timeout_seconds: float,
    ) -> bool:
        """Wait on this process's owned refresher, returning false while a follower."""

        with self._condition:
            manager = self._manager if self._is_refresh_owner else None
        if manager is None:
            return False
        return manager.wait_for_refresh_attempt(
            after_completed_count=after_completed_count,
            timeout_seconds=timeout_seconds,
        )

    def close(self, *, timeout_seconds: float = 30.0) -> None:
        """Stop coordination, stop any owned refresher, and release ownership."""

        timeout = _managed_seconds(
            timeout_seconds,
            name="timeout_seconds",
            minimum=0.1,
            maximum=300.0,
        )
        deadline = time.monotonic() + timeout
        with self._lifecycle_lock:
            with self._condition:
                thread = self._thread
                if not self._closed:
                    self._closed = True
                    self._stop_event.set()
                    self._condition.notify_all()
                elif thread is None and self._manager is None:
                    return
            if thread is not None:
                thread.join(timeout=max(0.0, deadline - time.monotonic()))
                if thread.is_alive():
                    raise EntraTrustUnavailableError(
                        "coordination_worker_stop_timeout",
                        "coordinated Entra supervision worker did not stop within its deadline",
                    )
            with self._condition:
                manager = self._manager
            if manager is not None:
                remaining = deadline - time.monotonic()
                if remaining < 0.1:
                    raise EntraTrustUnavailableError(
                        "refresh_worker_stop_timeout",
                        "owned Entra refresh worker did not stop within its deadline",
                    )
                manager.close(timeout_seconds=remaining)
            self._coordinator.close()
            with self._condition:
                self._started = False
                self._thread = None
                self._manager = None
                self._is_refresh_owner = False

    def __enter__(self) -> CoordinatedEntraAccessTokenVerifier:
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
