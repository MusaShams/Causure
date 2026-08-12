"""Transactional hard-quota proxy for a bounded OpenAI-compatible Responses API."""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import os
import re
import secrets
import sqlite3
import ssl
from collections.abc import Callable, Iterable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import ROUND_CEILING, ROUND_FLOOR, Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Protocol
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import (
    HTTPRedirectHandler,
    HTTPSHandler,
    ProxyHandler,
    Request,
    build_opener,
)

from causure.attestations import utc_timestamp
from causure.constants import (
    OPENAI_QUOTA_CONFIG_SCHEMA_VERSION,
    PACKAGE_VERSION,
    QuotaEnforcement,
)
from causure.io import InputDocumentError, parse_json_text
from causure.sandbox_protocol import (
    QuotaLease,
    QuotaReservation,
    QuotaSettlement,
)

MAX_OPENAI_QUOTA_CONFIG_BYTES = 64 * 1024
MAX_OPENAI_QUOTA_REQUEST_BYTES = 4 * 1024 * 1024
MAX_OPENAI_QUOTA_RESPONSE_BYTES = 16 * 1024 * 1024
OPENAI_QUOTA_STORE_SCHEMA_VERSION = 1
OPENAI_QUOTA_STORE_APPLICATION_ID = 0x5042514F
DEFAULT_OPENAI_QUOTA_BUSY_TIMEOUT_MS = 5_000
MAX_OPENAI_QUOTA_BUSY_TIMEOUT_MS = 60_000
MIN_OPENAI_QUOTA_SECRET_CHARACTERS = 32
OPENAI_QUOTA_NANO_USD_SCALE = 1_000_000_000
_SQLITE_MAX_INTEGER = 2**63 - 1

_PRICE_PATTERN = re.compile(r"^(0|[1-9][0-9]{0,5})\.[0-9]{1,9}$")
_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{2,127}$")
_MODEL_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{1,127}$")
_OPENAI_LEASE_ID_PATTERN = re.compile(r"^oq-[a-f0-9]{32}$")
_LEASE_PATH_PATTERN = re.compile(r"^/admin/v1/leases/(oq-[a-f0-9]{32})/(settle|cancel)$")
_ADMIN_CLIENT_PATH_PATTERN = re.compile(
    r"^/admin/v1/leases(?:/(?:oq-[a-f0-9]{32})/(?:settle|cancel))?$"
)
_CONTENT_LENGTH_PATTERN = re.compile(r"^(0|[1-9][0-9]*)$")
_UTC_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_AUTHORIZATION_PREFIX = "Bearer "
_RESPONSES_PATH = "/v1/responses"
_ADMIN_RESERVE_PATH = "/admin/v1/leases"
_ALLOWED_REQUEST_FIELDS = frozenset(
    {
        "input",
        "instructions",
        "max_output_tokens",
        "metadata",
        "model",
        "reasoning",
        "store",
        "stream",
        "temperature",
        "text",
        "top_p",
    }
)
_ALLOWED_MESSAGE_ROLES = frozenset({"developer", "system", "user", "assistant"})
_STATUS_REASONS = {
    200: "OK",
    201: "Created",
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    404: "Not Found",
    405: "Method Not Allowed",
    409: "Conflict",
    411: "Length Required",
    413: "Content Too Large",
    415: "Unsupported Media Type",
    429: "Too Many Requests",
    500: "Internal Server Error",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
}


class OpenAIQuotaError(ValueError):
    """Base error carrying a stable non-secret machine code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"OpenAI-compatible quota failed [{code}]: {message}")


class OpenAIQuotaConfigurationError(OpenAIQuotaError):
    """Raised when protected quota configuration is invalid."""


class OpenAIQuotaStoreError(OpenAIQuotaError):
    """Raised when transactional lease state cannot be read or changed."""


class OpenAIQuotaConflictError(OpenAIQuotaStoreError):
    """Raised when a lease cannot admit the requested operation."""


class OpenAIQuotaUpstreamError(OpenAIQuotaError):
    """Raised when the fixed provider endpoint cannot be used authoritatively."""


class OpenAIQuotaControllerError(OpenAIQuotaError):
    """Raised when the sandbox-side controller cannot use the admin API."""


class _QuotaHTTPError(OpenAIQuotaError):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        *,
        headers: tuple[tuple[str, str], ...] = (),
    ) -> None:
        self.status = status
        self.headers = headers
        super().__init__(code, message)


def _bounded_secret(value: str, name: str) -> str:
    if (
        not isinstance(value, str)
        or not MIN_OPENAI_QUOTA_SECRET_CHARACTERS <= len(value) <= 8_192
        or any(not 33 <= ord(character) <= 126 for character in value)
    ):
        raise ValueError(
            f"{name} must contain from {MIN_OPENAI_QUOTA_SECRET_CHARACTERS} through "
            "8192 non-whitespace characters"
        )
    return value


def _safe_text(
    value: Any,
    name: str,
    *,
    minimum: int = 1,
    maximum: int = 128,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or not value.strip()
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or (pattern is not None and pattern.fullmatch(value) is None)
    ):
        raise OpenAIQuotaConfigurationError("configuration_invalid", f"{name} is invalid")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            f"{name} must contain valid Unicode scalar values",
        ) from exc
    return value


def _integer(value: Any, name: str, *, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            f"{name} must be an integer from {minimum} through {maximum}",
        )
    return value


def _number(value: Any, name: str, *, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            f"{name} must be numeric",
        )
    converted = float(value)
    if not math.isfinite(converted) or not minimum <= converted <= maximum:
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            f"{name} must be from {minimum} through {maximum}",
        )
    return converted


def _closed_object(
    value: Any,
    *,
    name: str,
    required: set[str],
    optional: set[str] | None = None,
) -> Mapping[str, Any]:
    if type(value) is not dict:
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            f"{name} must be an object",
        )
    allowed = required | (optional or set())
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - allowed)
    if missing or unknown:
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            f"{name} does not match the closed configuration contract",
        )
    return value


def _https_url(
    value: Any,
    name: str,
    *,
    required_path: str | None = None,
    required_hostname: str | None = None,
) -> str:
    if not isinstance(value, str) or not value or len(value) > 2_048:
        raise OpenAIQuotaConfigurationError("configuration_invalid", f"{name} is invalid")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            f"{name} must be a valid HTTPS URL",
        ) from exc
    authority = hostname if port is None else f"{hostname}:{port}"
    if (
        parsed.scheme != "https"
        or not hostname
        or port == 0
        or parsed.netloc != authority
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or (required_path is not None and parsed.path != required_path)
        or (required_hostname is not None and hostname != required_hostname)
    ):
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            f"{name} must be an exact credential-free HTTPS URL",
        )
    return value


def _decimal_price(value: Any, name: str) -> str:
    if not isinstance(value, str) or _PRICE_PATTERN.fullmatch(value) is None:
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            f"{name} must be a fixed-point USD string with 1 through 9 decimal places",
        )
    try:
        price = Decimal(value)
    except InvalidOperation as exc:
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            f"{name} is not a valid price",
        ) from exc
    if not price.is_finite() or price < 0 or price > Decimal("100000"):
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            f"{name} is outside the supported price range",
        )
    return value


@dataclass(frozen=True, slots=True)
class OpenAIModelPricing:
    """Protected exact-model rates and token bounds used by the proxy."""

    model: str
    input_usd_per_million_tokens: str
    cached_input_usd_per_million_tokens: str
    output_usd_per_million_tokens: str
    max_input_tokens: int
    max_output_tokens: int

    def __post_init__(self) -> None:
        _safe_text(self.model, "model", pattern=_MODEL_PATTERN)
        regular = Decimal(
            _decimal_price(
                self.input_usd_per_million_tokens,
                "input_usd_per_million_tokens",
            )
        )
        cached = Decimal(
            _decimal_price(
                self.cached_input_usd_per_million_tokens,
                "cached_input_usd_per_million_tokens",
            )
        )
        output = Decimal(
            _decimal_price(
                self.output_usd_per_million_tokens,
                "output_usd_per_million_tokens",
            )
        )
        if regular <= 0 or output <= 0:
            raise OpenAIQuotaConfigurationError(
                "configuration_invalid",
                "regular input and output prices must be greater than zero",
            )
        if cached > regular:
            raise OpenAIQuotaConfigurationError(
                "configuration_invalid",
                "cached input price must not exceed the regular input price",
            )
        _integer(
            self.max_input_tokens,
            "max_input_tokens",
            minimum=1,
            maximum=10_000_000,
        )
        _integer(
            self.max_output_tokens,
            "max_output_tokens",
            minimum=1,
            maximum=1_000_000,
        )

    def _cost(self, tokens: int, rate: str) -> int:
        value = (
            Decimal(tokens)
            * Decimal(rate)
            * Decimal(OPENAI_QUOTA_NANO_USD_SCALE)
            / Decimal(1_000_000)
        )
        return int(value.to_integral_value(rounding=ROUND_CEILING))

    def maximum_cost_nusd(self, input_tokens: int, output_tokens: int) -> int:
        return self._cost(input_tokens, self.input_usd_per_million_tokens) + self._cost(
            output_tokens,
            self.output_usd_per_million_tokens,
        )

    def actual_cost_nusd(
        self,
        *,
        input_tokens: int,
        cached_input_tokens: int,
        output_tokens: int,
    ) -> int:
        regular_tokens = input_tokens - cached_input_tokens
        return (
            self._cost(regular_tokens, self.input_usd_per_million_tokens)
            + self._cost(
                cached_input_tokens,
                self.cached_input_usd_per_million_tokens,
            )
            + self._cost(output_tokens, self.output_usd_per_million_tokens)
        )


@dataclass(frozen=True, slots=True)
class OpenAIQuotaConfiguration:
    """Non-secret protected configuration for one quota proxy deployment."""

    schema_version: str
    service_id: str
    upstream_responses_url: str
    worker_proxy_url: str
    proxy_container_name: str
    network_name: str
    lease_cleanup_seconds: int
    upstream_timeout_seconds: float
    max_request_bytes: int
    max_response_bytes: int
    models: tuple[OpenAIModelPricing, ...]

    def __post_init__(self) -> None:
        if self.schema_version != OPENAI_QUOTA_CONFIG_SCHEMA_VERSION:
            raise OpenAIQuotaConfigurationError(
                "configuration_invalid",
                f"schema_version must be {OPENAI_QUOTA_CONFIG_SCHEMA_VERSION}",
            )
        _safe_text(self.service_id, "service_id", pattern=_SAFE_ID_PATTERN)
        _safe_text(
            self.proxy_container_name,
            "proxy_container_name",
            maximum=63,
            pattern=re.compile(r"^[a-z0-9][a-z0-9.-]{1,62}$"),
        )
        _safe_text(
            self.network_name,
            "network_name",
            pattern=re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$"),
        )
        _https_url(
            self.upstream_responses_url,
            "upstream_responses_url",
            required_path=_RESPONSES_PATH,
        )
        _https_url(
            self.worker_proxy_url,
            "worker_proxy_url",
            required_path="/v1",
            required_hostname=self.proxy_container_name,
        )
        _integer(
            self.lease_cleanup_seconds,
            "lease_cleanup_seconds",
            minimum=30,
            maximum=3_600,
        )
        _number(
            self.upstream_timeout_seconds,
            "upstream_timeout_seconds",
            minimum=1.0,
            maximum=300.0,
        )
        _integer(
            self.max_request_bytes,
            "max_request_bytes",
            minimum=1_024,
            maximum=MAX_OPENAI_QUOTA_REQUEST_BYTES,
        )
        _integer(
            self.max_response_bytes,
            "max_response_bytes",
            minimum=1_024,
            maximum=MAX_OPENAI_QUOTA_RESPONSE_BYTES,
        )
        if not isinstance(self.models, tuple) or not 1 <= len(self.models) <= 1_000:
            raise OpenAIQuotaConfigurationError(
                "configuration_invalid",
                "models must contain from 1 through 1000 exact pricing records",
            )
        if any(type(model) is not OpenAIModelPricing for model in self.models):
            raise OpenAIQuotaConfigurationError(
                "configuration_invalid",
                "models must contain OpenAIModelPricing values",
            )
        if len({model.model for model in self.models}) != len(self.models):
            raise OpenAIQuotaConfigurationError(
                "configuration_invalid",
                "model identifiers must be unique",
            )

    def pricing_for(self, model: str) -> OpenAIModelPricing:
        for pricing in self.models:
            if hmac.compare_digest(pricing.model, model):
                return pricing
        raise OpenAIQuotaConflictError(
            "model_not_allowed",
            "the requested model is not present in protected quota configuration",
        )


def parse_openai_quota_configuration(value: Any) -> OpenAIQuotaConfiguration:
    """Parse one closed, non-secret OpenAI-compatible quota configuration."""

    root = _closed_object(
        value,
        name="$",
        required={
            "schema_version",
            "service_id",
            "upstream_responses_url",
            "worker_proxy_url",
            "proxy_container_name",
            "network_name",
            "lease_cleanup_seconds",
            "upstream_timeout_seconds",
            "max_request_bytes",
            "max_response_bytes",
            "models",
        },
    )
    model_values = root["models"]
    if type(model_values) is not list:
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            "$.models must be an array",
        )
    models: list[OpenAIModelPricing] = []
    for index, item in enumerate(model_values):
        model = _closed_object(
            item,
            name=f"$.models[{index}]",
            required={
                "model",
                "input_usd_per_million_tokens",
                "cached_input_usd_per_million_tokens",
                "output_usd_per_million_tokens",
                "max_input_tokens",
                "max_output_tokens",
            },
        )
        models.append(OpenAIModelPricing(**model))
    return OpenAIQuotaConfiguration(
        schema_version=root["schema_version"],
        service_id=root["service_id"],
        upstream_responses_url=root["upstream_responses_url"],
        worker_proxy_url=root["worker_proxy_url"],
        proxy_container_name=root["proxy_container_name"],
        network_name=root["network_name"],
        lease_cleanup_seconds=root["lease_cleanup_seconds"],
        upstream_timeout_seconds=root["upstream_timeout_seconds"],
        max_request_bytes=root["max_request_bytes"],
        max_response_bytes=root["max_response_bytes"],
        models=tuple(models),
    )


def parse_openai_quota_configuration_bytes(data: bytes) -> OpenAIQuotaConfiguration:
    if not isinstance(data, bytes) or not 1 <= len(data) <= MAX_OPENAI_QUOTA_CONFIG_BYTES:
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            "configuration bytes are empty or oversized",
        )
    try:
        value = parse_json_text(
            data.decode("utf-8"),
            source="OpenAI-compatible quota configuration",
            max_bytes=MAX_OPENAI_QUOTA_CONFIG_BYTES,
        )
    except (InputDocumentError, UnicodeDecodeError) as exc:
        raise OpenAIQuotaConfigurationError(
            "configuration_invalid",
            "configuration must be strict UTF-8 JSON",
        ) from exc
    return parse_openai_quota_configuration(value)


def load_openai_quota_configuration(path: str | Path) -> OpenAIQuotaConfiguration:
    try:
        with Path(path).open("rb") as stream:
            data = stream.read(MAX_OPENAI_QUOTA_CONFIG_BYTES + 1)
    except OSError as exc:
        raise OpenAIQuotaConfigurationError(
            "configuration_unavailable",
            "configuration file could not be read",
        ) from exc
    return parse_openai_quota_configuration_bytes(data)


def _configuration_document(configuration: OpenAIQuotaConfiguration) -> dict[str, Any]:
    return {
        "schema_version": configuration.schema_version,
        "service_id": configuration.service_id,
        "upstream_responses_url": configuration.upstream_responses_url,
        "worker_proxy_url": configuration.worker_proxy_url,
        "proxy_container_name": configuration.proxy_container_name,
        "network_name": configuration.network_name,
        "lease_cleanup_seconds": configuration.lease_cleanup_seconds,
        "upstream_timeout_seconds": configuration.upstream_timeout_seconds,
        "max_request_bytes": configuration.max_request_bytes,
        "max_response_bytes": configuration.max_response_bytes,
        "models": [
            {
                "model": model.model,
                "input_usd_per_million_tokens": model.input_usd_per_million_tokens,
                "cached_input_usd_per_million_tokens": (model.cached_input_usd_per_million_tokens),
                "output_usd_per_million_tokens": model.output_usd_per_million_tokens,
                "max_input_tokens": model.max_input_tokens,
                "max_output_tokens": model.max_output_tokens,
            }
            for model in configuration.models
        ],
    }


def render_openai_quota_configuration(configuration: OpenAIQuotaConfiguration) -> str:
    if type(configuration) is not OpenAIQuotaConfiguration:
        raise TypeError("configuration must be an OpenAIQuotaConfiguration")
    return (
        json.dumps(
            _configuration_document(configuration),
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _validate_clock(clock: Callable[[], datetime]) -> datetime:
    value = clock()
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise OpenAIQuotaStoreError(
            "clock_invalid",
            "quota clock must return a timezone-aware datetime",
        )
    return value.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).strftime(_UTC_TIMESTAMP_FORMAT)


def _parse_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.strptime(value, _UTC_TIMESTAMP_FORMAT).replace(tzinfo=UTC)
    except (TypeError, ValueError) as exc:
        raise OpenAIQuotaStoreError(
            "stored_timestamp_invalid",
            "quota store contains an invalid timestamp",
        ) from exc
    return parsed


def _usd_to_nusd_floor(value: float) -> int:
    try:
        converted = Decimal(str(value)) * Decimal(OPENAI_QUOTA_NANO_USD_SCALE)
    except InvalidOperation as exc:
        raise OpenAIQuotaStoreError("cost_invalid", "cost could not be represented") from exc
    return int(converted.to_integral_value(rounding=ROUND_FLOOR))


def _nusd_to_usd(value: int) -> float:
    return float(Decimal(value) / Decimal(OPENAI_QUOTA_NANO_USD_SCALE))


def _translate_sqlite_error(exc: sqlite3.Error) -> OpenAIQuotaStoreError:
    if isinstance(exc, sqlite3.OperationalError) and "locked" in str(exc).lower():
        return OpenAIQuotaConflictError("store_busy", "quota store is busy; retry the request")
    return OpenAIQuotaStoreError("store_failed", "quota store operation failed")


_QUOTA_SCHEMA = (
    """
    CREATE TABLE quota_metadata (
        key TEXT NOT NULL PRIMARY KEY,
        value TEXT NOT NULL
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE quota_leases (
        lease_id TEXT NOT NULL PRIMARY KEY,
        token_sha256 TEXT NOT NULL UNIQUE
            CHECK (length(token_sha256) = 64 AND lower(token_sha256) = token_sha256),
        case_id TEXT NOT NULL,
        state TEXT NOT NULL
            CHECK (state IN ('active', 'settled', 'canceled', 'failed')),
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        max_cost_nusd INTEGER NOT NULL CHECK (max_cost_nusd >= 0),
        max_concurrency INTEGER NOT NULL CHECK (max_concurrency BETWEEN 1 AND 64),
        max_operations INTEGER NOT NULL CHECK (max_operations BETWEEN 1 AND 10000),
        operation_count INTEGER NOT NULL DEFAULT 0 CHECK (operation_count >= 0),
        successful_operations INTEGER NOT NULL DEFAULT 0
            CHECK (successful_operations >= 0),
        in_flight INTEGER NOT NULL DEFAULT 0 CHECK (in_flight >= 0),
        held_cost_nusd INTEGER NOT NULL DEFAULT 0 CHECK (held_cost_nusd >= 0),
        actual_cost_nusd INTEGER NOT NULL DEFAULT 0 CHECK (actual_cost_nusd >= 0),
        uncertain_cost_nusd INTEGER NOT NULL DEFAULT 0
            CHECK (uncertain_cost_nusd >= 0),
        terminal_reason TEXT,
        terminal_at TEXT,
        CHECK (operation_count <= max_operations),
        CHECK (successful_operations <= operation_count),
        CHECK (in_flight <= max_concurrency),
        CHECK (actual_cost_nusd + held_cost_nusd + uncertain_cost_nusd <= max_cost_nusd),
        CHECK (
            (state = 'active' AND terminal_reason IS NULL AND terminal_at IS NULL)
            OR (state != 'active' AND terminal_reason IS NOT NULL AND terminal_at IS NOT NULL)
        )
    ) WITHOUT ROWID
    """,
    """
    CREATE TABLE quota_operations (
        lease_id TEXT NOT NULL,
        sequence INTEGER NOT NULL CHECK (sequence >= 1),
        request_sha256 TEXT NOT NULL
            CHECK (length(request_sha256) = 64 AND lower(request_sha256) = request_sha256),
        model TEXT NOT NULL,
        input_token_limit INTEGER NOT NULL CHECK (input_token_limit >= 1),
        output_token_limit INTEGER NOT NULL CHECK (output_token_limit >= 1),
        reserved_cost_nusd INTEGER NOT NULL CHECK (reserved_cost_nusd >= 0),
        status TEXT NOT NULL
            CHECK (status IN ('forwarding', 'completed', 'uncertain', 'accounting_failed')),
        started_at TEXT NOT NULL,
        finished_at TEXT,
        input_tokens INTEGER CHECK (input_tokens IS NULL OR input_tokens >= 0),
        cached_input_tokens INTEGER
            CHECK (cached_input_tokens IS NULL OR cached_input_tokens >= 0),
        output_tokens INTEGER CHECK (output_tokens IS NULL OR output_tokens >= 0),
        actual_cost_nusd INTEGER
            CHECK (actual_cost_nusd IS NULL OR actual_cost_nusd >= 0),
        upstream_response_id TEXT,
        failure_reason TEXT,
        CHECK (
            (status IN ('forwarding', 'completed') AND failure_reason IS NULL)
            OR (status IN ('uncertain', 'accounting_failed') AND failure_reason IS NOT NULL)
        ),
        PRIMARY KEY (lease_id, sequence),
        FOREIGN KEY (lease_id) REFERENCES quota_leases (lease_id)
    ) WITHOUT ROWID
    """,
    """
    CREATE INDEX quota_operations_status
    ON quota_operations (lease_id, status)
    """,
)


@dataclass(frozen=True, slots=True)
class OpenAIQuotaOperation:
    lease_id: str
    sequence: int
    model: str
    input_token_limit: int
    output_token_limit: int
    reserved_cost_nusd: int


class SQLiteOpenAIQuotaStore:
    """Crash-consistent single-host lease and operation accounting."""

    def __init__(
        self,
        database_path: str | os.PathLike[str],
        *,
        busy_timeout_ms: int = DEFAULT_OPENAI_QUOTA_BUSY_TIMEOUT_MS,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        raw_path = os.fspath(database_path)
        if not raw_path or raw_path == ":memory:" or raw_path.startswith("file:"):
            raise OpenAIQuotaStoreError(
                "database_path_invalid",
                "database_path must be a persistent filesystem path",
            )
        if (
            type(busy_timeout_ms) is not int
            or not 1 <= busy_timeout_ms <= MAX_OPENAI_QUOTA_BUSY_TIMEOUT_MS
        ):
            raise OpenAIQuotaStoreError(
                "busy_timeout_invalid",
                "busy_timeout_ms is outside the supported range",
            )
        if not callable(clock):
            raise TypeError("clock must be callable")
        self._path = Path(raw_path)
        self._busy_timeout_ms = busy_timeout_ms
        self._clock = clock

    @property
    def database_path(self) -> Path:
        return self._path

    def _connect(self, *, create: bool = False) -> sqlite3.Connection:
        if not create and not self._path.is_file():
            raise OpenAIQuotaStoreError(
                "store_not_initialized",
                "quota store does not exist",
            )
        if self._path.exists() and not self._path.is_file():
            raise OpenAIQuotaStoreError(
                "database_path_invalid",
                "quota store path is not a file",
            )
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                self._path,
                isolation_level=None,
                timeout=self._busy_timeout_ms / 1_000,
            )
            connection.row_factory = sqlite3.Row
            connection.execute(f"PRAGMA busy_timeout = {self._busy_timeout_ms}")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA recursive_triggers = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA synchronous = FULL")
            return connection
        except sqlite3.Error as exc:
            if connection is not None:
                connection.close()
            raise _translate_sqlite_error(exc) from exc

    def _require_schema(self, connection: sqlite3.Connection) -> None:
        version = int(connection.execute("PRAGMA user_version").fetchone()[0])
        application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
        if (
            version != OPENAI_QUOTA_STORE_SCHEMA_VERSION
            or application_id != OPENAI_QUOTA_STORE_APPLICATION_ID
        ):
            raise OpenAIQuotaStoreError(
                "schema_incompatible",
                "database is not a compatible Causure quota store",
            )
        required = {"quota_metadata", "quota_leases", "quota_operations"}
        found = {
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        if not required.issubset(found):
            raise OpenAIQuotaStoreError(
                "schema_incompatible",
                "quota store is missing required schema objects",
            )
        metadata = connection.execute(
            "SELECT value FROM quota_metadata WHERE key = 'schema_version'"
        ).fetchone()
        if metadata is None or metadata["value"] != str(OPENAI_QUOTA_STORE_SCHEMA_VERSION):
            raise OpenAIQuotaStoreError(
                "schema_incompatible",
                "quota store metadata is inconsistent",
            )
        if str(connection.execute("PRAGMA journal_mode").fetchone()[0]).lower() != "wal":
            raise OpenAIQuotaStoreError(
                "journal_mode_invalid",
                "quota store must use SQLite WAL journal mode",
            )

    @contextmanager
    def _write(self) -> Iterable[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            self._require_schema(connection)
            yield connection
            connection.execute("COMMIT")
        except OpenAIQuotaError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise _translate_sqlite_error(exc) from exc
        except Exception:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()

    @contextmanager
    def _read(self) -> Iterable[sqlite3.Connection]:
        connection = self._connect()
        try:
            self._require_schema(connection)
            connection.execute("PRAGMA query_only = ON")
            connection.execute("BEGIN")
            yield connection
            connection.execute("COMMIT")
        except OpenAIQuotaError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise _translate_sqlite_error(exc) from exc
        finally:
            connection.close()

    def initialize(self, *, created_at: str | None = None) -> None:
        if not self._path.parent.is_dir():
            raise OpenAIQuotaStoreError(
                "database_parent_missing",
                "quota database parent directory does not exist",
            )
        instant = created_at or utc_timestamp(_validate_clock(self._clock))
        _parse_timestamp(instant)
        connection = self._connect(create=True)
        try:
            mode = str(connection.execute("PRAGMA journal_mode = WAL").fetchone()[0]).lower()
            if mode != "wal":
                raise OpenAIQuotaStoreError(
                    "wal_unavailable",
                    "SQLite WAL journal mode could not be enabled",
                )
            connection.execute("BEGIN IMMEDIATE")
            version = int(connection.execute("PRAGMA user_version").fetchone()[0])
            application_id = int(connection.execute("PRAGMA application_id").fetchone()[0])
            object_count = int(
                connection.execute(
                    "SELECT count(*) FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'"
                ).fetchone()[0]
            )
            if (
                version == OPENAI_QUOTA_STORE_SCHEMA_VERSION
                and application_id == OPENAI_QUOTA_STORE_APPLICATION_ID
            ):
                connection.execute("COMMIT")
                self._require_schema(connection)
                return
            if version != 0 or application_id != 0 or object_count != 0:
                raise OpenAIQuotaStoreError(
                    "schema_incompatible",
                    "refusing to initialize a non-empty or incompatible database",
                )
            for statement in _QUOTA_SCHEMA:
                connection.execute(statement)
            connection.executemany(
                "INSERT INTO quota_metadata (key, value) VALUES (?, ?)",
                (
                    ("schema_version", str(OPENAI_QUOTA_STORE_SCHEMA_VERSION)),
                    ("created_at", instant),
                ),
            )
            connection.execute(f"PRAGMA application_id = {OPENAI_QUOTA_STORE_APPLICATION_ID}")
            connection.execute(f"PRAGMA user_version = {OPENAI_QUOTA_STORE_SCHEMA_VERSION}")
            connection.execute("COMMIT")
            self._require_schema(connection)
        except OpenAIQuotaError:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        except sqlite3.Error as exc:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise _translate_sqlite_error(exc) from exc
        finally:
            connection.close()

    def check(self) -> None:
        with self._read() as connection:
            result = str(connection.execute("PRAGMA quick_check").fetchone()[0])
            if result != "ok":
                raise OpenAIQuotaStoreError(
                    "integrity_check_failed",
                    "quota store quick integrity check failed",
                )

    def reserve(
        self,
        reservation: QuotaReservation,
        configuration: OpenAIQuotaConfiguration,
    ) -> QuotaLease:
        if type(reservation) is not QuotaReservation:
            raise TypeError("reservation must be a QuotaReservation")
        if type(configuration) is not OpenAIQuotaConfiguration:
            raise TypeError("configuration must be an OpenAIQuotaConfiguration")
        now = _validate_clock(self._clock)
        expires_epoch = math.ceil(
            now.timestamp() + reservation.timeout_seconds + configuration.lease_cleanup_seconds + 1
        )
        expires_at = _timestamp(datetime.fromtimestamp(expires_epoch, UTC))
        lease_id = f"oq-{secrets.token_hex(16)}"
        lease_token = secrets.token_urlsafe(32)
        token_sha256 = hashlib.sha256(lease_token.encode("ascii")).hexdigest()
        max_cost_nusd = _usd_to_nusd_floor(reservation.max_cost_usd)
        if max_cost_nusd > _SQLITE_MAX_INTEGER:
            raise OpenAIQuotaStoreError(
                "cost_invalid",
                "reservation cost exceeds the persistent accounting range",
            )
        with self._write() as connection:
            connection.execute(
                """
                INSERT INTO quota_leases (
                    lease_id, token_sha256, case_id, state, created_at, expires_at,
                    max_cost_nusd, max_concurrency, max_operations
                ) VALUES (?, ?, ?, 'active', ?, ?, ?, ?, ?)
                """,
                (
                    lease_id,
                    token_sha256,
                    reservation.case_id,
                    _timestamp(now),
                    expires_at,
                    max_cost_nusd,
                    reservation.max_concurrency,
                    reservation.max_operations,
                ),
            )
        return QuotaLease(
            lease_id=lease_id,
            lease_token=lease_token,
            enforcement=QuotaEnforcement.PROVIDER_HARD_LIMIT,
            proxy_url=configuration.worker_proxy_url,
            proxy_container_name=configuration.proxy_container_name,
            network_name=configuration.network_name,
            expires_at=expires_at,
            max_cost_usd=_nusd_to_usd(max_cost_nusd),
            max_concurrency=reservation.max_concurrency,
            max_operations=reservation.max_operations,
        )

    def begin_operation(
        self,
        *,
        lease_id: str,
        lease_token: str,
        request_sha256: str,
        model: str,
        input_token_limit: int,
        output_token_limit: int,
        reserved_cost_nusd: int,
    ) -> OpenAIQuotaOperation:
        if not isinstance(lease_id, str) or _OPENAI_LEASE_ID_PATTERN.fullmatch(lease_id) is None:
            raise OpenAIQuotaConflictError("lease_authentication_failed", "lease is invalid")
        try:
            _bounded_secret(lease_token, "lease_token")
        except ValueError as exc:
            raise OpenAIQuotaConflictError(
                "lease_authentication_failed",
                "lease credential is invalid",
            ) from exc
        if (
            not isinstance(request_sha256, str)
            or re.fullmatch(r"[a-f0-9]{64}", request_sha256) is None
        ):
            raise OpenAIQuotaStoreError("operation_invalid", "request SHA-256 is invalid")
        if not isinstance(model, str) or _MODEL_PATTERN.fullmatch(model) is None:
            raise OpenAIQuotaStoreError("operation_invalid", "operation model is invalid")
        if (
            type(input_token_limit) is not int
            or not 1 <= input_token_limit <= 10_000_000
            or type(output_token_limit) is not int
            or not 1 <= output_token_limit <= 1_000_000
            or type(reserved_cost_nusd) is not int
            or not 0 <= reserved_cost_nusd <= _SQLITE_MAX_INTEGER
        ):
            raise OpenAIQuotaStoreError("operation_invalid", "operation limits are invalid")
        token_sha256 = hashlib.sha256(lease_token.encode("utf-8")).hexdigest()
        now = _validate_clock(self._clock)
        with self._write() as connection:
            row = connection.execute(
                "SELECT * FROM quota_leases WHERE lease_id = ?",
                (lease_id,),
            ).fetchone()
            if row is None or not hmac.compare_digest(str(row["token_sha256"]), token_sha256):
                raise OpenAIQuotaConflictError(
                    "lease_authentication_failed",
                    "lease credential is invalid",
                )
            if row["state"] != "active":
                raise OpenAIQuotaConflictError(
                    "lease_inactive",
                    "lease is not active",
                )
            if now > _parse_timestamp(str(row["expires_at"])):
                raise OpenAIQuotaConflictError("lease_expired", "lease has expired")
            if int(row["operation_count"]) >= int(row["max_operations"]):
                raise OpenAIQuotaConflictError(
                    "operation_limit_exceeded",
                    "lease operation limit is exhausted",
                )
            if int(row["in_flight"]) >= int(row["max_concurrency"]):
                raise OpenAIQuotaConflictError(
                    "concurrency_limit_exceeded",
                    "lease concurrency limit is exhausted",
                )
            liability = (
                int(row["actual_cost_nusd"])
                + int(row["held_cost_nusd"])
                + int(row["uncertain_cost_nusd"])
                + reserved_cost_nusd
            )
            if liability > int(row["max_cost_nusd"]):
                raise OpenAIQuotaConflictError(
                    "cost_limit_exceeded",
                    "request maximum cost exceeds the remaining lease budget",
                )
            sequence = int(row["operation_count"]) + 1
            connection.execute(
                """
                INSERT INTO quota_operations (
                    lease_id, sequence, request_sha256, model, input_token_limit,
                    output_token_limit, reserved_cost_nusd, status, started_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, 'forwarding', ?)
                """,
                (
                    lease_id,
                    sequence,
                    request_sha256,
                    model,
                    input_token_limit,
                    output_token_limit,
                    reserved_cost_nusd,
                    _timestamp(now),
                ),
            )
            connection.execute(
                """
                UPDATE quota_leases
                SET operation_count = operation_count + 1,
                    in_flight = in_flight + 1,
                    held_cost_nusd = held_cost_nusd + ?
                WHERE lease_id = ?
                """,
                (reserved_cost_nusd, lease_id),
            )
        return OpenAIQuotaOperation(
            lease_id=lease_id,
            sequence=sequence,
            model=model,
            input_token_limit=input_token_limit,
            output_token_limit=output_token_limit,
            reserved_cost_nusd=reserved_cost_nusd,
        )

    def complete_operation(
        self,
        operation: OpenAIQuotaOperation,
        *,
        input_tokens: int,
        cached_input_tokens: int,
        output_tokens: int,
        actual_cost_nusd: int,
        upstream_response_id: str | None,
    ) -> None:
        if type(operation) is not OpenAIQuotaOperation:
            raise TypeError("operation must be an OpenAIQuotaOperation")
        if (
            type(input_tokens) is not int
            or type(cached_input_tokens) is not int
            or type(output_tokens) is not int
            or type(actual_cost_nusd) is not int
            or not 0 <= cached_input_tokens <= input_tokens <= operation.input_token_limit
            or not 0 <= output_tokens <= operation.output_token_limit
            or not 0 <= actual_cost_nusd <= _SQLITE_MAX_INTEGER
            or (
                upstream_response_id is not None
                and (
                    not isinstance(upstream_response_id, str)
                    or not 1 <= len(upstream_response_id) <= 255
                    or any(
                        ord(character) < 32 or ord(character) == 127
                        for character in upstream_response_id
                    )
                )
            )
        ):
            raise OpenAIQuotaStoreError(
                "provider_accounting_invalid",
                "provider accounting values are invalid",
            )
        now = _timestamp(_validate_clock(self._clock))
        with self._write() as connection:
            row = connection.execute(
                """
                SELECT status, reserved_cost_nusd
                FROM quota_operations
                WHERE lease_id = ? AND sequence = ?
                """,
                (operation.lease_id, operation.sequence),
            ).fetchone()
            if row is None or row["status"] != "forwarding":
                raise OpenAIQuotaStoreError(
                    "operation_state_invalid",
                    "operation is not awaiting provider accounting",
                )
            reserved = int(row["reserved_cost_nusd"])
            if actual_cost_nusd > reserved:
                connection.execute(
                    """
                    UPDATE quota_operations
                    SET status = 'accounting_failed', finished_at = ?,
                        input_tokens = ?, cached_input_tokens = ?, output_tokens = ?,
                        actual_cost_nusd = ?, upstream_response_id = ?,
                        failure_reason = 'provider_accounting_exceeded_authorization'
                    WHERE lease_id = ? AND sequence = ?
                    """,
                    (
                        now,
                        input_tokens,
                        cached_input_tokens,
                        output_tokens,
                        actual_cost_nusd,
                        upstream_response_id,
                        operation.lease_id,
                        operation.sequence,
                    ),
                )
                connection.execute(
                    """
                    UPDATE quota_leases
                    SET state = CASE WHEN state = 'active' THEN 'failed' ELSE state END,
                        in_flight = in_flight - 1,
                        held_cost_nusd = held_cost_nusd - ?,
                        uncertain_cost_nusd = uncertain_cost_nusd + ?,
                        terminal_reason = CASE
                            WHEN state = 'active'
                            THEN 'provider_accounting_exceeded_authorization'
                            ELSE terminal_reason
                        END,
                        terminal_at = CASE WHEN state = 'active' THEN ? ELSE terminal_at END
                    WHERE lease_id = ?
                    """,
                    (reserved, reserved, now, operation.lease_id),
                )
                raise OpenAIQuotaStoreError(
                    "provider_accounting_exceeded_authorization",
                    "provider accounting exceeded the preauthorized maximum",
                )
            connection.execute(
                """
                UPDATE quota_operations
                SET status = 'completed', finished_at = ?, input_tokens = ?,
                    cached_input_tokens = ?, output_tokens = ?, actual_cost_nusd = ?,
                    upstream_response_id = ?
                WHERE lease_id = ? AND sequence = ?
                """,
                (
                    now,
                    input_tokens,
                    cached_input_tokens,
                    output_tokens,
                    actual_cost_nusd,
                    upstream_response_id,
                    operation.lease_id,
                    operation.sequence,
                ),
            )
            connection.execute(
                """
                UPDATE quota_leases
                SET successful_operations = successful_operations + 1,
                    in_flight = in_flight - 1,
                    held_cost_nusd = held_cost_nusd - ?,
                    actual_cost_nusd = actual_cost_nusd + ?
                WHERE lease_id = ?
                """,
                (reserved, actual_cost_nusd, operation.lease_id),
            )

    def mark_operation_uncertain(
        self,
        operation: OpenAIQuotaOperation,
        *,
        reason_code: str,
    ) -> None:
        _safe_text(reason_code, "reason_code", pattern=_SAFE_ID_PATTERN)
        now = _timestamp(_validate_clock(self._clock))
        with self._write() as connection:
            row = connection.execute(
                """
                SELECT status, reserved_cost_nusd
                FROM quota_operations
                WHERE lease_id = ? AND sequence = ?
                """,
                (operation.lease_id, operation.sequence),
            ).fetchone()
            if row is None:
                raise OpenAIQuotaStoreError("operation_not_found", "operation does not exist")
            if row["status"] != "forwarding":
                return
            reserved = int(row["reserved_cost_nusd"])
            connection.execute(
                """
                UPDATE quota_operations
                SET status = 'uncertain', finished_at = ?, failure_reason = ?
                WHERE lease_id = ? AND sequence = ?
                """,
                (now, reason_code, operation.lease_id, operation.sequence),
            )
            lease = connection.execute(
                "SELECT state FROM quota_leases WHERE lease_id = ?",
                (operation.lease_id,),
            ).fetchone()
            if lease is None:
                raise OpenAIQuotaStoreError("lease_not_found", "lease does not exist")
            terminal_update = (
                ", state = 'failed', terminal_reason = ?, terminal_at = ?"
                if lease["state"] == "active"
                else ""
            )
            parameters: tuple[Any, ...] = (reserved, reserved)
            if terminal_update:
                parameters += (reason_code, now)
            parameters += (operation.lease_id,)
            connection.execute(
                f"""
                UPDATE quota_leases
                SET in_flight = in_flight - 1,
                    held_cost_nusd = held_cost_nusd - ?,
                    uncertain_cost_nusd = uncertain_cost_nusd + ?
                    {terminal_update}
                WHERE lease_id = ?
                """,
                parameters,
            )

    def settle(self, lease_id: str, *, completed_operations: int) -> QuotaSettlement:
        now = _timestamp(_validate_clock(self._clock))
        with self._write() as connection:
            row = connection.execute(
                "SELECT * FROM quota_leases WHERE lease_id = ?",
                (lease_id,),
            ).fetchone()
            if row is None:
                raise OpenAIQuotaStoreError("lease_not_found", "lease does not exist")
            if row["state"] != "active":
                raise OpenAIQuotaConflictError(
                    "lease_not_settleable",
                    "lease is not active and cleanly settleable",
                )
            if int(row["in_flight"]) != 0 or int(row["held_cost_nusd"]) != 0:
                raise OpenAIQuotaConflictError(
                    "operations_in_flight",
                    "lease still has provider operations in flight",
                )
            if int(row["uncertain_cost_nusd"]) != 0:
                raise OpenAIQuotaConflictError(
                    "provider_cost_uncertain",
                    "lease includes an operation without authoritative provider accounting",
                )
            if (
                type(completed_operations) is not int
                or completed_operations != int(row["successful_operations"])
                or int(row["operation_count"]) != int(row["successful_operations"])
            ):
                raise OpenAIQuotaConflictError(
                    "completed_operations_mismatch",
                    "sandbox completion count does not match successful provider operations",
                )
            connection.execute(
                """
                UPDATE quota_leases
                SET state = 'settled', terminal_reason = 'settled', terminal_at = ?
                WHERE lease_id = ?
                """,
                (now, lease_id),
            )
            actual_cost_nusd = int(row["actual_cost_nusd"])
        return QuotaSettlement(
            lease_id=lease_id,
            status="settled",
            actual_cost_usd=_nusd_to_usd(actual_cost_nusd),
            completed_operations=completed_operations,
        )

    def cancel(self, lease_id: str, *, reason_code: str) -> None:
        _safe_text(reason_code, "reason_code", pattern=_SAFE_ID_PATTERN)
        now = _timestamp(_validate_clock(self._clock))
        with self._write() as connection:
            row = connection.execute(
                "SELECT state, terminal_reason FROM quota_leases WHERE lease_id = ?",
                (lease_id,),
            ).fetchone()
            if row is None:
                raise OpenAIQuotaStoreError("lease_not_found", "lease does not exist")
            if row["state"] == "settled":
                raise OpenAIQuotaConflictError(
                    "lease_already_settled",
                    "settled lease cannot be canceled",
                )
            if row["state"] == "failed":
                return
            if row["state"] == "canceled":
                if row["terminal_reason"] != reason_code:
                    raise OpenAIQuotaConflictError(
                        "cancellation_reason_mismatch",
                        "lease was already canceled for a different reason",
                    )
                return
            connection.execute(
                """
                UPDATE quota_leases
                SET state = 'canceled', terminal_reason = ?, terminal_at = ?
                WHERE lease_id = ?
                """,
                (reason_code, now, lease_id),
            )

    def lease_snapshot(self, lease_id: str) -> Mapping[str, Any]:
        """Return a non-secret diagnostic snapshot for tests and operators."""

        with self._read() as connection:
            row = connection.execute(
                """
                SELECT lease_id, case_id, state, created_at, expires_at, max_cost_nusd,
                       max_concurrency, max_operations, operation_count,
                       successful_operations, in_flight, held_cost_nusd,
                       actual_cost_nusd, uncertain_cost_nusd, terminal_reason, terminal_at
                FROM quota_leases WHERE lease_id = ?
                """,
                (lease_id,),
            ).fetchone()
            if row is None:
                raise OpenAIQuotaStoreError("lease_not_found", "lease does not exist")
            return dict(row)


@dataclass(frozen=True, slots=True)
class OpenAIUpstreamResponse:
    status: int
    content_type: str
    body: bytes


class OpenAIUpstreamTransport(Protocol):
    def send(self, body: bytes) -> OpenAIUpstreamResponse: ...


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


def _read_bounded_response(response: Any, maximum_bytes: int) -> tuple[str, bytes]:
    content_types = _header_values(response.headers, "Content-Type")
    if len(content_types) != 1:
        raise OpenAIQuotaUpstreamError(
            "upstream_content_type_invalid",
            "provider response is not application/json",
        )
    content_type = content_types[0]
    media_type = content_type.split(";", maxsplit=1)[0].strip().lower()
    if media_type != "application/json":
        raise OpenAIQuotaUpstreamError(
            "upstream_content_type_invalid",
            "provider response is not application/json",
        )
    encodings = _header_values(response.headers, "Content-Encoding")
    if encodings and (len(encodings) != 1 or encodings[0].strip().lower() not in {"", "identity"}):
        raise OpenAIQuotaUpstreamError(
            "upstream_content_encoding_invalid",
            "compressed provider responses are not accepted",
        )
    lengths = _header_values(response.headers, "Content-Length")
    if lengths:
        if len(lengths) != 1 or not lengths[0].isdigit() or int(lengths[0]) > maximum_bytes:
            raise OpenAIQuotaUpstreamError(
                "upstream_response_too_large",
                "provider response exceeds the configured size limit",
            )
    body = response.read(maximum_bytes + 1)
    if not isinstance(body, bytes) or not 1 <= len(body) <= maximum_bytes:
        raise OpenAIQuotaUpstreamError(
            "upstream_response_too_large",
            "provider response is empty or exceeds the configured size limit",
        )
    if lengths and len(body) != int(lengths[0]):
        raise OpenAIQuotaUpstreamError(
            "upstream_content_length_mismatch",
            "provider response length changed during transfer",
        )
    return str(content_type), body


def _header_values(headers: Any, name: str) -> list[str]:
    if hasattr(headers, "get_all"):
        return [str(value) for value in headers.get_all(name, [])]
    value = headers.get(name) if hasattr(headers, "get") else None
    return [] if value is None else [str(value)]


class HTTPSOpenAIResponsesTransport:
    """Fixed verified HTTPS transport that owns the real provider credential."""

    def __init__(
        self,
        configuration: OpenAIQuotaConfiguration,
        provider_api_key: str,
        *,
        opener: Any | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        if type(configuration) is not OpenAIQuotaConfiguration:
            raise TypeError("configuration must be an OpenAIQuotaConfiguration")
        self._api_key = _bounded_secret(provider_api_key, "provider_api_key")
        if opener is not None and not hasattr(opener, "open"):
            raise TypeError("opener must provide open()")
        if opener is not None and ssl_context is not None:
            raise ValueError("ssl_context cannot be combined with a custom opener")
        if opener is None:
            context = ssl_context or ssl.create_default_context()
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError("ssl_context must verify certificates and hostnames")
            opener = build_opener(
                ProxyHandler({}),
                _NoRedirectHandler(),
                HTTPSHandler(context=context),
            )
        self._configuration = configuration
        self._opener = opener

    def __repr__(self) -> str:
        return (
            f"{type(self).__name__}(upstream_responses_url="
            f"{self._configuration.upstream_responses_url!r})"
        )

    def send(self, body: bytes) -> OpenAIUpstreamResponse:
        request = Request(
            self._configuration.upstream_responses_url,
            data=body,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._api_key}",
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": f"causure/{PACKAGE_VERSION}",
            },
            method="POST",
        )
        response: Any | None = None
        try:
            response = self._opener.open(
                request,
                timeout=self._configuration.upstream_timeout_seconds,
            )
            if response.geturl() != self._configuration.upstream_responses_url:
                raise OpenAIQuotaUpstreamError(
                    "upstream_redirect_rejected",
                    "provider endpoint redirected",
                )
            content_type, response_body = _read_bounded_response(
                response,
                self._configuration.max_response_bytes,
            )
            return OpenAIUpstreamResponse(
                status=int(response.status),
                content_type=content_type,
                body=response_body,
            )
        except HTTPError as exc:
            try:
                if 300 <= int(exc.code) < 400:
                    raise OpenAIQuotaUpstreamError(
                        "upstream_redirect_rejected",
                        "provider endpoint redirected",
                    ) from exc
                if exc.geturl() != self._configuration.upstream_responses_url:
                    raise OpenAIQuotaUpstreamError(
                        "upstream_redirect_rejected",
                        "provider endpoint changed its final URL",
                    ) from exc
                content_type, response_body = _read_bounded_response(
                    exc,
                    self._configuration.max_response_bytes,
                )
                return OpenAIUpstreamResponse(
                    status=int(exc.code),
                    content_type=content_type,
                    body=response_body,
                )
            finally:
                exc.close()
        except OpenAIQuotaUpstreamError:
            raise
        except (TimeoutError, URLError, OSError) as exc:
            raise OpenAIQuotaUpstreamError(
                "upstream_unavailable",
                "provider endpoint could not be reached securely",
            ) from exc
        finally:
            if response is not None:
                response.close()


def _strict_json_object(data: bytes, *, name: str, maximum_bytes: int) -> Mapping[str, Any]:
    try:
        value = parse_json_text(
            data.decode("utf-8"),
            source=name,
            max_bytes=maximum_bytes,
        )
    except (InputDocumentError, UnicodeDecodeError) as exc:
        raise OpenAIQuotaError("json_invalid", f"{name} is not strict UTF-8 JSON") from exc
    if type(value) is not dict:
        raise OpenAIQuotaError("json_invalid", f"{name} must be a JSON object")
    return value


def _validate_input_content(value: Any, *, path: str) -> None:
    if isinstance(value, str):
        if len(value) > MAX_OPENAI_QUOTA_REQUEST_BYTES:
            raise OpenAIQuotaConflictError("request_invalid", f"{path} is oversized")
        return
    if type(value) is not list or not value:
        raise OpenAIQuotaConflictError(
            "request_invalid",
            f"{path} must be text or a non-empty text-message array",
        )
    for index, message_value in enumerate(value):
        if type(message_value) is not dict or set(message_value) != {"role", "content"}:
            raise OpenAIQuotaConflictError(
                "request_invalid",
                f"{path}[{index}] must contain only role and content",
            )
        if message_value["role"] not in _ALLOWED_MESSAGE_ROLES:
            raise OpenAIQuotaConflictError(
                "request_invalid",
                f"{path}[{index}].role is not allowed",
            )
        content = message_value["content"]
        if isinstance(content, str):
            continue
        if type(content) is not list or not content:
            raise OpenAIQuotaConflictError(
                "request_invalid",
                f"{path}[{index}].content must be text-only",
            )
        for content_index, part in enumerate(content):
            if type(part) is not dict or set(part) != {"type", "text"}:
                raise OpenAIQuotaConflictError(
                    "request_invalid",
                    f"{path}[{index}].content[{content_index}] must be input_text only",
                )
            if part["type"] != "input_text" or not isinstance(part["text"], str):
                raise OpenAIQuotaConflictError(
                    "request_invalid",
                    f"{path}[{index}].content[{content_index}] must be input_text only",
                )


@dataclass(frozen=True, slots=True)
class _AuthorizedRequest:
    body: bytes
    model: str
    pricing: OpenAIModelPricing
    input_token_limit: int
    output_token_limit: int
    maximum_cost_nusd: int


def _authorize_request(
    body: bytes,
    configuration: OpenAIQuotaConfiguration,
) -> _AuthorizedRequest:
    try:
        document = _strict_json_object(
            body,
            name="OpenAI-compatible request",
            maximum_bytes=configuration.max_request_bytes,
        )
    except OpenAIQuotaError as exc:
        raise OpenAIQuotaConflictError("request_invalid", exc.message) from exc
    unknown = sorted(set(document) - _ALLOWED_REQUEST_FIELDS)
    required = {"model", "input", "max_output_tokens", "store"}
    missing = sorted(required - set(document))
    if unknown or missing:
        raise OpenAIQuotaConflictError(
            "request_invalid",
            "request does not match the closed text-only Responses contract",
        )
    model = document["model"]
    if not isinstance(model, str) or _MODEL_PATTERN.fullmatch(model) is None:
        raise OpenAIQuotaConflictError("request_invalid", "request model is invalid")
    pricing = configuration.pricing_for(model)
    if document["store"] is not False:
        raise OpenAIQuotaConflictError(
            "request_invalid",
            "request must explicitly set store to false",
        )
    if document.get("stream", False) is not False:
        raise OpenAIQuotaConflictError(
            "request_invalid",
            "streaming responses are outside the qualified quota contract",
        )
    instructions = document.get("instructions")
    if instructions is not None and not isinstance(instructions, str):
        raise OpenAIQuotaConflictError(
            "request_invalid",
            "instructions must be text when present",
        )
    _validate_input_content(document["input"], path="$.input")
    output_limit = document["max_output_tokens"]
    if type(output_limit) is not int or not 1 <= output_limit <= pricing.max_output_tokens:
        raise OpenAIQuotaConflictError(
            "request_invalid",
            "max_output_tokens is absent or exceeds protected model configuration",
        )
    input_limit = pricing.max_input_tokens
    maximum_cost = pricing.maximum_cost_nusd(input_limit, output_limit)
    return _AuthorizedRequest(
        body=body,
        model=model,
        pricing=pricing,
        input_token_limit=input_limit,
        output_token_limit=output_limit,
        maximum_cost_nusd=maximum_cost,
    )


def _usage_accounting(
    response_body: bytes,
    authorized: _AuthorizedRequest,
) -> tuple[int, int, int, int, str | None]:
    try:
        document = _strict_json_object(
            response_body,
            name="OpenAI-compatible response",
            maximum_bytes=MAX_OPENAI_QUOTA_RESPONSE_BYTES,
        )
    except OpenAIQuotaError as exc:
        raise OpenAIQuotaUpstreamError("upstream_json_invalid", exc.message) from exc
    if document.get("model") != authorized.model:
        raise OpenAIQuotaUpstreamError(
            "upstream_model_mismatch",
            "provider response model does not match protected request model",
        )
    usage = document.get("usage")
    if type(usage) is not dict:
        raise OpenAIQuotaUpstreamError(
            "upstream_usage_missing",
            "provider response omitted authoritative token usage",
        )
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    details = usage.get("input_tokens_details", {})
    if type(details) is not dict:
        raise OpenAIQuotaUpstreamError(
            "upstream_usage_invalid",
            "provider cached-token usage is invalid",
        )
    cached_tokens = details.get("cached_tokens", 0)
    if (
        type(input_tokens) is not int
        or type(output_tokens) is not int
        or type(cached_tokens) is not int
        or not 0 <= cached_tokens <= input_tokens <= authorized.input_token_limit
        or not 0 <= output_tokens <= authorized.output_token_limit
    ):
        raise OpenAIQuotaUpstreamError(
            "upstream_usage_out_of_bounds",
            "provider usage exceeds the preauthorized token bounds",
        )
    response_id = document.get("id")
    if response_id is not None and (
        not isinstance(response_id, str)
        or not 1 <= len(response_id) <= 255
        or any(ord(character) < 32 or ord(character) == 127 for character in response_id)
    ):
        raise OpenAIQuotaUpstreamError(
            "upstream_response_id_invalid",
            "provider response identifier is invalid",
        )
    actual_cost = authorized.pricing.actual_cost_nusd(
        input_tokens=input_tokens,
        cached_input_tokens=cached_tokens,
        output_tokens=output_tokens,
    )
    return input_tokens, cached_tokens, output_tokens, actual_cost, response_id


def _json_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")


def _read_wsgi_json(environ: Mapping[str, Any], maximum_bytes: int) -> bytes:
    content_type = environ.get("CONTENT_TYPE")
    if not isinstance(content_type, str) or not content_type:
        raise _QuotaHTTPError(
            415,
            "content_type_unsupported",
            "Content-Type must be application/json",
        )
    segments = [segment.strip() for segment in content_type.split(";")]
    if segments[0].lower() != "application/json" or any(
        parameter.lower() not in {"charset=utf-8", 'charset="utf-8"'} for parameter in segments[1:]
    ):
        raise _QuotaHTTPError(
            415,
            "content_type_unsupported",
            "Content-Type must be UTF-8 application/json",
        )
    raw_length = environ.get("CONTENT_LENGTH")
    if not isinstance(raw_length, str) or not raw_length:
        raise _QuotaHTTPError(411, "content_length_required", "Content-Length is required")
    if _CONTENT_LENGTH_PATTERN.fullmatch(raw_length) is None:
        raise _QuotaHTTPError(400, "content_length_invalid", "Content-Length is invalid")
    length = int(raw_length)
    if not 1 <= length <= maximum_bytes:
        raise _QuotaHTTPError(
            413,
            "request_too_large",
            "request is empty or exceeds the configured size limit",
        )
    stream = environ.get("wsgi.input")
    if stream is None or not hasattr(stream, "read"):
        raise _QuotaHTTPError(400, "request_invalid", "request body stream is unavailable")
    body = stream.read(length + 1)
    if not isinstance(body, bytes) or len(body) != length:
        raise _QuotaHTTPError(
            400,
            "content_length_mismatch",
            "request body length does not match Content-Length",
        )
    return body


def _authorization(environ: Mapping[str, Any]) -> str:
    value = environ.get("HTTP_AUTHORIZATION")
    if not isinstance(value, str) or not value.startswith(_AUTHORIZATION_PREFIX) or "," in value:
        raise _QuotaHTTPError(
            401,
            "authentication_required",
            "a single bearer credential is required",
            headers=(("WWW-Authenticate", "Bearer"),),
        )
    token = value[len(_AUTHORIZATION_PREFIX) :]
    try:
        return _bounded_secret(token, "bearer_token")
    except ValueError as exc:
        raise _QuotaHTTPError(
            401,
            "authentication_required",
            "bearer credential is invalid",
            headers=(("WWW-Authenticate", "Bearer"),),
        ) from exc


def _lease_id_header(environ: Mapping[str, Any]) -> str:
    value = environ.get("HTTP_X_CAUSURE_LEASE_ID")
    if not isinstance(value, str) or _OPENAI_LEASE_ID_PATTERN.fullmatch(value) is None:
        raise _QuotaHTTPError(
            400,
            "lease_id_required",
            "X-Causure-Lease-Id is required",
        )
    return value


def _validate_upstream_response(
    response: Any,
    *,
    maximum_bytes: int,
) -> OpenAIUpstreamResponse:
    if (
        type(response) is not OpenAIUpstreamResponse
        or type(response.status) is not int
        or not 100 <= response.status <= 599
        or not isinstance(response.content_type, str)
        or response.content_type.split(";", maxsplit=1)[0].strip().lower() != "application/json"
        or any(ord(character) < 32 or ord(character) == 127 for character in response.content_type)
        or not isinstance(response.body, bytes)
        or not 1 <= len(response.body) <= maximum_bytes
    ):
        raise OpenAIQuotaUpstreamError(
            "upstream_response_invalid",
            "provider transport returned an invalid bounded response",
        )
    return response


_StartResponse = Callable[[str, list[tuple[str, str]]], Any]


class OpenAIQuotaWSGIApplication:
    """Closed admin and worker HTTP boundary around one transactional quota store."""

    def __init__(
        self,
        configuration: OpenAIQuotaConfiguration,
        store: SQLiteOpenAIQuotaStore,
        admin_token: str,
        upstream: OpenAIUpstreamTransport,
    ) -> None:
        if type(configuration) is not OpenAIQuotaConfiguration:
            raise TypeError("configuration must be an OpenAIQuotaConfiguration")
        if type(store) is not SQLiteOpenAIQuotaStore:
            raise TypeError("store must be a SQLiteOpenAIQuotaStore")
        if not hasattr(upstream, "send"):
            raise TypeError("upstream must provide send()")
        self._configuration = configuration
        self._store = store
        self._admin_token = _bounded_secret(admin_token, "admin_token")
        self._upstream = upstream

    def __repr__(self) -> str:
        return f"{type(self).__name__}(service_id={self._configuration.service_id!r})"

    @staticmethod
    def _response(
        start_response: _StartResponse,
        status: int,
        body: bytes,
        *,
        content_type: str = "application/json; charset=utf-8",
        headers: Iterable[tuple[str, str]] = (),
    ) -> list[bytes]:
        response_headers = [
            ("Content-Type", content_type),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            *headers,
        ]
        start_response(f"{status} {_STATUS_REASONS[status]}", response_headers)
        return [body]

    @classmethod
    def _error(
        cls,
        start_response: _StartResponse,
        status: int,
        code: str,
        message: str,
        *,
        headers: Iterable[tuple[str, str]] = (),
    ) -> list[bytes]:
        return cls._response(
            start_response,
            status,
            _json_bytes(
                {
                    "error": {
                        "message": message,
                        "type": "causure_quota_error",
                        "code": code,
                    }
                }
            ),
            headers=headers,
        )

    @staticmethod
    def _require_https(environ: Mapping[str, Any]) -> None:
        if environ.get("wsgi.url_scheme") != "https":
            raise _QuotaHTTPError(
                400,
                "https_required",
                "quota API requires a trusted HTTPS hosting boundary",
            )

    @staticmethod
    def _require_post(environ: Mapping[str, Any]) -> None:
        if environ.get("REQUEST_METHOD") != "POST":
            raise _QuotaHTTPError(
                405,
                "method_not_allowed",
                "route accepts POST only",
                headers=(("Allow", "POST"),),
            )

    @staticmethod
    def _require_no_query(environ: Mapping[str, Any]) -> None:
        if environ.get("QUERY_STRING") not in {None, ""}:
            raise _QuotaHTTPError(400, "query_rejected", "query parameters are not accepted")

    def _require_admin(self, environ: Mapping[str, Any]) -> None:
        token = _authorization(environ)
        if not hmac.compare_digest(token, self._admin_token):
            raise _QuotaHTTPError(
                401,
                "authentication_failed",
                "admin credential is invalid",
                headers=(("WWW-Authenticate", "Bearer"),),
            )

    def _reserve(self, body: bytes) -> bytes:
        try:
            document = _strict_json_object(
                body,
                name="quota reservation",
                maximum_bytes=self._configuration.max_request_bytes,
            )
            if set(document) != {
                "case_id",
                "max_cost_usd",
                "max_concurrency",
                "max_operations",
                "timeout_seconds",
            }:
                raise OpenAIQuotaError(
                    "reservation_invalid",
                    "reservation does not match the closed admin contract",
                )
            reservation = QuotaReservation(**document)
        except (OpenAIQuotaError, TypeError, ValueError) as exc:
            raise _QuotaHTTPError(
                400,
                "reservation_invalid",
                "quota reservation is invalid",
            ) from exc
        lease = self._store.reserve(reservation, self._configuration)
        return _json_bytes(
            {
                "lease_id": lease.lease_id,
                "lease_token": lease.lease_token,
                "enforcement": lease.enforcement.value,
                "proxy_url": lease.proxy_url,
                "proxy_container_name": lease.proxy_container_name,
                "network_name": lease.network_name,
                "expires_at": lease.expires_at,
                "max_cost_usd": lease.max_cost_usd,
                "max_concurrency": lease.max_concurrency,
                "max_operations": lease.max_operations,
            }
        )

    def _settle(self, lease_id: str, body: bytes) -> bytes:
        try:
            document = _strict_json_object(
                body,
                name="quota settlement",
                maximum_bytes=self._configuration.max_request_bytes,
            )
            if set(document) != {"completed_operations"}:
                raise OpenAIQuotaError(
                    "settlement_invalid",
                    "settlement does not match the closed admin contract",
                )
            settlement = self._store.settle(
                lease_id,
                completed_operations=document["completed_operations"],
            )
        except OpenAIQuotaConflictError as exc:
            raise _QuotaHTTPError(409, exc.code, exc.message) from exc
        except OpenAIQuotaStoreError:
            raise
        except (OpenAIQuotaError, TypeError, ValueError) as exc:
            raise _QuotaHTTPError(
                400,
                "settlement_invalid",
                "quota settlement is invalid",
            ) from exc
        return _json_bytes(
            {
                "lease_id": settlement.lease_id,
                "status": settlement.status,
                "actual_cost_usd": settlement.actual_cost_usd,
                "completed_operations": settlement.completed_operations,
            }
        )

    def _cancel(self, lease_id: str, body: bytes) -> bytes:
        try:
            document = _strict_json_object(
                body,
                name="quota cancellation",
                maximum_bytes=self._configuration.max_request_bytes,
            )
            if set(document) != {"reason_code"}:
                raise OpenAIQuotaError(
                    "cancellation_invalid",
                    "cancellation does not match the closed admin contract",
                )
            self._store.cancel(lease_id, reason_code=document["reason_code"])
        except OpenAIQuotaConflictError as exc:
            raise _QuotaHTTPError(409, exc.code, exc.message) from exc
        except OpenAIQuotaStoreError:
            raise
        except (OpenAIQuotaError, TypeError, ValueError) as exc:
            raise _QuotaHTTPError(
                400,
                "cancellation_invalid",
                "quota cancellation is invalid",
            ) from exc
        return _json_bytes({"lease_id": lease_id, "status": "canceled"})

    def _forward(self, environ: Mapping[str, Any], body: bytes) -> OpenAIUpstreamResponse:
        lease_id = _lease_id_header(environ)
        lease_token = _authorization(environ)
        try:
            authorized = _authorize_request(body, self._configuration)
            operation = self._store.begin_operation(
                lease_id=lease_id,
                lease_token=lease_token,
                request_sha256=hashlib.sha256(body).hexdigest(),
                model=authorized.model,
                input_token_limit=authorized.input_token_limit,
                output_token_limit=authorized.output_token_limit,
                reserved_cost_nusd=authorized.maximum_cost_nusd,
            )
        except OpenAIQuotaConflictError as exc:
            status = {
                "lease_authentication_failed": 401,
                "lease_inactive": 401,
                "lease_expired": 401,
                "cost_limit_exceeded": 402,
                "concurrency_limit_exceeded": 429,
                "operation_limit_exceeded": 429,
            }.get(exc.code, 400)
            raise _QuotaHTTPError(status, exc.code, exc.message) from exc
        try:
            response = _validate_upstream_response(
                self._upstream.send(body),
                maximum_bytes=self._configuration.max_response_bytes,
            )
            if response.status != 200:
                self._store.mark_operation_uncertain(
                    operation,
                    reason_code="upstream_non_success",
                )
                raise OpenAIQuotaUpstreamError(
                    "upstream_non_success",
                    "provider did not return a successful authoritative response",
                )
            (
                input_tokens,
                cached_tokens,
                output_tokens,
                actual_cost,
                response_id,
            ) = _usage_accounting(response.body, authorized)
            self._store.complete_operation(
                operation,
                input_tokens=input_tokens,
                cached_input_tokens=cached_tokens,
                output_tokens=output_tokens,
                actual_cost_nusd=actual_cost,
                upstream_response_id=response_id,
            )
            return response
        except OpenAIQuotaUpstreamError:
            self._store.mark_operation_uncertain(operation, reason_code="upstream_unavailable")
            raise
        except OpenAIQuotaStoreError:
            self._store.mark_operation_uncertain(
                operation,
                reason_code="provider_accounting_failed",
            )
            raise
        except Exception as exc:
            self._store.mark_operation_uncertain(operation, reason_code="upstream_failed")
            raise OpenAIQuotaUpstreamError(
                "upstream_failed",
                "provider operation failed without authoritative accounting",
            ) from exc

    def _dispatch(
        self,
        environ: Mapping[str, Any],
        start_response: _StartResponse,
    ) -> list[bytes]:
        path = environ.get("PATH_INFO")
        method = environ.get("REQUEST_METHOD")
        if path == "/healthz":
            if method != "GET":
                raise _QuotaHTTPError(
                    405,
                    "method_not_allowed",
                    "route accepts GET only",
                    headers=(("Allow", "GET"),),
                )
            return self._response(
                start_response,
                200,
                _json_bytes({"status": "ok", "version": PACKAGE_VERSION}),
            )
        if path == "/readyz":
            if method != "GET":
                raise _QuotaHTTPError(
                    405,
                    "method_not_allowed",
                    "route accepts GET only",
                    headers=(("Allow", "GET"),),
                )
            self._store.check()
            return self._response(
                start_response,
                200,
                _json_bytes({"status": "ready", "version": PACKAGE_VERSION}),
            )
        self._require_https(environ)
        self._require_no_query(environ)
        self._require_post(environ)
        if path == _ADMIN_RESERVE_PATH:
            self._require_admin(environ)
            body = _read_wsgi_json(environ, self._configuration.max_request_bytes)
            return self._response(start_response, 201, self._reserve(body))
        match = _LEASE_PATH_PATTERN.fullmatch(path) if isinstance(path, str) else None
        if match is not None:
            self._require_admin(environ)
            body = _read_wsgi_json(environ, self._configuration.max_request_bytes)
            if match.group(2) == "settle":
                return self._response(start_response, 200, self._settle(match.group(1), body))
            return self._response(start_response, 200, self._cancel(match.group(1), body))
        if path == _RESPONSES_PATH:
            body = _read_wsgi_json(environ, self._configuration.max_request_bytes)
            response = self._forward(environ, body)
            return self._response(
                start_response,
                response.status,
                response.body,
                content_type="application/json; charset=utf-8",
            )
        raise _QuotaHTTPError(404, "route_not_found", "requested route does not exist")

    def __call__(
        self,
        environ: Mapping[str, Any],
        start_response: _StartResponse,
    ) -> list[bytes]:
        try:
            return self._dispatch(environ, start_response)
        except _QuotaHTTPError as exc:
            return self._error(
                start_response,
                exc.status,
                exc.code,
                exc.message,
                headers=exc.headers,
            )
        except OpenAIQuotaConflictError as exc:
            return self._error(start_response, 409, exc.code, exc.message)
        except OpenAIQuotaUpstreamError as exc:
            status = 504 if exc.code == "upstream_unavailable" else 502
            return self._error(start_response, status, exc.code, exc.message)
        except OpenAIQuotaStoreError as exc:
            status = 503 if exc.code == "store_busy" else 500
            return self._error(
                start_response,
                status,
                exc.code,
                "quota accounting is unavailable",
            )
        except Exception:
            return self._error(
                start_response,
                500,
                "internal_error",
                "quota service failed closed",
            )


class OpenAIQuotaAdminTransport(Protocol):
    def post(self, path: str, document: Mapping[str, Any]) -> Mapping[str, Any]: ...


class HTTPSOpenAIQuotaAdminClient:
    """Direct verified HTTPS client for the protected quota admin API."""

    def __init__(
        self,
        admin_base_url: str,
        admin_token: str,
        *,
        timeout_seconds: float = 10.0,
        maximum_bytes: int = 64 * 1024,
        opener: Any | None = None,
        ssl_context: ssl.SSLContext | None = None,
    ) -> None:
        base = _https_url(admin_base_url, "admin_base_url")
        parsed = urlsplit(base)
        if parsed.path not in {"", "/"}:
            raise OpenAIQuotaConfigurationError(
                "configuration_invalid",
                "admin_base_url must not contain a path",
            )
        if opener is not None and not hasattr(opener, "open"):
            raise TypeError("opener must provide open()")
        if opener is not None and ssl_context is not None:
            raise ValueError("ssl_context cannot be combined with a custom opener")
        if opener is None:
            context = ssl_context or ssl.create_default_context()
            if not context.check_hostname or context.verify_mode != ssl.CERT_REQUIRED:
                raise ValueError("ssl_context must verify certificates and hostnames")
            opener = build_opener(
                ProxyHandler({}),
                _NoRedirectHandler(),
                HTTPSHandler(context=context),
            )
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 1.0 <= float(timeout_seconds) <= 30.0
            or type(maximum_bytes) is not int
            or not 1_024 <= maximum_bytes <= 1024 * 1024
        ):
            raise ValueError("admin client bounds are invalid")
        self._base_url = base.rstrip("/") + "/"
        self._admin_token = _bounded_secret(admin_token, "admin_token")
        self._timeout_seconds = float(timeout_seconds)
        self._maximum_bytes = maximum_bytes
        self._opener = opener

    def __repr__(self) -> str:
        return f"{type(self).__name__}(admin_base_url={self._base_url!r})"

    def post(self, path: str, document: Mapping[str, Any]) -> Mapping[str, Any]:
        if not isinstance(path, str) or _ADMIN_CLIENT_PATH_PATTERN.fullmatch(path) is None:
            raise OpenAIQuotaControllerError("admin_path_invalid", "admin path is invalid")
        url = urljoin(self._base_url, path.lstrip("/"))
        body = _json_bytes(document)
        request = Request(
            url,
            data=body,
            headers={
                "Accept": "application/json",
                "Authorization": f"Bearer {self._admin_token}",
                "Content-Type": "application/json; charset=utf-8",
                "User-Agent": f"causure/{PACKAGE_VERSION}",
            },
            method="POST",
        )
        response: Any | None = None
        try:
            response = self._opener.open(request, timeout=self._timeout_seconds)
            if response.geturl() != url or int(response.status) not in {200, 201}:
                raise OpenAIQuotaControllerError(
                    "admin_response_invalid",
                    "quota admin API returned an invalid response",
                )
            _, response_body = _read_bounded_response(response, self._maximum_bytes)
        except HTTPError as exc:
            try:
                raise OpenAIQuotaControllerError(
                    "admin_request_rejected",
                    "quota admin API rejected the request",
                ) from exc
            finally:
                exc.close()
        except OpenAIQuotaControllerError:
            raise
        except (OpenAIQuotaError, TimeoutError, URLError, OSError) as exc:
            raise OpenAIQuotaControllerError(
                "admin_unavailable",
                "quota admin API is unavailable",
            ) from exc
        finally:
            if response is not None:
                response.close()
        try:
            return _strict_json_object(
                response_body,
                name="quota admin response",
                maximum_bytes=self._maximum_bytes,
            )
        except OpenAIQuotaError as exc:
            raise OpenAIQuotaControllerError(
                "admin_response_invalid",
                "quota admin API returned invalid JSON",
            ) from exc


class OpenAIQuotaController:
    """Sandbox ProviderQuotaController backed by the protected admin API."""

    def __init__(self, client: OpenAIQuotaAdminTransport) -> None:
        if not hasattr(client, "post"):
            raise TypeError("client must provide post()")
        self._client = client

    def reserve(self, reservation: QuotaReservation) -> QuotaLease:
        if type(reservation) is not QuotaReservation:
            raise TypeError("reservation must be a QuotaReservation")
        document = self._client.post(
            _ADMIN_RESERVE_PATH,
            {
                "case_id": reservation.case_id,
                "max_cost_usd": reservation.max_cost_usd,
                "max_concurrency": reservation.max_concurrency,
                "max_operations": reservation.max_operations,
                "timeout_seconds": reservation.timeout_seconds,
            },
        )
        try:
            if set(document) != {
                "lease_id",
                "lease_token",
                "enforcement",
                "proxy_url",
                "proxy_container_name",
                "network_name",
                "expires_at",
                "max_cost_usd",
                "max_concurrency",
                "max_operations",
            }:
                raise ValueError("closed lease response mismatch")
            lease = QuotaLease(
                lease_id=document["lease_id"],
                lease_token=document["lease_token"],
                enforcement=QuotaEnforcement(document["enforcement"]),
                proxy_url=document["proxy_url"],
                proxy_container_name=document["proxy_container_name"],
                network_name=document["network_name"],
                expires_at=document["expires_at"],
                max_cost_usd=document["max_cost_usd"],
                max_concurrency=document["max_concurrency"],
                max_operations=document["max_operations"],
            )
            if _OPENAI_LEASE_ID_PATTERN.fullmatch(lease.lease_id) is None:
                raise ValueError("OpenAI-compatible lease identifier is invalid")
            return lease
        except (TypeError, ValueError) as exc:
            raise OpenAIQuotaControllerError(
                "lease_response_invalid",
                "quota admin API returned an invalid lease",
            ) from exc

    def settle(self, lease_id: str, *, completed_operations: int) -> QuotaSettlement:
        if not isinstance(lease_id, str) or _OPENAI_LEASE_ID_PATTERN.fullmatch(lease_id) is None:
            raise OpenAIQuotaControllerError("lease_id_invalid", "lease identifier is invalid")
        document = self._client.post(
            f"/admin/v1/leases/{lease_id}/settle",
            {"completed_operations": completed_operations},
        )
        try:
            if set(document) != {
                "lease_id",
                "status",
                "actual_cost_usd",
                "completed_operations",
            }:
                raise ValueError("closed settlement response mismatch")
            return QuotaSettlement(**document)
        except (TypeError, ValueError) as exc:
            raise OpenAIQuotaControllerError(
                "settlement_response_invalid",
                "quota admin API returned an invalid settlement",
            ) from exc

    def cancel(self, lease_id: str, *, reason_code: str) -> None:
        if not isinstance(lease_id, str) or _OPENAI_LEASE_ID_PATTERN.fullmatch(lease_id) is None:
            raise OpenAIQuotaControllerError("lease_id_invalid", "lease identifier is invalid")
        document = self._client.post(
            f"/admin/v1/leases/{lease_id}/cancel",
            {"reason_code": reason_code},
        )
        if document != {"lease_id": lease_id, "status": "canceled"}:
            raise OpenAIQuotaControllerError(
                "cancellation_response_invalid",
                "quota admin API returned an invalid cancellation",
            )
