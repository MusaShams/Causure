"""Closed single-host composition and serving boundary for the Team service."""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import json
import math
import os
import stat
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path
from typing import Any

from causure.constants import TEAM_HOST_CONFIG_SCHEMA_VERSION
from causure.io import InputDocumentError, parse_json_text
from causure.team_admission import TeamAdmissionControlMiddleware
from causure.team_application import TeamApplicationService
from causure.team_entra import EntraTeamIdentityMiddleware
from causure.team_entra_refresh import (
    MAX_ENTRA_REFRESH_CONFIG_BYTES,
    EntraRefreshConfiguration,
    ManagedEntraAccessTokenVerifier,
    parse_entra_refresh_configuration_bytes,
)
from causure.team_http import MAX_TEAM_HTTP_REQUEST_BYTES, TeamWSGIApplication
from causure.team_store import SQLiteTeamStore

MAX_TEAM_HOST_CONFIG_BYTES = 256 * 1024
MAX_TEAM_HOST_PATH_CHARACTERS = 4096
TEAM_HOST_SERVER_IMPLEMENTATION = "waitress"
TEAM_HOST_WAITRESS_VERSION = "3.0.2"
TEAM_HOST_REQUEST_SHUTDOWN_SECONDS = 5.0

_SAFE_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{2,127}$"
_SHA256_PATTERN = r"^[a-f0-9]{64}$"
_StartResponse = Callable[[str, list[tuple[str, str]]], Any]
_Application = Callable[[Mapping[str, Any], _StartResponse], Iterable[bytes]]
_CreateServer = Callable[..., Any]
_CloseAll = Callable[[dict[Any, Any]], Any]


def _is_expected_listener_close_error(exc: OSError) -> bool:
    return (
        exc.errno in {errno.EBADF, errno.ENOTSOCK, 10038} or getattr(exc, "winerror", None) == 10038
    )


class TeamHostConfigurationError(ValueError):
    """Raised when a protected Team host configuration is invalid."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"Invalid Team host configuration at {path}: {message}")


class TeamHostDependencyError(ValueError):
    """Raised when the qualified optional serving dependency is unavailable."""


class TeamHostRuntimeError(ValueError):
    """Raised with a stable code when host startup or shutdown fails closed."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"Team host failed [{code}]: {message}")


@dataclass(frozen=True, slots=True)
class TeamHostDatabaseConfiguration:
    path: str
    busy_timeout_ms: int


@dataclass(frozen=True, slots=True)
class TeamHostServerConfiguration:
    implementation: str
    version: str
    listen_host: str
    listen_port: int
    trusted_external_scheme: str
    threads: int
    connection_limit: int
    backlog: int
    channel_timeout_seconds: int
    max_request_header_bytes: int


@dataclass(frozen=True, slots=True)
class TeamHostIdentityConfiguration:
    refresh_configuration_path: str
    refresh_configuration_sha256: str
    refresh_configuration_byte_count: int
    trust_store_path: str
    store_id: str
    clock_skew_seconds: int
    refresh_timeout_seconds: float
    refresh_interval_seconds: float
    failure_retry_seconds: float
    unknown_key_refresh_seconds: float


@dataclass(frozen=True, slots=True)
class TeamHostAdmissionConfiguration:
    max_concurrency: int
    global_requests_per_window: int
    per_source_requests_per_window: int | None
    rate_window_seconds: float
    max_tracked_sources: int
    source_idle_seconds: float


@dataclass(frozen=True, slots=True)
class TeamHostConfiguration:
    schema_version: str
    database: TeamHostDatabaseConfiguration
    server: TeamHostServerConfiguration
    identity: TeamHostIdentityConfiguration
    admission: TeamHostAdmissionConfiguration


@dataclass(frozen=True, slots=True)
class TeamHostConfigurationSubject:
    path: str
    sha256: str
    byte_count: int
    configuration: TeamHostConfiguration


@dataclass(slots=True)
class TeamHostRuntime:
    """Own one composed application and its managed Entra refresh lifecycle."""

    configuration: TeamHostConfiguration
    store: SQLiteTeamStore
    verifier: ManagedEntraAccessTokenVerifier
    application: _Application
    _closed: bool = field(default=False, init=False, repr=False)

    def close(self, *, timeout_seconds: float = 30.0) -> None:
        if self._closed:
            return
        self.verifier.close(timeout_seconds=timeout_seconds)
        self._closed = True

    def __enter__(self) -> TeamHostRuntime:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


@dataclass(slots=True)
class TeamHostServer:
    """Own one controllable Waitress listener and its complete Team runtime."""

    configuration: TeamHostConfiguration
    runtime: TeamHostRuntime
    server: Any
    close_all: _CloseAll
    _closed: bool = field(default=False, init=False, repr=False)
    _run_started: bool = field(default=False, init=False, repr=False)
    _lifecycle_lock: threading.RLock = field(
        default_factory=threading.RLock,
        init=False,
        repr=False,
    )

    @property
    def closed(self) -> bool:
        with self._lifecycle_lock:
            return self._closed

    def run(self) -> None:
        with self._lifecycle_lock:
            if self._closed:
                raise TeamHostRuntimeError("server_closed", "the Team host server is closed")
            if self._run_started:
                raise TeamHostRuntimeError(
                    "server_already_run",
                    "the Team host server can be run only once",
                )
            self._run_started = True
        try:
            self.server.run()
        except OSError as exc:
            with self._lifecycle_lock:
                shutdown_started = self._closed
            if not shutdown_started or not _is_expected_listener_close_error(exc):
                raise
        finally:
            self.close()

    def close(
        self,
        *,
        request_timeout_seconds: float = TEAM_HOST_REQUEST_SHUTDOWN_SECONDS,
        refresh_timeout_seconds: float = 30.0,
    ) -> None:
        if (
            isinstance(request_timeout_seconds, bool)
            or not isinstance(request_timeout_seconds, (int, float))
            or not math.isfinite(float(request_timeout_seconds))
            or not 0.1 <= float(request_timeout_seconds) <= 30.0
        ):
            raise ValueError("request_timeout_seconds must be from 0.1 through 30 seconds")
        with self._lifecycle_lock:
            if self._closed:
                return
            self._closed = True
            failure: BaseException | None = None
            try:
                self.server.close()
            except BaseException as exc:
                failure = exc
            dispatcher = getattr(self.server, "task_dispatcher", None)
            if dispatcher is not None:
                try:
                    dispatcher.shutdown(
                        cancel_pending=True,
                        timeout=float(request_timeout_seconds),
                    )
                except BaseException as exc:
                    if failure is None:
                        failure = exc
            server_map = getattr(self.server, "_map", None)
            if server_map is None:
                server_map = getattr(self.server, "map", None)
            if isinstance(server_map, dict):
                try:
                    self.close_all(server_map)
                except BaseException as exc:
                    if failure is None:
                        failure = exc
            try:
                self.runtime.close(timeout_seconds=refresh_timeout_seconds)
            except BaseException as exc:
                if failure is None:
                    failure = exc
            if failure is not None:
                raise TeamHostRuntimeError(
                    "server_shutdown_failed",
                    "the Team host did not shut down cleanly",
                ) from failure

    def __enter__(self) -> TeamHostServer:
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


def _closed_object(
    value: Any,
    *,
    path: str,
    required: set[str],
) -> dict[str, Any]:
    if type(value) is not dict:
        raise TeamHostConfigurationError(path, "must be an object")
    keys = set(value)
    missing = required - keys
    unknown = keys - required
    if missing:
        raise TeamHostConfigurationError(path, f"missing required field {sorted(missing)[0]!r}")
    if unknown:
        raise TeamHostConfigurationError(path, f"unknown field {sorted(unknown)[0]!r}")
    return value


def _text(
    value: Any,
    *,
    path: str,
    minimum: int = 1,
    maximum: int,
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise TeamHostConfigurationError(
            path,
            f"must be text from {minimum} through {maximum} characters",
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise TeamHostConfigurationError(path, "must not contain control characters")
    return value


def _absolute_path(value: Any, *, path: str) -> str:
    text = _text(value, path=path, maximum=MAX_TEAM_HOST_PATH_CHARACTERS)
    if not Path(text).is_absolute():
        raise TeamHostConfigurationError(path, "must be an absolute path")
    if os.name == "nt" and text.startswith(("\\\\", "//")):
        raise TeamHostConfigurationError(path, "must be a local absolute path")
    return text


def _integer(value: Any, *, path: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise TeamHostConfigurationError(
            path,
            f"must be an integer from {minimum} through {maximum}",
        )
    return value


def _number(value: Any, *, path: str, minimum: float, maximum: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TeamHostConfigurationError(
            path,
            f"must be a number from {minimum:g} through {maximum:g}",
        )
    numeric = float(value)
    if not math.isfinite(numeric) or not minimum <= numeric <= maximum:
        raise TeamHostConfigurationError(
            path,
            f"must be a number from {minimum:g} through {maximum:g}",
        )
    return numeric


def _sha256(value: Any, *, path: str) -> str:
    text = _text(value, path=path, minimum=64, maximum=64)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise TeamHostConfigurationError(path, f"must match {_SHA256_PATTERN}")
    return text


def _safe_id(value: Any, *, path: str) -> str:
    text = _text(value, path=path, minimum=3, maximum=128)
    first = text[0]
    if (
        not first.isascii()
        or not first.isalnum()
        or any(
            not character.isascii() or (not character.isalnum() and character not in "._:+/@-")
            for character in text[1:]
        )
    ):
        raise TeamHostConfigurationError(path, f"must match {_SAFE_ID_PATTERN}")
    return text


def _canonical_loopback(value: Any, *, path: str) -> str:
    text = _text(value, path=path, maximum=64)
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise TeamHostConfigurationError(
            path,
            "must be a canonical loopback IP address",
        ) from exc
    if not address.is_loopback or str(address) != text or text not in {"127.0.0.1", "::1"}:
        raise TeamHostConfigurationError(path, "must be a canonical loopback IP address")
    return text


def _path_identity(value: str) -> str:
    return os.path.normcase(str(Path(value).resolve(strict=False)))


def parse_team_host_configuration(document: Any) -> TeamHostConfiguration:
    """Parse the complete closed configuration for one single-process Team host."""

    root = _closed_object(
        document,
        path="$",
        required={"schema_version", "database", "server", "identity", "admission"},
    )
    if root["schema_version"] != TEAM_HOST_CONFIG_SCHEMA_VERSION:
        raise TeamHostConfigurationError(
            "$.schema_version",
            f"must be {TEAM_HOST_CONFIG_SCHEMA_VERSION!r}",
        )

    database_value = _closed_object(
        root["database"],
        path="$.database",
        required={"path", "busy_timeout_ms"},
    )
    database = TeamHostDatabaseConfiguration(
        path=_absolute_path(database_value["path"], path="$.database.path"),
        busy_timeout_ms=_integer(
            database_value["busy_timeout_ms"],
            path="$.database.busy_timeout_ms",
            minimum=100,
            maximum=60000,
        ),
    )

    server_value = _closed_object(
        root["server"],
        path="$.server",
        required={
            "implementation",
            "version",
            "listen_host",
            "listen_port",
            "trusted_external_scheme",
            "threads",
            "connection_limit",
            "backlog",
            "channel_timeout_seconds",
            "max_request_header_bytes",
        },
    )
    if server_value["implementation"] != TEAM_HOST_SERVER_IMPLEMENTATION:
        raise TeamHostConfigurationError(
            "$.server.implementation",
            f"must be {TEAM_HOST_SERVER_IMPLEMENTATION!r}",
        )
    if server_value["version"] != TEAM_HOST_WAITRESS_VERSION:
        raise TeamHostConfigurationError(
            "$.server.version",
            f"must be {TEAM_HOST_WAITRESS_VERSION!r}",
        )
    if server_value["trusted_external_scheme"] != "https":
        raise TeamHostConfigurationError(
            "$.server.trusted_external_scheme",
            "must be 'https'",
        )
    server = TeamHostServerConfiguration(
        implementation=TEAM_HOST_SERVER_IMPLEMENTATION,
        version=TEAM_HOST_WAITRESS_VERSION,
        listen_host=_canonical_loopback(
            server_value["listen_host"],
            path="$.server.listen_host",
        ),
        listen_port=_integer(
            server_value["listen_port"],
            path="$.server.listen_port",
            minimum=1024,
            maximum=65535,
        ),
        trusted_external_scheme="https",
        threads=_integer(
            server_value["threads"],
            path="$.server.threads",
            minimum=1,
            maximum=64,
        ),
        connection_limit=_integer(
            server_value["connection_limit"],
            path="$.server.connection_limit",
            minimum=1,
            maximum=1024,
        ),
        backlog=_integer(
            server_value["backlog"],
            path="$.server.backlog",
            minimum=1,
            maximum=1024,
        ),
        channel_timeout_seconds=_integer(
            server_value["channel_timeout_seconds"],
            path="$.server.channel_timeout_seconds",
            minimum=5,
            maximum=300,
        ),
        max_request_header_bytes=_integer(
            server_value["max_request_header_bytes"],
            path="$.server.max_request_header_bytes",
            minimum=8192,
            maximum=65536,
        ),
    )
    if server.connection_limit < server.threads:
        raise TeamHostConfigurationError(
            "$.server.connection_limit",
            "must be at least the configured thread count",
        )
    if server.backlog > server.connection_limit:
        raise TeamHostConfigurationError(
            "$.server.backlog",
            "must not exceed the configured connection limit",
        )

    identity_value = _closed_object(
        root["identity"],
        path="$.identity",
        required={
            "refresh_configuration_path",
            "refresh_configuration_sha256",
            "refresh_configuration_byte_count",
            "trust_store_path",
            "store_id",
            "clock_skew_seconds",
            "refresh_timeout_seconds",
            "refresh_interval_seconds",
            "failure_retry_seconds",
            "unknown_key_refresh_seconds",
        },
    )
    identity = TeamHostIdentityConfiguration(
        refresh_configuration_path=_absolute_path(
            identity_value["refresh_configuration_path"],
            path="$.identity.refresh_configuration_path",
        ),
        refresh_configuration_sha256=_sha256(
            identity_value["refresh_configuration_sha256"],
            path="$.identity.refresh_configuration_sha256",
        ),
        refresh_configuration_byte_count=_integer(
            identity_value["refresh_configuration_byte_count"],
            path="$.identity.refresh_configuration_byte_count",
            minimum=1,
            maximum=MAX_ENTRA_REFRESH_CONFIG_BYTES,
        ),
        trust_store_path=_absolute_path(
            identity_value["trust_store_path"],
            path="$.identity.trust_store_path",
        ),
        store_id=_safe_id(identity_value["store_id"], path="$.identity.store_id"),
        clock_skew_seconds=_integer(
            identity_value["clock_skew_seconds"],
            path="$.identity.clock_skew_seconds",
            minimum=0,
            maximum=300,
        ),
        refresh_timeout_seconds=_number(
            identity_value["refresh_timeout_seconds"],
            path="$.identity.refresh_timeout_seconds",
            minimum=1,
            maximum=30,
        ),
        refresh_interval_seconds=_number(
            identity_value["refresh_interval_seconds"],
            path="$.identity.refresh_interval_seconds",
            minimum=60,
            maximum=86400,
        ),
        failure_retry_seconds=_number(
            identity_value["failure_retry_seconds"],
            path="$.identity.failure_retry_seconds",
            minimum=30,
            maximum=86400,
        ),
        unknown_key_refresh_seconds=_number(
            identity_value["unknown_key_refresh_seconds"],
            path="$.identity.unknown_key_refresh_seconds",
            minimum=300,
            maximum=86400,
        ),
    )
    if identity.failure_retry_seconds > identity.refresh_interval_seconds:
        raise TeamHostConfigurationError(
            "$.identity.failure_retry_seconds",
            "must not exceed refresh_interval_seconds",
        )

    admission_value = _closed_object(
        root["admission"],
        path="$.admission",
        required={
            "max_concurrency",
            "global_requests_per_window",
            "per_source_requests_per_window",
            "rate_window_seconds",
            "max_tracked_sources",
            "source_idle_seconds",
        },
    )
    per_source_value = admission_value["per_source_requests_per_window"]
    if per_source_value is None:
        per_source = None
    else:
        per_source = _integer(
            per_source_value,
            path="$.admission.per_source_requests_per_window",
            minimum=1,
            maximum=1000000,
        )
    admission = TeamHostAdmissionConfiguration(
        max_concurrency=_integer(
            admission_value["max_concurrency"],
            path="$.admission.max_concurrency",
            minimum=1,
            maximum=64,
        ),
        global_requests_per_window=_integer(
            admission_value["global_requests_per_window"],
            path="$.admission.global_requests_per_window",
            minimum=1,
            maximum=1000000,
        ),
        per_source_requests_per_window=per_source,
        rate_window_seconds=_number(
            admission_value["rate_window_seconds"],
            path="$.admission.rate_window_seconds",
            minimum=1,
            maximum=3600,
        ),
        max_tracked_sources=_integer(
            admission_value["max_tracked_sources"],
            path="$.admission.max_tracked_sources",
            minimum=1,
            maximum=100000,
        ),
        source_idle_seconds=_number(
            admission_value["source_idle_seconds"],
            path="$.admission.source_idle_seconds",
            minimum=1,
            maximum=86400,
        ),
    )
    if admission.max_concurrency > server.threads:
        raise TeamHostConfigurationError(
            "$.admission.max_concurrency",
            "must not exceed the configured server thread count",
        )
    if admission.global_requests_per_window < admission.max_concurrency:
        raise TeamHostConfigurationError(
            "$.admission.global_requests_per_window",
            "must be at least max_concurrency",
        )
    if (
        admission.per_source_requests_per_window is not None
        and admission.per_source_requests_per_window > admission.global_requests_per_window
    ):
        raise TeamHostConfigurationError(
            "$.admission.per_source_requests_per_window",
            "must not exceed global_requests_per_window",
        )
    if admission.source_idle_seconds < admission.rate_window_seconds:
        raise TeamHostConfigurationError(
            "$.admission.source_idle_seconds",
            "must be at least rate_window_seconds",
        )

    paths = {
        _path_identity(database.path),
        _path_identity(identity.refresh_configuration_path),
        _path_identity(identity.trust_store_path),
    }
    if len(paths) != 3:
        raise TeamHostConfigurationError(
            "$",
            "database, refresh configuration, and trust store paths must differ",
        )
    return TeamHostConfiguration(
        schema_version=TEAM_HOST_CONFIG_SCHEMA_VERSION,
        database=database,
        server=server,
        identity=identity,
        admission=admission,
    )


def parse_team_host_configuration_bytes(data: bytes) -> TeamHostConfiguration:
    """Decode bounded, duplicate-key-rejecting UTF-8 Team host JSON."""

    if not isinstance(data, bytes):
        raise TeamHostConfigurationError("$", "host configuration must be bytes")
    if not 1 <= len(data) <= MAX_TEAM_HOST_CONFIG_BYTES:
        raise TeamHostConfigurationError(
            "$",
            f"host configuration must contain from 1 to {MAX_TEAM_HOST_CONFIG_BYTES} bytes",
        )
    try:
        document = parse_json_text(
            data.decode("utf-8"),
            source="Team host configuration",
            max_bytes=MAX_TEAM_HOST_CONFIG_BYTES,
        )
    except (InputDocumentError, UnicodeDecodeError) as exc:
        raise TeamHostConfigurationError("$", f"must be strict UTF-8 JSON: {exc}") from exc
    return parse_team_host_configuration(document)


def _read_team_host_configuration_file(path: str | Path) -> tuple[Path, bytes]:
    source = Path(path)
    try:
        before = source.stat()
        if not stat.S_ISREG(before.st_mode):
            raise TeamHostConfigurationError("$", "host configuration path must be a file")
        with source.open("rb") as stream:
            data = stream.read(MAX_TEAM_HOST_CONFIG_BYTES + 1)
        after = source.stat()
    except TeamHostConfigurationError:
        raise
    except OSError as exc:
        raise TeamHostConfigurationError("$", "host configuration could not be read") from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or len(data) != before.st_size:
        raise TeamHostConfigurationError("$", "host configuration changed while being read")
    return source, data


def load_team_host_configuration(path: str | Path) -> TeamHostConfiguration:
    """Load one protected Team host configuration without accepting standard input."""

    _, data = _read_team_host_configuration_file(path)
    return parse_team_host_configuration_bytes(data)


def load_team_host_configuration_subject(
    path: str | Path,
) -> TeamHostConfigurationSubject:
    """Load a protected host configuration and return its exact registration subject."""

    source, data = _read_team_host_configuration_file(path)
    return TeamHostConfigurationSubject(
        path=str(source),
        sha256=hashlib.sha256(data).hexdigest(),
        byte_count=len(data),
        configuration=parse_team_host_configuration_bytes(data),
    )


def _configuration_document(configuration: TeamHostConfiguration) -> dict[str, Any]:
    return {
        "schema_version": configuration.schema_version,
        "database": {
            "path": configuration.database.path,
            "busy_timeout_ms": configuration.database.busy_timeout_ms,
        },
        "server": {
            "implementation": configuration.server.implementation,
            "version": configuration.server.version,
            "listen_host": configuration.server.listen_host,
            "listen_port": configuration.server.listen_port,
            "trusted_external_scheme": configuration.server.trusted_external_scheme,
            "threads": configuration.server.threads,
            "connection_limit": configuration.server.connection_limit,
            "backlog": configuration.server.backlog,
            "channel_timeout_seconds": configuration.server.channel_timeout_seconds,
            "max_request_header_bytes": configuration.server.max_request_header_bytes,
        },
        "identity": {
            "refresh_configuration_path": configuration.identity.refresh_configuration_path,
            "refresh_configuration_sha256": configuration.identity.refresh_configuration_sha256,
            "refresh_configuration_byte_count": (
                configuration.identity.refresh_configuration_byte_count
            ),
            "trust_store_path": configuration.identity.trust_store_path,
            "store_id": configuration.identity.store_id,
            "clock_skew_seconds": configuration.identity.clock_skew_seconds,
            "refresh_timeout_seconds": configuration.identity.refresh_timeout_seconds,
            "refresh_interval_seconds": configuration.identity.refresh_interval_seconds,
            "failure_retry_seconds": configuration.identity.failure_retry_seconds,
            "unknown_key_refresh_seconds": configuration.identity.unknown_key_refresh_seconds,
        },
        "admission": {
            "max_concurrency": configuration.admission.max_concurrency,
            "global_requests_per_window": configuration.admission.global_requests_per_window,
            "per_source_requests_per_window": (
                configuration.admission.per_source_requests_per_window
            ),
            "rate_window_seconds": configuration.admission.rate_window_seconds,
            "max_tracked_sources": configuration.admission.max_tracked_sources,
            "source_idle_seconds": configuration.admission.source_idle_seconds,
        },
    }


def render_team_host_configuration(configuration: TeamHostConfiguration) -> str:
    """Render a validated host configuration deterministically."""

    if not isinstance(configuration, TeamHostConfiguration):
        raise TypeError("configuration must be a TeamHostConfiguration")
    validated = parse_team_host_configuration(_configuration_document(configuration))
    return json.dumps(_configuration_document(validated), ensure_ascii=False, indent=2) + "\n"


def _read_refresh_configuration(
    configuration: TeamHostIdentityConfiguration,
) -> EntraRefreshConfiguration:
    source = Path(configuration.refresh_configuration_path)
    try:
        before = source.stat()
        if not stat.S_ISREG(before.st_mode):
            raise TeamHostRuntimeError(
                "identity_configuration_invalid",
                "the Entra refresh configuration path is not a regular file",
            )
        if before.st_size != configuration.refresh_configuration_byte_count:
            raise TeamHostRuntimeError(
                "identity_configuration_subject_mismatch",
                "the Entra refresh configuration byte count does not match host policy",
            )
        with source.open("rb") as stream:
            data = stream.read(MAX_ENTRA_REFRESH_CONFIG_BYTES + 1)
        after = source.stat()
    except TeamHostRuntimeError:
        raise
    except OSError as exc:
        raise TeamHostRuntimeError(
            "identity_configuration_unavailable",
            "the Entra refresh configuration could not be read",
        ) from exc
    if (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
    ) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or len(data) != before.st_size:
        raise TeamHostRuntimeError(
            "identity_configuration_changed",
            "the Entra refresh configuration changed while being read",
        )
    if hashlib.sha256(data).hexdigest() != configuration.refresh_configuration_sha256:
        raise TeamHostRuntimeError(
            "identity_configuration_subject_mismatch",
            "the Entra refresh configuration digest does not match host policy",
        )
    parsed = parse_entra_refresh_configuration_bytes(data)
    if parsed.store_id != configuration.store_id:
        raise TeamHostRuntimeError(
            "identity_store_mismatch",
            "the Entra refresh configuration store does not match host policy",
        )
    return parsed


def _validate_runtime_paths(configuration: TeamHostConfiguration) -> None:
    database = Path(configuration.database.path)
    trust_store = Path(configuration.identity.trust_store_path)
    for path, name in ((database, "database"), (trust_store, "trust store")):
        try:
            parent = path.parent
            if not parent.is_dir():
                raise TeamHostRuntimeError(
                    "path_parent_unavailable",
                    f"the configured {name} parent directory is unavailable",
                )
            if path.exists() and not path.is_file():
                raise TeamHostRuntimeError(
                    "path_invalid",
                    f"the configured {name} path is not a regular file",
                )
        except OSError as exc:
            raise TeamHostRuntimeError(
                "path_unavailable",
                f"the configured {name} path could not be inspected",
            ) from exc


def create_team_host_runtime(configuration: TeamHostConfiguration) -> TeamHostRuntime:
    """Initialize the store and compose admission, Entra, and Team WSGI layers."""

    if not isinstance(configuration, TeamHostConfiguration):
        raise TypeError("configuration must be a TeamHostConfiguration")
    configuration = parse_team_host_configuration(_configuration_document(configuration))
    _validate_runtime_paths(configuration)
    refresh_configuration = _read_refresh_configuration(configuration.identity)
    store = SQLiteTeamStore(
        configuration.database.path,
        busy_timeout_ms=configuration.database.busy_timeout_ms,
    )
    store.initialize()
    verifier = ManagedEntraAccessTokenVerifier(
        refresh_configuration,
        configuration.identity.trust_store_path,
        clock_skew_seconds=configuration.identity.clock_skew_seconds,
        timeout_seconds=configuration.identity.refresh_timeout_seconds,
        refresh_interval_seconds=configuration.identity.refresh_interval_seconds,
        failure_retry_seconds=configuration.identity.failure_retry_seconds,
        unknown_key_refresh_seconds=configuration.identity.unknown_key_refresh_seconds,
    )
    try:
        verifier.start()
        team = TeamWSGIApplication(TeamApplicationService(store))
        authenticated = EntraTeamIdentityMiddleware(team, verifier, require_https=True)
        admission = configuration.admission
        application = TeamAdmissionControlMiddleware(
            authenticated,
            max_concurrency=admission.max_concurrency,
            global_requests_per_window=admission.global_requests_per_window,
            per_source_requests_per_window=admission.per_source_requests_per_window,
            rate_window_seconds=admission.rate_window_seconds,
            max_tracked_sources=admission.max_tracked_sources,
            source_idle_seconds=admission.source_idle_seconds,
        )
        return TeamHostRuntime(
            configuration=configuration,
            store=store,
            verifier=verifier,
            application=application,
        )
    except BaseException:
        verifier.close()
        raise


def _load_waitress_server(expected_version: str) -> tuple[_CreateServer, _CloseAll, type[Any]]:
    try:
        installed_version = metadata.version(TEAM_HOST_SERVER_IMPLEMENTATION)
        from waitress import create_server
        from waitress.adjustments import Adjustments
        from waitress.wasyncore import close_all
    except (ImportError, metadata.PackageNotFoundError) as exc:
        raise TeamHostDependencyError(
            "team-serve requires the pinned 'causure[service]' optional dependencies"
        ) from exc
    if installed_version != expected_version:
        raise TeamHostDependencyError(
            "team-serve requires exact Waitress version "
            f"{expected_version}; found {installed_version}"
        )
    return create_server, close_all, Adjustments


def _waitress_arguments(configuration: TeamHostConfiguration) -> dict[str, Any]:
    server = configuration.server
    return {
        "host": server.listen_host,
        "port": server.listen_port,
        "threads": server.threads,
        "connection_limit": server.connection_limit,
        "backlog": server.backlog,
        "channel_timeout": server.channel_timeout_seconds,
        "cleanup_interval": min(30, server.channel_timeout_seconds),
        "max_request_header_size": server.max_request_header_bytes,
        "max_request_body_size": MAX_TEAM_HTTP_REQUEST_BYTES,
        "url_scheme": server.trusted_external_scheme,
        "server_name": "causure.invalid",
        "ident": "Causure",
        "trusted_proxy": None,
        "trusted_proxy_headers": set(),
        "clear_untrusted_proxy_headers": True,
        "log_untrusted_proxy_headers": False,
        "expose_tracebacks": False,
        "channel_request_lookahead": 0,
    }


def _validated_waitress_server(
    configuration: TeamHostConfiguration,
) -> tuple[_CreateServer, _CloseAll]:
    create_server, close_all, adjustments_type = _load_waitress_server(configuration.server.version)
    try:
        adjustments = adjustments_type(**_waitress_arguments(configuration))
    except Exception as exc:
        raise TeamHostDependencyError(
            "the pinned Waitress runtime rejected the qualified Team host settings"
        ) from exc
    if (
        adjustments.trusted_proxy is not None
        or adjustments.trusted_proxy_headers != set()
        or adjustments.clear_untrusted_proxy_headers is not True
        or adjustments.url_scheme != "https"
        or adjustments.max_request_body_size != MAX_TEAM_HTTP_REQUEST_BYTES
    ):
        raise TeamHostDependencyError(
            "the pinned Waitress runtime normalized Team host security settings unexpectedly"
        )
    return create_server, close_all


def validate_team_host_dependencies(configuration: TeamHostConfiguration) -> None:
    """Fail closed on serving dependency drift or unsafe Waitress normalization."""

    if not isinstance(configuration, TeamHostConfiguration):
        raise TypeError("configuration must be a TeamHostConfiguration")
    configuration = parse_team_host_configuration(_configuration_document(configuration))
    _validated_waitress_server(configuration)


def create_team_host_server(configuration: TeamHostConfiguration) -> TeamHostServer:
    """Create one bound, controllable loopback Waitress server and owned Team runtime."""

    if not isinstance(configuration, TeamHostConfiguration):
        raise TypeError("configuration must be a TeamHostConfiguration")
    configuration = parse_team_host_configuration(_configuration_document(configuration))
    create_server, close_all = _validated_waitress_server(configuration)
    runtime = create_team_host_runtime(configuration)
    try:
        server = create_server(runtime.application, **_waitress_arguments(configuration))
    except BaseException as exc:
        runtime.close()
        raise TeamHostRuntimeError(
            "server_start_failed",
            "the loopback Waitress listener could not be created",
        ) from exc
    return TeamHostServer(
        configuration=configuration,
        runtime=runtime,
        server=server,
        close_all=close_all,
    )


def serve_team_host(configuration: TeamHostConfiguration) -> None:
    """Run the pinned loopback Waitress host and close all owned state on exit."""

    if not isinstance(configuration, TeamHostConfiguration):
        raise TypeError("configuration must be a TeamHostConfiguration")
    configuration = parse_team_host_configuration(_configuration_document(configuration))
    with create_team_host_server(configuration) as server:
        server.run()
