"""Closed single-process host for the OpenAI-compatible quota service."""

from __future__ import annotations

import errno
import hashlib
import ipaddress
import json
import math
import os
import signal
import stat
import threading
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from importlib import metadata
from pathlib import Path, PurePosixPath
from typing import Any, Protocol

from causure.constants import (
    OPENAI_QUOTA_HOST_CONFIG_SCHEMA_VERSION,
    PACKAGE_VERSION,
)
from causure.io import InputDocumentError, parse_json_text
from causure.openai_quota import (
    MAX_OPENAI_QUOTA_BUSY_TIMEOUT_MS,
    MAX_OPENAI_QUOTA_CONFIG_BYTES,
    MAX_OPENAI_QUOTA_REQUEST_BYTES,
    HTTPSOpenAIResponsesTransport,
    OpenAIQuotaConfiguration,
    OpenAIQuotaWSGIApplication,
    SQLiteOpenAIQuotaStore,
    parse_openai_quota_configuration_bytes,
)

MAX_OPENAI_QUOTA_HOST_CONFIG_BYTES = 64 * 1024
MAX_OPENAI_QUOTA_HOST_PATH_CHARACTERS = 4096
MAX_OPENAI_QUOTA_HOST_SECRET_BYTES = 8192
OPENAI_QUOTA_HOST_SERVER_IMPLEMENTATION = "waitress"
OPENAI_QUOTA_HOST_WAITRESS_VERSION = "3.0.2"
OPENAI_QUOTA_HOST_REQUEST_SHUTDOWN_SECONDS = 5.0

_SHA256_PATTERN = "^[a-f0-9]{64}$"
_ALLOWED_LISTEN_HOSTS = frozenset({"0.0.0.0", "127.0.0.1", "::", "::1"})


class OpenAIQuotaHostError(ValueError):
    """Base host error carrying a stable, non-secret machine code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        self.message = message
        super().__init__(f"OpenAI quota host failed [{code}]: {message}")


class OpenAIQuotaHostConfigurationError(OpenAIQuotaHostError):
    """Raised when the closed host configuration is invalid."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        super().__init__("host_configuration_invalid", f"{path} {message}")


class OpenAIQuotaHostDependencyError(OpenAIQuotaHostError):
    """Raised when the exact serving dependency is unavailable or drifts."""


class OpenAIQuotaHostRuntimeError(OpenAIQuotaHostError):
    """Raised when protected runtime inputs or the listener fail closed."""


@dataclass(frozen=True, slots=True)
class OpenAIQuotaHostQuotaConfiguration:
    path: str
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class OpenAIQuotaHostDatabaseConfiguration:
    path: str
    busy_timeout_ms: int


@dataclass(frozen=True, slots=True)
class OpenAIQuotaHostSecretsConfiguration:
    admin_token_path: str
    provider_api_key_path: str


@dataclass(frozen=True, slots=True)
class OpenAIQuotaHostServerConfiguration:
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
class OpenAIQuotaHostConfiguration:
    schema_version: str
    quota_configuration: OpenAIQuotaHostQuotaConfiguration
    database: OpenAIQuotaHostDatabaseConfiguration
    secrets: OpenAIQuotaHostSecretsConfiguration
    server: OpenAIQuotaHostServerConfiguration


@dataclass(frozen=True, slots=True)
class OpenAIQuotaHostConfigurationSubject:
    path: str
    sha256: str
    byte_count: int
    configuration: OpenAIQuotaHostConfiguration


_Application = Callable[
    [Mapping[str, Any], Callable[[str, list[tuple[str, str]]], Any]],
    Iterable[bytes],
]


@dataclass(slots=True)
class OpenAIQuotaHostRuntime:
    """Own the loaded secrets, quota store, and composed WSGI application."""

    host_configuration: OpenAIQuotaHostConfiguration
    quota_configuration: OpenAIQuotaConfiguration
    store: SQLiteOpenAIQuotaStore
    application: _Application
    _closed: bool = field(default=False, init=False, repr=False)

    @property
    def closed(self) -> bool:
        return self._closed

    def close(self) -> None:
        self._closed = True

    def __enter__(self) -> OpenAIQuotaHostRuntime:
        if self._closed:
            raise OpenAIQuotaHostRuntimeError(
                "runtime_closed",
                "the quota host runtime is already closed",
            )
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()


class _CreateServer(Protocol):
    def __call__(self, application: _Application, **kwargs: Any) -> Any: ...


class _CloseAll(Protocol):
    def __call__(self, server_map: dict[Any, Any]) -> None: ...


def _is_expected_listener_close_error(exc: OSError) -> bool:
    return (
        exc.errno in {errno.EBADF, errno.ENOTSOCK, 10038} or getattr(exc, "winerror", None) == 10038
    )


@dataclass(slots=True)
class OpenAIQuotaHostServer:
    """Own one controllable Waitress listener and its quota runtime."""

    configuration: OpenAIQuotaHostConfiguration
    runtime: OpenAIQuotaHostRuntime
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
                raise OpenAIQuotaHostRuntimeError(
                    "server_closed",
                    "the quota host server is closed",
                )
            if self._run_started:
                raise OpenAIQuotaHostRuntimeError(
                    "server_already_run",
                    "the quota host server can be run only once",
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
        request_timeout_seconds: float = OPENAI_QUOTA_HOST_REQUEST_SHUTDOWN_SECONDS,
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
            self.runtime.close()
            if failure is not None:
                raise OpenAIQuotaHostRuntimeError(
                    "server_shutdown_failed",
                    "the quota host did not shut down cleanly",
                ) from failure

    def __enter__(self) -> OpenAIQuotaHostServer:
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
        raise OpenAIQuotaHostConfigurationError(path, "must be an object")
    keys = set(value)
    missing = required - keys
    unknown = keys - required
    if missing:
        raise OpenAIQuotaHostConfigurationError(
            path,
            f"missing required field {sorted(missing)[0]!r}",
        )
    if unknown:
        raise OpenAIQuotaHostConfigurationError(
            path,
            f"unknown field {sorted(unknown)[0]!r}",
        )
    return value


def _text(
    value: Any,
    *,
    path: str,
    minimum: int = 1,
    maximum: int,
) -> str:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise OpenAIQuotaHostConfigurationError(
            path,
            f"must be text from {minimum} through {maximum} characters",
        )
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise OpenAIQuotaHostConfigurationError(path, "must not contain control characters")
    return value


def _absolute_path(value: Any, *, path: str) -> str:
    text = _text(value, path=path, maximum=MAX_OPENAI_QUOTA_HOST_PATH_CHARACTERS)
    if not Path(text).is_absolute() and not PurePosixPath(text).is_absolute():
        raise OpenAIQuotaHostConfigurationError(path, "must be an absolute path")
    if os.name == "nt" and text.startswith(("\\\\", "//")):
        raise OpenAIQuotaHostConfigurationError(path, "must be a local absolute path")
    return text


def _integer(value: Any, *, path: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise OpenAIQuotaHostConfigurationError(
            path,
            f"must be an integer from {minimum} through {maximum}",
        )
    return value


def _sha256(value: Any, *, path: str) -> str:
    text = _text(value, path=path, minimum=64, maximum=64)
    if any(character not in "0123456789abcdef" for character in text):
        raise OpenAIQuotaHostConfigurationError(path, f"must match {_SHA256_PATTERN}")
    return text


def _listen_host(value: Any, *, path: str) -> str:
    text = _text(value, path=path, maximum=64)
    try:
        address = ipaddress.ip_address(text)
    except ValueError as exc:
        raise OpenAIQuotaHostConfigurationError(
            path,
            "must be a supported canonical IP listener",
        ) from exc
    if str(address) != text or text not in _ALLOWED_LISTEN_HOSTS:
        raise OpenAIQuotaHostConfigurationError(
            path,
            "must be a supported canonical IP listener",
        )
    return text


def _path_identity(value: str) -> str:
    return os.path.normcase(str(Path(value).resolve(strict=False)))


def _is_same_or_descendant(path: str, parent: str) -> bool:
    path_value = Path(_path_identity(path))
    parent_value = Path(_path_identity(parent))
    return path_value == parent_value or parent_value in path_value.parents


def parse_openai_quota_host_configuration(document: Any) -> OpenAIQuotaHostConfiguration:
    """Parse one closed quota-host configuration without reading its subjects."""

    root = _closed_object(
        document,
        path="$",
        required={"schema_version", "quota_configuration", "database", "secrets", "server"},
    )
    if root["schema_version"] != OPENAI_QUOTA_HOST_CONFIG_SCHEMA_VERSION:
        raise OpenAIQuotaHostConfigurationError(
            "$.schema_version",
            f"must equal {OPENAI_QUOTA_HOST_CONFIG_SCHEMA_VERSION!r}",
        )

    quota_value = _closed_object(
        root["quota_configuration"],
        path="$.quota_configuration",
        required={"path", "sha256", "byte_count"},
    )
    quota = OpenAIQuotaHostQuotaConfiguration(
        path=_absolute_path(quota_value["path"], path="$.quota_configuration.path"),
        sha256=_sha256(quota_value["sha256"], path="$.quota_configuration.sha256"),
        byte_count=_integer(
            quota_value["byte_count"],
            path="$.quota_configuration.byte_count",
            minimum=1,
            maximum=MAX_OPENAI_QUOTA_CONFIG_BYTES,
        ),
    )

    database_value = _closed_object(
        root["database"],
        path="$.database",
        required={"path", "busy_timeout_ms"},
    )
    database = OpenAIQuotaHostDatabaseConfiguration(
        path=_absolute_path(database_value["path"], path="$.database.path"),
        busy_timeout_ms=_integer(
            database_value["busy_timeout_ms"],
            path="$.database.busy_timeout_ms",
            minimum=1,
            maximum=MAX_OPENAI_QUOTA_BUSY_TIMEOUT_MS,
        ),
    )

    secrets_value = _closed_object(
        root["secrets"],
        path="$.secrets",
        required={"admin_token_path", "provider_api_key_path"},
    )
    secrets_configuration = OpenAIQuotaHostSecretsConfiguration(
        admin_token_path=_absolute_path(
            secrets_value["admin_token_path"],
            path="$.secrets.admin_token_path",
        ),
        provider_api_key_path=_absolute_path(
            secrets_value["provider_api_key_path"],
            path="$.secrets.provider_api_key_path",
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
    implementation = _text(
        server_value["implementation"],
        path="$.server.implementation",
        maximum=32,
    )
    if implementation != OPENAI_QUOTA_HOST_SERVER_IMPLEMENTATION:
        raise OpenAIQuotaHostConfigurationError(
            "$.server.implementation",
            f"must equal {OPENAI_QUOTA_HOST_SERVER_IMPLEMENTATION!r}",
        )
    version = _text(server_value["version"], path="$.server.version", maximum=32)
    if version != OPENAI_QUOTA_HOST_WAITRESS_VERSION:
        raise OpenAIQuotaHostConfigurationError(
            "$.server.version",
            f"must equal {OPENAI_QUOTA_HOST_WAITRESS_VERSION!r}",
        )
    trusted_scheme = _text(
        server_value["trusted_external_scheme"],
        path="$.server.trusted_external_scheme",
        maximum=8,
    )
    if trusted_scheme != "https":
        raise OpenAIQuotaHostConfigurationError(
            "$.server.trusted_external_scheme",
            "must equal 'https'",
        )
    server = OpenAIQuotaHostServerConfiguration(
        implementation=implementation,
        version=version,
        listen_host=_listen_host(server_value["listen_host"], path="$.server.listen_host"),
        listen_port=_integer(
            server_value["listen_port"],
            path="$.server.listen_port",
            minimum=1,
            maximum=65535,
        ),
        trusted_external_scheme=trusted_scheme,
        threads=_integer(
            server_value["threads"],
            path="$.server.threads",
            minimum=1,
            maximum=256,
        ),
        connection_limit=_integer(
            server_value["connection_limit"],
            path="$.server.connection_limit",
            minimum=1,
            maximum=10_000,
        ),
        backlog=_integer(
            server_value["backlog"],
            path="$.server.backlog",
            minimum=1,
            maximum=4096,
        ),
        channel_timeout_seconds=_integer(
            server_value["channel_timeout_seconds"],
            path="$.server.channel_timeout_seconds",
            minimum=5,
            maximum=3600,
        ),
        max_request_header_bytes=_integer(
            server_value["max_request_header_bytes"],
            path="$.server.max_request_header_bytes",
            minimum=1024,
            maximum=65_536,
        ),
    )
    if server.connection_limit < server.threads + 2:
        raise OpenAIQuotaHostConfigurationError(
            "$.server.connection_limit",
            "must leave at least two connections beyond the worker thread count",
        )

    path_values = {
        "$.quota_configuration.path": quota.path,
        "$.database.path": database.path,
        "$.secrets.admin_token_path": secrets_configuration.admin_token_path,
        "$.secrets.provider_api_key_path": secrets_configuration.provider_api_key_path,
    }
    identities: dict[str, str] = {}
    for path_name, path_value in path_values.items():
        identity = _path_identity(path_value)
        if identity in identities:
            raise OpenAIQuotaHostConfigurationError(
                path_name,
                f"must differ from {identities[identity]}",
            )
        identities[identity] = path_name
    database_parent = str(Path(database.path).parent)
    for path_name, path_value in path_values.items():
        if path_name != "$.database.path" and _is_same_or_descendant(
            path_value,
            database_parent,
        ):
            raise OpenAIQuotaHostConfigurationError(
                path_name,
                "must not be inside the writable database directory",
            )

    return OpenAIQuotaHostConfiguration(
        schema_version=OPENAI_QUOTA_HOST_CONFIG_SCHEMA_VERSION,
        quota_configuration=quota,
        database=database,
        secrets=secrets_configuration,
        server=server,
    )


def parse_openai_quota_host_configuration_bytes(data: bytes) -> OpenAIQuotaHostConfiguration:
    """Decode bounded, duplicate-key-rejecting UTF-8 host JSON."""

    if not isinstance(data, bytes):
        raise OpenAIQuotaHostConfigurationError("$", "host configuration must be bytes")
    if not 1 <= len(data) <= MAX_OPENAI_QUOTA_HOST_CONFIG_BYTES:
        raise OpenAIQuotaHostConfigurationError(
            "$",
            "host configuration must contain from 1 through "
            f"{MAX_OPENAI_QUOTA_HOST_CONFIG_BYTES} bytes",
        )
    try:
        document = parse_json_text(
            data.decode("utf-8"),
            source="OpenAI quota host configuration",
            max_bytes=MAX_OPENAI_QUOTA_HOST_CONFIG_BYTES,
        )
    except (InputDocumentError, UnicodeDecodeError) as exc:
        raise OpenAIQuotaHostConfigurationError("$", f"must be strict UTF-8 JSON: {exc}") from exc
    return parse_openai_quota_host_configuration(document)


def _read_stable_file(
    path: str | Path,
    *,
    maximum_bytes: int,
    description: str,
    allow_empty: bool = False,
) -> tuple[Path, bytes]:
    source = Path(path)
    try:
        before_link = source.lstat()
        if stat.S_ISLNK(before_link.st_mode):
            raise OpenAIQuotaHostRuntimeError(
                "protected_file_invalid",
                f"{description} cannot be a symbolic link",
            )
        before = source.stat()
        if not stat.S_ISREG(before.st_mode):
            raise OpenAIQuotaHostRuntimeError(
                "protected_file_invalid",
                f"{description} must be a regular file",
            )
        with source.open("rb") as stream:
            data = stream.read(maximum_bytes + 1)
        after = source.stat()
        after_link = source.lstat()
    except OpenAIQuotaHostRuntimeError:
        raise
    except OSError as exc:
        raise OpenAIQuotaHostRuntimeError(
            "protected_file_unavailable",
            f"{description} could not be read",
        ) from exc
    if (
        stat.S_ISLNK(after_link.st_mode)
        or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        or len(data) != before.st_size
    ):
        raise OpenAIQuotaHostRuntimeError(
            "protected_file_changed",
            f"{description} changed while being read",
        )
    if len(data) > maximum_bytes or (not allow_empty and not data):
        raise OpenAIQuotaHostRuntimeError(
            "protected_file_invalid",
            f"{description} has an invalid byte count",
        )
    return source, data


def load_openai_quota_host_configuration(path: str | Path) -> OpenAIQuotaHostConfiguration:
    """Load one protected host configuration without accepting standard input."""

    _, data = _read_stable_file(
        path,
        maximum_bytes=MAX_OPENAI_QUOTA_HOST_CONFIG_BYTES,
        description="host configuration",
    )
    return parse_openai_quota_host_configuration_bytes(data)


def load_openai_quota_host_configuration_subject(
    path: str | Path,
) -> OpenAIQuotaHostConfigurationSubject:
    """Load a host configuration and return its exact registration subject."""

    source, data = _read_stable_file(
        path,
        maximum_bytes=MAX_OPENAI_QUOTA_HOST_CONFIG_BYTES,
        description="host configuration",
    )
    return OpenAIQuotaHostConfigurationSubject(
        path=str(source),
        sha256=hashlib.sha256(data).hexdigest(),
        byte_count=len(data),
        configuration=parse_openai_quota_host_configuration_bytes(data),
    )


def _configuration_document(configuration: OpenAIQuotaHostConfiguration) -> dict[str, Any]:
    return {
        "schema_version": configuration.schema_version,
        "quota_configuration": {
            "path": configuration.quota_configuration.path,
            "sha256": configuration.quota_configuration.sha256,
            "byte_count": configuration.quota_configuration.byte_count,
        },
        "database": {
            "path": configuration.database.path,
            "busy_timeout_ms": configuration.database.busy_timeout_ms,
        },
        "secrets": {
            "admin_token_path": configuration.secrets.admin_token_path,
            "provider_api_key_path": configuration.secrets.provider_api_key_path,
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
    }


def render_openai_quota_host_configuration(configuration: OpenAIQuotaHostConfiguration) -> str:
    """Render canonical secret-free host configuration JSON."""

    if type(configuration) is not OpenAIQuotaHostConfiguration:
        raise TypeError("configuration must be an OpenAIQuotaHostConfiguration")
    normalized = parse_openai_quota_host_configuration(_configuration_document(configuration))
    return (
        json.dumps(
            _configuration_document(normalized),
            ensure_ascii=False,
            indent=2,
            sort_keys=False,
        )
        + "\n"
    )


def _read_quota_configuration(
    subject: OpenAIQuotaHostQuotaConfiguration,
) -> OpenAIQuotaConfiguration:
    _, data = _read_stable_file(
        subject.path,
        maximum_bytes=MAX_OPENAI_QUOTA_CONFIG_BYTES,
        description="quota configuration",
    )
    if len(data) != subject.byte_count or hashlib.sha256(data).hexdigest() != subject.sha256:
        raise OpenAIQuotaHostRuntimeError(
            "quota_configuration_mismatch",
            "quota configuration bytes do not match the protected host subject",
        )
    try:
        return parse_openai_quota_configuration_bytes(data)
    except ValueError as exc:
        raise OpenAIQuotaHostRuntimeError(
            "quota_configuration_invalid",
            "quota configuration is invalid",
        ) from exc


def _read_secret(path: str, *, description: str) -> str:
    _, data = _read_stable_file(
        path,
        maximum_bytes=MAX_OPENAI_QUOTA_HOST_SECRET_BYTES,
        description=description,
    )
    try:
        value = data.decode("ascii")
    except UnicodeDecodeError as exc:
        raise OpenAIQuotaHostRuntimeError(
            "secret_invalid",
            f"{description} must contain visible ASCII",
        ) from exc
    if not 32 <= len(value) <= MAX_OPENAI_QUOTA_HOST_SECRET_BYTES or any(
        not 32 <= ord(character) <= 126 for character in value
    ):
        raise OpenAIQuotaHostRuntimeError(
            "secret_invalid",
            f"{description} must contain 32 through {MAX_OPENAI_QUOTA_HOST_SECRET_BYTES} "
            "visible ASCII characters with no newline",
        )
    return value


def _validate_runtime_paths(configuration: OpenAIQuotaHostConfiguration) -> None:
    database = Path(configuration.database.path)
    try:
        if database.is_symlink():
            raise OpenAIQuotaHostRuntimeError(
                "database_path_invalid",
                "quota database cannot be a symbolic link",
            )
        if not database.parent.is_dir():
            raise OpenAIQuotaHostRuntimeError(
                "database_parent_unavailable",
                "quota database parent directory is unavailable",
            )
        if database.exists() and not database.is_file():
            raise OpenAIQuotaHostRuntimeError(
                "database_path_invalid",
                "quota database path is not a regular file",
            )
    except OpenAIQuotaHostRuntimeError:
        raise
    except OSError as exc:
        raise OpenAIQuotaHostRuntimeError(
            "database_path_unavailable",
            "quota database path could not be inspected",
        ) from exc


def create_openai_quota_host_runtime(
    configuration: OpenAIQuotaHostConfiguration,
) -> OpenAIQuotaHostRuntime:
    """Load exact protected inputs and compose one quota WSGI runtime."""

    if type(configuration) is not OpenAIQuotaHostConfiguration:
        raise TypeError("configuration must be an OpenAIQuotaHostConfiguration")
    configuration = parse_openai_quota_host_configuration(_configuration_document(configuration))
    _validate_runtime_paths(configuration)
    quota_configuration = _read_quota_configuration(configuration.quota_configuration)
    if (
        configuration.server.channel_timeout_seconds
        < math.ceil(quota_configuration.upstream_timeout_seconds) + 5
    ):
        raise OpenAIQuotaHostRuntimeError(
            "server_timeout_invalid",
            "server channel timeout must exceed the upstream timeout by at least five seconds",
        )
    admin_token = _read_secret(
        configuration.secrets.admin_token_path,
        description="admin token",
    )
    provider_api_key = _read_secret(
        configuration.secrets.provider_api_key_path,
        description="provider API key",
    )
    store = SQLiteOpenAIQuotaStore(
        configuration.database.path,
        busy_timeout_ms=configuration.database.busy_timeout_ms,
    )
    store.initialize()
    upstream = HTTPSOpenAIResponsesTransport(quota_configuration, provider_api_key)
    application = OpenAIQuotaWSGIApplication(
        quota_configuration,
        store,
        admin_token,
        upstream,
    )
    return OpenAIQuotaHostRuntime(
        host_configuration=configuration,
        quota_configuration=quota_configuration,
        store=store,
        application=application,
    )


def _load_waitress_server(expected_version: str) -> tuple[_CreateServer, _CloseAll, type[Any]]:
    try:
        installed_version = metadata.version(OPENAI_QUOTA_HOST_SERVER_IMPLEMENTATION)
        from waitress import create_server
        from waitress.adjustments import Adjustments
        from waitress.wasyncore import close_all
    except (ImportError, metadata.PackageNotFoundError) as exc:
        raise OpenAIQuotaHostDependencyError(
            "dependency_unavailable",
            "openai-quota-serve requires the pinned 'causure[quota-service]' optional dependencies",
        ) from exc
    if installed_version != expected_version:
        raise OpenAIQuotaHostDependencyError(
            "dependency_version_mismatch",
            "openai-quota-serve requires exact Waitress version "
            f"{expected_version}; found {installed_version}",
        )
    return create_server, close_all, Adjustments


def _waitress_arguments(configuration: OpenAIQuotaHostConfiguration) -> dict[str, Any]:
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
        "max_request_body_size": MAX_OPENAI_QUOTA_REQUEST_BYTES,
        "url_scheme": server.trusted_external_scheme,
        "server_name": "causure-quota.invalid",
        "ident": "Causure-Quota",
        "trusted_proxy": None,
        "trusted_proxy_headers": set(),
        "clear_untrusted_proxy_headers": True,
        "log_untrusted_proxy_headers": False,
        "expose_tracebacks": False,
        "channel_request_lookahead": 0,
        "asyncore_use_poll": True,
    }


def _validated_waitress_server(
    configuration: OpenAIQuotaHostConfiguration,
) -> tuple[_CreateServer, _CloseAll]:
    create_server, close_all, adjustments_type = _load_waitress_server(configuration.server.version)
    try:
        adjustments = adjustments_type(**_waitress_arguments(configuration))
    except Exception as exc:
        raise OpenAIQuotaHostDependencyError(
            "dependency_settings_rejected",
            "the pinned Waitress runtime rejected the quota host settings",
        ) from exc
    if (
        adjustments.trusted_proxy is not None
        or adjustments.trusted_proxy_headers != set()
        or adjustments.clear_untrusted_proxy_headers is not True
        or adjustments.url_scheme != "https"
        or adjustments.max_request_body_size != MAX_OPENAI_QUOTA_REQUEST_BYTES
    ):
        raise OpenAIQuotaHostDependencyError(
            "dependency_settings_drifted",
            "the pinned Waitress runtime normalized quota host security settings unexpectedly",
        )
    return create_server, close_all


def validate_openai_quota_host_dependencies(
    configuration: OpenAIQuotaHostConfiguration,
) -> None:
    """Fail closed on serving dependency drift or unsafe normalization."""

    if type(configuration) is not OpenAIQuotaHostConfiguration:
        raise TypeError("configuration must be an OpenAIQuotaHostConfiguration")
    configuration = parse_openai_quota_host_configuration(_configuration_document(configuration))
    _validated_waitress_server(configuration)


def create_openai_quota_host_server(
    configuration: OpenAIQuotaHostConfiguration,
) -> OpenAIQuotaHostServer:
    """Create one bound, controllable quota-core Waitress server."""

    if type(configuration) is not OpenAIQuotaHostConfiguration:
        raise TypeError("configuration must be an OpenAIQuotaHostConfiguration")
    configuration = parse_openai_quota_host_configuration(_configuration_document(configuration))
    create_server, close_all = _validated_waitress_server(configuration)
    runtime = create_openai_quota_host_runtime(configuration)
    try:
        server = create_server(runtime.application, **_waitress_arguments(configuration))
    except BaseException as exc:
        runtime.close()
        raise OpenAIQuotaHostRuntimeError(
            "server_start_failed",
            "the quota-core Waitress listener could not be created",
        ) from exc
    return OpenAIQuotaHostServer(
        configuration=configuration,
        runtime=runtime,
        server=server,
        close_all=close_all,
    )


def serve_openai_quota_host(configuration: OpenAIQuotaHostConfiguration) -> None:
    """Run the pinned quota-core host and close all owned state on exit."""

    if type(configuration) is not OpenAIQuotaHostConfiguration:
        raise TypeError("configuration must be an OpenAIQuotaHostConfiguration")
    configuration = parse_openai_quota_host_configuration(_configuration_document(configuration))
    with create_openai_quota_host_server(configuration) as server:
        previous_handlers: dict[signal.Signals, Any] = {}
        if threading.current_thread() is threading.main_thread():

            def request_shutdown(signum: int, frame: Any) -> None:
                del signum, frame
                server.close()

            for candidate in (signal.SIGINT, signal.SIGTERM):
                previous_handlers[candidate] = signal.getsignal(candidate)
                signal.signal(candidate, request_shutdown)
        try:
            server.run()
        finally:
            for candidate, previous in previous_handlers.items():
                signal.signal(candidate, previous)


def openai_quota_host_runtime_summary(
    configuration: OpenAIQuotaHostConfiguration,
) -> dict[str, Any]:
    """Return a secret-free startup summary for operators and qualification evidence."""

    if type(configuration) is not OpenAIQuotaHostConfiguration:
        raise TypeError("configuration must be an OpenAIQuotaHostConfiguration")
    configuration = parse_openai_quota_host_configuration(_configuration_document(configuration))
    return {
        "schema_version": OPENAI_QUOTA_HOST_CONFIG_SCHEMA_VERSION,
        "package_version": PACKAGE_VERSION,
        "server": {
            "implementation": configuration.server.implementation,
            "version": configuration.server.version,
            "listen_host": configuration.server.listen_host,
            "listen_port": configuration.server.listen_port,
            "trusted_external_scheme": configuration.server.trusted_external_scheme,
        },
        "quota_configuration": {
            "sha256": configuration.quota_configuration.sha256,
            "byte_count": configuration.quota_configuration.byte_count,
        },
        "secret_sources": {
            "admin_token": "protected-file",
            "provider_api_key": "protected-file",
        },
    }
