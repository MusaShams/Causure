"""Bounded process-local WSGI admission control ahead of authentication."""

from __future__ import annotations

import ipaddress
import json
import math
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

DEFAULT_TEAM_MAX_CONCURRENCY = 64
DEFAULT_TEAM_GLOBAL_REQUESTS_PER_WINDOW = 600
DEFAULT_TEAM_PER_SOURCE_REQUESTS_PER_WINDOW = 120
DEFAULT_TEAM_RATE_WINDOW_SECONDS = 60.0
DEFAULT_TEAM_MAX_TRACKED_SOURCES = 4096
DEFAULT_TEAM_SOURCE_IDLE_SECONDS = 600.0

_MAX_TEAM_RATE_LIMIT = 1_000_000
_MAX_TEAM_CONCURRENCY = 10_000
_MAX_TEAM_TRACKED_SOURCES = 100_000
_SOURCE_KEY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_LIVENESS_PATH = "/healthz"
_READINESS_PATH = "/readyz"

_StartResponse = Callable[..., Any]
_Application = Callable[[Mapping[str, Any], _StartResponse], Iterable[bytes]]
_SourceResolver = Callable[[Mapping[str, Any]], str]
_Clock = Callable[[], float]


@dataclass(frozen=True, slots=True)
class TeamAdmissionStatus:
    active_requests: int
    tracked_sources: int
    admitted_request_count: int
    rate_rejected_count: int
    concurrency_rejected_count: int
    integration_rejected_count: int
    last_error_code: str | None


@dataclass(slots=True)
class _TokenBucket:
    tokens: float
    updated_at: float
    last_seen_at: float


class _AdmissionUnavailableError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


class _ReleasingIterable:
    def __init__(self, iterable: Iterable[bytes], release: Callable[[], None]) -> None:
        self._iterable = iterable
        self._release = release
        self._lock = threading.Lock()
        self._iteration_started = False
        self._closed = False

    def __iter__(self) -> Iterator[bytes]:
        with self._lock:
            if self._iteration_started:
                raise RuntimeError("admission-controlled WSGI iterable is single-use")
            self._iteration_started = True
        try:
            yield from self._iterable
        finally:
            self.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
        try:
            closer = getattr(self._iterable, "close", None)
            if callable(closer):
                closer()
        finally:
            self._release()


def _bounded_integer(value: Any, *, name: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} through {maximum}")
    return value


def _bounded_seconds(value: Any, *, name: str, minimum: float, maximum: float) -> float:
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


def _socket_source(environ: Mapping[str, Any]) -> str:
    value = environ.get("REMOTE_ADDR")
    if not isinstance(value, str) or not value:
        return "unknown"
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        return "unknown"


class TeamAdmissionControlMiddleware:
    """Apply process-local concurrency and token-bucket limits before authentication."""

    def __init__(
        self,
        application: _Application,
        *,
        max_concurrency: int = DEFAULT_TEAM_MAX_CONCURRENCY,
        global_requests_per_window: int = DEFAULT_TEAM_GLOBAL_REQUESTS_PER_WINDOW,
        per_source_requests_per_window: int | None = (DEFAULT_TEAM_PER_SOURCE_REQUESTS_PER_WINDOW),
        rate_window_seconds: float = DEFAULT_TEAM_RATE_WINDOW_SECONDS,
        max_tracked_sources: int = DEFAULT_TEAM_MAX_TRACKED_SOURCES,
        source_idle_seconds: float = DEFAULT_TEAM_SOURCE_IDLE_SECONDS,
        source_resolver: _SourceResolver | None = None,
        monotonic_clock: _Clock = time.monotonic,
    ) -> None:
        if not callable(application):
            raise TypeError("application must be callable")
        if source_resolver is not None and not callable(source_resolver):
            raise TypeError("source_resolver must be callable")
        if not callable(monotonic_clock):
            raise TypeError("monotonic_clock must be callable")
        self._max_concurrency = _bounded_integer(
            max_concurrency,
            name="max_concurrency",
            minimum=1,
            maximum=_MAX_TEAM_CONCURRENCY,
        )
        self._global_capacity = _bounded_integer(
            global_requests_per_window,
            name="global_requests_per_window",
            minimum=1,
            maximum=_MAX_TEAM_RATE_LIMIT,
        )
        if per_source_requests_per_window is None:
            self._source_capacity: int | None = None
        else:
            self._source_capacity = _bounded_integer(
                per_source_requests_per_window,
                name="per_source_requests_per_window",
                minimum=1,
                maximum=_MAX_TEAM_RATE_LIMIT,
            )
        if self._source_capacity is None and source_resolver is not None:
            raise ValueError(
                "source_resolver requires per_source_requests_per_window to be enabled"
            )
        self._window_seconds = _bounded_seconds(
            rate_window_seconds,
            name="rate_window_seconds",
            minimum=1.0,
            maximum=3600.0,
        )
        self._max_tracked_sources = _bounded_integer(
            max_tracked_sources,
            name="max_tracked_sources",
            minimum=1,
            maximum=_MAX_TEAM_TRACKED_SOURCES,
        )
        self._source_idle_seconds = _bounded_seconds(
            source_idle_seconds,
            name="source_idle_seconds",
            minimum=self._window_seconds,
            maximum=86400.0,
        )
        self._application = application
        self._source_resolver = source_resolver or _socket_source
        self._clock = monotonic_clock
        self._state_lock = threading.RLock()
        self._slots = threading.BoundedSemaphore(self._max_concurrency)
        self._active_requests = 0
        self._admitted_request_count = 0
        self._rate_rejected_count = 0
        self._concurrency_rejected_count = 0
        self._integration_rejected_count = 0
        self._last_error_code: str | None = None
        now = self._monotonic_now()
        self._global_bucket = _TokenBucket(
            tokens=float(self._global_capacity),
            updated_at=now,
            last_seen_at=now,
        )
        self._source_buckets: OrderedDict[str, _TokenBucket] = OrderedDict()

    def _monotonic_now(self) -> float:
        try:
            value = self._clock()
            numeric = float(value)
        except Exception as exc:
            raise _AdmissionUnavailableError("admission_clock_invalid") from exc
        if isinstance(value, bool) or not math.isfinite(numeric) or numeric < 0:
            raise _AdmissionUnavailableError("admission_clock_invalid")
        return numeric

    def _source_key(self, environ: Mapping[str, Any]) -> str:
        try:
            value = self._source_resolver(environ)
        except Exception as exc:
            raise _AdmissionUnavailableError("admission_source_invalid") from exc
        if not isinstance(value, str) or _SOURCE_KEY_PATTERN.fullmatch(value) is None:
            raise _AdmissionUnavailableError("admission_source_invalid")
        return value

    def _refill(self, bucket: _TokenBucket, *, now: float, capacity: int) -> None:
        if now < bucket.updated_at:
            raise _AdmissionUnavailableError("admission_clock_invalid")
        elapsed = now - bucket.updated_at
        bucket.tokens = min(
            float(capacity),
            bucket.tokens + (elapsed * float(capacity) / self._window_seconds),
        )
        bucket.updated_at = now
        bucket.last_seen_at = now

    def _retry_after(self, bucket: _TokenBucket, *, capacity: int) -> int:
        rate = float(capacity) / self._window_seconds
        return max(1, math.ceil((1.0 - bucket.tokens) / rate))

    def _prune_sources(self, now: float) -> None:
        while self._source_buckets:
            key, bucket = next(iter(self._source_buckets.items()))
            if now - bucket.last_seen_at < self._source_idle_seconds:
                break
            del self._source_buckets[key]

    def _admit(self, environ: Mapping[str, Any]) -> int | None:
        now = self._monotonic_now()
        source_key = self._source_key(environ) if self._source_capacity is not None else None
        with self._state_lock:
            self._refill(
                self._global_bucket,
                now=now,
                capacity=self._global_capacity,
            )
            if self._global_bucket.tokens < 1.0:
                self._rate_rejected_count += 1
                return self._retry_after(
                    self._global_bucket,
                    capacity=self._global_capacity,
                )
            self._global_bucket.tokens -= 1.0
            source_capacity = self._source_capacity
            if source_capacity is not None and source_key is not None:
                self._prune_sources(now)
                source_bucket = self._source_buckets.get(source_key)
                if source_bucket is None:
                    if len(self._source_buckets) >= self._max_tracked_sources:
                        self._source_buckets.popitem(last=False)
                    source_bucket = _TokenBucket(
                        tokens=float(source_capacity),
                        updated_at=now,
                        last_seen_at=now,
                    )
                    self._source_buckets[source_key] = source_bucket
                else:
                    self._source_buckets.move_to_end(source_key)
                self._refill(source_bucket, now=now, capacity=source_capacity)
                if source_bucket.tokens < 1.0:
                    self._rate_rejected_count += 1
                    return self._retry_after(source_bucket, capacity=source_capacity)
                source_bucket.tokens -= 1.0
            self._admitted_request_count += 1
            self._last_error_code = None
            return None

    @property
    def status(self) -> TeamAdmissionStatus:
        with self._state_lock:
            return TeamAdmissionStatus(
                active_requests=self._active_requests,
                tracked_sources=len(self._source_buckets),
                admitted_request_count=self._admitted_request_count,
                rate_rejected_count=self._rate_rejected_count,
                concurrency_rejected_count=self._concurrency_rejected_count,
                integration_rejected_count=self._integration_rejected_count,
                last_error_code=self._last_error_code,
            )

    @staticmethod
    def _error(
        start_response: _StartResponse,
        *,
        status: int,
        code: str,
        message: str,
        scheme: str,
        retry_after: int,
    ) -> list[bytes]:
        body = (
            json.dumps(
                {"error": {"code": code, "message": message}},
                ensure_ascii=False,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
        headers = [
            ("Content-Type", "application/json; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("Retry-After", str(retry_after)),
        ]
        if scheme == "https":
            headers.append(("Strict-Transport-Security", "max-age=31536000"))
        reason = "Too Many Requests" if status == 429 else "Service Unavailable"
        start_response(f"{status} {reason}", headers)
        return [body]

    def _release_slot(self) -> None:
        with self._state_lock:
            self._active_requests -= 1
        self._slots.release()

    def __call__(
        self,
        environ: Mapping[str, Any],
        start_response: _StartResponse,
    ) -> Iterable[bytes]:
        path = str(environ.get("PATH_INFO", "") or "/")
        if path == _LIVENESS_PATH:
            return self._application(environ, start_response)
        scheme = str(environ.get("wsgi.url_scheme", "")).lower()
        if path == _READINESS_PATH:
            try:
                now = self._monotonic_now()
                with self._state_lock:
                    self._refill(
                        self._global_bucket,
                        now=now,
                        capacity=self._global_capacity,
                    )
            except _AdmissionUnavailableError as exc:
                with self._state_lock:
                    self._integration_rejected_count += 1
                    self._last_error_code = exc.code
                return self._error(
                    start_response,
                    status=503,
                    code="admission_control_unavailable",
                    message="the Team API admission control is unavailable",
                    scheme=scheme,
                    retry_after=1,
                )
            return self._application(environ, start_response)
        if not self._slots.acquire(blocking=False):
            with self._state_lock:
                self._concurrency_rejected_count += 1
            return self._error(
                start_response,
                status=503,
                code="server_busy",
                message="the Team API is at its local concurrency limit",
                scheme=scheme,
                retry_after=1,
            )
        with self._state_lock:
            self._active_requests += 1
        try:
            retry_after = self._admit(environ)
        except _AdmissionUnavailableError as exc:
            with self._state_lock:
                self._integration_rejected_count += 1
                self._last_error_code = exc.code
            try:
                return self._error(
                    start_response,
                    status=503,
                    code="admission_control_unavailable",
                    message="the Team API admission control is unavailable",
                    scheme=scheme,
                    retry_after=1,
                )
            finally:
                self._release_slot()
        if retry_after is not None:
            try:
                return self._error(
                    start_response,
                    status=429,
                    code="rate_limited",
                    message="the Team API request rate limit was exceeded",
                    scheme=scheme,
                    retry_after=retry_after,
                )
            finally:
                self._release_slot()
        try:
            iterable = self._application(environ, start_response)
        except Exception:
            self._release_slot()
            raise
        return _ReleasingIterable(iterable, self._release_slot)
