"""Adversarial tests for process-local WSGI admission control."""

from __future__ import annotations

import json
import unittest
from collections.abc import Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from causure.team_admission import TeamAdmissionControlMiddleware
from causure.team_application import AuthenticatedTeamIdentity
from causure.team_entra import (
    EntraTeamIdentityMiddleware,
    EntraTokenVerifier,
    EntraVerifiedPrincipal,
)


class _CaptureApplication:
    def __init__(self) -> None:
        self.calls = 0
        self.environ: Mapping[str, Any] | None = None

    def __call__(
        self,
        environ: Mapping[str, Any],
        start_response: Any,
    ) -> list[bytes]:
        self.calls += 1
        self.environ = environ
        body = b'{"status":"ok"}\n'
        start_response(
            "200 OK",
            [
                ("Content-Type", "application/json"),
                ("Content-Length", str(len(body))),
            ],
        )
        return [body]


class _CountingVerifier(EntraTokenVerifier):
    def __init__(self) -> None:
        self.verify_calls = 0
        self.ready_calls = 0

    def check_ready(self) -> None:
        self.ready_calls += 1

    def verify(self, token: str) -> EntraVerifiedPrincipal:
        self.verify_calls += 1
        return EntraVerifiedPrincipal(
            identity=AuthenticatedTeamIdentity(
                tenant_id="tenant-acme",
                identity_provider="entra:11111111-1111-4111-8111-111111111111",
                subject_id="55555555-5555-4555-8555-555555555555",
            ),
            entra_tenant_id="11111111-1111-4111-8111-111111111111",
            object_id="55555555-5555-4555-8555-555555555555",
            client_id="44444444-4444-4444-8444-444444444444",
            grant_type="delegated",
            permissions=("Causure.Access",),
            issued_at=1,
            expires_at=2,
        )


def _request(
    application: Any,
    *,
    path: str = "/v1/team/summary",
    remote_addr: str = "192.0.2.1",
    authorization: str | None = None,
    forwarded_for: str | None = None,
    scheme: str = "https",
) -> tuple[str, dict[str, str], bytes]:
    environ: dict[str, Any] = {
        "PATH_INFO": path,
        "REQUEST_METHOD": "GET",
        "REMOTE_ADDR": remote_addr,
        "wsgi.url_scheme": scheme,
    }
    if authorization is not None:
        environ["HTTP_AUTHORIZATION"] = authorization
    if forwarded_for is not None:
        environ["HTTP_X_FORWARDED_FOR"] = forwarded_for
    response: dict[str, Any] = {}

    def start_response(
        status: str,
        headers: list[tuple[str, str]],
        exc_info: Any = None,
    ) -> None:
        response["status"] = status
        response["headers"] = dict(headers)

    iterable: Iterable[bytes] = application(environ, start_response)
    try:
        body = b"".join(iterable)
    finally:
        closer = getattr(iterable, "close", None)
        if callable(closer):
            closer()
    return response["status"], response["headers"], body


class TeamAdmissionControlTests(unittest.TestCase):
    def test_configuration_is_closed_and_bounded(self) -> None:
        application = _CaptureApplication()
        cases = [
            {"max_concurrency": 0},
            {"max_concurrency": True},
            {"global_requests_per_window": 0},
            {"per_source_requests_per_window": 0},
            {"rate_window_seconds": float("nan")},
            {"max_tracked_sources": 0},
            {"rate_window_seconds": 10, "source_idle_seconds": 9},
        ]
        for options in cases:
            with self.subTest(options=options), self.assertRaises(ValueError):
                TeamAdmissionControlMiddleware(application, **options)
        with self.assertRaises(TypeError):
            TeamAdmissionControlMiddleware(application, source_resolver="REMOTE_ADDR")  # type: ignore[arg-type]
        with self.assertRaises(ValueError):
            TeamAdmissionControlMiddleware(
                application,
                per_source_requests_per_window=None,
                source_resolver=lambda _environ: "source",
            )

    def test_forwarded_headers_cannot_evade_default_per_source_limit(self) -> None:
        application = _CaptureApplication()
        middleware = TeamAdmissionControlMiddleware(
            application,
            max_concurrency=2,
            global_requests_per_window=10,
            per_source_requests_per_window=1,
            rate_window_seconds=10,
            max_tracked_sources=2,
            source_idle_seconds=10,
            monotonic_clock=lambda: 0.0,
        )

        first = _request(
            middleware,
            authorization="Bearer first",
            forwarded_for="198.51.100.1",
        )
        second = _request(
            middleware,
            authorization="Bearer secret-second-value",
            forwarded_for="203.0.113.9",
        )
        other_source = _request(
            middleware,
            remote_addr="192.0.2.2",
            forwarded_for="198.51.100.1",
        )

        self.assertEqual("200 OK", first[0])
        self.assertEqual("429 Too Many Requests", second[0])
        self.assertEqual("10", second[1]["Retry-After"])
        self.assertEqual("no-store", second[1]["Cache-Control"])
        self.assertEqual("max-age=31536000", second[1]["Strict-Transport-Security"])
        self.assertEqual("rate_limited", json.loads(second[2])["error"]["code"])
        self.assertNotIn(b"secret-second-value", second[2])
        self.assertEqual("200 OK", other_source[0])
        self.assertEqual(2, application.calls)
        self.assertEqual(2, middleware.status.tracked_sources)
        self.assertEqual(1, middleware.status.rate_rejected_count)

    def test_global_bucket_refills_and_backward_clock_fails_closed(self) -> None:
        current_time = [0.0]
        application = _CaptureApplication()
        middleware = TeamAdmissionControlMiddleware(
            application,
            global_requests_per_window=2,
            per_source_requests_per_window=None,
            rate_window_seconds=10,
            monotonic_clock=lambda: current_time[0],
        )

        self.assertEqual("200 OK", _request(middleware)[0])
        self.assertEqual("200 OK", _request(middleware)[0])
        limited = _request(middleware)
        self.assertEqual("429 Too Many Requests", limited[0])
        self.assertEqual("5", limited[1]["Retry-After"])

        current_time[0] = 5.0
        self.assertEqual("200 OK", _request(middleware)[0])
        current_time[0] = 4.0
        unavailable = _request(middleware)
        self.assertEqual("503 Service Unavailable", unavailable[0])
        self.assertEqual(
            "admission_control_unavailable",
            json.loads(unavailable[2])["error"]["code"],
        )
        self.assertEqual("admission_clock_invalid", middleware.status.last_error_code)
        self.assertEqual(1, middleware.status.integration_rejected_count)
        readiness = _request(middleware, path="/readyz")
        self.assertEqual("503 Service Unavailable", readiness[0])
        self.assertEqual(3, application.calls)

    def test_source_tracking_is_bounded_and_idle_entries_are_pruned(self) -> None:
        current_time = [0.0]
        middleware = TeamAdmissionControlMiddleware(
            _CaptureApplication(),
            global_requests_per_window=20,
            per_source_requests_per_window=2,
            rate_window_seconds=10,
            max_tracked_sources=2,
            source_idle_seconds=10,
            monotonic_clock=lambda: current_time[0],
        )
        for address in ("192.0.2.1", "192.0.2.2", "192.0.2.3"):
            self.assertEqual("200 OK", _request(middleware, remote_addr=address)[0])
        self.assertEqual(2, middleware.status.tracked_sources)

        current_time[0] = 10.0
        self.assertEqual("200 OK", _request(middleware, remote_addr="192.0.2.4")[0])
        self.assertEqual(1, middleware.status.tracked_sources)

    def test_concurrency_slot_is_held_until_iterable_close(self) -> None:
        application = _CaptureApplication()
        middleware = TeamAdmissionControlMiddleware(
            application,
            max_concurrency=1,
            global_requests_per_window=100,
            per_source_requests_per_window=None,
            monotonic_clock=lambda: 0.0,
        )
        response: dict[str, Any] = {}

        def start_response(
            status: str,
            headers: list[tuple[str, str]],
            exc_info: Any = None,
        ) -> None:
            response["status"] = status
            response["headers"] = dict(headers)

        first = middleware(
            {
                "PATH_INFO": "/v1/team/summary",
                "REMOTE_ADDR": "192.0.2.1",
                "wsgi.url_scheme": "https",
            },
            start_response,
        )
        self.assertEqual(1, middleware.status.active_requests)
        self.assertEqual("200 OK", _request(middleware, path="/healthz")[0])

        busy = _request(middleware, remote_addr="192.0.2.2")
        self.assertEqual("503 Service Unavailable", busy[0])
        self.assertEqual("server_busy", json.loads(busy[2])["error"]["code"])
        self.assertEqual("1", busy[1]["Retry-After"])
        self.assertEqual(2, application.calls)
        self.assertEqual(1, middleware.status.concurrency_rejected_count)

        closer = first.close  # type: ignore[attr-defined]
        closer()
        closer()
        self.assertEqual(0, middleware.status.active_requests)
        self.assertEqual("200 OK", _request(middleware, remote_addr="192.0.2.2")[0])

    def test_concurrent_burst_admits_exactly_the_global_capacity(self) -> None:
        application = _CaptureApplication()
        middleware = TeamAdmissionControlMiddleware(
            application,
            max_concurrency=100,
            global_requests_per_window=10,
            per_source_requests_per_window=None,
            monotonic_clock=lambda: 0.0,
        )
        with ThreadPoolExecutor(max_workers=25) as executor:
            results = list(executor.map(lambda _index: _request(middleware)[0], range(50)))

        self.assertEqual(10, results.count("200 OK"))
        self.assertEqual(40, results.count("429 Too Many Requests"))
        self.assertEqual(10, application.calls)
        self.assertEqual(10, middleware.status.admitted_request_count)
        self.assertEqual(40, middleware.status.rate_rejected_count)
        self.assertEqual(0, middleware.status.active_requests)

    def test_slot_is_released_when_application_or_stream_raises(self) -> None:
        def raising_application(_environ: Mapping[str, Any], _start_response: Any) -> list[bytes]:
            raise RuntimeError("simulated application failure")

        middleware = TeamAdmissionControlMiddleware(
            raising_application,
            per_source_requests_per_window=None,
        )
        with self.assertRaises(RuntimeError):
            middleware(
                {"PATH_INFO": "/v1/team/summary", "wsgi.url_scheme": "https"},
                lambda _status, _headers: None,
            )
        self.assertEqual(0, middleware.status.active_requests)

        def streaming_application(
            _environ: Mapping[str, Any],
            start_response: Any,
        ) -> Iterable[bytes]:
            start_response("200 OK", [])

            def stream() -> Iterable[bytes]:
                yield b"first"
                raise RuntimeError("simulated stream failure")

            return stream()

        streaming = TeamAdmissionControlMiddleware(
            streaming_application,
            per_source_requests_per_window=None,
        )
        iterable = streaming(
            {"PATH_INFO": "/v1/team/summary", "wsgi.url_scheme": "https"},
            lambda _status, _headers: None,
        )
        with self.assertRaises(RuntimeError):
            b"".join(iterable)
        self.assertEqual(0, streaming.status.active_requests)

    def test_health_and_ready_probes_bypass_exhausted_rate_capacity(self) -> None:
        application = _CaptureApplication()
        middleware = TeamAdmissionControlMiddleware(
            application,
            global_requests_per_window=1,
            per_source_requests_per_window=None,
            monotonic_clock=lambda: 0.0,
        )
        self.assertEqual("200 OK", _request(middleware)[0])
        self.assertEqual("429 Too Many Requests", _request(middleware)[0])
        self.assertEqual("200 OK", _request(middleware, path="/healthz")[0])
        self.assertEqual("200 OK", _request(middleware, path="/readyz")[0])
        self.assertEqual(3, application.calls)

    def test_admission_rejects_before_bearer_parsing_or_verification(self) -> None:
        capture = _CaptureApplication()
        verifier = _CountingVerifier()
        authenticated = EntraTeamIdentityMiddleware(capture, verifier)
        middleware = TeamAdmissionControlMiddleware(
            authenticated,
            global_requests_per_window=10,
            per_source_requests_per_window=1,
            rate_window_seconds=10,
            monotonic_clock=lambda: 0.0,
        )

        first = _request(
            middleware,
            authorization="Bearer first-token",
            forwarded_for="198.51.100.1",
        )
        second = _request(
            middleware,
            authorization="not-even-a-bearer-token",
            forwarded_for="203.0.113.9",
        )

        self.assertEqual("200 OK", first[0])
        self.assertEqual("429 Too Many Requests", second[0])
        self.assertEqual(1, verifier.verify_calls)
        self.assertEqual(1, capture.calls)

    def test_invalid_trusted_source_resolver_fails_closed(self) -> None:
        application = _CaptureApplication()
        middleware = TeamAdmissionControlMiddleware(
            application,
            source_resolver=lambda _environ: "invalid\nsource",
        )
        status, _, body = _request(middleware)
        self.assertEqual("503 Service Unavailable", status)
        self.assertEqual("admission_control_unavailable", json.loads(body)["error"]["code"])
        self.assertEqual("admission_source_invalid", middleware.status.last_error_code)
        self.assertEqual(0, application.calls)


if __name__ == "__main__":
    unittest.main()
