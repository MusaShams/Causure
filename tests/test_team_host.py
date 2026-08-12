"""Single-host Team service configuration and lifecycle tests."""

from __future__ import annotations

import copy
import hashlib
import io
import json
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import Mock, patch

import causure.team_host as team_host
from causure.team_entra import EntraTokenVerifier
from causure.team_host import (
    MAX_TEAM_HOST_CONFIG_BYTES,
    TEAM_HOST_WAITRESS_VERSION,
    TeamHostConfigurationError,
    TeamHostDependencyError,
    TeamHostRuntimeError,
    TeamHostServer,
    create_team_host_runtime,
    create_team_host_server,
    load_team_host_configuration,
    load_team_host_configuration_subject,
    parse_team_host_configuration,
    parse_team_host_configuration_bytes,
    render_team_host_configuration,
    serve_team_host,
    validate_team_host_dependencies,
)
from causure.team_http import MAX_TEAM_HTTP_REQUEST_BYTES
from tests.helpers import PROJECT_ROOT


class _FakeManagedVerifier(EntraTokenVerifier):
    instances: list[_FakeManagedVerifier] = []

    def __init__(self, configuration: Any, path: str, **kwargs: Any) -> None:
        self.configuration = configuration
        self.path = path
        self.kwargs = kwargs
        self.started = False
        self.closed = False
        self.close_timeout: float | None = None
        self.instances.append(self)

    def start(self) -> _FakeManagedVerifier:
        self.started = True
        return self

    def close(self, *, timeout_seconds: float = 30.0) -> None:
        self.closed = True
        self.close_timeout = timeout_seconds

    def check_ready(self) -> None:
        if not self.started or self.closed:
            raise RuntimeError("fake verifier is unavailable")

    def verify(self, token: str) -> Any:
        raise AssertionError(f"unexpected token verification: {token}")


class _FailingManagedVerifier(_FakeManagedVerifier):
    def start(self) -> _FailingManagedVerifier:
        self.started = True
        raise RuntimeError("managed startup failed")


class _FakeDispatcher:
    def __init__(self) -> None:
        self.calls: list[tuple[bool, float]] = []

    def shutdown(self, *, cancel_pending: bool, timeout: float) -> None:
        self.calls.append((cancel_pending, timeout))


class _FakeWaitressServer:
    def __init__(self, application: Any, kwargs: dict[str, Any]) -> None:
        self.application = application
        self.kwargs = kwargs
        self.task_dispatcher = _FakeDispatcher()
        self._map: dict[str, object] = {"listener": object()}
        self.run_count = 0
        self.close_count = 0
        self.run_error: BaseException | None = None

    def run(self) -> None:
        self.run_count += 1
        status, _, _ = _health_request(self.application)
        if status != "200 OK":
            raise AssertionError(f"unexpected health status: {status}")
        if self.run_error is not None:
            raise self.run_error

    def close(self) -> None:
        self.close_count += 1


def _host_document(directory: str) -> tuple[dict[str, Any], bytes]:
    root = Path(directory)
    refresh_bytes = (PROJECT_ROOT / "examples" / "team" / "acme-entra-refresh.json").read_bytes()
    refresh_path = root / "entra-refresh.json"
    refresh_path.write_bytes(refresh_bytes)
    document: dict[str, Any] = {
        "schema_version": "1.0",
        "database": {
            "path": str(root / "team.sqlite3"),
            "busy_timeout_ms": 5000,
        },
        "server": {
            "implementation": "waitress",
            "version": TEAM_HOST_WAITRESS_VERSION,
            "listen_host": "127.0.0.1",
            "listen_port": 8080,
            "trusted_external_scheme": "https",
            "threads": 8,
            "connection_limit": 64,
            "backlog": 64,
            "channel_timeout_seconds": 30,
            "max_request_header_bytes": 32768,
        },
        "identity": {
            "refresh_configuration_path": str(refresh_path),
            "refresh_configuration_sha256": hashlib.sha256(refresh_bytes).hexdigest(),
            "refresh_configuration_byte_count": len(refresh_bytes),
            "trust_store_path": str(root / "entra-trust.json"),
            "store_id": "entra-production",
            "clock_skew_seconds": 60,
            "refresh_timeout_seconds": 10,
            "refresh_interval_seconds": 3600,
            "failure_retry_seconds": 300,
            "unknown_key_refresh_seconds": 300,
        },
        "admission": {
            "max_concurrency": 8,
            "global_requests_per_window": 600,
            "per_source_requests_per_window": None,
            "rate_window_seconds": 60,
            "max_tracked_sources": 4096,
            "source_idle_seconds": 600,
        },
    }
    return document, refresh_bytes


def _health_request(application: Any) -> tuple[str, dict[str, str], bytes]:
    captured: dict[str, Any] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = status
        captured["headers"] = dict(headers)

    response = application(
        {
            "REQUEST_METHOD": "GET",
            "PATH_INFO": "/healthz",
            "QUERY_STRING": "",
            "CONTENT_LENGTH": "0",
            "SERVER_NAME": "localhost",
            "SERVER_PORT": "8080",
            "SCRIPT_NAME": "",
            "wsgi.url_scheme": "https",
            "wsgi.input": io.BytesIO(),
            "wsgi.errors": io.StringIO(),
            "wsgi.version": (1, 0),
            "wsgi.multithread": True,
            "wsgi.multiprocess": False,
            "wsgi.run_once": False,
            "REMOTE_ADDR": "127.0.0.1",
        },
        start_response,
    )
    body = b"".join(response)
    close = getattr(response, "close", None)
    if callable(close):
        close()
    return str(captured["status"]), dict(captured["headers"]), body


class TeamHostConfigurationTests(unittest.TestCase):
    def test_parse_render_and_load_closed_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document, _ = _host_document(directory)
            configuration = parse_team_host_configuration(document)
            rendered = render_team_host_configuration(configuration)
            path = Path(directory) / "host.json"
            path.write_text(rendered, encoding="utf-8")

            loaded = load_team_host_configuration(path)
            subject = load_team_host_configuration_subject(path)
            registered_bytes = path.read_bytes()

        self.assertEqual(configuration, loaded)
        self.assertEqual(configuration, subject.configuration)
        self.assertEqual(str(path), subject.path)
        self.assertEqual(hashlib.sha256(registered_bytes).hexdigest(), subject.sha256)
        self.assertEqual(len(registered_bytes), subject.byte_count)
        self.assertEqual("127.0.0.1", loaded.server.listen_host)
        self.assertEqual("https", loaded.server.trusted_external_scheme)
        self.assertIsNone(loaded.admission.per_source_requests_per_window)

    def test_bytes_reject_duplicates_invalid_utf8_and_oversize(self) -> None:
        duplicate = b'{"schema_version":"1.0","schema_version":"1.0"}'
        for value in (duplicate, b"\xff", b"x" * (MAX_TEAM_HOST_CONFIG_BYTES + 1)):
            with self.subTest(value_length=len(value)):
                with self.assertRaises(TeamHostConfigurationError):
                    parse_team_host_configuration_bytes(value)

    def test_configuration_rejects_unsafe_or_inconsistent_values(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            original, _ = _host_document(directory)
            cases: list[tuple[str, Any]] = [
                ("unknown field", lambda item: item.__setitem__("unexpected", True)),
                (
                    "non-loopback listener",
                    lambda item: item["server"].__setitem__("listen_host", "0.0.0.0"),
                ),
                (
                    "untrusted scheme",
                    lambda item: item["server"].__setitem__("trusted_external_scheme", "http"),
                ),
                (
                    "wrong server version",
                    lambda item: item["server"].__setitem__("version", "3.0.1"),
                ),
                (
                    "relative database",
                    lambda item: item["database"].__setitem__("path", "team.sqlite3"),
                ),
                (
                    "network database",
                    lambda item: item["database"].__setitem__(
                        "path", r"\\server\share\team.sqlite3"
                    ),
                ),
                (
                    "path collision",
                    lambda item: item["identity"].__setitem__(
                        "trust_store_path", item["database"]["path"]
                    ),
                ),
                (
                    "concurrency exceeds threads",
                    lambda item: item["admission"].__setitem__("max_concurrency", 9),
                ),
                (
                    "per-source exceeds global",
                    lambda item: item["admission"].__setitem__(
                        "per_source_requests_per_window", 601
                    ),
                ),
                (
                    "retry exceeds interval",
                    lambda item: item["identity"].__setitem__("failure_retry_seconds", 3601),
                ),
            ]
            for name, mutate in cases:
                with self.subTest(name=name):
                    candidate = copy.deepcopy(original)
                    mutate(candidate)
                    with self.assertRaises(TeamHostConfigurationError):
                        parse_team_host_configuration(candidate)


class TeamHostRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        _FakeManagedVerifier.instances.clear()

    def test_runtime_composes_health_path_and_closes_refresh_worker(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document, _ = _host_document(directory)
            configuration = parse_team_host_configuration(document)
            with patch(
                "causure.team_host.ManagedEntraAccessTokenVerifier",
                _FakeManagedVerifier,
            ):
                runtime = create_team_host_runtime(configuration)
                status, headers, body = _health_request(runtime.application)
                runtime.close(timeout_seconds=7)
                runtime.close(timeout_seconds=7)

            self.assertTrue(Path(configuration.database.path).is_file())

        self.assertEqual("200 OK", status)
        self.assertEqual("no-store", headers["Cache-Control"])
        self.assertEqual("ok", json.loads(body)["status"])
        verifier = _FakeManagedVerifier.instances[0]
        self.assertTrue(verifier.started)
        self.assertTrue(verifier.closed)
        self.assertEqual(7, verifier.close_timeout)
        self.assertEqual("entra-production", verifier.configuration.store_id)

    def test_subject_mismatch_fails_before_database_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document, _ = _host_document(directory)
            configuration = parse_team_host_configuration(document)
            Path(configuration.identity.refresh_configuration_path).write_bytes(b"{}")

            with self.assertRaises(TeamHostRuntimeError) as raised:
                create_team_host_runtime(configuration)

            self.assertFalse(Path(configuration.database.path).exists())
        self.assertEqual("identity_configuration_subject_mismatch", raised.exception.code)

    def test_managed_startup_failure_still_closes_verifier(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document, _ = _host_document(directory)
            configuration = parse_team_host_configuration(document)

            with (
                patch(
                    "causure.team_host.ManagedEntraAccessTokenVerifier",
                    _FailingManagedVerifier,
                ),
                self.assertRaisesRegex(RuntimeError, "managed startup failed"),
            ):
                create_team_host_runtime(configuration)

        verifier = _FakeManagedVerifier.instances[0]
        self.assertTrue(verifier.started)
        self.assertTrue(verifier.closed)

    def test_serve_passes_hardened_waitress_settings_and_always_closes(self) -> None:
        from waitress.adjustments import Adjustments

        with tempfile.TemporaryDirectory() as directory:
            document, _ = _host_document(directory)
            configuration = parse_team_host_configuration(document)
            servers: list[_FakeWaitressServer] = []
            closed_maps: list[dict[Any, Any]] = []

            def fake_create_server(application: Any, **kwargs: Any) -> _FakeWaitressServer:
                server = _FakeWaitressServer(application, kwargs)
                servers.append(server)
                return server

            def fake_close_all(server_map: dict[Any, Any]) -> None:
                closed_maps.append(server_map)
                server_map.clear()

            with (
                patch(
                    "causure.team_host.ManagedEntraAccessTokenVerifier",
                    _FakeManagedVerifier,
                ),
                patch(
                    "causure.team_host._load_waitress_server",
                    return_value=(fake_create_server, fake_close_all, Adjustments),
                ) as load_server,
            ):
                serve_team_host(configuration)

        load_server.assert_called_once_with(TEAM_HOST_WAITRESS_VERSION)
        self.assertEqual(1, len(servers))
        server = servers[0]
        arguments = server.kwargs
        self.assertEqual("127.0.0.1", arguments["host"])
        self.assertEqual("https", arguments["url_scheme"])
        self.assertEqual(MAX_TEAM_HTTP_REQUEST_BYTES, arguments["max_request_body_size"])
        self.assertIsNone(arguments["trusted_proxy"])
        self.assertEqual(set(), arguments["trusted_proxy_headers"])
        self.assertTrue(arguments["clear_untrusted_proxy_headers"])
        self.assertFalse(arguments["expose_tracebacks"])
        self.assertEqual(1, server.run_count)
        self.assertEqual(1, server.close_count)
        self.assertEqual([(True, 5.0)], server.task_dispatcher.calls)
        self.assertEqual([{}], closed_maps)
        self.assertTrue(_FakeManagedVerifier.instances[0].closed)

    def test_waitress_parser_does_not_promote_any_proxy_header_to_trusted(self) -> None:
        from waitress.adjustments import Adjustments

        with tempfile.TemporaryDirectory() as directory:
            document, _ = _host_document(directory)
            configuration = parse_team_host_configuration(document)

            adjustments = Adjustments(**team_host._waitress_arguments(configuration))

        self.assertIsNone(adjustments.trusted_proxy)
        self.assertEqual(set(), adjustments.trusted_proxy_headers)
        self.assertTrue(adjustments.clear_untrusted_proxy_headers)
        self.assertEqual("https", adjustments.url_scheme)
        self.assertEqual(MAX_TEAM_HTTP_REQUEST_BYTES, adjustments.max_request_body_size)

    def test_server_failure_still_closes_refresh_worker(self) -> None:
        from waitress.adjustments import Adjustments

        with tempfile.TemporaryDirectory() as directory:
            document, _ = _host_document(directory)
            configuration = parse_team_host_configuration(document)
            servers: list[_FakeWaitressServer] = []

            def fake_create_server(application: Any, **kwargs: Any) -> _FakeWaitressServer:
                server = _FakeWaitressServer(application, kwargs)
                server.run_error = OSError("server loop failed")
                servers.append(server)
                return server

            with (
                patch(
                    "causure.team_host.ManagedEntraAccessTokenVerifier",
                    _FakeManagedVerifier,
                ),
                patch(
                    "causure.team_host._load_waitress_server",
                    return_value=(
                        fake_create_server,
                        lambda server_map: server_map.clear(),
                        Adjustments,
                    ),
                ),
                self.assertRaisesRegex(OSError, "server loop failed"),
            ):
                serve_team_host(configuration)

        self.assertEqual(1, servers[0].close_count)
        self.assertTrue(_FakeManagedVerifier.instances[0].closed)

    def test_listener_creation_failure_closes_refresh_worker(self) -> None:
        from waitress.adjustments import Adjustments

        with tempfile.TemporaryDirectory() as directory:
            document, _ = _host_document(directory)
            configuration = parse_team_host_configuration(document)

            def failed_create_server(application: Any, **kwargs: Any) -> Any:
                raise OSError("address already in use")

            with (
                patch(
                    "causure.team_host.ManagedEntraAccessTokenVerifier",
                    _FakeManagedVerifier,
                ),
                patch(
                    "causure.team_host._load_waitress_server",
                    return_value=(failed_create_server, lambda server_map: None, Adjustments),
                ),
                self.assertRaises(TeamHostRuntimeError) as raised,
            ):
                create_team_host_server(configuration)

        self.assertEqual("server_start_failed", raised.exception.code)
        self.assertTrue(_FakeManagedVerifier.instances[0].closed)

    def test_controllable_server_rejects_second_run_and_invalid_timeout(self) -> None:
        from waitress.adjustments import Adjustments

        with tempfile.TemporaryDirectory() as directory:
            document, _ = _host_document(directory)
            configuration = parse_team_host_configuration(document)
            servers: list[_FakeWaitressServer] = []

            def fake_create_server(application: Any, **kwargs: Any) -> _FakeWaitressServer:
                server = _FakeWaitressServer(application, kwargs)
                servers.append(server)
                return server

            with (
                patch(
                    "causure.team_host.ManagedEntraAccessTokenVerifier",
                    _FakeManagedVerifier,
                ),
                patch(
                    "causure.team_host._load_waitress_server",
                    return_value=(
                        fake_create_server,
                        lambda server_map: server_map.clear(),
                        Adjustments,
                    ),
                ),
            ):
                controller = create_team_host_server(configuration)
                with self.assertRaises(ValueError):
                    controller.close(request_timeout_seconds=0)
                controller.run()
                with self.assertRaises(TeamHostRuntimeError) as raised:
                    controller.run()

        self.assertEqual("server_closed", raised.exception.code)
        self.assertTrue(controller.closed)
        self.assertEqual(1, servers[0].run_count)

    def test_exact_waitress_dependency_and_normalized_settings_validate(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document, _ = _host_document(directory)
            configuration = parse_team_host_configuration(document)

            validate_team_host_dependencies(configuration)

    def test_expected_closed_socket_error_is_suppressed_only_during_shutdown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            document, _ = _host_document(directory)
            configuration = parse_team_host_configuration(document)
            runtime = Mock()
            started = threading.Event()
            released = threading.Event()

            class ClosingSocketServer:
                task_dispatcher = _FakeDispatcher()
                _map: dict[str, object] = {"listener": object()}

                def run(self) -> None:
                    started.set()
                    if not released.wait(timeout=2):
                        raise AssertionError("server close was not requested")
                    raise OSError(10038, "not a socket")

                def close(self) -> None:
                    released.set()

            controller = TeamHostServer(
                configuration=configuration,
                runtime=runtime,
                server=ClosingSocketServer(),
                close_all=lambda server_map: server_map.clear(),
            )
            failures: list[BaseException] = []

            def run() -> None:
                try:
                    controller.run()
                except BaseException as exc:
                    failures.append(exc)

            thread = threading.Thread(target=run)
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            controller.close(request_timeout_seconds=1)
            thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual([], failures)
        runtime.close.assert_called_once_with(timeout_seconds=30.0)

    def test_real_waitress_loop_can_be_stopped_from_a_service_control_thread(self) -> None:
        from waitress import create_server
        from waitress.wasyncore import close_all

        with tempfile.TemporaryDirectory() as directory:
            document, _ = _host_document(directory)
            configuration = parse_team_host_configuration(document)
            runtime = Mock()

            def application(environ: Any, start_response: Any) -> list[bytes]:
                start_response("200 OK", [("Content-Length", "0")])
                return [b""]

            waitress_server = create_server(
                application,
                host="127.0.0.1",
                port=0,
                threads=1,
                asyncore_loop_timeout=0.1,
            )
            started = threading.Event()
            original_run = waitress_server.run

            def observed_run() -> None:
                started.set()
                original_run()

            waitress_server.run = observed_run
            controller = TeamHostServer(
                configuration=configuration,
                runtime=runtime,
                server=waitress_server,
                close_all=close_all,
            )
            failures: list[BaseException] = []

            def run() -> None:
                try:
                    controller.run()
                except BaseException as exc:
                    failures.append(exc)

            thread = threading.Thread(target=run)
            thread.start()
            self.assertTrue(started.wait(timeout=2))
            controller.close(request_timeout_seconds=1)
            thread.join(timeout=2)

        self.assertFalse(thread.is_alive())
        self.assertEqual([], failures)
        runtime.close.assert_called_once_with(timeout_seconds=30.0)

    def test_wrong_waitress_version_fails_closed(self) -> None:
        with patch.object(team_host.metadata, "version", return_value="9.9.9"):
            with self.assertRaises(TeamHostDependencyError):
                team_host._load_waitress_server(TEAM_HOST_WAITRESS_VERSION)


if __name__ == "__main__":
    unittest.main()
