"""Tests for the bounded OpenAI-compatible provider quota implementation."""

from __future__ import annotations

import hashlib
import io
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from causure.openai_quota import (
    HTTPSOpenAIResponsesTransport,
    OpenAIModelPricing,
    OpenAIQuotaConfiguration,
    OpenAIQuotaConfigurationError,
    OpenAIQuotaConflictError,
    OpenAIQuotaController,
    OpenAIQuotaControllerError,
    OpenAIQuotaOperation,
    OpenAIQuotaWSGIApplication,
    OpenAIUpstreamResponse,
    SQLiteOpenAIQuotaStore,
    parse_openai_quota_configuration_bytes,
    render_openai_quota_configuration,
)
from causure.sandbox_protocol import QuotaReservation
from tests.helpers import PROJECT_ROOT

_NOW = datetime(2026, 8, 9, 16, 0, tzinfo=UTC)
_ADMIN_TOKEN = "admin-secret-value-that-is-long-enough-123456"
_PROVIDER_KEY = "provider-secret-value-that-is-long-enough-123"


class _Clock:
    def __init__(self, value: datetime = _NOW) -> None:
        self.value = value

    def __call__(self) -> datetime:
        return self.value


def _configuration(**overrides: Any) -> OpenAIQuotaConfiguration:
    values: dict[str, Any] = {
        "schema_version": "1.0",
        "service_id": "openai-quota-production",
        "upstream_responses_url": "https://api.example.test/v1/responses",
        "worker_proxy_url": "https://openai-quota:8443/v1",
        "proxy_container_name": "openai-quota",
        "network_name": "causure-quota",
        "lease_cleanup_seconds": 30,
        "upstream_timeout_seconds": 20.0,
        "max_request_bytes": 65_536,
        "max_response_bytes": 65_536,
        "models": (
            OpenAIModelPricing(
                model="model-exact-2026-08-01",
                input_usd_per_million_tokens="1.000000",
                cached_input_usd_per_million_tokens="0.500000",
                output_usd_per_million_tokens="2.000000",
                max_input_tokens=10_000,
                max_output_tokens=1_000,
            ),
        ),
    }
    values.update(overrides)
    return OpenAIQuotaConfiguration(**values)


def _reservation(**overrides: Any) -> QuotaReservation:
    values: dict[str, Any] = {
        "case_id": "case-openai-quota",
        "max_cost_usd": 1.0,
        "max_concurrency": 1,
        "max_operations": 1,
        "timeout_seconds": 60.0,
    }
    values.update(overrides)
    return QuotaReservation(**values)


def _request_document(**overrides: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "model": "model-exact-2026-08-01",
        "input": "Return the word safe.",
        "max_output_tokens": 20,
        "store": False,
    }
    document.update(overrides)
    return document


def _response_body(
    *,
    input_tokens: int = 12,
    cached_tokens: int = 2,
    output_tokens: int = 3,
    model: str = "model-exact-2026-08-01",
) -> bytes:
    return json.dumps(
        {
            "id": "resp_test_001",
            "model": model,
            "status": "completed",
            "output": [],
            "usage": {
                "input_tokens": input_tokens,
                "input_tokens_details": {"cached_tokens": cached_tokens},
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            },
        },
        separators=(",", ":"),
    ).encode("utf-8")


class _FakeUpstream:
    def __init__(self, response: OpenAIUpstreamResponse | None = None) -> None:
        self.response = response or OpenAIUpstreamResponse(
            status=200,
            content_type="application/json",
            body=_response_body(),
        )
        self.requests: list[bytes] = []

    def send(self, body: bytes) -> OpenAIUpstreamResponse:
        self.requests.append(body)
        return self.response


def _invoke_wsgi(
    application: OpenAIQuotaWSGIApplication,
    path: str,
    *,
    method: str = "POST",
    document: dict[str, Any] | None = None,
    token: str | None = None,
    lease_id: str | None = None,
    scheme: str = "https",
    query: str = "",
) -> tuple[int, dict[str, str], bytes]:
    body = b"" if document is None else json.dumps(document, separators=(",", ":")).encode()
    environ: dict[str, Any] = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": query,
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": "application/json",
        "SERVER_NAME": "quota.invalid",
        "SERVER_PORT": "443",
        "SCRIPT_NAME": "",
        "wsgi.url_scheme": scheme,
        "wsgi.input": io.BytesIO(body),
        "wsgi.errors": io.StringIO(),
        "wsgi.version": (1, 0),
        "wsgi.multithread": True,
        "wsgi.multiprocess": False,
        "wsgi.run_once": False,
    }
    if token is not None:
        environ["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    if lease_id is not None:
        environ["HTTP_X_CAUSURE_LEASE_ID"] = lease_id
    captured: dict[str, Any] = {}

    def start_response(status: str, headers: list[tuple[str, str]]) -> None:
        captured["status"] = int(status.split(" ", maxsplit=1)[0])
        captured["headers"] = dict(headers)

    response_body = b"".join(application(environ, start_response))
    return captured["status"], captured["headers"], response_body


class _InProcessAdminClient:
    def __init__(self, application: OpenAIQuotaWSGIApplication) -> None:
        self.application = application

    def post(self, path: str, document: dict[str, Any]) -> dict[str, Any]:
        status, _, body = _invoke_wsgi(
            self.application,
            path,
            document=document,
            token=_ADMIN_TOKEN,
        )
        parsed = json.loads(body)
        if status not in {200, 201}:
            raise OpenAIQuotaControllerError(
                parsed["error"]["code"],
                parsed["error"]["message"],
            )
        return parsed


class OpenAIQuotaConfigurationTests(unittest.TestCase):
    def test_configuration_round_trips_as_closed_secret_free_json(self) -> None:
        configuration = _configuration()
        rendered = render_openai_quota_configuration(configuration)
        parsed = parse_openai_quota_configuration_bytes(rendered.encode("utf-8"))

        self.assertEqual(configuration, parsed)
        self.assertNotIn("api_key", rendered.lower())
        self.assertNotIn("admin_token", rendered)
        self.assertEqual("/v1/responses", configuration.upstream_responses_url[-13:])

    def test_committed_example_is_valid_and_deliberately_non_operational(self) -> None:
        path = PROJECT_ROOT / "examples" / "quota" / "openai-compatible-reference.json"
        configuration = parse_openai_quota_configuration_bytes(path.read_bytes())

        self.assertEqual("api.openai.invalid", configuration.upstream_responses_url.split("/")[2])
        self.assertEqual("replace-with-an-exact-model-revision", configuration.models[0].model)
        self.assertEqual("100000.000000", configuration.models[0].input_usd_per_million_tokens)

    def test_configuration_rejects_duplicates_unknowns_and_unsafe_urls(self) -> None:
        rendered = render_openai_quota_configuration(_configuration())
        duplicate = rendered.replace(
            '"schema_version": "1.0",',
            '"schema_version": "1.0",\n  "schema_version": "1.0",',
            1,
        )
        with self.assertRaises(OpenAIQuotaConfigurationError):
            parse_openai_quota_configuration_bytes(duplicate.encode())

        document = json.loads(rendered)
        document["unknown"] = True
        with self.assertRaises(OpenAIQuotaConfigurationError):
            parse_openai_quota_configuration_bytes(json.dumps(document).encode())

        with self.assertRaises(OpenAIQuotaConfigurationError):
            _configuration(upstream_responses_url="http://api.example.test/v1/responses")
        with self.assertRaises(OpenAIQuotaConfigurationError):
            _configuration(worker_proxy_url="https://different-name:8443/v1")

    def test_pricing_is_exact_ceiling_arithmetic(self) -> None:
        pricing = _configuration().models[0]

        self.assertEqual(1_005_000, pricing.maximum_cost_nusd(1, 502))
        self.assertEqual(
            7_500_000,
            pricing.actual_cost_nusd(
                input_tokens=2_000,
                cached_input_tokens=1_000,
                output_tokens=3_000,
            ),
        )


class SQLiteOpenAIQuotaStoreTests(unittest.TestCase):
    def _store(self, root: str, clock: _Clock | None = None) -> SQLiteOpenAIQuotaStore:
        store = SQLiteOpenAIQuotaStore(Path(root) / "quota.sqlite3", clock=clock or _Clock())
        store.initialize(created_at="2026-08-09T16:00:00Z")
        return store

    def test_reservation_hashes_token_at_rest_and_covers_cleanup_margin(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            lease = store.reserve(_reservation(), _configuration())
            with closing(sqlite3.connect(store.database_path)) as connection:
                token_hash = connection.execute(
                    "SELECT token_sha256 FROM quota_leases WHERE lease_id = ?",
                    (lease.lease_id,),
                ).fetchone()[0]
                raw_dump = "\n".join(connection.iterdump())

        self.assertEqual(hashlib.sha256(lease.lease_token.encode()).hexdigest(), token_hash)
        self.assertNotIn(lease.lease_token, raw_dump)
        self.assertNotIn(lease.lease_token, repr(lease))
        self.assertGreaterEqual(lease.expires_at, "2026-08-09T16:01:31Z")

    def test_complete_and_settle_use_provider_usage_not_worker_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            lease = store.reserve(_reservation(max_operations=2), _configuration())
            operation = store.begin_operation(
                lease_id=lease.lease_id,
                lease_token=lease.lease_token,
                request_sha256="a" * 64,
                model="model-exact-2026-08-01",
                input_token_limit=100,
                output_token_limit=20,
                reserved_cost_nusd=50_000,
            )
            store.complete_operation(
                operation,
                input_tokens=12,
                cached_input_tokens=2,
                output_tokens=3,
                actual_cost_nusd=17_000,
                upstream_response_id="resp_test",
            )
            settlement = store.settle(lease.lease_id, completed_operations=1)
            snapshot = store.lease_snapshot(lease.lease_id)

        self.assertEqual("settled", settlement.status)
        self.assertEqual(0.000017, settlement.actual_cost_usd)
        self.assertEqual("settled", snapshot["state"])
        self.assertEqual(0, snapshot["held_cost_nusd"])

    def test_cost_operation_concurrency_and_expiry_limits_fail_before_admission(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            clock = _Clock()
            store = self._store(directory, clock)
            lease = store.reserve(
                _reservation(max_cost_usd=0.00005, max_operations=2),
                _configuration(),
            )
            first = store.begin_operation(
                lease_id=lease.lease_id,
                lease_token=lease.lease_token,
                request_sha256="b" * 64,
                model="model-exact-2026-08-01",
                input_token_limit=100,
                output_token_limit=20,
                reserved_cost_nusd=40_000,
            )
            with self.assertRaisesRegex(OpenAIQuotaConflictError, "concurrency_limit"):
                store.begin_operation(
                    lease_id=lease.lease_id,
                    lease_token=lease.lease_token,
                    request_sha256="c" * 64,
                    model="model-exact-2026-08-01",
                    input_token_limit=100,
                    output_token_limit=20,
                    reserved_cost_nusd=1,
                )
            store.complete_operation(
                first,
                input_tokens=1,
                cached_input_tokens=0,
                output_tokens=1,
                actual_cost_nusd=30_000,
                upstream_response_id=None,
            )
            with self.assertRaisesRegex(OpenAIQuotaConflictError, "cost_limit"):
                store.begin_operation(
                    lease_id=lease.lease_id,
                    lease_token=lease.lease_token,
                    request_sha256="d" * 64,
                    model="model-exact-2026-08-01",
                    input_token_limit=100,
                    output_token_limit=20,
                    reserved_cost_nusd=30_000,
                )
            clock.value += timedelta(minutes=3)
            with self.assertRaisesRegex(OpenAIQuotaConflictError, "lease_expired"):
                store.begin_operation(
                    lease_id=lease.lease_id,
                    lease_token=lease.lease_token,
                    request_sha256="e" * 64,
                    model="model-exact-2026-08-01",
                    input_token_limit=100,
                    output_token_limit=20,
                    reserved_cost_nusd=1,
                )

    def test_uncertain_operation_burns_its_maximum_and_blocks_settlement(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            lease = store.reserve(_reservation(), _configuration())
            operation = store.begin_operation(
                lease_id=lease.lease_id,
                lease_token=lease.lease_token,
                request_sha256="f" * 64,
                model="model-exact-2026-08-01",
                input_token_limit=100,
                output_token_limit=20,
                reserved_cost_nusd=50_000,
            )
            store.mark_operation_uncertain(operation, reason_code="upstream_failed")
            snapshot = store.lease_snapshot(lease.lease_id)
            with self.assertRaisesRegex(OpenAIQuotaConflictError, "not_settleable"):
                store.settle(lease.lease_id, completed_operations=0)
            store.cancel(lease.lease_id, reason_code="sandbox_execution_failed")
            after_cancel = store.lease_snapshot(lease.lease_id)

        self.assertEqual("failed", snapshot["state"])
        self.assertEqual(50_000, snapshot["uncertain_cost_nusd"])
        self.assertEqual(0, snapshot["in_flight"])
        self.assertEqual("failed", after_cancel["state"])
        self.assertEqual("upstream_failed", after_cancel["terminal_reason"])

    def test_cancel_is_same_reason_idempotent_and_revokes_new_operations(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            lease = store.reserve(_reservation(), _configuration())
            store.cancel(lease.lease_id, reason_code="sandbox_failed")
            store.cancel(lease.lease_id, reason_code="sandbox_failed")
            with self.assertRaisesRegex(OpenAIQuotaConflictError, "lease_inactive"):
                store.begin_operation(
                    lease_id=lease.lease_id,
                    lease_token=lease.lease_token,
                    request_sha256="1" * 64,
                    model="model-exact-2026-08-01",
                    input_token_limit=100,
                    output_token_limit=20,
                    reserved_cost_nusd=1,
                )
            with self.assertRaisesRegex(OpenAIQuotaConflictError, "reason_mismatch"):
                store.cancel(lease.lease_id, reason_code="different_reason")

    def test_begin_operation_is_atomic_under_concurrency(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = self._store(directory)
            lease = store.reserve(_reservation(max_operations=2), _configuration())
            barrier = threading.Barrier(2)

            def begin(index: int) -> OpenAIQuotaOperation | str:
                barrier.wait()
                try:
                    return store.begin_operation(
                        lease_id=lease.lease_id,
                        lease_token=lease.lease_token,
                        request_sha256=str(index) * 64,
                        model="model-exact-2026-08-01",
                        input_token_limit=100,
                        output_token_limit=20,
                        reserved_cost_nusd=1,
                    )
                except OpenAIQuotaConflictError as exc:
                    return exc.code

            with ThreadPoolExecutor(max_workers=2) as executor:
                results = list(executor.map(begin, (2, 3)))

        self.assertEqual(1, sum(isinstance(item, OpenAIQuotaOperation) for item in results))
        self.assertIn("concurrency_limit_exceeded", results)


class OpenAIQuotaWSGIApplicationTests(unittest.TestCase):
    def _application(
        self,
        root: str,
        upstream: _FakeUpstream | None = None,
        *,
        configuration: OpenAIQuotaConfiguration | None = None,
    ) -> tuple[OpenAIQuotaWSGIApplication, SQLiteOpenAIQuotaStore, _FakeUpstream]:
        selected_configuration = configuration or _configuration()
        store = SQLiteOpenAIQuotaStore(Path(root) / "quota.sqlite3", clock=_Clock())
        store.initialize(created_at="2026-08-09T16:00:00Z")
        selected_upstream = upstream or _FakeUpstream()
        return (
            OpenAIQuotaWSGIApplication(
                selected_configuration,
                store,
                _ADMIN_TOKEN,
                selected_upstream,
            ),
            store,
            selected_upstream,
        )

    def test_controller_worker_and_settlement_complete_end_to_end(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store, upstream = self._application(directory)
            controller = OpenAIQuotaController(_InProcessAdminClient(application))
            lease = controller.reserve(_reservation())
            status, headers, body = _invoke_wsgi(
                application,
                "/v1/responses",
                document=_request_document(),
                token=lease.lease_token,
                lease_id=lease.lease_id,
            )
            settlement = controller.settle(lease.lease_id, completed_operations=1)
            snapshot = store.lease_snapshot(lease.lease_id)

        self.assertEqual(200, status)
        self.assertEqual(_response_body(), body)
        self.assertEqual("no-store", headers["Cache-Control"])
        self.assertEqual(1, len(upstream.requests))
        self.assertEqual("settled", snapshot["state"])
        self.assertEqual(0.000017, settlement.actual_cost_usd)
        self.assertNotIn(lease.lease_token, repr(application))

    def test_admin_and_worker_routes_require_https_and_distinct_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, _, _ = self._application(directory)
            status, _, body = _invoke_wsgi(
                application,
                "/admin/v1/leases",
                document={
                    "case_id": "case-openai-quota",
                    "max_cost_usd": 1.0,
                    "max_concurrency": 1,
                    "max_operations": 1,
                    "timeout_seconds": 60.0,
                },
                token="worker-lease-secret-that-is-long-enough-1234",
            )
            http_status, _, _ = _invoke_wsgi(
                application,
                "/admin/v1/leases",
                document={"invalid": True},
                token=_ADMIN_TOKEN,
                scheme="http",
            )

        self.assertEqual(401, status)
        self.assertNotIn("worker-lease-secret", body.decode())
        self.assertEqual(400, http_status)

    def test_closed_request_rejects_unbounded_features_before_upstream(self) -> None:
        invalid_documents = (
            _request_document(stream=True),
            _request_document(store=True),
            _request_document(tools=[{"type": "web_search"}]),
            _request_document(
                input=[
                    {
                        "role": "user",
                        "content": [{"type": "input_image", "image_url": "https://example.test/x"}],
                    }
                ]
            ),
            _request_document(model="unconfigured-model"),
        )
        with tempfile.TemporaryDirectory() as directory:
            application, _, upstream = self._application(directory)
            controller = OpenAIQuotaController(_InProcessAdminClient(application))
            for document in invalid_documents:
                with self.subTest(document=document):
                    lease = controller.reserve(_reservation())
                    status, _, _ = _invoke_wsgi(
                        application,
                        "/v1/responses",
                        document=document,
                        token=lease.lease_token,
                        lease_id=lease.lease_id,
                    )
                    self.assertEqual(400, status)
                    controller.cancel(lease.lease_id, reason_code="request_rejected")

        self.assertEqual([], upstream.requests)

    def test_cost_is_reserved_before_forwarding(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store, upstream = self._application(directory)
            controller = OpenAIQuotaController(_InProcessAdminClient(application))
            lease = controller.reserve(_reservation(max_cost_usd=0.005))
            status, _, body = _invoke_wsgi(
                application,
                "/v1/responses",
                document=_request_document(max_output_tokens=1),
                token=lease.lease_token,
                lease_id=lease.lease_id,
            )
            snapshot = store.lease_snapshot(lease.lease_id)

        self.assertEqual(402, status)
        self.assertIn(b"cost_limit_exceeded", body)
        self.assertEqual([], upstream.requests)
        self.assertEqual(0, snapshot["operation_count"])

    def test_missing_usage_revokes_lease_and_retains_worst_case_liability(self) -> None:
        upstream = _FakeUpstream(
            OpenAIUpstreamResponse(
                status=200,
                content_type="application/json",
                body=b'{"id":"resp_bad","model":"model-exact-2026-08-01"}',
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            application, store, _ = self._application(directory, upstream)
            controller = OpenAIQuotaController(_InProcessAdminClient(application))
            lease = controller.reserve(_reservation())
            status, _, body = _invoke_wsgi(
                application,
                "/v1/responses",
                document=_request_document(),
                token=lease.lease_token,
                lease_id=lease.lease_id,
            )
            snapshot = store.lease_snapshot(lease.lease_id)
            with self.assertRaises(OpenAIQuotaControllerError):
                controller.settle(lease.lease_id, completed_operations=1)

        self.assertEqual(502, status)
        self.assertIn(b"upstream_usage_missing", body)
        self.assertEqual("failed", snapshot["state"])
        self.assertGreater(snapshot["uncertain_cost_nusd"], 0)

    def test_non_success_provider_response_is_not_treated_as_zero_cost(self) -> None:
        upstream = _FakeUpstream(
            OpenAIUpstreamResponse(
                status=429,
                content_type="application/json",
                body=b'{"error":{"message":"limited"}}',
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            application, store, _ = self._application(directory, upstream)
            controller = OpenAIQuotaController(_InProcessAdminClient(application))
            lease = controller.reserve(_reservation())
            status, _, _ = _invoke_wsgi(
                application,
                "/v1/responses",
                document=_request_document(),
                token=lease.lease_token,
                lease_id=lease.lease_id,
            )
            snapshot = store.lease_snapshot(lease.lease_id)

        self.assertEqual(502, status)
        self.assertEqual("failed", snapshot["state"])
        self.assertGreater(snapshot["uncertain_cost_nusd"], 0)

    def test_health_and_readiness_are_secret_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, _, _ = self._application(directory)
            health, _, health_body = _invoke_wsgi(
                application,
                "/healthz",
                method="GET",
                scheme="http",
            )
            ready, _, ready_body = _invoke_wsgi(
                application,
                "/readyz",
                method="GET",
                scheme="http",
            )

        self.assertEqual(200, health)
        self.assertEqual(200, ready)
        self.assertNotIn(_ADMIN_TOKEN.encode(), health_body + ready_body)


class _FakeHTTPResponse:
    def __init__(self, body: bytes, *, url: str, status: int = 200) -> None:
        self._body = body
        self._url = url
        self.status = status
        self.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }
        self.closed = False

    def geturl(self) -> str:
        return self._url

    def read(self, maximum: int) -> bytes:
        return self._body[:maximum]

    def close(self) -> None:
        self.closed = True


class _FakeOpener:
    def __init__(self, response: _FakeHTTPResponse) -> None:
        self.response = response
        self.requests: list[Any] = []
        self.timeouts: list[float] = []

    def open(self, request: Any, *, timeout: float) -> _FakeHTTPResponse:
        self.requests.append(request)
        self.timeouts.append(timeout)
        return self.response


class HTTPSOpenAIResponsesTransportTests(unittest.TestCase):
    def test_transport_owns_provider_key_without_rendering_it(self) -> None:
        configuration = _configuration()
        response = _FakeHTTPResponse(
            _response_body(),
            url=configuration.upstream_responses_url,
        )
        opener = _FakeOpener(response)
        transport = HTTPSOpenAIResponsesTransport(
            configuration,
            _PROVIDER_KEY,
            opener=opener,
        )
        body = json.dumps(_request_document()).encode()

        result = transport.send(body)
        request = opener.requests[0]

        self.assertEqual(200, result.status)
        self.assertEqual(f"Bearer {_PROVIDER_KEY}", request.get_header("Authorization"))
        self.assertEqual(body, request.data)
        self.assertNotIn(_PROVIDER_KEY, repr(transport))
        self.assertEqual([20.0], opener.timeouts)
        self.assertTrue(response.closed)

    def test_transport_rejects_redirected_final_url(self) -> None:
        configuration = _configuration()
        response = _FakeHTTPResponse(
            _response_body(),
            url="https://different.example/v1/responses",
        )
        transport = HTTPSOpenAIResponsesTransport(
            configuration,
            _PROVIDER_KEY,
            opener=_FakeOpener(response),
        )

        with self.assertRaisesRegex(Exception, "redirect"):
            transport.send(json.dumps(_request_document()).encode())


if __name__ == "__main__":
    unittest.main()
