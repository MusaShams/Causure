"""Adversarial WSGI tests for the trusted-identity Team HTTP boundary."""

from __future__ import annotations

import base64
import io
import json
import tempfile
import unittest
from copy import deepcopy
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from wsgiref.util import setup_testing_defaults

from causure.engine import review_case
from causure.models import parse_change_case
from causure.report import render_json
from causure.team_application import (
    AuthenticatedTeamIdentity,
    TeamApplicationService,
)
from causure.team_http import (
    MAX_TEAM_HTTP_REQUEST_BYTES,
    TEAM_IDENTITY_ENVIRON_KEY,
    TEAM_REQUEST_INTEGRITY_ENVIRON_KEY,
    TeamWSGIApplication,
)
from causure.team_store import SQLiteTeamStore
from tests.helpers import load_example
from tests.test_team_application import _Identifiers, _investigation_fixtures
from tests.test_team_cases import _approval_artifacts, _base_artifacts
from tests.test_team_service import _policy_bytes

_MISSING = object()


class _AdvancingClock:
    def __init__(self) -> None:
        self._next = datetime(2026, 7, 28, 10, 0, tzinfo=UTC)

    def __call__(self) -> str:
        value = self._next.strftime("%Y-%m-%dT%H:%M:%SZ")
        self._next += timedelta(minutes=1)
        return value


def _identity(subject_id: str = "alice-investigator") -> AuthenticatedTeamIdentity:
    return AuthenticatedTeamIdentity(
        tenant_id="tenant-acme",
        identity_provider="entra:contoso",
        subject_id=subject_id,
    )


def _application(
    directory: str,
    *,
    initialize: bool = True,
) -> tuple[TeamWSGIApplication, SQLiteTeamStore]:
    store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
    if initialize:
        store.initialize()
        store.put_policy(_policy_bytes())
    service = TeamApplicationService(
        store,
        clock=_AdvancingClock(),
        identifier_factory=_Identifiers(),
    )
    return TeamWSGIApplication(service), store


def _action_document(
    *,
    expected_head_sha256: str | None,
    action: str = "investigation_write",
    resource_type: str = "investigation",
    resource_id: str = "investigation-17",
    outcome: str = "succeeded",
    payload_bytes: bytes = b'{"status":"opened"}',
) -> dict[str, Any]:
    return {
        "action": action,
        "resource": {
            "type": resource_type,
            "id": resource_id,
        },
        "outcome": outcome,
        "payload": {
            "media_type": "application/json",
            "base64url": base64.urlsafe_b64encode(payload_bytes).rstrip(b"=").decode("ascii"),
        },
        "expected_head_sha256": expected_head_sha256,
    }


def _encoded_artifact(raw_bytes: bytes) -> dict[str, str]:
    return {"base64url": base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")}


def _case_document(
    case_bytes: bytes,
    review_bytes: bytes,
    *,
    expected_head_sha256: str | None,
    publication_bytes: bytes | None = None,
    verification_bytes: bytes | None = None,
    approval_bytes: bytes | None = None,
    canary_bytes: bytes | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "case_id": json.loads(case_bytes)["case_id"],
        "change_case": _encoded_artifact(case_bytes),
        "review_result": _encoded_artifact(review_bytes),
        "expected_head_sha256": expected_head_sha256,
    }
    for name, raw_bytes in (
        ("azure_publication", publication_bytes),
        ("azure_verification", verification_bytes),
        ("approval_verification", approval_bytes),
        ("canary_result", canary_bytes),
    ):
        if raw_bytes is not None:
            document[name] = _encoded_artifact(raw_bytes)
    return document


def _investigation_open_document(
    fixture_bytes: bytes,
    cluster_id: str,
    *,
    expected_head_sha256: str | None,
    investigation_id: str = "investigation-http-001",
    title: str = "Unexpected refund-tool behavior",
) -> dict[str, Any]:
    return {
        "investigation_id": investigation_id,
        "fixture": _encoded_artifact(fixture_bytes),
        "cluster_id": cluster_id,
        "title": title,
        "priority": "high",
        "expected_revision": 0,
        "expected_head_sha256": expected_head_sha256,
    }


def _investigation_attach_document(
    fixture_bytes: bytes,
    cluster_id: str,
    *,
    expected_revision: int,
    expected_head_sha256: str,
) -> dict[str, Any]:
    return {
        "fixture": _encoded_artifact(fixture_bytes),
        "cluster_id": cluster_id,
        "expected_revision": expected_revision,
        "expected_head_sha256": expected_head_sha256,
    }


def _investigation_transition_document(
    *,
    expected_revision: int,
    expected_head_sha256: str,
    title: str = "Refund-tool cluster under investigation",
) -> dict[str, Any]:
    return {
        "title": title,
        "status": "investigating",
        "priority": "critical",
        "assigned_to": {
            "identity_provider": "entra:contoso",
            "subject_id": "alice-investigator",
        },
        "expected_revision": expected_revision,
        "expected_head_sha256": expected_head_sha256,
    }


def _request(
    application: TeamWSGIApplication,
    path: str,
    *,
    method: str = "GET",
    document: object = _MISSING,
    raw_body: bytes | None = None,
    identity: object = _MISSING,
    integrity_verified: bool = False,
    content_type: str | None = "application/json",
    content_length: str | None = None,
    query: str = "",
    environ_updates: dict[str, Any] | None = None,
) -> tuple[int, dict[str, str], bytes, str]:
    environ: dict[str, Any] = {}
    setup_testing_defaults(environ)
    environ["REQUEST_METHOD"] = method
    environ["PATH_INFO"] = path
    environ["QUERY_STRING"] = query
    error_stream = io.StringIO()
    environ["wsgi.errors"] = error_stream
    if raw_body is None:
        raw_body = (
            b""
            if document is _MISSING
            else json.dumps(document, separators=(",", ":")).encode("utf-8")
        )
    environ["wsgi.input"] = io.BytesIO(raw_body)
    environ.pop("CONTENT_LENGTH", None)
    environ.pop("CONTENT_TYPE", None)
    if document is not _MISSING or raw_body:
        environ["CONTENT_LENGTH"] = str(len(raw_body)) if content_length is None else content_length
        if content_type is not None:
            environ["CONTENT_TYPE"] = content_type
    elif content_length is not None:
        environ["CONTENT_LENGTH"] = content_length
        if content_type is not None:
            environ["CONTENT_TYPE"] = content_type
    if identity is not _MISSING:
        environ[TEAM_IDENTITY_ENVIRON_KEY] = identity
    if integrity_verified:
        environ[TEAM_REQUEST_INTEGRITY_ENVIRON_KEY] = True
    if environ_updates:
        environ.update(environ_updates)

    captured: dict[str, Any] = {}

    def start_response(
        status: str,
        headers: list[tuple[str, str]],
        exc_info: object = None,
    ) -> None:
        captured["status"] = status
        captured["headers"] = headers
        captured["exc_info"] = exc_info

    body = b"".join(application(environ, start_response))
    status_code = int(str(captured["status"]).split(" ", maxsplit=1)[0])
    headers = {name: value for name, value in captured["headers"]}
    return status_code, headers, body, error_stream.getvalue()


class TeamHttpHealthAndIdentityTests(unittest.TestCase):
    def test_health_and_readiness_are_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, _ = _application(directory)
            health = _request(application, "/healthz")
            ready = _request(application, "/readyz")

            self.assertEqual(200, health[0])
            self.assertEqual("ok", json.loads(health[2])["status"])
            self.assertEqual(200, ready[0])
            self.assertEqual("ready", json.loads(ready[2])["status"])

        with tempfile.TemporaryDirectory() as directory:
            unready_application, _ = _application(directory, initialize=False)
            unready = _request(unready_application, "/readyz")
            self.assertEqual(503, unready[0])
            self.assertEqual("store_unavailable", json.loads(unready[2])["error"]["code"])

    def test_raw_auth_and_tenant_headers_never_create_a_trusted_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, _ = _application(directory)
            status, headers, body, _ = _request(
                application,
                "/v1/team/summary",
                environ_updates={
                    "HTTP_AUTHORIZATION": "Bearer attacker-controlled",
                    "HTTP_X_TENANT_ID": "tenant-acme",
                    "HTTP_X_ROLE": "policy_administrator",
                    "REMOTE_USER": "alice-investigator",
                },
            )

            self.assertEqual(401, status)
            self.assertEqual("Causure-External", headers["WWW-Authenticate"])
            self.assertEqual("authentication_required", json.loads(body)["error"]["code"])

    def test_summary_uses_only_injected_identity_and_current_membership(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, _ = _application(directory)
            allowed = _request(
                application,
                "/v1/team/summary",
                identity=_identity(),
            )
            denied = _request(
                application,
                "/v1/team/summary",
                identity=_identity("outsider"),
            )

            summary = json.loads(allowed[2])
            self.assertEqual(200, allowed[0])
            self.assertEqual("tenant-acme", summary["tenant_id"])
            self.assertEqual(["investigator"], summary["assigned_roles"])
            self.assertNotIn("memberships", summary)
            self.assertEqual(403, denied[0])
            self.assertEqual("principal_not_member", json.loads(denied[2])["error"]["code"])

    def test_invalid_injected_identity_is_a_host_error_not_client_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, _ = _application(directory)
            status, _, body, errors = _request(
                application,
                "/v1/team/summary",
                identity={"tenant_id": "tenant-acme", "role": "policy_administrator"},
            )

            self.assertEqual(500, status)
            self.assertEqual("identity_context_invalid", json.loads(body)["error"]["code"])
            self.assertEqual("", errors)


class TeamHttpActionTests(unittest.TestCase):
    def test_state_change_requires_trusted_request_integrity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store = _application(directory)
            status, _, body, _ = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=_action_document(expected_head_sha256=None),
                identity=_identity(),
            )

            self.assertEqual(403, status)
            self.assertEqual("request_integrity_required", json.loads(body)["error"]["code"])
            self.assertEqual(0, store.get_head("tenant-acme").sequence)

    def test_allowed_stale_and_denied_actions_have_atomic_http_results(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store = _application(directory)
            first = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=_action_document(expected_head_sha256=None),
                identity=_identity(),
                integrity_verified=True,
            )
            first_document = json.loads(first[2])
            stale = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=_action_document(expected_head_sha256=None),
                identity=_identity(),
                integrity_verified=True,
            )
            denied = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=_action_document(
                    expected_head_sha256=first_document["head"]["event_sha256"],
                    action="approval_issue",
                    resource_type="approval",
                    resource_id="approval-17",
                ),
                identity=_identity(),
                integrity_verified=True,
            )
            denied_document = json.loads(denied[2])

            self.assertEqual(201, first[0])
            self.assertEqual("recorded", first_document["status"])
            self.assertEqual(
                "alice-investigator", first_document["authorization"]["principal"]["subject_id"]
            )
            self.assertTrue(first_document["authorization"]["decision_id"].startswith("decision-"))
            self.assertTrue(first_document["event"]["entry"]["event_id"].startswith("event-"))
            self.assertNotIn("opened", first[2].decode("utf-8"))
            self.assertEqual(409, stale[0])
            self.assertEqual("head_conflict", json.loads(stale[2])["error"]["code"])
            self.assertEqual(403, denied[0])
            self.assertEqual("action_denied", denied_document["error"]["code"])
            self.assertEqual("denied", denied_document["event"]["entry"]["outcome"])
            self.assertEqual(2, denied_document["head"]["sequence"])
            self.assertEqual(2, store.get_head("tenant-acme").sequence)

    def test_event_endpoint_returns_exact_bytes_after_membership_check(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store = _application(directory)
            created = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=_action_document(expected_head_sha256=None),
                identity=_identity(),
                integrity_verified=True,
            )
            fetched = _request(
                application,
                "/v1/team/events/1",
                identity=_identity(),
            )
            outsider = _request(
                application,
                "/v1/team/events/1",
                identity=_identity("outsider"),
            )
            missing = _request(
                application,
                "/v1/team/events/2",
                identity=_identity(),
            )

            self.assertEqual(201, created[0])
            self.assertEqual(200, fetched[0])
            self.assertEqual(
                "application/vnd.causure.team-audit-event+json",
                fetched[1]["Content-Type"],
            )
            self.assertEqual(store.get_event_bytes("tenant-acme", 1), fetched[2])
            self.assertEqual(403, outsider[0])
            self.assertEqual(404, missing[0])
            self.assertEqual("event_not_found", json.loads(missing[2])["error"]["code"])

    def test_request_cannot_supply_tenant_roles_ids_or_timestamps(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store = _application(directory)
            forged = _action_document(expected_head_sha256=None)
            forged.update(
                {
                    "tenant_id": "tenant-other",
                    "roles": ["policy_administrator"],
                    "decision_id": "client-decision",
                    "event_id": "client-event",
                    "occurred_at": "2030-01-01T00:00:00Z",
                }
            )
            status, _, body, _ = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=forged,
                identity=_identity(),
                integrity_verified=True,
            )

            self.assertEqual(400, status)
            self.assertEqual("request_invalid", json.loads(body)["error"]["code"])
            self.assertIn("unknown field", json.loads(body)["error"]["message"])
            self.assertEqual(0, store.get_head("tenant-acme").sequence)


class TeamHttpExportAndHardeningTests(unittest.TestCase):
    def test_export_is_policy_authorized_and_returned_from_exact_store_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store = _application(directory)
            created = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=_action_document(expected_head_sha256=None),
                identity=_identity(),
                integrity_verified=True,
            )
            denied = _request(
                application,
                "/v1/team/audit-exports",
                method="POST",
                document={},
                identity=_identity(),
                integrity_verified=True,
            )
            exported = _request(
                application,
                "/v1/team/audit-exports",
                method="POST",
                document={},
                identity=_identity("pat-policy"),
                integrity_verified=True,
            )
            export_document = json.loads(exported[2])

            self.assertEqual(201, created[0])
            self.assertEqual(403, denied[0])
            self.assertFalse(json.loads(denied[2])["authorization"]["authorized"])
            self.assertEqual(201, exported[0])
            self.assertEqual(
                "application/vnd.causure.team-audit-export+json",
                exported[1]["Content-Type"],
            )
            self.assertEqual(
                exported[2],
                store.get_export_bytes("tenant-acme", export_document["export_id"]),
            )

    def test_json_body_and_http_metadata_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store = _application(directory)
            duplicate_json = (
                b'{"action":"investigation_write","action":"policy_write",'
                b'"resource":{"type":"investigation","id":"investigation-17"},'
                b'"outcome":"succeeded","payload":{"media_type":"application/json",'
                b'"base64url":"e30"},"expected_head_sha256":null}'
            )
            duplicate = _request(
                application,
                "/v1/team/actions",
                method="POST",
                raw_body=duplicate_json,
                identity=_identity(),
                integrity_verified=True,
            )
            wrong_type = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=_action_document(expected_head_sha256=None),
                identity=_identity(),
                integrity_verified=True,
                content_type="text/plain",
            )
            missing_length = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=_action_document(expected_head_sha256=None),
                identity=_identity(),
                integrity_verified=True,
                content_length="",
            )
            too_large = _request(
                application,
                "/v1/team/actions",
                method="POST",
                raw_body=b"{}",
                identity=_identity(),
                integrity_verified=True,
                content_length=str(MAX_TEAM_HTTP_REQUEST_BYTES + 1),
            )
            query = _request(application, "/healthz", query="tenant_id=tenant-acme")
            method = _request(application, "/v1/team/summary", method="POST")

            self.assertEqual(400, duplicate[0])
            self.assertEqual("request_json_invalid", json.loads(duplicate[2])["error"]["code"])
            self.assertNotIn("policy_write", duplicate[2].decode("utf-8"))
            self.assertEqual(415, wrong_type[0])
            self.assertEqual(411, missing_length[0])
            self.assertEqual(413, too_large[0])
            self.assertEqual(400, query[0])
            self.assertEqual(405, method[0])
            self.assertEqual("GET", method[1]["Allow"])
            self.assertEqual(0, store.get_head("tenant-acme").sequence)

    def test_noncanonical_payload_and_truncated_body_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store = _application(directory)
            bad_payload = _action_document(expected_head_sha256=None)
            bad_payload["payload"]["base64url"] = "e30="
            encoded = json.dumps(_action_document(expected_head_sha256=None)).encode()
            noncanonical = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=bad_payload,
                identity=_identity(),
                integrity_verified=True,
            )
            truncated = _request(
                application,
                "/v1/team/actions",
                method="POST",
                raw_body=encoded,
                identity=_identity(),
                integrity_verified=True,
                content_length=str(len(encoded) + 1),
            )

            self.assertEqual(400, noncanonical[0])
            self.assertEqual(
                "payload_encoding_invalid",
                json.loads(noncanonical[2])["error"]["code"],
            )
            self.assertEqual(400, truncated[0])
            self.assertEqual("request_truncated", json.loads(truncated[2])["error"]["code"])
            self.assertEqual(0, store.get_head("tenant-acme").sequence)

    def test_invalid_server_clock_is_not_reported_as_client_input(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
            store.initialize()
            store.put_policy(_policy_bytes())
            application = TeamWSGIApplication(
                TeamApplicationService(
                    store,
                    clock=lambda: "not-a-timestamp",
                    identifier_factory=_Identifiers(),
                )
            )
            status, headers, body, _ = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=_action_document(expected_head_sha256=None),
                identity=_identity(),
                integrity_verified=True,
            )

            self.assertEqual(500, status)
            self.assertEqual("server_integration_invalid", json.loads(body)["error"]["code"])
            self.assertNotIn("not-a-timestamp", body.decode("utf-8"))
            self.assertEqual("no-store", headers["Cache-Control"])
            self.assertEqual(0, store.get_head("tenant-acme").sequence)


class TeamHttpEvidenceConsoleTests(unittest.TestCase):
    def test_recent_event_api_and_dashboard_are_bounded_and_payload_free(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, _ = _application(directory)
            first = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=_action_document(
                    expected_head_sha256=None,
                    resource_id="investigation-first",
                    payload_bytes=b'<script>alert("payload-secret")</script>',
                ),
                identity=_identity(),
                integrity_verified=True,
            )
            first_head = json.loads(first[2])["head"]["event_sha256"]
            second = _request(
                application,
                "/v1/team/actions",
                method="POST",
                document=_action_document(
                    expected_head_sha256=first_head,
                    resource_id="investigation-second",
                    outcome="failed",
                ),
                identity=_identity(),
                integrity_verified=True,
            )
            recent = _request(
                application,
                "/v1/team/events",
                identity=_identity(),
                query="limit=1",
            )
            recent_document = json.loads(recent[2])
            older = _request(
                application,
                "/v1/team/events",
                identity=_identity(),
                query=(f"limit=1&before_sequence={recent_document['next_before_sequence']}"),
            )
            dashboard = _request(
                application,
                "/",
                identity=_identity(),
                query="limit=1",
            )
            stylesheet = _request(application, "/team.css")

            self.assertEqual(201, first[0])
            self.assertEqual(201, second[0])
            self.assertEqual(200, recent[0])
            self.assertEqual(2, recent_document["events"][0]["sequence"])
            self.assertEqual(
                "investigation-second", recent_document["events"][0]["resource"]["resource_id"]
            )
            self.assertEqual(2, recent_document["next_before_sequence"])
            self.assertEqual(1, json.loads(older[2])["events"][0]["sequence"])
            self.assertIsNone(json.loads(older[2])["next_before_sequence"])
            self.assertNotIn("payload-secret", recent[2].decode("utf-8"))

            dashboard_text = dashboard[2].decode("utf-8")
            self.assertEqual(200, dashboard[0])
            self.assertEqual("text/html; charset=utf-8", dashboard[1]["Content-Type"])
            self.assertIn("Tenant evidence console", dashboard_text)
            self.assertIn("investigation-second", dashboard_text)
            self.assertIn("View older events", dashboard_text)
            self.assertNotIn("payload-secret", dashboard_text)
            self.assertNotIn("<form", dashboard_text)
            self.assertIn("style-src 'self'", dashboard[1]["Content-Security-Policy"])
            self.assertEqual("DENY", dashboard[1]["X-Frame-Options"])
            self.assertEqual("no-referrer", dashboard[1]["Referrer-Policy"])

            self.assertEqual(200, stylesheet[0])
            self.assertEqual("text/css; charset=utf-8", stylesheet[1]["Content-Type"])
            self.assertIn("--accent:", stylesheet[2].decode("utf-8"))

    def test_event_page_query_and_membership_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, _ = _application(directory)
            outsider = _request(
                application,
                "/v1/team/events",
                identity=_identity("outsider"),
            )
            unauthenticated_dashboard = _request(application, "/team")
            invalid_queries = [
                "limit=0",
                "limit=101",
                "limit=1&limit=2",
                "tenant_id=tenant-acme",
                "limit=%31",
                "before_sequence=10002",
            ]

            self.assertEqual(403, outsider[0])
            self.assertEqual(401, unauthenticated_dashboard[0])
            for query in invalid_queries:
                with self.subTest(query=query):
                    response = _request(
                        application,
                        "/v1/team/events",
                        identity=_identity(),
                        query=query,
                    )
                    self.assertEqual(400, response[0])
                    self.assertEqual(
                        "query_invalid",
                        json.loads(response[2])["error"]["code"],
                    )


class TeamHttpCaseDashboardTests(unittest.TestCase):
    def test_publication_list_detail_and_html_join_minimized_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, _ = _application(directory)
            case, review, _, publication, verification, approval = _approval_artifacts()
            created = _request(
                application,
                "/v1/team/cases",
                method="POST",
                document=_case_document(
                    case,
                    review,
                    expected_head_sha256=None,
                    publication_bytes=publication,
                    verification_bytes=verification,
                    approval_bytes=approval,
                ),
                identity=_identity(),
                integrity_verified=True,
            )
            page = _request(application, "/v1/team/cases", identity=_identity())
            detail = _request(
                application,
                "/v1/team/cases/refund-tool-description-001",
                identity=_identity(),
            )
            overview_html = _request(application, "/team/cases", identity=_identity())
            detail_html = _request(
                application,
                "/team/cases/refund-tool-description-001",
                identity=_identity(),
            )

            created_document = json.loads(created[2])
            page_document = json.loads(page[2])
            detail_document = json.loads(detail[2])
            self.assertEqual(201, created[0])
            self.assertEqual("published", created_document["status"])
            self.assertEqual(1, created_document["record"]["revision"])
            self.assertEqual("approve", created_document["record"]["approval"]["action"])
            self.assertEqual(200, page[0])
            self.assertEqual(1, len(page_document["cases"]))
            self.assertEqual(
                created_document["record"],
                page_document["cases"][0]["record"],
            )
            self.assertEqual(
                created_document["record"],
                detail_document["case"]["record"],
            )

            raw_source_ref = json.loads(case)["incident"]["source_refs"][0]
            for body in (created[2], page[2], detail[2], overview_html[2], detail_html[2]):
                text = body.decode("utf-8")
                self.assertNotIn(raw_source_ref, text)
                self.assertNotIn("evidence_refs", text)
                self.assertNotIn("observed_behavior", text)
            self.assertEqual(200, overview_html[0])
            self.assertEqual("text/html; charset=utf-8", overview_html[1]["Content-Type"])
            self.assertIn("Change cases", overview_html[2].decode())
            self.assertIn("Approval receipt", detail_html[2].decode())
            self.assertIn("point-in-time", detail_html[2].decode())
            self.assertNotIn("<script", detail_html[2].decode())

    def test_case_publication_boundary_rejects_forgery_and_incomplete_chains(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store = _application(directory)
            case, review, _ = _base_artifacts()
            valid = _case_document(case, review, expected_head_sha256=None)
            no_integrity = _request(
                application,
                "/v1/team/cases",
                method="POST",
                document=valid,
                identity=_identity(),
            )
            padded = deepcopy(valid)
            padded["change_case"]["base64url"] += "="
            bad_encoding = _request(
                application,
                "/v1/team/cases",
                method="POST",
                document=padded,
                identity=_identity(),
                integrity_verified=True,
            )
            incomplete = deepcopy(valid)
            incomplete["azure_publication"] = _encoded_artifact(b"{}")
            bad_chain = _request(
                application,
                "/v1/team/cases",
                method="POST",
                document=incomplete,
                identity=_identity(),
                integrity_verified=True,
            )
            approval_only = deepcopy(valid)
            approval_only["approval_verification"] = _encoded_artifact(b"{}")
            bad_approval = _request(
                application,
                "/v1/team/cases",
                method="POST",
                document=approval_only,
                identity=_identity(),
                integrity_verified=True,
            )
            forged = deepcopy(valid)
            forged["tenant_id"] = "tenant-other"
            unknown = _request(
                application,
                "/v1/team/cases",
                method="POST",
                document=forged,
                identity=_identity(),
                integrity_verified=True,
            )

            self.assertEqual(403, no_integrity[0])
            self.assertEqual(
                "request_integrity_required", json.loads(no_integrity[2])["error"]["code"]
            )
            self.assertEqual(400, bad_encoding[0])
            self.assertEqual(
                "payload_encoding_invalid", json.loads(bad_encoding[2])["error"]["code"]
            )
            self.assertEqual(400, bad_chain[0])
            self.assertEqual("case_chain_invalid", json.loads(bad_chain[2])["error"]["code"])
            self.assertEqual(400, bad_approval[0])
            self.assertEqual("case_chain_invalid", json.loads(bad_approval[2])["error"]["code"])
            self.assertEqual(400, unknown[0])
            self.assertEqual("request_invalid", json.loads(unknown[2])["error"]["code"])
            self.assertEqual(0, store.get_head("tenant-acme").sequence)

    def test_denial_stale_head_not_found_queries_and_html_escaping_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store = _application(directory)
            case, review, _ = _base_artifacts()
            denied = _request(
                application,
                "/v1/team/cases",
                method="POST",
                document=_case_document(case, review, expected_head_sha256=None),
                identity=_identity("pat-policy"),
                integrity_verified=True,
            )
            self.assertEqual(403, denied[0])
            self.assertEqual("denied", json.loads(denied[2])["status"])
            self.assertNotIn("record", json.loads(denied[2]))
            self.assertEqual(1, store.get_head("tenant-acme").sequence)

            stale = _request(
                application,
                "/v1/team/cases",
                method="POST",
                document=_case_document(case, review, expected_head_sha256=None),
                identity=_identity(),
                integrity_verified=True,
            )
            missing = _request(
                application,
                "/v1/team/cases/missing-case",
                identity=_identity(),
            )
            query = _request(
                application,
                "/v1/team/cases/refund-tool-description-001",
                identity=_identity(),
                query="limit=1",
            )
            self.assertEqual(409, stale[0])
            self.assertEqual("head_conflict", json.loads(stale[2])["error"]["code"])
            self.assertEqual(404, missing[0])
            self.assertEqual("case_not_found", json.loads(missing[2])["error"]["code"])
            self.assertEqual(400, query[0])
            self.assertEqual("query_unsupported", json.loads(query[2])["error"]["code"])

        with tempfile.TemporaryDirectory() as directory:
            application, _ = _application(directory)
            document = load_example()
            malicious = '<img src=x onerror="alert(1)">'
            document["title"] = malicious
            parsed_case = parse_change_case(document)
            review_result = review_case(
                parsed_case,
                reviewed_at=datetime(2026, 7, 28, 9, 0, tzinfo=UTC),
            )
            case_bytes = (json.dumps(document, indent=2) + "\n").encode()
            review_bytes = render_json(review_result).encode()
            created = _request(
                application,
                "/v1/team/cases",
                method="POST",
                document=_case_document(
                    case_bytes,
                    review_bytes,
                    expected_head_sha256=None,
                ),
                identity=_identity(),
                integrity_verified=True,
            )
            html = _request(
                application,
                "/team/cases/refund-tool-description-001",
                identity=_identity(),
            )
            self.assertEqual(201, created[0])
            self.assertEqual(200, html[0])
            self.assertNotIn(malicious, html[2].decode())
            self.assertIn("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;", html[2].decode())


class TeamHttpInvestigationDashboardTests(unittest.TestCase):
    def test_open_attach_transition_list_detail_and_html_are_minimized(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, _ = _application(directory)
            fixture, cluster, second_fixture, second_cluster = _investigation_fixtures()
            title = '<img src=x onerror="alert(1)">'
            opened = _request(
                application,
                "/v1/team/investigations",
                method="POST",
                document=_investigation_open_document(
                    fixture,
                    cluster,
                    expected_head_sha256=None,
                    title=title,
                ),
                identity=_identity(),
                integrity_verified=True,
            )
            opened_document = json.loads(opened[2])
            attached = _request(
                application,
                "/v1/team/investigations/investigation-http-001/observations",
                method="POST",
                document=_investigation_attach_document(
                    second_fixture,
                    second_cluster,
                    expected_revision=1,
                    expected_head_sha256=opened_document["head"]["event_sha256"],
                ),
                identity=_identity(),
                integrity_verified=True,
            )
            attached_document = json.loads(attached[2])
            transitioned = _request(
                application,
                "/v1/team/investigations/investigation-http-001/transition",
                method="POST",
                document=_investigation_transition_document(
                    expected_revision=2,
                    expected_head_sha256=attached_document["head"]["event_sha256"],
                    title=title,
                ),
                identity=_identity(),
                integrity_verified=True,
            )
            page = _request(
                application,
                "/v1/team/investigations",
                identity=_identity(),
                query="limit=10&status=investigating&priority=critical",
            )
            detail = _request(
                application,
                "/v1/team/investigations/investigation-http-001",
                identity=_identity(),
            )
            overview_html = _request(
                application,
                "/team/investigations",
                identity=_identity(),
                query="status=investigating&priority=critical",
            )
            detail_html = _request(
                application,
                "/team/investigations/investigation-http-001",
                identity=_identity(),
            )

            transitioned_document = json.loads(transitioned[2])
            page_document = json.loads(page[2])
            detail_document = json.loads(detail[2])
            self.assertEqual(201, opened[0])
            self.assertEqual(200, attached[0])
            self.assertEqual(200, transitioned[0])
            self.assertEqual(3, transitioned_document["record"]["revision"])
            self.assertEqual(2, len(transitioned_document["record"]["observations"]))
            self.assertEqual("investigating", transitioned_document["record"]["status"])
            self.assertEqual(1, len(page_document["investigations"]))
            self.assertEqual(
                transitioned_document["record"],
                detail_document["investigation"]["record"],
            )
            for body in (
                opened[2],
                attached[2],
                transitioned[2],
                page[2],
                detail[2],
                overview_html[2],
                detail_html[2],
            ):
                text = body.decode("utf-8")
                self.assertNotIn("span_evidence_refs", text)
                self.assertNotIn("trace_ref", text)
            self.assertEqual(200, overview_html[0])
            self.assertIn("Investigation queue", overview_html[2].decode())
            self.assertIn("Candidate only", detail_html[2].decode())
            self.assertNotIn(title, detail_html[2].decode())
            self.assertIn(
                "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;",
                detail_html[2].decode(),
            )
            self.assertNotIn("<script", detail_html[2].decode())
            self.assertIn("style-src 'self'", detail_html[1]["Content-Security-Policy"])

    def test_mutation_boundary_denial_conflicts_and_queries_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            application, store = _application(directory)
            fixture, cluster, _, _ = _investigation_fixtures()
            valid = _investigation_open_document(
                fixture,
                cluster,
                expected_head_sha256=None,
                investigation_id="investigation-boundary-001",
            )
            no_integrity = _request(
                application,
                "/v1/team/investigations",
                method="POST",
                document=valid,
                identity=_identity(),
            )
            forged = deepcopy(valid)
            forged["tenant_id"] = "tenant-other"
            unknown = _request(
                application,
                "/v1/team/investigations",
                method="POST",
                document=forged,
                identity=_identity(),
                integrity_verified=True,
            )
            wrong_revision = deepcopy(valid)
            wrong_revision["expected_revision"] = 1
            bad_revision = _request(
                application,
                "/v1/team/investigations",
                method="POST",
                document=wrong_revision,
                identity=_identity(),
                integrity_verified=True,
            )
            invalid_queries = (
                "status=unknown",
                "priority=urgent",
                "status=queued&status=blocked",
                "tenant_id=tenant-acme",
                "limit=0",
            )

            self.assertEqual(403, no_integrity[0])
            self.assertEqual(400, unknown[0])
            self.assertEqual(400, bad_revision[0])
            for query in invalid_queries:
                with self.subTest(query=query):
                    response = _request(
                        application,
                        "/v1/team/investigations",
                        identity=_identity(),
                        query=query,
                    )
                    self.assertEqual(400, response[0])
                    self.assertEqual("query_invalid", json.loads(response[2])["error"]["code"])
            self.assertEqual(0, store.get_head("tenant-acme").sequence)

            denied = _request(
                application,
                "/v1/team/investigations",
                method="POST",
                document=valid,
                identity=_identity("pat-policy"),
                integrity_verified=True,
            )
            self.assertEqual(403, denied[0])
            self.assertEqual("denied", json.loads(denied[2])["status"])
            self.assertNotIn("record", json.loads(denied[2]))
            self.assertEqual(1, store.get_head("tenant-acme").sequence)

            stale = _request(
                application,
                "/v1/team/investigations",
                method="POST",
                document=valid,
                identity=_identity(),
                integrity_verified=True,
            )
            missing = _request(
                application,
                "/v1/team/investigations/missing-investigation",
                identity=_identity(),
            )
            detail_query = _request(
                application,
                "/team/investigations/missing-investigation",
                identity=_identity(),
                query="status=queued",
            )
            self.assertEqual(409, stale[0])
            self.assertEqual("head_conflict", json.loads(stale[2])["error"]["code"])
            self.assertEqual(404, missing[0])
            self.assertEqual(
                "investigation_not_found",
                json.loads(missing[2])["error"]["code"],
            )
            self.assertEqual(400, detail_query[0])
            self.assertEqual("query_unsupported", json.loads(detail_query[2])["error"]["code"])


if __name__ == "__main__":
    unittest.main()
