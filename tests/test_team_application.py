"""Trusted-identity application service tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from causure.collector import collect_otlp_trace_manifest, render_trace_manifest
from causure.constants import (
    TeamAction,
    TeamAuditOutcome,
    TeamResourceType,
    TeamRole,
)
from causure.fixtures import (
    generate_investigation_fixture,
    render_investigation_fixture,
)
from causure.team_application import (
    AuthenticatedTeamIdentity,
    TeamAccessDeniedError,
    TeamApplicationError,
    TeamApplicationService,
    TeamIdentityError,
)
from causure.team_service import (
    TeamPrincipal,
    parse_team_access_policy_bytes,
    render_team_audit_export,
)
from causure.team_store import SQLiteTeamStore, TeamStoreConflictError
from tests.helpers import PROJECT_ROOT
from tests.test_team_cases import _azure_artifacts, _base_artifacts
from tests.test_team_service import _policy_bytes


class _PolicyAdvancingStore(SQLiteTeamStore):
    def __init__(self, database_path: Path) -> None:
        super().__init__(database_path)
        self.required_active_policy: bool | None = None

    def append_event(
        self,
        event_bytes: bytes,
        *,
        expected_head_sha256: str | None,
        require_active_policy: bool = False,
    ):
        self.required_active_policy = require_active_policy
        self.put_policy(_policy_bytes(revision=2))
        return super().append_event(
            event_bytes,
            expected_head_sha256=expected_head_sha256,
            require_active_policy=require_active_policy,
        )


class _Identifiers:
    def __init__(self) -> None:
        self._next = 0

    def __call__(self, prefix: str) -> str:
        self._next += 1
        return f"{prefix}-{self._next}"


class _Clock:
    def __init__(self, *values: str) -> None:
        self._values = iter(values)

    def __call__(self) -> str:
        return next(self._values)


def _store(directory: str) -> SQLiteTeamStore:
    store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
    store.initialize()
    store.put_policy(_policy_bytes())
    return store


def _investigator() -> AuthenticatedTeamIdentity:
    return AuthenticatedTeamIdentity(
        tenant_id="tenant-acme",
        identity_provider="entra:contoso",
        subject_id="alice-investigator",
    )


def _policy_administrator() -> AuthenticatedTeamIdentity:
    return AuthenticatedTeamIdentity(
        tenant_id="tenant-acme",
        identity_provider="entra:contoso",
        subject_id="pat-policy",
    )


def _investigation_fixtures() -> tuple[bytes, str, bytes, str]:
    trace_path = PROJECT_ROOT / "examples" / "traces" / "refund-openinference-otlp.json"
    trace_bytes = trace_path.read_bytes()
    manifest = collect_otlp_trace_manifest(
        json.loads(trace_bytes),
        raw_bytes=trace_bytes,
        source_id="refund-openinference-fixture",
    )
    manifest_bytes = render_trace_manifest(manifest).encode("utf-8")
    fixture = generate_investigation_fixture(
        json.loads(manifest_bytes),
        raw_bytes=manifest_bytes,
        fixture_id="refund-investigation-app-001",
    )
    first_bytes = render_investigation_fixture(fixture).encode("utf-8")
    second = json.loads(first_bytes)
    trace_id = "a" * 64
    second["fixture_id"] = "refund-investigation-app-002"
    cluster = second["candidate_clusters"][0]
    cluster["cluster_id"] = f"trace-{trace_id}"
    cluster["trace_id_sha256"] = trace_id
    cluster["trace_ref"] = (
        f"trace-sha256://{second['source']['trace_source_sha256']}/traces/{trace_id}"
    )
    second_bytes = (json.dumps(second, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    return (
        first_bytes,
        fixture.candidate_clusters[0].cluster_id,
        second_bytes,
        cluster["cluster_id"],
    )


class TeamApplicationServiceTests(unittest.TestCase):
    def test_case_publication_advances_one_joined_record_and_serves_current_views(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory)
            service = TeamApplicationService(
                store,
                clock=_Clock(
                    "2026-08-03T12:00:00Z",
                    "2026-08-03T12:01:00Z",
                ),
                identifier_factory=_Identifiers(),
            )
            case, review, _, publication, verification = _azure_artifacts()
            first = service.publish_case(
                _investigator(),
                case_id="refund-tool-description-001",
                change_case_bytes=case,
                review_result_bytes=review,
                expected_head_sha256=None,
            )
            second = service.publish_case(
                _investigator(),
                case_id="refund-tool-description-001",
                change_case_bytes=case,
                review_result_bytes=review,
                azure_publication_bytes=publication,
                azure_verification_bytes=verification,
                expected_head_sha256=first.head.event_sha256,
            )

            page = service.list_cases(_investigator())
            detail = service.get_case(_investigator(), "refund-tool-description-001")
            self.assertEqual(1, first.record.revision)
            self.assertEqual(2, second.record.revision)
            self.assertEqual(123, second.record.delivery.changeset_id)
            self.assertEqual((detail.case,), page.cases)
            self.assertEqual(second.record, detail.case.record)
            self.assertEqual(2, page.summary.head.sequence)
            self.assertEqual("investigation_write", detail.case.event.action.value)

    def test_denied_case_publication_records_minimized_attempt_without_case_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory)
            service = TeamApplicationService(
                store,
                clock=_Clock("2026-08-03T12:00:00Z"),
                identifier_factory=_Identifiers(),
            )
            case, review, _ = _base_artifacts()

            denied = service.publish_case(
                _policy_administrator(),
                case_id="refund-tool-description-001",
                change_case_bytes=case,
                review_result_bytes=review,
                expected_head_sha256=None,
            )

            self.assertFalse(denied.authorization.authorized)
            self.assertIsNone(denied.record)
            self.assertIs(TeamAuditOutcome.DENIED, denied.event.entry.outcome)
            self.assertEqual(1, denied.head.sequence)
            self.assertIsNone(
                store.get_case_record_snapshot("tenant-acme", "refund-tool-description-001").item
            )
            stored_event = store.get_event_bytes("tenant-acme", 1)
            self.assertNotIn(case, stored_event)
            self.assertNotIn(review, stored_event)

    def test_case_publication_rejects_stale_head_and_mismatched_case_before_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory)
            case, review, _ = _base_artifacts()
            stale_service = TeamApplicationService(store)
            with self.assertRaisesRegex(TeamStoreConflictError, "head_conflict"):
                stale_service.publish_case(
                    _investigator(),
                    case_id="refund-tool-description-001",
                    change_case_bytes=case,
                    review_result_bytes=review,
                    expected_head_sha256="0" * 64,
                )

            invalid_service = TeamApplicationService(
                store,
                clock=_Clock("2026-08-03T12:00:00Z"),
                identifier_factory=_Identifiers(),
            )
            with self.assertRaisesRegex(TeamApplicationError, "case_source_invalid"):
                invalid_service.publish_case(
                    _investigator(),
                    case_id="different-case-id",
                    change_case_bytes=case,
                    review_result_bytes=review,
                    expected_head_sha256=None,
                )
            self.assertEqual(0, store.get_head("tenant-acme").sequence)

    def test_investigation_open_attach_transition_and_current_views(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory)
            service = TeamApplicationService(
                store,
                clock=_Clock(
                    "2026-08-03T12:00:00Z",
                    "2026-08-03T12:01:00Z",
                    "2026-08-03T12:02:00Z",
                ),
                identifier_factory=_Identifiers(),
            )
            fixture, cluster, second_fixture, second_cluster = _investigation_fixtures()
            opened = service.open_investigation(
                _investigator(),
                investigation_id="investigation-refund-app-001",
                fixture_bytes=fixture,
                cluster_id=cluster,
                title="Unexpected refund-tool behavior",
                priority="high",
                expected_revision=0,
                expected_head_sha256=None,
            )
            attached = service.attach_investigation_observation(
                _investigator(),
                investigation_id="investigation-refund-app-001",
                fixture_bytes=second_fixture,
                cluster_id=second_cluster,
                expected_revision=1,
                expected_head_sha256=opened.head.event_sha256,
            )
            principal = TeamPrincipal(
                identity_provider="entra:contoso",
                subject_id="alice-investigator",
            )
            active = service.transition_investigation(
                _investigator(),
                investigation_id="investigation-refund-app-001",
                title="Refund-tool cluster under investigation",
                status="investigating",
                priority="critical",
                assigned_to=principal,
                expected_revision=2,
                expected_head_sha256=attached.head.event_sha256,
            )

            page = service.list_investigations(
                _investigator(),
                status="investigating",
                priority="critical",
            )
            detail = service.get_investigation(
                _investigator(),
                "investigation-refund-app-001",
            )
            self.assertEqual(1, opened.record.revision)
            self.assertEqual(2, len(attached.record.observations))
            self.assertEqual(3, active.record.revision)
            self.assertEqual(principal, active.record.assigned_to)
            self.assertEqual((detail.investigation,), page.investigations)
            self.assertEqual(active.record, detail.investigation.record)
            self.assertEqual(3, page.summary.head.sequence)
            self.assertEqual(
                "investigation_write",
                detail.investigation.event.action.value,
            )

    def test_denied_investigation_open_is_a_minimized_audit_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory)
            service = TeamApplicationService(
                store,
                clock=_Clock("2026-08-03T12:00:00Z"),
                identifier_factory=_Identifiers(),
            )
            fixture, cluster, _, _ = _investigation_fixtures()

            denied = service.open_investigation(
                _policy_administrator(),
                investigation_id="investigation-denied-001",
                fixture_bytes=fixture,
                cluster_id=cluster,
                title="Sensitive incident title that must not enter the ledger",
                priority="normal",
                expected_revision=0,
                expected_head_sha256=None,
            )

            self.assertFalse(denied.authorization.authorized)
            self.assertIsNone(denied.record)
            self.assertIs(TeamAuditOutcome.DENIED, denied.event.entry.outcome)
            self.assertEqual(1, denied.head.sequence)
            self.assertIsNone(
                store.get_investigation_record_snapshot(
                    "tenant-acme",
                    "investigation-denied-001",
                ).item
            )
            stored_event = store.get_event_bytes("tenant-acme", 1)
            self.assertNotIn(fixture, stored_event)
            self.assertNotIn(b"Sensitive incident title", stored_event)

    def test_investigation_revision_and_assignee_checks_fail_without_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory)
            service = TeamApplicationService(
                store,
                clock=_Clock(
                    "2026-08-03T12:00:00Z",
                    "2026-08-03T12:01:00Z",
                    "2026-08-03T12:02:00Z",
                ),
                identifier_factory=_Identifiers(),
            )
            fixture, cluster, _, _ = _investigation_fixtures()
            opened = service.open_investigation(
                _investigator(),
                investigation_id="investigation-conflict-001",
                fixture_bytes=fixture,
                cluster_id=cluster,
                title="Conflict checks",
                priority="normal",
                expected_revision=0,
                expected_head_sha256=None,
            )

            with self.assertRaisesRegex(
                TeamStoreConflictError,
                "investigation_revision_conflict",
            ):
                service.attach_investigation_observation(
                    _investigator(),
                    investigation_id="investigation-conflict-001",
                    fixture_bytes=fixture,
                    cluster_id=cluster,
                    expected_revision=0,
                    expected_head_sha256=opened.head.event_sha256,
                )
            with self.assertRaisesRegex(
                TeamApplicationError,
                "investigation_assignee_invalid",
            ):
                service.transition_investigation(
                    _investigator(),
                    investigation_id="investigation-conflict-001",
                    title="Conflict checks",
                    status="investigating",
                    priority="normal",
                    assigned_to=TeamPrincipal(
                        identity_provider="entra:contoso",
                        subject_id="pat-policy",
                    ),
                    expected_revision=1,
                    expected_head_sha256=opened.head.event_sha256,
                )
            self.assertEqual(opened.head, store.get_head("tenant-acme"))
            self.assertEqual(1, len(store.list_event_bytes("tenant-acme")))

    def test_summary_derives_current_roles_and_hides_other_memberships(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = TeamApplicationService(_store(directory))
            summary = service.get_tenant_summary(_investigator())

            self.assertEqual("tenant-acme", summary.tenant_id)
            self.assertEqual("access-acme", summary.policy_id)
            self.assertEqual(1, summary.policy_revision)
            self.assertEqual((TeamRole.INVESTIGATOR,), summary.assigned_roles)
            self.assertEqual(0, summary.head.sequence)
            self.assertEqual(64, len(summary.policy_sha256))

    def test_allowed_and_denied_actions_are_cas_appended_with_server_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory)
            service = TeamApplicationService(
                store,
                clock=_Clock(
                    "2026-07-28T10:00:00Z",
                    "2026-07-28T10:01:00Z",
                ),
                identifier_factory=_Identifiers(),
            )
            first = service.record_action(
                _investigator(),
                b'{"status":"opened"}',
                payload_media_type="application/json",
                action=TeamAction.INVESTIGATION_WRITE,
                resource_type=TeamResourceType.INVESTIGATION,
                resource_id="investigation-17",
                outcome=TeamAuditOutcome.SUCCEEDED,
                expected_head_sha256=None,
            )
            second = service.record_action(
                _investigator(),
                b'{"request":"approval"}',
                payload_media_type="application/json",
                action=TeamAction.APPROVAL_ISSUE,
                resource_type=TeamResourceType.APPROVAL,
                resource_id="approval-17",
                outcome=TeamAuditOutcome.SUCCEEDED,
                expected_head_sha256=first.head.event_sha256,
            )

            self.assertTrue(first.authorization.authorized)
            self.assertEqual("alice-investigator", first.authorization.principal.subject_id)
            self.assertEqual("decision-1", first.authorization.decision_id)
            self.assertEqual("event-2", first.event.entry.event_id)
            self.assertIs(TeamAuditOutcome.SUCCEEDED, first.event.entry.outcome)
            self.assertFalse(second.authorization.authorized)
            self.assertIs(TeamAuditOutcome.DENIED, second.event.entry.outcome)
            self.assertEqual(2, second.head.sequence)
            self.assertNotIn(b'"status":"opened"', store.get_event_bytes("tenant-acme", 1))

    def test_stale_expected_head_fails_before_generating_or_storing_an_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory)
            identifiers = _Identifiers()
            service = TeamApplicationService(
                store,
                clock=_Clock("2026-07-28T10:00:00Z"),
                identifier_factory=identifiers,
            )
            with self.assertRaisesRegex(TeamStoreConflictError, "head_conflict"):
                service.record_action(
                    _investigator(),
                    b"{}",
                    payload_media_type="application/json",
                    action=TeamAction.INVESTIGATION_WRITE,
                    resource_type=TeamResourceType.INVESTIGATION,
                    resource_id="investigation-17",
                    outcome=TeamAuditOutcome.SUCCEEDED,
                    expected_head_sha256="0" * 64,
                )

            self.assertEqual(0, store.get_head("tenant-acme").sequence)
            self.assertEqual("decision-1", identifiers("decision"))

    def test_policy_advance_during_request_rejects_the_old_authorization(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _PolicyAdvancingStore(Path(directory) / "team.sqlite3")
            store.initialize()
            store.put_policy(_policy_bytes(revision=1))
            service = TeamApplicationService(
                store,
                clock=_Clock("2026-07-28T10:00:00Z"),
                identifier_factory=_Identifiers(),
            )

            with self.assertRaisesRegex(TeamStoreConflictError, "event_policy_stale"):
                service.record_action(
                    _investigator(),
                    b"{}",
                    payload_media_type="application/json",
                    action=TeamAction.INVESTIGATION_WRITE,
                    resource_type=TeamResourceType.INVESTIGATION,
                    resource_id="investigation-17",
                    outcome=TeamAuditOutcome.SUCCEEDED,
                    expected_head_sha256=None,
                )

            self.assertTrue(store.required_active_policy)
            self.assertEqual(0, store.get_head("tenant-acme").sequence)
            self.assertEqual(
                2,
                parse_team_access_policy_bytes(
                    store.get_active_policy_bytes("tenant-acme")
                ).revision,
            )

    def test_export_requires_current_policy_administrator(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory)
            service = TeamApplicationService(
                store,
                clock=_Clock(
                    "2026-07-28T10:00:00Z",
                    "2026-07-28T10:01:00Z",
                    "2026-07-28T10:02:00Z",
                ),
                identifier_factory=_Identifiers(),
            )
            recorded = service.record_action(
                _investigator(),
                b"{}",
                payload_media_type="application/json",
                action=TeamAction.INVESTIGATION_WRITE,
                resource_type=TeamResourceType.INVESTIGATION,
                resource_id="investigation-17",
                outcome=TeamAuditOutcome.SUCCEEDED,
                expected_head_sha256=None,
            )
            with self.assertRaises(TeamAccessDeniedError) as denied:
                service.create_audit_export(_investigator())
            export = service.create_audit_export(_policy_administrator())

            self.assertFalse(denied.exception.decision.authorized)
            self.assertEqual(recorded.head.event_sha256, export.head_event_sha256)
            self.assertEqual(
                render_team_audit_export(export).encode("utf-8"),
                store.get_export_bytes("tenant-acme", export.export_id),
            )

    def test_current_membership_is_required_for_reads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = TeamApplicationService(_store(directory))
            outsider = AuthenticatedTeamIdentity(
                tenant_id="tenant-acme",
                identity_provider="entra:contoso",
                subject_id="outsider",
            )
            with self.assertRaisesRegex(TeamAccessDeniedError, "principal_not_member"):
                service.get_tenant_summary(outsider)
            with self.assertRaisesRegex(TeamAccessDeniedError, "principal_not_member"):
                service.get_event_bytes(outsider, 1)
            with self.assertRaisesRegex(TeamAccessDeniedError, "principal_not_member"):
                service.list_recent_events(outsider)
            with self.assertRaisesRegex(TeamAccessDeniedError, "principal_not_member"):
                service.list_cases(outsider)
            with self.assertRaisesRegex(TeamAccessDeniedError, "principal_not_member"):
                service.get_case(outsider, "refund-tool-description-001")

    def test_recent_event_summaries_are_bounded_and_cursor_paginated(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory)
            service = TeamApplicationService(
                store,
                clock=_Clock(
                    "2026-07-28T10:00:00Z",
                    "2026-07-28T10:01:00Z",
                    "2026-07-28T10:02:00Z",
                ),
                identifier_factory=_Identifiers(),
            )
            head: str | None = None
            for sequence in range(1, 4):
                record = service.record_action(
                    _investigator(),
                    f'{{"private":"payload-{sequence}"}}'.encode(),
                    payload_media_type="application/json",
                    action=TeamAction.INVESTIGATION_WRITE,
                    resource_type=TeamResourceType.INVESTIGATION,
                    resource_id=f"investigation-{sequence}",
                    outcome=TeamAuditOutcome.SUCCEEDED,
                    expected_head_sha256=head,
                )
                head = record.head.event_sha256

            first_page = service.list_recent_events(_investigator(), limit=2)
            second_page = service.list_recent_events(
                _investigator(),
                limit=2,
                before_sequence=first_page.next_before_sequence,
            )

            self.assertEqual(3, first_page.summary.head.sequence)
            self.assertEqual((TeamRole.INVESTIGATOR,), first_page.summary.assigned_roles)
            self.assertEqual([3, 2], [event.sequence for event in first_page.events])
            self.assertEqual(
                ["investigation-3", "investigation-2"],
                [event.resource.resource_id for event in first_page.events],
            )
            self.assertEqual(2, first_page.next_before_sequence)
            self.assertEqual([1], [event.sequence for event in second_page.events])
            self.assertIsNone(second_page.next_before_sequence)
            self.assertNotIn(
                "payload-3",
                first_page.events[0].payload.sha256,
            )

    def test_identity_and_server_generated_values_are_strict(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = _store(directory)
            service = TeamApplicationService(store)
            with self.assertRaisesRegex(TeamIdentityError, "identity_context_invalid"):
                service.get_tenant_summary(  # type: ignore[arg-type]
                    {
                        "tenant_id": "tenant-acme",
                        "identity_provider": "entra:contoso",
                        "subject_id": "alice-investigator",
                        "role": "policy_administrator",
                    }
                )

            invalid_identifier_service = TeamApplicationService(
                store,
                clock=_Clock("2026-07-28T10:00:00Z"),
                identifier_factory=lambda prefix: f"{prefix} with spaces",
            )
            with self.assertRaisesRegex(
                TeamApplicationError,
                "generated_identifier_invalid",
            ):
                invalid_identifier_service.record_action(
                    _investigator(),
                    b"{}",
                    payload_media_type="application/json",
                    action=TeamAction.INVESTIGATION_WRITE,
                    resource_type=TeamResourceType.INVESTIGATION,
                    resource_id="investigation-17",
                    outcome=TeamAuditOutcome.SUCCEEDED,
                    expected_head_sha256=None,
                )

    def test_client_cannot_report_denied_as_an_outcome(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            service = TeamApplicationService(_store(directory))
            with self.assertRaisesRegex(TeamApplicationError, "outcome_invalid"):
                service.record_action(
                    _investigator(),
                    b"{}",
                    payload_media_type="application/json",
                    action=TeamAction.INVESTIGATION_WRITE,
                    resource_type=TeamResourceType.INVESTIGATION,
                    resource_id="investigation-17",
                    outcome=TeamAuditOutcome.DENIED,
                    expected_head_sha256=None,
                )


if __name__ == "__main__":
    unittest.main()
