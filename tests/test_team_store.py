"""Transactional and adversarial tests for the SQLite Team store."""

from __future__ import annotations

import contextlib
import json
import sqlite3
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from pathlib import Path

from causure.collector import collect_otlp_trace_manifest, render_trace_manifest
from causure.constants import (
    TeamAction,
    TeamAuditOutcome,
    TeamInvestigationPriority,
    TeamResourceType,
)
from causure.fixtures import (
    generate_investigation_fixture,
    render_investigation_fixture,
)
from causure.team_cases import (
    TEAM_CASE_RECORD_MEDIA_TYPE,
    create_team_case_record,
    render_team_case_record,
)
from causure.team_investigations import (
    TEAM_INVESTIGATION_RECORD_MEDIA_TYPE,
    create_team_investigation_record,
    render_team_investigation_record,
    transition_team_investigation_record,
)
from causure.team_service import (
    TeamPrincipal,
    create_team_audit_event,
    parse_team_audit_event_bytes,
    render_team_audit_event,
    render_team_audit_export,
)
from causure.team_store import (
    SQLiteTeamStore,
    TeamStoreConflictError,
    TeamStoreError,
    TeamStoreSchemaError,
)
from tests.helpers import PROJECT_ROOT
from tests.test_team_cases import _azure_artifacts, _base_artifacts
from tests.test_team_service import _authorization_bytes, _policy_bytes


def _event_bytes(
    policy_bytes: bytes,
    *,
    decision_id: str,
    event_id: str,
    decided_at: str,
    occurred_at: str,
    previous_event_bytes: bytes | None = None,
    subject_id: str = "alice-investigator",
) -> bytes:
    authorization_bytes = _authorization_bytes(
        policy_bytes,
        decision_id=decision_id,
        subject_id=subject_id,
        action=TeamAction.INVESTIGATION_WRITE,
        resource_type=TeamResourceType.INVESTIGATION,
        resource_id=f"investigation-{event_id}",
        decided_at=decided_at,
    )
    event = create_team_audit_event(
        policy_bytes,
        authorization_bytes,
        b'{"status":"recorded"}',
        payload_media_type="application/json",
        event_id=event_id,
        outcome=TeamAuditOutcome.SUCCEEDED,
        occurred_at=occurred_at,
        previous_event_bytes=previous_event_bytes,
    )
    return render_team_audit_event(event).encode("utf-8")


def _case_event_bytes(
    policy_bytes: bytes,
    case_record_bytes: bytes,
    *,
    decision_id: str,
    event_id: str,
    decided_at: str,
    occurred_at: str,
    previous_event_bytes: bytes | None = None,
) -> bytes:
    case_id = json.loads(case_record_bytes)["case_id"]
    authorization_bytes = _authorization_bytes(
        policy_bytes,
        decision_id=decision_id,
        subject_id="alice-investigator",
        action=TeamAction.INVESTIGATION_WRITE,
        resource_type=TeamResourceType.INVESTIGATION,
        resource_id=case_id,
        decided_at=decided_at,
    )
    event = create_team_audit_event(
        policy_bytes,
        authorization_bytes,
        case_record_bytes,
        payload_media_type=TEAM_CASE_RECORD_MEDIA_TYPE,
        event_id=event_id,
        outcome=TeamAuditOutcome.SUCCEEDED,
        occurred_at=occurred_at,
        previous_event_bytes=previous_event_bytes,
    )
    return render_team_audit_event(event).encode("utf-8")


def _investigation_fixture_bytes() -> tuple[bytes, str]:
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
        fixture_id="refund-investigation-store-001",
    )
    return (
        render_investigation_fixture(fixture).encode("utf-8"),
        fixture.candidate_clusters[0].cluster_id,
    )


def _investigation_event_bytes(
    policy_bytes: bytes,
    record_bytes: bytes,
    *,
    decision_id: str,
    event_id: str,
    decided_at: str,
    occurred_at: str,
    previous_event_bytes: bytes | None = None,
) -> bytes:
    investigation_id = json.loads(record_bytes)["investigation_id"]
    authorization_bytes = _authorization_bytes(
        policy_bytes,
        decision_id=decision_id,
        subject_id="alice-investigator",
        action=TeamAction.INVESTIGATION_WRITE,
        resource_type=TeamResourceType.INVESTIGATION,
        resource_id=investigation_id,
        decided_at=decided_at,
    )
    event = create_team_audit_event(
        policy_bytes,
        authorization_bytes,
        record_bytes,
        payload_media_type=TEAM_INVESTIGATION_RECORD_MEDIA_TYPE,
        event_id=event_id,
        outcome=TeamAuditOutcome.SUCCEEDED,
        occurred_at=occurred_at,
        previous_event_bytes=previous_event_bytes,
    )
    return render_team_audit_event(event).encode("utf-8")


class SQLiteTeamStorePolicyTests(unittest.TestCase):
    def test_concurrent_initialization_is_safe_and_retryable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "team.sqlite3"
            barrier = threading.Barrier(3)

            def initialize() -> str:
                barrier.wait()
                try:
                    SQLiteTeamStore(database, busy_timeout_ms=2_000).initialize()
                    return "initialized"
                except TeamStoreConflictError as exc:
                    return exc.code

            with ThreadPoolExecutor(max_workers=2) as executor:
                attempts = [executor.submit(initialize) for _ in range(2)]
                barrier.wait()
                results = [attempt.result() for attempt in attempts]

            store = SQLiteTeamStore(database)
            store.initialize()
            store.put_policy(_policy_bytes())
            self.assertIn("initialized", results)
            self.assertLessEqual(set(results), {"initialized", "store_busy"})
            self.assertEqual(0, store.get_head("tenant-acme").sequence)

    def test_policy_revisions_are_exact_idempotent_and_forward_only(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "team.sqlite3"
            store = SQLiteTeamStore(database)
            with self.assertRaisesRegex(TeamStoreSchemaError, "store_not_initialized"):
                store.get_head("tenant-acme")

            store.initialize(created_at="2026-07-29T10:00:00Z")
            store.initialize(created_at="2026-07-29T10:01:00Z")
            revision_one = _policy_bytes(revision=1)
            revision_two = _policy_bytes(revision=2)
            store.put_policy(revision_one)
            store.put_policy(revision_one)

            empty_head = store.get_head("tenant-acme")
            self.assertEqual(0, empty_head.sequence)
            self.assertIsNone(empty_head.event_sha256)
            self.assertEqual(revision_one, store.get_active_policy_bytes("tenant-acme"))

            changed_exact_bytes = revision_one.replace(b'  "memberships"', b'   "memberships"')
            with self.assertRaisesRegex(
                TeamStoreConflictError,
                "policy_revision_conflict",
            ):
                store.put_policy(changed_exact_bytes)

            store.put_policy(revision_two)
            self.assertEqual(revision_two, store.get_active_policy_bytes("tenant-acme"))
            self.assertEqual(
                revision_one,
                store.get_policy_bytes("tenant-acme", "access-acme", 1),
            )

            stale_other_policy = _policy_bytes(policy_id="access-replacement", revision=1)
            with self.assertRaisesRegex(TeamStoreConflictError, "policy_revision_stale"):
                store.put_policy(stale_other_policy)

    def test_foreign_database_and_incompatible_schema_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            foreign_path = Path(directory) / "foreign.sqlite3"
            with contextlib.closing(sqlite3.connect(foreign_path)) as connection:
                connection.execute("CREATE TABLE unrelated (value TEXT)")
                connection.commit()
            with self.assertRaisesRegex(TeamStoreSchemaError, "schema_incompatible"):
                SQLiteTeamStore(foreign_path).initialize()
            with contextlib.closing(sqlite3.connect(foreign_path)) as connection:
                self.assertIsNotNone(
                    connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE name = 'unrelated'"
                    ).fetchone()
                )

            store_path = Path(directory) / "team.sqlite3"
            store = SQLiteTeamStore(store_path)
            store.initialize()
            with contextlib.closing(sqlite3.connect(store_path)) as connection:
                connection.execute("PRAGMA user_version = 4")
                connection.commit()
            with self.assertRaisesRegex(TeamStoreSchemaError, "schema_incompatible"):
                store.get_head("tenant-acme")

    def test_busy_writer_has_a_stable_retryable_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "team.sqlite3"
            store = SQLiteTeamStore(database)
            store.initialize()
            store.put_policy(_policy_bytes(revision=1))

            lock = sqlite3.connect(database, isolation_level=None)
            try:
                lock.execute("BEGIN IMMEDIATE")
                contender = SQLiteTeamStore(database, busy_timeout_ms=25)
                with self.assertRaisesRegex(TeamStoreConflictError, "store_busy"):
                    contender.put_policy(_policy_bytes(revision=2))
            finally:
                lock.execute("ROLLBACK")
                lock.close()


class SQLiteTeamStoreLedgerTests(unittest.TestCase):
    def test_recent_event_pages_are_bounded_newest_first_and_snapshot_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
            store.initialize()
            policy_bytes = _policy_bytes()
            store.put_policy(policy_bytes)
            events: list[bytes] = []
            previous: bytes | None = None
            expected_head: str | None = None
            for sequence in range(1, 4):
                event_bytes = _event_bytes(
                    policy_bytes,
                    decision_id=f"decision-page-{sequence}",
                    event_id=f"event-page-{sequence}",
                    decided_at=f"2026-07-28T10:0{sequence * 2 - 2}:00Z",
                    occurred_at=f"2026-07-28T10:0{sequence * 2 - 1}:00Z",
                    previous_event_bytes=previous,
                )
                head = store.append_event(
                    event_bytes,
                    expected_head_sha256=expected_head,
                )
                events.append(event_bytes)
                previous = event_bytes
                expected_head = head.event_sha256

            first_page = store.get_event_page_snapshot("tenant-acme", limit=2)
            second_page = store.get_event_page_snapshot(
                "tenant-acme",
                limit=2,
                before_sequence=first_page.next_before_sequence,
            )
            empty_page = store.get_event_page_snapshot(
                "tenant-acme",
                before_sequence=1,
            )

            self.assertEqual(policy_bytes, first_page.policy_bytes)
            self.assertEqual(3, first_page.head.sequence)
            self.assertEqual((events[2], events[1]), first_page.event_bytes)
            self.assertEqual(2, first_page.next_before_sequence)
            self.assertEqual((events[0],), second_page.event_bytes)
            self.assertIsNone(second_page.next_before_sequence)
            self.assertEqual((), empty_page.event_bytes)
            self.assertIsNone(empty_page.next_before_sequence)

            with self.assertRaisesRegex(TeamStoreError, "invalid_page_limit"):
                store.get_event_page_snapshot("tenant-acme", limit=101)
            with self.assertRaisesRegex(TeamStoreError, "invalid_before_sequence"):
                store.get_event_page_snapshot("tenant-acme", before_sequence=0)

    def test_active_policy_requirement_closes_service_authorization_race(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
            store.initialize()
            revision_one = _policy_bytes(revision=1)
            store.put_policy(revision_one)
            first_bytes = _event_bytes(
                revision_one,
                decision_id="decision-event-1",
                event_id="event-1",
                decided_at="2026-07-28T10:00:00Z",
                occurred_at="2026-07-28T10:01:00Z",
            )
            first_head = store.append_event(first_bytes, expected_head_sha256=None)
            old_policy_successor = _event_bytes(
                revision_one,
                decision_id="decision-event-old-policy",
                event_id="event-old-policy",
                decided_at="2026-07-28T10:02:00Z",
                occurred_at="2026-07-28T10:03:00Z",
                previous_event_bytes=first_bytes,
            )
            store.put_policy(_policy_bytes(revision=2))

            with self.assertRaisesRegex(TeamStoreConflictError, "event_policy_stale"):
                store.append_event(
                    old_policy_successor,
                    expected_head_sha256=first_head.event_sha256,
                    require_active_policy=True,
                )
            self.assertEqual(first_head, store.get_head("tenant-acme"))

            archived_head = store.append_event(
                old_policy_successor,
                expected_head_sha256=first_head.event_sha256,
            )
            self.assertEqual(2, archived_head.sequence)

    def test_two_genesis_writers_commit_exactly_one_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "team.sqlite3"
            store = SQLiteTeamStore(database)
            store.initialize()
            policy_bytes = _policy_bytes()
            store.put_policy(policy_bytes)
            event_bytes = _event_bytes(
                policy_bytes,
                decision_id="decision-concurrent",
                event_id="event-concurrent",
                decided_at="2026-07-28T10:00:00Z",
                occurred_at="2026-07-28T10:01:00Z",
            )
            barrier = threading.Barrier(3)

            def attempt_append() -> str:
                contender = SQLiteTeamStore(database, busy_timeout_ms=2_000)
                barrier.wait()
                try:
                    return (
                        contender.append_event(
                            event_bytes,
                            expected_head_sha256=None,
                        ).event_sha256
                        or ""
                    )
                except TeamStoreConflictError as exc:
                    return exc.code

            with ThreadPoolExecutor(max_workers=2) as executor:
                attempts = [executor.submit(attempt_append) for _ in range(2)]
                barrier.wait()
                results = [attempt.result() for attempt in attempts]

            self.assertEqual(1, results.count("head_conflict"))
            self.assertEqual(1, sum(result != "head_conflict" for result in results))
            self.assertEqual(1, store.get_head("tenant-acme").sequence)
            self.assertEqual((event_bytes,), store.list_event_bytes("tenant-acme"))

    def test_stale_cas_is_atomic_and_historical_policy_events_append(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
            store.initialize()
            revision_one = _policy_bytes(revision=1)
            revision_two = _policy_bytes(revision=2)
            store.put_policy(revision_one)

            first_bytes = _event_bytes(
                revision_one,
                decision_id="decision-event-1",
                event_id="event-1",
                decided_at="2026-07-28T10:00:00Z",
                occurred_at="2026-07-28T10:01:00Z",
            )
            first_head = store.append_event(first_bytes, expected_head_sha256=None)
            self.assertEqual(1, first_head.sequence)

            store.put_policy(revision_two)
            second_bytes = _event_bytes(
                revision_two,
                decision_id="decision-event-2",
                event_id="event-2",
                decided_at="2026-07-28T10:02:00Z",
                occurred_at="2026-07-28T10:03:00Z",
                previous_event_bytes=first_bytes,
            )
            with self.assertRaisesRegex(TeamStoreConflictError, "head_conflict"):
                store.append_event(second_bytes, expected_head_sha256=None)
            self.assertEqual(first_head, store.get_head("tenant-acme"))
            self.assertEqual((first_bytes,), store.list_event_bytes("tenant-acme"))

            second_head = store.append_event(
                second_bytes,
                expected_head_sha256=first_head.event_sha256,
            )
            self.assertEqual(2, second_head.sequence)
            self.assertEqual(revision_one, store.get_policy_bytes("tenant-acme", "access-acme", 1))
            self.assertEqual(
                (first_bytes, second_bytes),
                store.list_event_bytes("tenant-acme"),
            )

    def test_duplicate_ids_fail_without_advancing_the_head(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
            store.initialize()
            policy_bytes = _policy_bytes()
            store.put_policy(policy_bytes)
            first_bytes = _event_bytes(
                policy_bytes,
                decision_id="decision-event-1",
                event_id="event-1",
                decided_at="2026-07-28T10:00:00Z",
                occurred_at="2026-07-28T10:01:00Z",
            )
            first_head = store.append_event(first_bytes, expected_head_sha256=None)

            duplicate_event_id = _event_bytes(
                policy_bytes,
                decision_id="decision-event-2",
                event_id="event-1",
                decided_at="2026-07-28T10:02:00Z",
                occurred_at="2026-07-28T10:03:00Z",
                previous_event_bytes=first_bytes,
            )
            with self.assertRaisesRegex(TeamStoreConflictError, "duplicate_event_id"):
                store.append_event(
                    duplicate_event_id,
                    expected_head_sha256=first_head.event_sha256,
                )
            self.assertEqual(first_head, store.get_head("tenant-acme"))

            duplicate_decision_id = _event_bytes(
                policy_bytes,
                decision_id="decision-event-1",
                event_id="event-2",
                decided_at="2026-07-28T10:02:00Z",
                occurred_at="2026-07-28T10:03:00Z",
                previous_event_bytes=first_bytes,
            )
            with self.assertRaisesRegex(TeamStoreConflictError, "duplicate_decision_id"):
                store.append_event(
                    duplicate_decision_id,
                    expected_head_sha256=first_head.event_sha256,
                )
            self.assertEqual(first_head, store.get_head("tenant-acme"))

    def test_tenant_heads_are_independent(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
            store.initialize()
            acme_policy = _policy_bytes(tenant_id="tenant-acme", policy_id="access-acme")
            beta_policy = _policy_bytes(tenant_id="tenant-beta", policy_id="access-beta")
            store.put_policy(acme_policy)
            store.put_policy(beta_policy)
            acme_event = _event_bytes(
                acme_policy,
                decision_id="decision-acme",
                event_id="event-acme",
                decided_at="2026-07-28T10:00:00Z",
                occurred_at="2026-07-28T10:01:00Z",
            )
            beta_event = _event_bytes(
                beta_policy,
                decision_id="decision-beta",
                event_id="event-beta",
                decided_at="2026-07-28T10:00:00Z",
                occurred_at="2026-07-28T10:01:00Z",
            )

            acme_head = store.append_event(acme_event, expected_head_sha256=None)
            beta_head = store.append_event(beta_event, expected_head_sha256=None)

            self.assertEqual(1, acme_head.sequence)
            self.assertEqual(1, beta_head.sequence)
            self.assertNotEqual(acme_head.event_sha256, beta_head.event_sha256)
            self.assertEqual((acme_event,), store.list_event_bytes("tenant-acme"))
            self.assertEqual((beta_event,), store.list_event_bytes("tenant-beta"))

    def test_missing_exact_policy_rejects_event(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
            store.initialize()
            stored_policy = _policy_bytes()
            store.put_policy(stored_policy)
            different_exact_policy = stored_policy.replace(
                b'  "memberships"',
                b'   "memberships"',
            )
            event_bytes = _event_bytes(
                different_exact_policy,
                decision_id="decision-untracked-policy",
                event_id="event-untracked-policy",
                decided_at="2026-07-28T10:00:00Z",
                occurred_at="2026-07-28T10:01:00Z",
            )
            with self.assertRaisesRegex(TeamStoreSchemaError, "historical_policy_not_found"):
                store.append_event(event_bytes, expected_head_sha256=None)
            self.assertEqual(0, store.get_head("tenant-acme").sequence)


class SQLiteTeamStoreExportTests(unittest.TestCase):
    def test_decision_ids_are_unique_across_events_and_exports(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
            store.initialize()
            policy_bytes = _policy_bytes()
            store.put_policy(policy_bytes)
            event_bytes = _event_bytes(
                policy_bytes,
                decision_id="decision-shared",
                event_id="event-1",
                decided_at="2026-07-28T10:00:00Z",
                occurred_at="2026-07-28T10:01:00Z",
            )
            head = store.append_event(event_bytes, expected_head_sha256=None)
            reused_export_authorization = _authorization_bytes(
                policy_bytes,
                decision_id="decision-shared",
                subject_id="pat-policy",
                action=TeamAction.AUDIT_EXPORT,
                resource_type=TeamResourceType.AUDIT_EXPORT,
                resource_id="export-reused",
                decided_at="2026-07-28T10:02:00Z",
            )
            with self.assertRaisesRegex(
                TeamStoreConflictError,
                "duplicate_export_decision_id",
            ):
                store.create_export(
                    reused_export_authorization,
                    export_id="export-reused",
                    created_at="2026-07-28T10:03:00Z",
                )

            export_authorization = _authorization_bytes(
                policy_bytes,
                decision_id="decision-export",
                subject_id="pat-policy",
                action=TeamAction.AUDIT_EXPORT,
                resource_type=TeamResourceType.AUDIT_EXPORT,
                resource_id="export-1",
                decided_at="2026-07-28T10:02:00Z",
            )
            store.create_export(
                export_authorization,
                export_id="export-1",
                created_at="2026-07-28T10:03:00Z",
            )
            reused_event_decision = _event_bytes(
                policy_bytes,
                decision_id="decision-export",
                event_id="event-2",
                decided_at="2026-07-28T10:04:00Z",
                occurred_at="2026-07-28T10:05:00Z",
                previous_event_bytes=event_bytes,
            )
            with self.assertRaisesRegex(TeamStoreConflictError, "duplicate_decision_id"):
                store.append_event(
                    reused_event_decision,
                    expected_head_sha256=head.event_sha256,
                )
            self.assertEqual(head, store.get_head("tenant-acme"))

    def test_export_is_stored_at_head_and_backup_reopens_exact_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            database = root / "team.sqlite3"
            backup = root / "team-backup.sqlite3"
            store = SQLiteTeamStore(database)
            store.initialize()
            policy_bytes = _policy_bytes()
            store.put_policy(policy_bytes)
            event_bytes = _event_bytes(
                policy_bytes,
                decision_id="decision-event-1",
                event_id="event-1",
                decided_at="2026-07-28T10:00:00Z",
                occurred_at="2026-07-28T10:01:00Z",
            )
            head = store.append_event(event_bytes, expected_head_sha256=None)
            export_authorization = _authorization_bytes(
                policy_bytes,
                decision_id="decision-export-1",
                subject_id="pat-policy",
                action=TeamAction.AUDIT_EXPORT,
                resource_type=TeamResourceType.AUDIT_EXPORT,
                resource_id="export-1",
                decided_at="2026-07-28T10:02:00Z",
            )
            export = store.create_export(
                export_authorization,
                export_id="export-1",
                created_at="2026-07-28T10:03:00Z",
            )
            export_bytes = render_team_audit_export(export).encode("utf-8")

            self.assertEqual(head.event_sha256, export.head_event_sha256)
            self.assertEqual(export_bytes, store.get_export_bytes("tenant-acme", "export-1"))
            self.assertEqual(backup, store.backup(backup))

            restored = SQLiteTeamStore(backup)
            self.assertEqual(store.get_head("tenant-acme"), restored.get_head("tenant-acme"))
            self.assertEqual(policy_bytes, restored.get_active_policy_bytes("tenant-acme"))
            self.assertEqual((event_bytes,), restored.list_event_bytes("tenant-acme"))
            self.assertEqual(
                export_bytes,
                restored.get_export_bytes("tenant-acme", "export-1"),
            )
            with self.assertRaisesRegex(TeamStoreError, "backup_exists"):
                store.backup(backup)

    def test_export_authorization_must_bind_the_active_policy(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
            store.initialize()
            revision_one = _policy_bytes(revision=1)
            store.put_policy(revision_one)
            event_bytes = _event_bytes(
                revision_one,
                decision_id="decision-event-1",
                event_id="event-1",
                decided_at="2026-07-28T10:00:00Z",
                occurred_at="2026-07-28T10:01:00Z",
            )
            store.append_event(event_bytes, expected_head_sha256=None)
            stale_export_authorization = _authorization_bytes(
                revision_one,
                decision_id="decision-export-stale",
                subject_id="pat-policy",
                action=TeamAction.AUDIT_EXPORT,
                resource_type=TeamResourceType.AUDIT_EXPORT,
                resource_id="export-stale",
                decided_at="2026-07-28T10:02:00Z",
            )
            store.put_policy(_policy_bytes(revision=2))

            with self.assertRaisesRegex(TeamStoreConflictError, "export_policy_stale"):
                store.create_export(
                    stale_export_authorization,
                    export_id="export-stale",
                    created_at="2026-07-28T10:03:00Z",
                )

    def test_normal_sql_cannot_update_or_delete_retained_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "team.sqlite3"
            store = SQLiteTeamStore(database)
            store.initialize()
            policy_bytes = _policy_bytes()
            store.put_policy(policy_bytes)
            event_bytes = _event_bytes(
                policy_bytes,
                decision_id="decision-event-1",
                event_id="event-1",
                decided_at="2026-07-28T10:00:00Z",
                occurred_at="2026-07-28T10:01:00Z",
            )
            store.append_event(event_bytes, expected_head_sha256=None)

            with contextlib.closing(sqlite3.connect(database)) as connection:
                with self.assertRaisesRegex(sqlite3.IntegrityError, "policies are immutable"):
                    connection.execute("UPDATE team_policies SET inserted_at = inserted_at")
                with self.assertRaisesRegex(sqlite3.IntegrityError, "events are immutable"):
                    connection.execute("DELETE FROM team_events")

            stored_event = parse_team_audit_event_bytes(store.get_event_bytes("tenant-acme", 1))
            self.assertEqual("event-1", stored_event.entry.event_id)


class SQLiteTeamInvestigationStoreTests(unittest.TestCase):
    def test_investigation_revisions_commit_atomically_and_filter_latest_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "team.sqlite3"
            store = SQLiteTeamStore(database)
            store.initialize()
            policy_bytes = _policy_bytes()
            store.put_policy(policy_bytes)
            fixture_bytes, cluster_id = _investigation_fixture_bytes()
            principal = TeamPrincipal(
                identity_provider="entra",
                subject_id="alice-investigator",
            )
            first = create_team_investigation_record(
                fixture_bytes,
                tenant_id="tenant-acme",
                investigation_id="investigation-refund-store-001",
                cluster_id=cluster_id,
                title="Unexpected refund-tool behavior",
                priority="high",
                opened_at="2026-08-03T12:00:00Z",
                opened_by=principal,
            )
            first_bytes = render_team_investigation_record(first).encode("utf-8")
            first_event = _investigation_event_bytes(
                policy_bytes,
                first_bytes,
                decision_id="decision-investigation-1",
                event_id="event-investigation-1",
                decided_at="2026-08-03T11:59:00Z",
                occurred_at=first.updated_at,
            )
            first_head = store.append_investigation_record(
                first_event,
                first_bytes,
                expected_head_sha256=None,
                require_active_policy=True,
            )

            second = transition_team_investigation_record(
                first,
                updated_at="2026-08-03T12:01:00Z",
                title=first.title,
                status="investigating",
                priority=TeamInvestigationPriority.CRITICAL,
                assigned_to=principal,
            )
            second_bytes = render_team_investigation_record(second).encode("utf-8")
            second_event = _investigation_event_bytes(
                policy_bytes,
                second_bytes,
                decision_id="decision-investigation-2",
                event_id="event-investigation-2",
                decided_at="2026-08-03T12:00:30Z",
                occurred_at=second.updated_at,
                previous_event_bytes=first_event,
            )
            second_head = store.append_investigation_record(
                second_event,
                second_bytes,
                expected_head_sha256=first_head.event_sha256,
                require_active_policy=True,
            )

            detail = store.get_investigation_record_snapshot(
                "tenant-acme",
                first.investigation_id,
            )
            active_page = store.get_investigation_page_snapshot(
                "tenant-acme",
                status="investigating",
                priority="critical",
            )
            queued_page = store.get_investigation_page_snapshot(
                "tenant-acme",
                status="queued",
            )
            missing = store.get_investigation_record_snapshot(
                "tenant-acme",
                "missing-investigation",
            )
            self.assertEqual(second_head, detail.head)
            self.assertEqual(second_bytes, detail.item.record_bytes)
            self.assertEqual(second_event, detail.item.event_bytes)
            self.assertEqual((detail.item,), active_page.items)
            self.assertEqual((), queued_page.items)
            self.assertIsNone(missing.item)

            invalid = replace(
                second,
                revision=3,
                updated_at="2026-08-03T12:02:00Z",
            )
            invalid_bytes = render_team_investigation_record(invalid).encode("utf-8")
            invalid_event = _investigation_event_bytes(
                policy_bytes,
                invalid_bytes,
                decision_id="decision-investigation-3",
                event_id="event-investigation-3",
                decided_at="2026-08-03T12:01:30Z",
                occurred_at=invalid.updated_at,
                previous_event_bytes=second_event,
            )
            with self.assertRaisesRegex(
                TeamStoreConflictError,
                "investigation_revision_conflict",
            ):
                store.append_investigation_record(
                    invalid_event,
                    invalid_bytes,
                    expected_head_sha256=second_head.event_sha256,
                )
            self.assertEqual(second_head, store.get_head("tenant-acme"))
            self.assertEqual(
                (first_event, second_event),
                store.list_event_bytes("tenant-acme"),
            )

            with contextlib.closing(sqlite3.connect(database)) as connection:
                with self.assertRaisesRegex(sqlite3.IntegrityError, "records are immutable"):
                    connection.execute(
                        "UPDATE team_investigation_records SET stored_at = stored_at"
                    )
                with self.assertRaisesRegex(sqlite3.IntegrityError, "records are immutable"):
                    connection.execute("DELETE FROM team_investigation_records")

    def test_missing_resolution_targets_roll_back_event_and_record(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
            store.initialize()
            policy_bytes = _policy_bytes()
            store.put_policy(policy_bytes)
            fixture_bytes, cluster_id = _investigation_fixture_bytes()
            principal = TeamPrincipal(
                identity_provider="entra",
                subject_id="alice-investigator",
            )
            first = create_team_investigation_record(
                fixture_bytes,
                tenant_id="tenant-acme",
                investigation_id="investigation-resolution-001",
                cluster_id=cluster_id,
                title="Resolution target validation",
                priority="normal",
                opened_at="2026-08-03T12:00:00Z",
                opened_by=principal,
            )
            first_bytes = render_team_investigation_record(first).encode("utf-8")
            first_event = _investigation_event_bytes(
                policy_bytes,
                first_bytes,
                decision_id="decision-resolution-1",
                event_id="event-resolution-1",
                decided_at="2026-08-03T11:59:00Z",
                occurred_at=first.updated_at,
            )
            head = store.append_investigation_record(
                first_event,
                first_bytes,
                expected_head_sha256=None,
            )
            closed = transition_team_investigation_record(
                first,
                updated_at="2026-08-03T12:01:00Z",
                title=first.title,
                status="closed",
                priority=first.priority,
                assigned_to=None,
                resolution="duplicate",
                duplicate_of="investigation-missing-999",
            )
            closed_bytes = render_team_investigation_record(closed).encode("utf-8")
            closed_event = _investigation_event_bytes(
                policy_bytes,
                closed_bytes,
                decision_id="decision-resolution-2",
                event_id="event-resolution-2",
                decided_at="2026-08-03T12:00:30Z",
                occurred_at=closed.updated_at,
                previous_event_bytes=first_event,
            )

            with self.assertRaisesRegex(
                TeamStoreConflictError,
                "investigation_duplicate_target_missing",
            ):
                store.append_investigation_record(
                    closed_event,
                    closed_bytes,
                    expected_head_sha256=head.event_sha256,
                )
            self.assertEqual(head, store.get_head("tenant-acme"))
            self.assertEqual((first_event,), store.list_event_bytes("tenant-acme"))

    def test_v2_store_migrates_without_rewriting_case_or_event_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "team.sqlite3"
            store = SQLiteTeamStore(database)
            store.initialize()
            policy_bytes = _policy_bytes()
            store.put_policy(policy_bytes)
            case, review, _ = _base_artifacts()
            record = create_team_case_record(
                case,
                review,
                tenant_id="tenant-acme",
                revision=1,
                published_at="2026-08-03T12:00:00Z",
            )
            record_bytes = render_team_case_record(record).encode("utf-8")
            event_bytes = _case_event_bytes(
                policy_bytes,
                record_bytes,
                decision_id="decision-case-before-v3",
                event_id="event-case-before-v3",
                decided_at="2026-08-03T11:59:00Z",
                occurred_at=record.published_at,
            )
            store.append_case_record(
                event_bytes,
                record_bytes,
                expected_head_sha256=None,
            )

            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.execute("DROP TABLE team_investigation_records")
                connection.execute("DROP TRIGGER team_store_metadata_no_update")
                connection.execute(
                    "UPDATE team_store_metadata SET value = '2' WHERE key = 'schema_version'"
                )
                connection.execute(
                    """
                    CREATE TRIGGER team_store_metadata_no_update
                    BEFORE UPDATE ON team_store_metadata
                    BEGIN
                        SELECT RAISE(ABORT, 'Team store metadata is immutable');
                    END
                    """
                )
                connection.execute("PRAGMA user_version = 2")
                connection.commit()

            store.initialize(created_at="2026-08-03T13:00:00Z")

            detail = store.get_case_record_snapshot("tenant-acme", record.case_id)
            self.assertEqual(record_bytes, detail.item.record_bytes)
            self.assertEqual(event_bytes, detail.item.event_bytes)
            self.assertEqual((), store.get_investigation_page_snapshot("tenant-acme").items)
            with contextlib.closing(sqlite3.connect(database)) as connection:
                self.assertEqual(3, connection.execute("PRAGMA user_version").fetchone()[0])
                metadata = dict(connection.execute("SELECT key, value FROM team_store_metadata"))
                self.assertEqual("3", metadata["schema_version"])
                self.assertEqual("2026-08-03T13:00:00Z", metadata["migrated_to_v3_at"])


class SQLiteTeamCaseStoreTests(unittest.TestCase):
    def test_case_event_and_revision_commit_atomically_with_exact_reads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "team.sqlite3"
            store = SQLiteTeamStore(database)
            store.initialize()
            policy_bytes = _policy_bytes()
            store.put_policy(policy_bytes)
            case, review, _, publication, verification = _azure_artifacts()
            first = create_team_case_record(
                case,
                review,
                tenant_id="tenant-acme",
                revision=1,
                published_at="2026-08-03T12:00:00Z",
            )
            first_bytes = render_team_case_record(first).encode()
            first_event = _case_event_bytes(
                policy_bytes,
                first_bytes,
                decision_id="decision-case-1",
                event_id="event-case-1",
                decided_at="2026-08-03T11:59:00Z",
                occurred_at=first.published_at,
            )
            first_head = store.append_case_record(
                first_event,
                first_bytes,
                expected_head_sha256=None,
                require_active_policy=True,
            )

            second = create_team_case_record(
                case,
                review,
                tenant_id="tenant-acme",
                revision=2,
                published_at="2026-08-03T12:01:00Z",
                azure_publication_bytes=publication,
                azure_verification_bytes=verification,
            )
            second_bytes = render_team_case_record(second).encode()
            second_event = _case_event_bytes(
                policy_bytes,
                second_bytes,
                decision_id="decision-case-2",
                event_id="event-case-2",
                decided_at="2026-08-03T12:00:30Z",
                occurred_at=second.published_at,
                previous_event_bytes=first_event,
            )
            second_head = store.append_case_record(
                second_event,
                second_bytes,
                expected_head_sha256=first_head.event_sha256,
                require_active_policy=True,
            )

            detail = store.get_case_record_snapshot("tenant-acme", first.case_id)
            page = store.get_case_page_snapshot("tenant-acme")
            missing = store.get_case_record_snapshot("tenant-acme", "missing-case")
            self.assertEqual(second_head, detail.head)
            self.assertEqual(second_bytes, detail.item.record_bytes)
            self.assertEqual(second_event, detail.item.event_bytes)
            self.assertEqual((detail.item,), page.items)
            self.assertIsNone(missing.item)
            self.assertEqual((first_event, second_event), store.list_event_bytes("tenant-acme"))

            invalid_successor = replace(
                second,
                revision=3,
                published_at="2026-08-03T12:02:00Z",
            )
            invalid_bytes = render_team_case_record(invalid_successor).encode()
            invalid_event = _case_event_bytes(
                policy_bytes,
                invalid_bytes,
                decision_id="decision-case-3",
                event_id="event-case-3",
                decided_at="2026-08-03T12:01:30Z",
                occurred_at=invalid_successor.published_at,
                previous_event_bytes=second_event,
            )
            with self.assertRaisesRegex(TeamStoreConflictError, "case_revision_conflict"):
                store.append_case_record(
                    invalid_event,
                    invalid_bytes,
                    expected_head_sha256=second_head.event_sha256,
                )
            self.assertEqual(second_head, store.get_head("tenant-acme"))
            self.assertEqual((first_event, second_event), store.list_event_bytes("tenant-acme"))

            with contextlib.closing(sqlite3.connect(database)) as connection:
                with self.assertRaisesRegex(sqlite3.IntegrityError, "records are immutable"):
                    connection.execute("UPDATE team_case_records SET stored_at = stored_at")
                with self.assertRaisesRegex(sqlite3.IntegrityError, "records are immutable"):
                    connection.execute("DELETE FROM team_case_records")

    def test_case_pages_select_latest_revision_and_cursor_across_cases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = SQLiteTeamStore(Path(directory) / "team.sqlite3")
            store.initialize()
            policy_bytes = _policy_bytes()
            store.put_policy(policy_bytes)
            head_sha256: str | None = None
            previous_event: bytes | None = None
            records: list[tuple[bytes, bytes]] = []
            for index, case_name in enumerate(
                (
                    "approve-refund-tool-description.json",
                    "reject-overbroad-prompt.json",
                ),
                start=1,
            ):
                case, review, _ = _base_artifacts(case_name)
                published_at = f"2026-08-03T12:0{index}:00Z"
                record = create_team_case_record(
                    case,
                    review,
                    tenant_id="tenant-acme",
                    revision=1,
                    published_at=published_at,
                )
                record_bytes = render_team_case_record(record).encode()
                event_bytes = _case_event_bytes(
                    policy_bytes,
                    record_bytes,
                    decision_id=f"decision-page-case-{index}",
                    event_id=f"event-page-case-{index}",
                    decided_at=f"2026-08-03T12:0{index - 1}:30Z",
                    occurred_at=published_at,
                    previous_event_bytes=previous_event,
                )
                head = store.append_case_record(
                    event_bytes,
                    record_bytes,
                    expected_head_sha256=head_sha256,
                )
                records.append((record_bytes, event_bytes))
                previous_event = event_bytes
                head_sha256 = head.event_sha256

            first_page = store.get_case_page_snapshot("tenant-acme", limit=1)
            second_page = store.get_case_page_snapshot(
                "tenant-acme",
                limit=1,
                before_sequence=first_page.next_before_sequence,
            )

            self.assertEqual(records[1][0], first_page.items[0].record_bytes)
            self.assertEqual(2, first_page.next_before_sequence)
            self.assertEqual(records[0][0], second_page.items[0].record_bytes)
            self.assertIsNone(second_page.next_before_sequence)

    def test_v1_store_migrates_additively_without_rewriting_retained_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "team.sqlite3"
            store = SQLiteTeamStore(database)
            store.initialize()
            policy_bytes = _policy_bytes()
            store.put_policy(policy_bytes)
            event_bytes = _event_bytes(
                policy_bytes,
                decision_id="decision-before-migration",
                event_id="event-before-migration",
                decided_at="2026-08-03T10:00:00Z",
                occurred_at="2026-08-03T10:01:00Z",
            )
            store.append_event(event_bytes, expected_head_sha256=None)

            with contextlib.closing(sqlite3.connect(database)) as connection:
                connection.execute("DROP TABLE team_investigation_records")
                connection.execute("DROP TABLE team_case_records")
                connection.execute("DROP TRIGGER team_store_metadata_no_update")
                connection.execute(
                    "UPDATE team_store_metadata SET value = '1' WHERE key = 'schema_version'"
                )
                connection.execute(
                    """
                    CREATE TRIGGER team_store_metadata_no_update
                    BEFORE UPDATE ON team_store_metadata
                    BEGIN
                        SELECT RAISE(ABORT, 'Team store metadata is immutable');
                    END
                    """
                )
                connection.execute("PRAGMA user_version = 1")
                connection.commit()

            store.initialize(created_at="2026-08-03T12:00:00Z")

            self.assertEqual(policy_bytes, store.get_active_policy_bytes("tenant-acme"))
            self.assertEqual((event_bytes,), store.list_event_bytes("tenant-acme"))
            self.assertEqual((), store.get_case_page_snapshot("tenant-acme").items)
            self.assertEqual(
                (),
                store.get_investigation_page_snapshot("tenant-acme").items,
            )
            with contextlib.closing(sqlite3.connect(database)) as connection:
                self.assertEqual(3, connection.execute("PRAGMA user_version").fetchone()[0])
                metadata = dict(connection.execute("SELECT key, value FROM team_store_metadata"))
                self.assertEqual("3", metadata["schema_version"])
                self.assertEqual("2026-08-03T12:00:00Z", metadata["migrated_to_v2_at"])
                self.assertEqual("2026-08-03T12:00:00Z", metadata["migrated_to_v3_at"])


if __name__ == "__main__":
    unittest.main()
