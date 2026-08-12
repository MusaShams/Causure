"""Candidate-only Team investigation queue contract tests."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from dataclasses import replace

from causure.collector import collect_otlp_trace_manifest, render_trace_manifest
from causure.constants import (
    TeamInvestigationPriority,
    TeamInvestigationResolution,
    TeamInvestigationStatus,
)
from causure.fixtures import (
    generate_investigation_fixture,
    render_investigation_fixture,
)
from causure.models import to_jsonable
from causure.team_investigations import (
    TeamInvestigationValidationError,
    attach_team_investigation_observation,
    create_team_investigation_record,
    parse_team_investigation_record,
    parse_team_investigation_record_bytes,
    render_team_investigation_record,
    transition_team_investigation_record,
    validate_team_investigation_successor,
)
from causure.team_service import TeamPrincipal
from tests.helpers import PROJECT_ROOT


class TeamInvestigationRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
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
            fixture_id="refund-investigation-001",
        )
        cls.fixture_bytes = render_investigation_fixture(fixture).encode("utf-8")
        cls.cluster_id = fixture.candidate_clusters[0].cluster_id
        cls.principal = TeamPrincipal(
            identity_provider="entra",
            subject_id="investigator-17",
        )

    @classmethod
    def second_fixture_bytes(cls) -> tuple[bytes, str]:
        document = json.loads(cls.fixture_bytes)
        trace_id = "a" * 64
        document["fixture_id"] = "refund-investigation-002"
        cluster = document["candidate_clusters"][0]
        cluster["cluster_id"] = f"trace-{trace_id}"
        cluster["trace_id_sha256"] = trace_id
        cluster["trace_ref"] = (
            f"trace-sha256://{document['source']['trace_source_sha256']}/traces/{trace_id}"
        )
        return (
            (json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
                "utf-8"
            ),
            cluster["cluster_id"],
        )

    def create(self):
        return create_team_investigation_record(
            self.fixture_bytes,
            tenant_id="tenant-acme",
            investigation_id="investigation-refund-001",
            cluster_id=self.cluster_id,
            title="Unexpected refund-tool behavior",
            priority=TeamInvestigationPriority.HIGH,
            opened_at="2026-08-03T12:00:00Z",
            opened_by=self.principal,
        )

    def test_base_record_is_minimized_candidate_only_and_round_trips(self) -> None:
        record = self.create()
        rendered = render_team_investigation_record(record)

        self.assertEqual(
            record,
            parse_team_investigation_record_bytes(rendered.encode("utf-8")),
        )
        self.assertTrue(record.candidate_only)
        self.assertFalse(record.gate_eligible)
        self.assertFalse(record.causal_claims_inferred)
        self.assertEqual(TeamInvestigationStatus.QUEUED, record.status)
        self.assertEqual(1, len(record.observations))
        self.assertNotIn("span_evidence_refs", rendered)
        self.assertNotIn("trace_ref", rendered)
        self.assertNotIn("refund customer", rendered.lower())

    def test_fixture_subject_binds_exact_bytes(self) -> None:
        document = json.loads(self.fixture_bytes)
        compact_bytes = (
            json.dumps(document, ensure_ascii=False, separators=(",", ":")) + "\n"
        ).encode("utf-8")

        record = create_team_investigation_record(
            compact_bytes,
            tenant_id="tenant-acme",
            investigation_id="investigation-refund-001",
            cluster_id=self.cluster_id,
            title="Unexpected refund-tool behavior",
            priority="high",
            opened_at="2026-08-03T12:00:00Z",
            opened_by=self.principal,
        )

        self.assertEqual(
            hashlib.sha256(compact_bytes).hexdigest(),
            record.observations[0].fixture.sha256,
        )
        self.assertNotEqual(
            hashlib.sha256(self.fixture_bytes).hexdigest(),
            record.observations[0].fixture.sha256,
        )

    def test_selected_cluster_must_exist_in_the_exact_fixture(self) -> None:
        with self.assertRaisesRegex(
            TeamInvestigationValidationError,
            "does not identify a candidate cluster",
        ):
            create_team_investigation_record(
                self.fixture_bytes,
                tenant_id="tenant-acme",
                investigation_id="investigation-refund-001",
                cluster_id=f"trace-{'f' * 64}",
                title="Unexpected refund-tool behavior",
                priority="normal",
                opened_at="2026-08-03T12:00:00Z",
                opened_by=self.principal,
            )

    def test_distinct_clusters_append_without_changing_queue_state(self) -> None:
        original = self.create()
        second_fixture, second_cluster = self.second_fixture_bytes()

        successor = attach_team_investigation_observation(
            original,
            second_fixture,
            cluster_id=second_cluster,
            attached_at="2026-08-03T12:01:00Z",
            attached_by=self.principal,
        )

        self.assertEqual(2, successor.revision)
        self.assertEqual(2, len(successor.observations))
        self.assertEqual(original.status, successor.status)
        self.assertEqual(original.priority, successor.priority)
        self.assertEqual(original.observations, successor.observations[:-1])

        with self.assertRaisesRegex(
            TeamInvestigationValidationError,
            "already attached",
        ):
            attach_team_investigation_observation(
                successor,
                second_fixture,
                cluster_id=second_cluster,
                attached_at="2026-08-03T12:02:00Z",
                attached_by=self.principal,
            )

    def test_queue_transition_supports_assignment_and_explicit_abstention(self) -> None:
        original = self.create()
        assignee = TeamPrincipal(identity_provider="entra", subject_id="investigator-22")
        active = transition_team_investigation_record(
            original,
            updated_at="2026-08-03T12:01:00Z",
            title=original.title,
            status="investigating",
            priority="critical",
            assigned_to=assignee,
        )
        closed = transition_team_investigation_record(
            active,
            updated_at="2026-08-03T12:02:00Z",
            title=active.title,
            status="closed",
            priority=active.priority,
            assigned_to=assignee,
            resolution="no_change_required",
        )

        self.assertEqual(TeamInvestigationStatus.INVESTIGATING, active.status)
        self.assertEqual(TeamInvestigationPriority.CRITICAL, active.priority)
        self.assertEqual(assignee, active.assigned_to)
        self.assertEqual(
            TeamInvestigationResolution.NO_CHANGE_REQUIRED,
            closed.resolution,
        )
        with self.assertRaisesRegex(
            TeamInvestigationValidationError,
            "terminal",
        ):
            transition_team_investigation_record(
                closed,
                updated_at="2026-08-03T12:03:00Z",
                title=closed.title,
                status="closed",
                priority=closed.priority,
                assigned_to=assignee,
                resolution="no_change_required",
            )

    def test_resolution_linkage_is_closed_and_typed(self) -> None:
        original = self.create()

        with self.assertRaisesRegex(
            TeamInvestigationValidationError,
            "require closed status",
        ):
            transition_team_investigation_record(
                original,
                updated_at="2026-08-03T12:01:00Z",
                title=original.title,
                status="investigating",
                priority=original.priority,
                assigned_to=None,
                linked_case_id="refund-tool-description-001",
            )

        linked = transition_team_investigation_record(
            original,
            updated_at="2026-08-03T12:01:00Z",
            title=original.title,
            status="closed",
            priority=original.priority,
            assigned_to=None,
            resolution="change_case_opened",
            linked_case_id="refund-tool-description-001",
        )
        self.assertEqual("refund-tool-description-001", linked.linked_case_id)

        with self.assertRaisesRegex(
            TeamInvestigationValidationError,
            "cannot duplicate itself",
        ):
            transition_team_investigation_record(
                original,
                updated_at="2026-08-03T12:01:00Z",
                title=original.title,
                status="closed",
                priority=original.priority,
                assigned_to=None,
                resolution="duplicate",
                duplicate_of=original.investigation_id,
            )

    def test_successor_rejects_evidence_rewrite_and_status_rewind(self) -> None:
        original = self.create()
        tampered_observation = replace(
            original.observations[0],
            fixture=replace(original.observations[0].fixture, sha256="0" * 64),
        )
        tampered = replace(
            original,
            revision=2,
            updated_at="2026-08-03T12:01:00Z",
            observations=(tampered_observation,),
        )
        with self.assertRaisesRegex(
            TeamInvestigationValidationError,
            "append exactly one immutable observation",
        ):
            validate_team_investigation_successor(original, tampered)

        blocked = transition_team_investigation_record(
            original,
            updated_at="2026-08-03T12:01:00Z",
            title=original.title,
            status="blocked",
            priority=original.priority,
            assigned_to=None,
        )
        with self.assertRaisesRegex(
            TeamInvestigationValidationError,
            "status transition",
        ):
            transition_team_investigation_record(
                blocked,
                updated_at="2026-08-03T12:02:00Z",
                title=blocked.title,
                status="queued",
                priority=blocked.priority,
                assigned_to=None,
            )

    def test_parser_rejects_unknown_duplicate_and_semantic_rewrites(self) -> None:
        record = self.create()
        document = to_jsonable(record)
        document["unknown"] = True
        with self.assertRaisesRegex(TeamInvestigationValidationError, "unknown field"):
            parse_team_investigation_record(document)

        rendered = render_team_investigation_record(record).rstrip()
        duplicate = rendered[:-1] + ',\n  "tenant_id": "tenant-other"\n}\n'
        with self.assertRaisesRegex(TeamInvestigationValidationError, "duplicate JSON key"):
            parse_team_investigation_record_bytes(duplicate.encode("utf-8"))

        rewritten = copy.deepcopy(to_jsonable(record))
        rewritten["gate_eligible"] = True
        with self.assertRaisesRegex(TeamInvestigationValidationError, "expected false"):
            parse_team_investigation_record(rewritten)


if __name__ == "__main__":
    unittest.main()
