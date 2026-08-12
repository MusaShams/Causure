"""Draft investigation-fixture generation contracts."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest

from causure.collector import (
    collect_otlp_trace_manifest,
    render_trace_manifest,
)
from causure.fixtures import (
    FixtureGenerationError,
    InvestigationFixtureValidationError,
    generate_investigation_fixture,
    parse_investigation_fixture,
    parse_investigation_fixture_bytes,
    render_investigation_fixture,
)
from tests.helpers import PROJECT_ROOT


class InvestigationFixtureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        trace_path = PROJECT_ROOT / "examples" / "traces" / "refund-openinference-otlp.json"
        raw_trace = trace_path.read_bytes()
        manifest = collect_otlp_trace_manifest(
            json.loads(raw_trace),
            raw_bytes=raw_trace,
            source_id="refund-openinference-fixture",
        )
        cls.manifest_bytes = render_trace_manifest(manifest).encode()
        cls.document = json.loads(cls.manifest_bytes)

    def generate(self):
        return generate_investigation_fixture(
            copy.deepcopy(self.document),
            raw_bytes=self.manifest_bytes,
            fixture_id="refund-investigation-001",
        )

    def test_generates_a_draft_without_inventing_gate_evidence(self) -> None:
        fixture = self.generate()

        self.assertTrue(fixture.draft_only)
        self.assertFalse(fixture.gate_eligible)
        self.assertFalse(fixture.causal_claims_inferred)
        self.assertIn("causal_attribution", fixture.missing_evidence)
        self.assertEqual(
            hashlib.sha256(self.manifest_bytes).hexdigest(),
            fixture.source.manifest_sha256,
        )
        self.assertEqual(1, len(fixture.candidate_clusters))

        cluster = fixture.candidate_clusters[0]
        self.assertEqual(2, cluster.span_count)
        self.assertEqual(1, cluster.root_span_count)
        self.assertEqual(0, cluster.error_span_count)
        self.assertEqual(("gpt-4.1-mini",), cluster.model_identifiers)
        self.assertEqual(("openai",), cluster.provider_identifiers)
        self.assertEqual(
            {"AGENT": 1, "LLM": 1},
            {item.name: item.count for item in cluster.span_kind_counts},
        )

    def test_fixture_rendering_is_deterministic(self) -> None:
        self.assertEqual(
            render_investigation_fixture(self.generate()),
            render_investigation_fixture(self.generate()),
        )

    def test_rendered_fixture_round_trips_through_the_strict_parser(self) -> None:
        fixture = self.generate()

        self.assertEqual(
            fixture,
            parse_investigation_fixture_bytes(
                render_investigation_fixture(fixture).encode("utf-8")
            ),
        )

    def test_strict_parser_rejects_unknown_and_duplicate_fields(self) -> None:
        document = json.loads(render_investigation_fixture(self.generate()))
        document["unexpected"] = True

        with self.assertRaisesRegex(
            InvestigationFixtureValidationError,
            "unknown field: unexpected",
        ):
            parse_investigation_fixture(document)

        raw_bytes = render_investigation_fixture(self.generate()).encode("utf-8")
        duplicate = raw_bytes.replace(
            b'{\n  "candidate_clusters"',
            b'{\n  "draft_only": true,\n  "candidate_clusters"',
            1,
        )
        with self.assertRaisesRegex(
            InvestigationFixtureValidationError,
            "duplicate JSON key: 'draft_only'",
        ):
            parse_investigation_fixture_bytes(duplicate)

    def test_strict_parser_rejects_unbound_trace_references(self) -> None:
        document = json.loads(render_investigation_fixture(self.generate()))
        document["candidate_clusters"][0]["trace_ref"] = (
            "trace-sha256://" + "a" * 64 + "/traces/" + "b" * 64
        )

        with self.assertRaisesRegex(
            InvestigationFixtureValidationError,
            "does not bind the declared trace source and trace id",
        ):
            parse_investigation_fixture(document)

    def test_strict_parser_rejects_inconsistent_counts(self) -> None:
        document = json.loads(render_investigation_fixture(self.generate()))
        document["source"]["span_count"] += 1

        with self.assertRaisesRegex(
            InvestigationFixtureValidationError,
            "candidate-cluster span total",
        ):
            parse_investigation_fixture(document)

    def test_strict_parser_rejects_unsorted_candidate_clusters(self) -> None:
        document = json.loads(render_investigation_fixture(self.generate()))
        template = document["candidate_clusters"][0]
        clusters = []
        for trace_id in ("b" * 64, "a" * 64):
            cluster = copy.deepcopy(template)
            cluster["cluster_id"] = f"trace-{trace_id}"
            cluster["trace_id_sha256"] = trace_id
            cluster["trace_ref"] = (
                f"trace-sha256://{document['source']['trace_source_sha256']}/traces/{trace_id}"
            )
            clusters.append(cluster)
        document["candidate_clusters"] = clusters
        document["source"]["trace_count"] = 2
        document["source"]["span_count"] = 2 * template["span_count"]

        with self.assertRaisesRegex(
            InvestigationFixtureValidationError,
            "cluster ids must be unique and sorted",
        ):
            parse_investigation_fixture(document)

    def test_byte_parser_requires_nonempty_immutable_bytes(self) -> None:
        for value in (b"", bytearray(b"{}")):
            with self.subTest(value_type=type(value).__name__):
                with self.assertRaisesRegex(
                    InvestigationFixtureValidationError,
                    "expected from 1 to",
                ):
                    parse_investigation_fixture_bytes(value)  # type: ignore[arg-type]

    def test_manifest_document_must_match_hashed_bytes(self) -> None:
        document = copy.deepcopy(self.document)
        document["collector_version"] = "different"

        with self.assertRaisesRegex(FixtureGenerationError, "does not match"):
            generate_investigation_fixture(
                document,
                raw_bytes=self.manifest_bytes,
                fixture_id="refund-investigation-001",
            )

    def test_cluster_limit_is_enforced(self) -> None:
        document = copy.deepcopy(self.document)
        document["spans"][1]["trace_id_sha256"] = "a" * 64
        document["source"]["trace_count"] = 2
        raw_bytes = json.dumps(document, sort_keys=True).encode()

        with self.assertRaisesRegex(
            FixtureGenerationError,
            "candidate trace count exceeds",
        ):
            generate_investigation_fixture(
                document,
                raw_bytes=raw_bytes,
                fixture_id="refund-investigation-001",
                max_clusters=1,
            )


if __name__ == "__main__":
    unittest.main()
