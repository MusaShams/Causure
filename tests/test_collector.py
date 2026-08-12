"""Redacted OTLP/OpenInference trace collection contracts."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from typing import Any

from causure.collector import (
    collect_otlp_trace_manifest,
    render_trace_manifest,
)
from causure.errors import TraceCollectionError
from tests.helpers import PROJECT_ROOT


class TraceCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.fixture_path = PROJECT_ROOT / "examples" / "traces" / "refund-openinference-otlp.json"
        cls.raw_bytes = cls.fixture_path.read_bytes()
        cls.document: dict[str, Any] = json.loads(cls.raw_bytes)

    def collect(self, document: dict[str, Any] | None = None, **kwargs: Any):
        selected_document = copy.deepcopy(document if document is not None else self.document)
        raw_bytes = (
            self.raw_bytes
            if document is None
            else json.dumps(selected_document, separators=(",", ":")).encode()
        )
        return collect_otlp_trace_manifest(
            selected_document,
            raw_bytes=raw_bytes,
            source_id="refund-openinference-fixture",
            **kwargs,
        )

    def test_collects_integrity_metadata_and_safe_attributes(self) -> None:
        manifest = self.collect()

        self.assertEqual("1.0", manifest.schema_version)
        self.assertEqual(hashlib.sha256(self.raw_bytes).hexdigest(), manifest.source.sha256)
        self.assertEqual(len(self.raw_bytes), manifest.source.byte_count)
        self.assertEqual(1, manifest.source.trace_count)
        self.assertEqual(2, manifest.source.span_count)
        self.assertFalse(manifest.source.source_embedded)
        self.assertFalse(manifest.redaction.raw_content_included)
        self.assertEqual(7, manifest.redaction.retained_attribute_count)
        self.assertEqual(5, manifest.redaction.redacted_attribute_count)
        self.assertEqual(1, manifest.redaction.dropped_attribute_count)
        self.assertEqual("AGENT", manifest.spans[0].attributes["openinference.span.kind"])
        self.assertEqual(123_000_000, int(manifest.spans[0].duration_nano or "0"))
        self.assertEqual(214, manifest.spans[1].attributes["llm.token_count.total"])

    def test_rendered_manifest_excludes_raw_content_and_identifiers(self) -> None:
        rendered = render_trace_manifest(self.collect())

        for forbidden in (
            "alice@example.com",
            "4111111111111111",
            "8675309",
            "sk-test-not-a-real-secret",
            "customer-session-123",
            "refund-agent run",
            "4bf92f3577b34da6a3ce929d0e0e4736",
            "00f067aa0ba902b7",
            "input.value",
            "output.value",
            "session.id",
            "api_key",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, rendered)

        self.assertIn('"llm.model_name": "gpt-4.1-mini"', rendered)
        self.assertIn('"raw_content_included": false', rendered)

    def test_same_input_renders_deterministically(self) -> None:
        first = render_trace_manifest(self.collect())
        second = render_trace_manifest(self.collect())

        self.assertEqual(first, second)

    def test_document_must_match_hashed_source_bytes(self) -> None:
        document = copy.deepcopy(self.document)
        document["futureTopLevelField"] = True

        with self.assertRaisesRegex(TraceCollectionError, "does not match"):
            collect_otlp_trace_manifest(
                document,
                raw_bytes=self.raw_bytes,
                source_id="refund-openinference-fixture",
            )

    def test_unknown_otlp_fields_are_ignored(self) -> None:
        document = copy.deepcopy(self.document)
        document["futureTopLevelField"] = {"raw": "must not escape"}
        document["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["futureSpanField"] = (
            "must not escape"
        )

        rendered = render_trace_manifest(self.collect(document))

        self.assertNotIn("futureTopLevelField", rendered)
        self.assertNotIn("must not escape", rendered)

    def test_unrecognized_usage_metric_cannot_smuggle_numeric_identity(self) -> None:
        document = copy.deepcopy(self.document)
        attributes = document["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
        attributes.append(
            {
                "key": "gen_ai.usage.user_id",
                "value": {"intValue": "8675309"},
            }
        )

        rendered = render_trace_manifest(self.collect(document))

        self.assertNotIn("gen_ai.usage.user_id", rendered)
        self.assertNotIn("8675309", rendered)

    def test_duplicate_attribute_keys_are_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        attributes = document["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["attributes"]
        attributes.append(copy.deepcopy(attributes[0]))

        with self.assertRaisesRegex(TraceCollectionError, "duplicate attribute key"):
            self.collect(document)

    def test_invalid_trace_id_is_rejected(self) -> None:
        document = copy.deepcopy(self.document)
        document["resourceSpans"][0]["scopeSpans"][0]["spans"][0]["traceId"] = "not-a-trace"

        with self.assertRaisesRegex(TraceCollectionError, "hexadecimal identifier"):
            self.collect(document)

    def test_all_zero_trace_or_span_ids_are_rejected(self) -> None:
        for field, value in (
            ("traceId", "0" * 32),
            ("spanId", "0" * 16),
        ):
            with self.subTest(field=field):
                document = copy.deepcopy(self.document)
                document["resourceSpans"][0]["scopeSpans"][0]["spans"][0][field] = value

                with self.assertRaisesRegex(TraceCollectionError, "all-zero"):
                    self.collect(document)

    def test_span_limit_is_enforced(self) -> None:
        with self.assertRaisesRegex(TraceCollectionError, "span count exceeds"):
            self.collect(max_spans=1)

    def test_same_span_id_in_different_traces_has_unique_reference(self) -> None:
        document = copy.deepcopy(self.document)
        spans = document["resourceSpans"][0]["scopeSpans"][0]["spans"]
        spans[1]["traceId"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        spans[1]["spanId"] = spans[0]["spanId"]

        manifest = self.collect(document)

        self.assertEqual(2, manifest.source.trace_count)
        self.assertEqual(2, len({span.evidence_ref for span in manifest.spans}))


if __name__ == "__main__":
    unittest.main()
