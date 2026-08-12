"""Strict redacted trace-manifest parsing contracts."""

from __future__ import annotations

import copy
import json
import unittest

from causure.collector import (
    collect_otlp_trace_manifest,
    render_trace_manifest,
)
from causure.trace_manifest import (
    TraceManifestValidationError,
    parse_trace_manifest,
)
from tests.helpers import PROJECT_ROOT


class TraceManifestParsingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        trace_path = PROJECT_ROOT / "examples" / "traces" / "refund-openinference-otlp.json"
        raw_trace = trace_path.read_bytes()
        manifest = collect_otlp_trace_manifest(
            json.loads(raw_trace),
            raw_bytes=raw_trace,
            source_id="refund-openinference-fixture",
        )
        cls.document = json.loads(render_trace_manifest(manifest))

    def test_parses_collector_output(self) -> None:
        manifest = parse_trace_manifest(copy.deepcopy(self.document))

        self.assertEqual(2, manifest.source.span_count)
        self.assertEqual(1, manifest.source.trace_count)
        self.assertEqual(
            7,
            manifest.redaction.retained_attribute_count,
        )

    def test_rejects_unknown_fields(self) -> None:
        document = copy.deepcopy(self.document)
        document["raw_trace"] = "must not be accepted"

        with self.assertRaisesRegex(
            TraceManifestValidationError,
            "unknown field",
        ):
            parse_trace_manifest(document)

    def test_rejects_mismatched_counts(self) -> None:
        document = copy.deepcopy(self.document)
        document["source"]["span_count"] = 3

        with self.assertRaisesRegex(
            TraceManifestValidationError,
            "count does not match",
        ):
            parse_trace_manifest(document)

    def test_rejects_evidence_ref_that_is_not_bound_to_span_hash(self) -> None:
        document = copy.deepcopy(self.document)
        document["spans"][0]["evidence_ref"] = "trace-sha256://" + "a" * 64 + "/spans/" + "b" * 64

        with self.assertRaisesRegex(
            TraceManifestValidationError,
            "reference does not match",
        ):
            parse_trace_manifest(document)

    def test_rejects_non_allowlisted_manifest_attributes(self) -> None:
        document = copy.deepcopy(self.document)
        document["spans"][0]["attributes"]["gen_ai.usage.user_id"] = 8675309
        document["redaction"]["retained_attribute_count"] += 1

        with self.assertRaisesRegex(
            TraceManifestValidationError,
            "unknown field",
        ):
            parse_trace_manifest(document)


if __name__ == "__main__":
    unittest.main()
