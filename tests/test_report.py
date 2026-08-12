"""Report rendering."""

from __future__ import annotations

import json
import unittest
from datetime import UTC, datetime

from causure.engine import review_case
from causure.models import parse_change_case
from causure.report import render_json, render_markdown
from tests.helpers import load_example


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.case = parse_change_case(load_example())
        self.result = review_case(
            self.case,
            reviewed_at=datetime(2026, 7, 27, 20, 0, tzinfo=UTC),
        )

    def test_json_report_is_valid_and_complete(self) -> None:
        document = json.loads(render_json(self.result))

        self.assertEqual("approve", document["decision"])
        self.assertEqual("patch", document["recommended_action"])
        self.assertEqual("2026-07-27T20:00:00Z", document["reviewed_at"])
        self.assertEqual(15, len(document["findings"]))

    def test_markdown_report_contains_decision_and_audit_details(self) -> None:
        report = render_markdown(self.case, self.result)

        self.assertIn("**APPROVE**", report)
        self.assertIn("CAUSURE-VAL-002", report)
        self.assertIn("Evidence document SHA-256", report)
        self.assertIn(self.case.proposed_change.prediction, report)


if __name__ == "__main__":
    unittest.main()
