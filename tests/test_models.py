"""Evidence-document structural validation."""

from __future__ import annotations

import math
import unittest

from causure.errors import DocumentValidationError
from causure.models import parse_change_case, to_jsonable
from tests.helpers import load_example


class ChangeCaseParsingTests(unittest.TestCase):
    def test_parses_the_reference_case(self) -> None:
        document = load_example()

        case = parse_change_case(document)

        self.assertEqual("refund-tool-description-001", case.case_id)
        self.assertEqual(document, to_jsonable(case))

    def test_rejects_unknown_fields(self) -> None:
        document = load_example()
        document["incident"]["surprise"] = "ignored fields would weaken the audit contract"

        with self.assertRaises(DocumentValidationError) as caught:
            parse_change_case(document)

        self.assertIn("$.incident.surprise", str(caught.exception))

    def test_reports_multiple_structural_errors(self) -> None:
        document = load_example()
        document["schema_version"] = "99"
        document["incident"]["severity"] = "catastrophic"
        document["proposed_change"]["changed_surface_count"] = 0

        with self.assertRaises(DocumentValidationError) as caught:
            parse_change_case(document)

        message = str(caught.exception)
        self.assertIn("$.schema_version", message)
        self.assertIn("$.incident.severity", message)
        self.assertIn("$.proposed_change.changed_surface_count", message)

    def test_requires_a_timezone_on_created_at(self) -> None:
        document = load_example()
        document["created_at"] = "2026-07-27T16:30:00"

        with self.assertRaises(DocumentValidationError) as caught:
            parse_change_case(document)

        self.assertIn("timezone", str(caught.exception))

    def test_rejects_duplicate_hypothesis_components(self) -> None:
        document = load_example()
        document["attribution"]["hypotheses"][1]["component"] = "tool_description"

        with self.assertRaises(DocumentValidationError) as caught:
            parse_change_case(document)

        self.assertIn("components must be unique", str(caught.exception))

    def test_rejects_programmatic_nonfinite_numbers(self) -> None:
        document = load_example()
        document["attribution"]["hypotheses"][0]["confidence"] = math.nan

        with self.assertRaises(DocumentValidationError) as caught:
            parse_change_case(document)

        self.assertIn("finite number", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
