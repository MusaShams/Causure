"""Input hardening and atomic output."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from causure.io import (
    InputDocumentError,
    atomic_write_bytes,
    atomic_write_text,
    parse_json_text,
    read_json_with_bytes,
)


class InputOutputTests(unittest.TestCase):
    def test_duplicate_json_keys_are_rejected(self) -> None:
        with self.assertRaisesRegex(InputDocumentError, "duplicate JSON key"):
            parse_json_text('{"decision": "approve", "decision": "reject"}', source="test")

    def test_invalid_json_includes_source_location(self) -> None:
        with self.assertRaisesRegex(InputDocumentError, r"bundle.json:1:"):
            parse_json_text('{"incomplete":', source="bundle.json")

    def test_nonfinite_json_numbers_are_rejected(self) -> None:
        for value in ("NaN", "Infinity", "-Infinity", "1e9999"):
            with self.subTest(value=value):
                with self.assertRaisesRegex(InputDocumentError, "non-finite"):
                    parse_json_text(f'{{"confidence": {value}}}', source="test")

    def test_atomic_write_replaces_existing_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "nested" / "report.md"
            atomic_write_text(destination, "first\n")
            atomic_write_text(destination, "second\n")

            self.assertEqual("second\n", destination.read_text(encoding="utf-8"))
            self.assertEqual([], list(destination.parent.glob("*.tmp")))

    def test_atomic_byte_write_preserves_exact_content(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "nested" / "artifact.bin"
            atomic_write_bytes(destination, b"\x00first\r\n")
            atomic_write_bytes(destination, b"\xffsecond\n")

            self.assertEqual(b"\xffsecond\n", destination.read_bytes())
            self.assertEqual([], list(destination.parent.glob("*.tmp")))

    def test_read_json_with_bytes_preserves_exact_artifact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "trace.json"
            raw = b'{\r\n  "resourceSpans": []\r\n}\r\n'
            source.write_bytes(raw)

            document, returned_bytes = read_json_with_bytes(source)

        self.assertEqual({"resourceSpans": []}, document)
        self.assertEqual(raw, returned_bytes)

    def test_custom_input_limit_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "large.json"
            source.write_text('{"value": "too large"}', encoding="utf-8")

            with self.assertRaisesRegex(InputDocumentError, "10-byte input limit"):
                read_json_with_bytes(source, max_bytes=10)


if __name__ == "__main__":
    unittest.main()
