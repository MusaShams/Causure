"""Guided trace-to-investigation workspace contracts."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from causure.cli import main
from causure.fixtures import parse_investigation_fixture_bytes
from causure.investigation_workspace import (
    InvestigationWorkspaceValidationError,
    load_verified_investigation_workspace,
)
from causure.trace_manifest import parse_trace_manifest
from tests.helpers import PROJECT_ROOT


class _TTYInput(io.StringIO):
    def isatty(self) -> bool:
        return True


def _snapshot(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class InvestigationWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.trace_path = PROJECT_ROOT / "examples" / "traces" / "refund-openinference-otlp.json"

    def test_investigate_writes_only_redacted_deterministic_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = root / "first"
            second = root / "second"
            for output in (first, second):
                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    exit_code = main(
                        [
                            "investigate",
                            str(self.trace_path),
                            "--output",
                            str(output),
                            "--yes",
                        ]
                    )
                self.assertEqual(0, exit_code)
                self.assertIn("Raw content included: NO", stdout.getvalue())
                self.assertIn("No raw trace content was written", stdout.getvalue())

            self.assertEqual(_snapshot(first), _snapshot(second))
            manifest_bytes = (first / "trace-manifest.json").read_bytes()
            fixture_bytes = (first / "investigation-fixture.json").read_bytes()
            manifest = parse_trace_manifest(json.loads(manifest_bytes))
            fixture = parse_investigation_fixture_bytes(fixture_bytes)
            selection = json.loads((first / "selection.json").read_text())
            verified = load_verified_investigation_workspace(first)

            self.assertFalse(manifest.redaction.raw_content_included)
            self.assertFalse(manifest.source.source_embedded)
            self.assertTrue(fixture.draft_only)
            self.assertFalse(fixture.gate_eligible)
            self.assertFalse(fixture.causal_claims_inferred)
            self.assertEqual(
                [fixture.candidate_clusters[0].cluster_id],
                selection["selected_cluster_ids"],
            )
            self.assertFalse(selection["source"]["raw_content_stored"])
            self.assertIsNone(verified.project_root)
            self.assertEqual(1, len(verified.selected_clusters))
            self.assertEqual(
                hashlib.sha256(manifest_bytes).hexdigest(),
                selection["manifest"]["sha256"],
            )
            self.assertEqual(
                hashlib.sha256(fixture_bytes).hexdigest(),
                selection["fixture"]["sha256"],
            )

            output_text = "\n".join(
                content.decode("utf-8") for content in _snapshot(first).values()
            )
            for secret in (
                "alice@example.com",
                "4111111111111111",
                "sk-" + "test-not-a-real-secret",
                "customer-session-123",
                "8675309",
                str(self.trace_path),
            ):
                with self.subTest(secret=secret):
                    self.assertNotIn(secret, output_text)

    def test_preview_only_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "must-not-exist"
            stdout = io.StringIO()
            with contextlib.redirect_stdout(stdout):
                exit_code = main(
                    [
                        "investigate",
                        str(self.trace_path),
                        "--output",
                        str(output),
                        "--preview-only",
                    ]
                )

            self.assertEqual(0, exit_code)
            self.assertIn("Nothing has been written yet", stdout.getvalue())
            self.assertFalse(output.exists())

    def test_initialized_project_uses_its_ignored_artifact_directory_by_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "project"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(0, main(["init", str(project), "--project-id", "agent-one"]))

            with contextlib.chdir(project), contextlib.redirect_stdout(io.StringIO()):
                exit_code = main(["investigate", str(self.trace_path), "--yes"])

            self.assertEqual(0, exit_code)
            artifact_root = project / ".causure/artifacts"
            workspaces = [path for path in artifact_root.iterdir() if path.is_dir()]
            self.assertEqual(1, len(workspaces))
            self.assertTrue((workspaces[0] / "investigation.md").is_file())
            self.assertEqual(
                project.resolve(),
                load_verified_investigation_workspace(workspaces[0]).project_root,
            )

    def test_workspace_verification_rejects_changed_artifact_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "investigation"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(
                    0,
                    main(
                        [
                            "investigate",
                            str(self.trace_path),
                            "--output",
                            str(output),
                            "--yes",
                        ]
                    ),
                )
            fixture_path = output / "investigation-fixture.json"
            fixture_path.write_bytes(fixture_path.read_bytes() + b"\n")

            with self.assertRaisesRegex(
                InvestigationWorkspaceValidationError,
                "byte count does not match",
            ):
                load_verified_investigation_workspace(output)

    def test_interactive_selection_previews_before_confirming(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "interactive"
            stdout = io.StringIO()
            with (
                patch("causure.cli.sys.stdin", _TTYInput("1\ny\n")),
                contextlib.redirect_stdout(stdout),
            ):
                exit_code = main(["investigate", str(self.trace_path), "--output", str(output)])

            self.assertEqual(0, exit_code)
            text = stdout.getvalue()
            self.assertLess(text.index("redaction preview"), text.index("Selected 1"))
            self.assertTrue((output / "investigation.md").is_file())

    def test_interactive_cancel_writes_nothing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "cancelled"
            stdout = io.StringIO()
            with (
                patch("causure.cli.sys.stdin", _TTYInput("q\n")),
                contextlib.redirect_stdout(stdout),
            ):
                exit_code = main(["investigate", str(self.trace_path), "--output", str(output)])

            self.assertEqual(0, exit_code)
            self.assertIn("Cancelled; no files were written", stdout.getvalue())
            self.assertFalse(output.exists())

    def test_noninteractive_use_requires_explicit_selection_and_confirmation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "noninteractive"
            stderr = io.StringIO()
            with (
                patch("causure.cli.sys.stdin", io.StringIO()),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = main(["investigate", str(self.trace_path), "--output", str(output)])

            self.assertEqual(2, exit_code)
            self.assertIn("--select all --yes", stderr.getvalue())
            self.assertFalse(output.exists())

    def test_invalid_selection_and_existing_output_fail_without_overwrite(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            invalid_output = root / "invalid"
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                invalid_exit = main(
                    [
                        "investigate",
                        str(self.trace_path),
                        "--select",
                        "2",
                        "--yes",
                        "--output",
                        str(invalid_output),
                    ]
                )
            self.assertEqual(2, invalid_exit)
            self.assertFalse(invalid_output.exists())

            existing = root / "existing"
            existing.mkdir()
            sentinel = existing / "keep.txt"
            sentinel.write_text("keep", encoding="utf-8")
            with (
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                collision_exit = main(
                    [
                        "investigate",
                        str(self.trace_path),
                        "--select",
                        "all",
                        "--yes",
                        "--output",
                        str(existing),
                    ]
                )
            self.assertEqual(2, collision_exit)
            self.assertEqual("keep", sentinel.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
