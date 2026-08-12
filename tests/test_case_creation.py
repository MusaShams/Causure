"""Guided no-manual-JSON change-case creation contracts."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from causure.case_creation import create_case_workspace
from causure.cli import main
from causure.constants import Decision, RecommendedAction
from causure.investigation_workspace import (
    load_verified_investigation_workspace,
)
from causure.io import load_change_case
from causure.models import parse_change_case
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


def _minimal_answers() -> str:
    answers = [
        "",  # generated case ID
        "",  # generated title
        "The agent may have denied an eligible refund.",
        "Eligible requests should receive the policy-approved refund.",
        "The selected trace metadata identifies the run for investigation.",
        "",  # medium severity
        "",  # unknown requirement status
        "",  # custom oracle
        "A company-owned refund-policy evaluator will decide correctness.",
        "",  # oracle is not yet independently confirmed
        "",  # one oracle reference
        "policy://refund/evaluator-planned",
        "",  # zero reproduction trials
        "",  # zero hypotheses
        "",  # proposed component: other
        "Clarify the smallest responsible harness component after attribution.",
        "The candidate should resolve eligible-refund failures without regressions.",
        "",  # one unaffected behavior
        "Ineligible refunds remain blocked.",
        "",  # zero known risks
        "",  # one changed surface
        "working-copy://refund-change",
        "",  # default no-change hypothesis
        "",  # zero evidence items against no change
        "",  # zero validation cases
        "",  # no metrics
    ]
    return "\n".join(answers) + "\n"


class CaseCreationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.trace_path = PROJECT_ROOT / "examples" / "traces" / "refund-openinference-otlp.json"

    def _initialized_investigation(self, root: Path) -> tuple[Path, Path]:
        project = root / "project"
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, main(["init", str(project), "--project-id", "refund-agent"]))
        with contextlib.chdir(project), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(0, main(["investigate", str(self.trace_path), "--yes"]))
        artifact_root = project / ".causure/artifacts"
        investigation = next(
            path for path in artifact_root.iterdir() if (path / "selection.json").is_file()
        )
        return project, investigation

    def test_guided_minimal_case_honestly_requests_missing_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project, investigation = self._initialized_investigation(root)
            stdout = io.StringIO()
            with (
                contextlib.chdir(project),
                patch("causure.cli.sys.stdin", _TTYInput(_minimal_answers())),
                contextlib.redirect_stdout(stdout),
            ):
                exit_code = main(["case", "create", str(investigation), "--yes"])

            self.assertEqual(0, exit_code)
            self.assertIn("Decision: NEEDS_EVIDENCE", stdout.getvalue())
            cases_root = project / ".causure/artifacts/cases"
            outputs = [path for path in cases_root.iterdir() if path.is_dir()]
            self.assertEqual(1, len(outputs))
            output = outputs[0]
            case = load_change_case(output / "change-case.json")
            review = json.loads((output / "review-result.json").read_text())
            source = json.loads((output / "case-source.json").read_text())
            verified = load_verified_investigation_workspace(investigation)

            self.assertEqual(Decision.NEEDS_EVIDENCE.value, review["decision"])
            self.assertEqual(
                RecommendedAction.COLLECT_EVIDENCE.value,
                review["recommended_action"],
            )
            self.assertEqual((), case.verification.reproduction_trials)
            self.assertEqual((), case.attribution.hypotheses)
            self.assertEqual((), case.null_hypothesis.evidence_against)
            self.assertEqual((), case.validation.cases)
            self.assertEqual(
                tuple(cluster.trace_ref for cluster in verified.selected_clusters),
                case.incident.source_refs,
            )
            self.assertFalse(source["raw_trace_content_stored"])
            self.assertEqual(
                hashlib.sha256(verified.selection_bytes).hexdigest(),
                source["investigation"]["selection_sha256"],
            )
            all_output = "\n".join(
                content.decode("utf-8") for content in _snapshot(output).values()
            )
            for raw_marker in (
                "alice@example.com",
                "4111111111111111",
                "sk-" + "test-not-a-real-secret",
                "customer-session-123",
            ):
                self.assertNotIn(raw_marker, all_output)

    def test_evidence_complete_case_can_produce_deterministic_approval(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, investigation_path = self._initialized_investigation(root)
            investigation = load_verified_investigation_workspace(investigation_path)
            document = json.loads(
                (
                    PROJECT_ROOT / "examples/change-cases/approve-refund-tool-description.json"
                ).read_text(encoding="utf-8")
            )
            document["case_id"] = "guided-approved-001"
            document["created_at"] = "2026-08-10T16:00:00Z"
            document["incident"]["source_refs"] = [
                cluster.trace_ref for cluster in investigation.selected_clusters
            ]
            case = parse_change_case(document)
            reviewed_at = datetime(2026, 8, 10, 16, 5, tzinfo=UTC)

            first = create_case_workspace(
                investigation,
                case,
                output_directory=root / "first",
                reviewed_at=reviewed_at,
            )
            second = create_case_workspace(
                investigation,
                case,
                output_directory=root / "second",
                reviewed_at=reviewed_at,
            )

            self.assertEqual(Decision.APPROVE, first.result.decision)
            self.assertEqual(RecommendedAction.PATCH, first.result.recommended_action)
            self.assertEqual(_snapshot(first.output_directory), _snapshot(second.output_directory))

    def test_case_creation_rejects_unbound_source_references(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _, investigation_path = self._initialized_investigation(root)
            investigation = load_verified_investigation_workspace(investigation_path)
            document = json.loads(
                (
                    PROJECT_ROOT / "examples/change-cases/approve-refund-tool-description.json"
                ).read_text(encoding="utf-8")
            )
            case = parse_change_case(document)

            with self.assertRaisesRegex(ValueError, "source references do not match"):
                create_case_workspace(
                    investigation,
                    case,
                    output_directory=root / "must-not-exist",
                )
            self.assertFalse((root / "must-not-exist").exists())

    def test_noninteractive_case_creation_fails_before_writing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project, investigation = self._initialized_investigation(root)
            output = root / "must-not-exist"
            stderr = io.StringIO()
            with (
                contextlib.chdir(project),
                patch("causure.cli.sys.stdin", io.StringIO()),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = main(
                    [
                        "case",
                        "create",
                        str(investigation),
                        "--output",
                        str(output),
                    ]
                )

            self.assertEqual(2, exit_code)
            self.assertIn("requires an interactive terminal", stderr.getvalue())
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
