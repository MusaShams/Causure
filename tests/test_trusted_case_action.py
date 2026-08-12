"""Protected trusted case-generator composite Action orchestration tests."""

from __future__ import annotations

import contextlib
import io
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from causure.github_selection import GitHubChangedFile
from causure.onboarding import (
    configure_github_component,
    configure_trusted_adapter,
    initialize_project,
)
from causure.trusted_case_action_runner import main as trusted_action_main
from tests.helpers import PROJECT_ROOT
from tests.test_github_checks import _environment, _event
from tests.test_trusted_case_generation import _adapter_source


class TrustedCaseActionTests(unittest.TestCase):
    def _workspace(self, root: Path) -> tuple[Path, Path]:
        trusted = root / "trusted-control"
        candidate = root / "candidate"
        initialize_project(trusted, project_id="agent-one")
        configure_github_component(
            trusted,
            component_id="refund-tool",
            component="tool_description",
            paths=("agent/tools/**/*.py",),
            case_file="evidence/generated-refund.case.json",
        )
        configure_trusted_adapter(
            trusted,
            adapter_id="company-case-generator",
            kind="case_generator",
            entry_point="company_generator:generate",
            component_id="refund-tool",
        )
        adapter_directory = trusted / ".causure/adapters"
        (adapter_directory / "company_generator.py").write_text(
            _adapter_source(),
            encoding="utf-8",
        )
        (adapter_directory / "template.json").write_bytes(
            (
                PROJECT_ROOT / "examples/change-cases/approve-refund-tool-description.json"
            ).read_bytes()
        )
        component = candidate / "agent/tools/payments/refund.py"
        component.parent.mkdir(parents=True)
        component.write_text(
            "raise SystemExit('candidate checkout must remain data')\n",
            encoding="utf-8",
        )
        return trusted, candidate

    def _environment(self, root: Path, *, fork: bool = False) -> dict[str, str]:
        event_path = root / "event.json"
        event_path.write_bytes(_event(fork=fork))
        environment = _environment()
        environment.update(
            {
                "GITHUB_WORKSPACE": str(root),
                "GITHUB_EVENT_PATH": str(event_path),
                "GITHUB_OUTPUT": str(root / "github-output.txt"),
                "GITHUB_STEP_SUMMARY": str(root / "step-summary.md"),
                "CAUSURE_TRUSTED_PROJECT": "trusted-control",
                "CAUSURE_CANDIDATE_ROOT": "candidate",
                "CAUSURE_TRUSTED_OUTPUT_DIRECTORY": (".causure/trusted-generation"),
                "CAUSURE_GITHUB_TOKEN": "short-lived-token",
                "CAUSURE_TRUSTED_TIMEOUT_SECONDS": "15",
                "CAUSURE_TRUSTED_MAXIMUM_CASE_BYTES": "5242880",
            }
        )
        return environment

    def test_generates_the_case_for_exact_protected_and_candidate_heads(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            trusted, candidate = self._workspace(root)
            stderr = io.StringIO()
            with (
                patch.dict(os.environ, self._environment(root), clear=True),
                patch(
                    "causure.trusted_case_action_runner.discover_github_pull_request_files",
                    return_value=(GitHubChangedFile("agent/tools/payments/refund.py", None),),
                ),
                patch(
                    "causure.trusted_case_action_runner._git_head_sha",
                    side_effect=lambda checkout: (
                        "b" * 40 if Path(checkout).samefile(trusted) else "c" * 40
                    ),
                ),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = trusted_action_main()

            self.assertEqual(0, exit_code, stderr.getvalue())
            outputs = (root / "github-output.txt").read_text(encoding="utf-8")
            self.assertIn("selection-status=generated\n", outputs)
            self.assertIn("component-id=refund-tool\n", outputs)
            self.assertIn(
                "configured-case=evidence/generated-refund.case.json\n",
                outputs,
            )
            self.assertTrue((candidate / "evidence/generated-refund.case.json").is_file())
            self.assertTrue(
                (candidate / ".causure/trusted-generation/trusted-case-generation.json").is_file()
            )

    def test_fork_with_a_generator_fails_before_checkout_or_adapter_execution(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._workspace(root)
            stderr = io.StringIO()
            with (
                patch.dict(os.environ, self._environment(root, fork=True), clear=True),
                patch(
                    "causure.trusted_case_action_runner.discover_github_pull_request_files",
                    return_value=(GitHubChangedFile("agent/tools/payments/refund.py", None),),
                ),
                patch(
                    "causure.trusted_case_action_runner._git_head_sha",
                    side_effect=AssertionError("Git checkout must not be inspected"),
                ),
                patch(
                    "causure.trusted_case_action_runner.generate_configured_github_case",
                    side_effect=AssertionError("Adapter must not run"),
                ),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = trusted_action_main()

            self.assertEqual(2, exit_code)
            self.assertIn("fork pull requests", stderr.getvalue())
            self.assertFalse((root / "github-output.txt").exists())

    def test_no_configured_match_succeeds_without_running_an_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self._workspace(root)
            with (
                patch.dict(os.environ, self._environment(root), clear=True),
                patch(
                    "causure.trusted_case_action_runner.discover_github_pull_request_files",
                    return_value=(GitHubChangedFile("docs/readme.md", None),),
                ),
                patch(
                    "causure.trusted_case_action_runner.generate_configured_github_case",
                    side_effect=AssertionError("Adapter must not run"),
                ),
            ):
                exit_code = trusted_action_main()

            self.assertEqual(0, exit_code)
            outputs = (root / "github-output.txt").read_text(encoding="utf-8")
            self.assertIn("selection-status=no_match\n", outputs)
            self.assertIn("configured-case=not-created\n", outputs)


if __name__ == "__main__":
    unittest.main()
