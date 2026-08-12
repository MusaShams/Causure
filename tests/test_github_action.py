"""One-step composite GitHub Action orchestration tests."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

from causure.constants import Decision
from causure.github_action import run_github_action
from causure.github_action_runner import main as action_main
from causure.github_checks import (
    GitHubHTTPResponse,
    parse_github_check_run_receipt_bytes,
    parse_github_check_run_request_bytes,
)
from causure.github_review import (
    parse_github_review_publication_bytes,
    parse_github_review_verification_bytes,
)
from causure.github_selection import GitHubChangedFile
from causure.onboarding import configure_github_component, initialize_project
from tests.helpers import PROJECT_ROOT, load_needs_evidence_example
from tests.test_github_checks import _environment, _event


class RecordingTransport:
    def __init__(self) -> None:
        self.calls = 0
        self.headers: dict[str, str] = {}

    def post(self, url, *, headers, body, timeout_seconds):
        self.calls += 1
        self.headers = dict(headers)
        request = json.loads(body)
        response = {
            "id": 70001,
            "name": request["name"],
            "head_sha": request["head_sha"],
            "status": request["status"],
            "conclusion": request["conclusion"],
            "external_id": request["external_id"],
            "html_url": "https://github.com/acme/agent-harness/runs/70001",
        }
        return GitHubHTTPResponse(
            status_code=201,
            headers={"content-type": "application/json"},
            body=json.dumps(response).encode("utf-8"),
        )


class GitHubActionTests(unittest.TestCase):
    run_at = datetime(2026, 8, 10, 21, 0, tzinfo=UTC)

    def _environment_with_event(self, root: Path, *, fork: bool = False) -> dict[str, str]:
        event_path = root / "event.json"
        event_path.write_bytes(_event(fork=fork))
        environment = _environment()
        environment["GITHUB_EVENT_PATH"] = str(event_path)
        return environment

    def test_same_repository_auto_mode_writes_complete_chain_and_check_receipt(self) -> None:
        case_path = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            summary_path = root / "step-summary.md"
            transport = RecordingTransport()
            run = run_github_action(
                case_path,
                policy_path=None,
                component_path="agent/tools/refund.py",
                output_directory=root / "output",
                environment=self._environment_with_event(root),
                publish_mode="auto",
                token="test-token",
                step_summary_path=summary_path,
                run_at=self.run_at,
                transport=transport,
            )

            self.assertEqual(Decision.APPROVE, run.decision)
            self.assertTrue(run.check_published)
            self.assertEqual("published", run.check_publication_status)
            self.assertEqual(70001, run.check_run_id)
            self.assertEqual(1, transport.calls)
            self.assertEqual("Bearer test-token", transport.headers["Authorization"])
            self.assertIsNotNone(run.artifacts.check_receipt)
            parse_github_review_publication_bytes(run.artifacts.publication.read_bytes())
            parse_github_review_verification_bytes(run.artifacts.verification.read_bytes())
            parse_github_check_run_request_bytes(run.artifacts.check_request.read_bytes())
            parse_github_check_run_receipt_bytes(run.artifacts.check_receipt.read_bytes())
            self.assertIn("Causure evidence gate", summary_path.read_text(encoding="utf-8"))
            combined = b"".join(
                path.read_bytes()
                for path in (
                    run.artifacts.result,
                    run.artifacts.report,
                    run.artifacts.publication,
                    run.artifacts.verification,
                    run.artifacts.check_request,
                    run.artifacts.check_summary,
                    run.artifacts.check_receipt,
                )
            )
            self.assertNotIn(b"test-token", combined)

    def test_same_repository_needs_evidence_publishes_complete_chain(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            case_path = root / "needs-evidence.case.json"
            case_path.write_text(
                json.dumps(load_needs_evidence_example(), indent=2) + "\n",
                encoding="utf-8",
            )
            transport = RecordingTransport()
            run = run_github_action(
                case_path,
                policy_path=None,
                component_path="agent/tools/refund.py",
                output_directory=root / "output",
                environment=self._environment_with_event(root),
                publish_mode="auto",
                token="test-token",
                run_at=self.run_at,
                transport=transport,
            )

            self.assertEqual(Decision.NEEDS_EVIDENCE, run.decision)
            self.assertTrue(run.check_published)
            self.assertEqual(1, transport.calls)
            request = parse_github_check_run_request_bytes(run.artifacts.check_request.read_bytes())
            self.assertEqual("action_required", request.conclusion)
            self.assertIsNotNone(run.artifacts.check_receipt)
            parse_github_review_publication_bytes(run.artifacts.publication.read_bytes())
            parse_github_review_verification_bytes(run.artifacts.verification.read_bytes())

    def test_fork_auto_mode_is_offline_secretless_and_keeps_stable_job_decision(self) -> None:
        case_path = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = RecordingTransport()
            run = run_github_action(
                case_path,
                policy_path=None,
                component_path="agent/tools/refund.py",
                output_directory=root / "output",
                environment=self._environment_with_event(root, fork=True),
                publish_mode="auto",
                token="",
                run_at=self.run_at,
                transport=transport,
            )

            self.assertEqual(Decision.APPROVE, run.decision)
            self.assertFalse(run.check_published)
            self.assertEqual("fork_skipped", run.check_publication_status)
            self.assertEqual(0, transport.calls)
            self.assertIsNone(run.artifacts.check_receipt)
            request = parse_github_check_run_request_bytes(run.artifacts.check_request.read_bytes())
            self.assertTrue(request.is_fork)

    def test_required_fork_and_missing_same_repository_token_fail_after_local_evidence(
        self,
    ) -> None:
        case_path = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ValueError, "unavailable for fork"):
                run_github_action(
                    case_path,
                    policy_path=None,
                    component_path="agent/tools/refund.py",
                    output_directory=root / "fork",
                    environment=self._environment_with_event(root, fork=True),
                    publish_mode="required",
                    run_at=self.run_at,
                )
            self.assertTrue((root / "fork" / "github-check-run-summary.md").is_file())

            with self.assertRaisesRegex(ValueError, "requires github-token"):
                run_github_action(
                    case_path,
                    policy_path=None,
                    component_path="agent/tools/refund.py",
                    output_directory=root / "same",
                    environment=self._environment_with_event(root),
                    publish_mode="auto",
                    token="",
                    run_at=self.run_at,
                )
            self.assertTrue((root / "same" / "github-check-run-request.json").is_file())

    def test_disabled_mode_reviews_rejection_without_network_and_refuses_overwrite(self) -> None:
        case_path = PROJECT_ROOT / "examples" / "change-cases" / "reject-overbroad-prompt.json"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            transport = RecordingTransport()
            output = root / "output"
            run = run_github_action(
                case_path,
                policy_path=None,
                component_path="agent/prompts/system.md",
                output_directory=output,
                environment=self._environment_with_event(root),
                publish_mode="disabled",
                token="",
                run_at=self.run_at,
                transport=transport,
            )
            self.assertEqual(Decision.REJECT, run.decision)
            self.assertEqual("disabled", run.check_publication_status)
            self.assertEqual(0, transport.calls)
            request = parse_github_check_run_request_bytes(run.artifacts.check_request.read_bytes())
            self.assertEqual("failure", request.conclusion)
            self.assertGreater(len(request.findings), 0)

            with self.assertRaisesRegex(ValueError, "refusing to overwrite"):
                run_github_action(
                    case_path,
                    policy_path=None,
                    component_path="agent/prompts/system.md",
                    output_directory=output,
                    environment=self._environment_with_event(root),
                    publish_mode="disabled",
                    run_at=self.run_at,
                )

    def test_environment_runner_writes_outputs_and_returns_gate_status(self) -> None:
        source_case = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            shutil.copy2(source_case, workspace / "case.json")
            event_path = workspace / "event.json"
            event_path.write_bytes(_event())
            step_summary = workspace / "step-summary.md"
            github_output = workspace / "github-output.txt"
            environment = _environment()
            environment.update(
                {
                    "GITHUB_WORKSPACE": str(workspace),
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GITHUB_STEP_SUMMARY": str(step_summary),
                    "GITHUB_OUTPUT": str(github_output),
                    "CAUSURE_CASE": "case.json",
                    "CAUSURE_COMPONENT_PATH": "agent/tools/refund.py",
                    "CAUSURE_POLICY": "",
                    "CAUSURE_OUTPUT_DIRECTORY": ".causure/github",
                    "CAUSURE_PUBLISH_CHECK": "disabled",
                    "CAUSURE_GITHUB_TOKEN": "",
                    "CAUSURE_ALLOW_CONDITIONAL": "false",
                    "CAUSURE_MAXIMUM_AGE_SECONDS": "3600",
                    "CAUSURE_TIMEOUT_SECONDS": "15",
                }
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.dict(os.environ, environment, clear=True),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = action_main()

            self.assertEqual(0, exit_code)
            self.assertEqual("", stderr.getvalue())
            self.assertIn("APPROVE", stdout.getvalue())
            outputs = github_output.read_text(encoding="utf-8")
            self.assertIn("decision=approve\n", outputs)
            self.assertIn("check-published=false\n", outputs)
            self.assertIn("check-publication-status=disabled\n", outputs)
            self.assertIn("check-receipt=not-published\n", outputs)
            self.assertIn("Causure evidence gate", step_summary.read_text(encoding="utf-8"))

    def test_dependabot_auto_mode_preserves_the_job_gate_without_a_check_write(self) -> None:
        source_case = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            shutil.copy2(source_case, workspace / "case.json")
            event_path = workspace / "event.json"
            event_path.write_bytes(_event())
            github_output = workspace / "github-output.txt"
            environment = _environment()
            environment.update(
                {
                    "GITHUB_ACTOR": "dependabot[bot]",
                    "GITHUB_WORKSPACE": str(workspace),
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GITHUB_STEP_SUMMARY": str(workspace / "step-summary.md"),
                    "GITHUB_OUTPUT": str(github_output),
                    "CAUSURE_CASE": "case.json",
                    "CAUSURE_COMPONENT_PATH": "agent/tools/refund.py",
                    "CAUSURE_POLICY": "",
                    "CAUSURE_OUTPUT_DIRECTORY": ".causure/github",
                    "CAUSURE_PUBLISH_CHECK": "auto",
                    "CAUSURE_GITHUB_TOKEN": "read-only-token",
                    "CAUSURE_ALLOW_CONDITIONAL": "false",
                    "CAUSURE_MAXIMUM_AGE_SECONDS": "3600",
                    "CAUSURE_TIMEOUT_SECONDS": "15",
                }
            )
            with (
                patch.dict(os.environ, environment, clear=True),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                exit_code = action_main()

            self.assertEqual(0, exit_code)
            outputs = github_output.read_text(encoding="utf-8")
            self.assertIn("decision=approve\n", outputs)
            self.assertIn("check-published=false\n", outputs)
            self.assertIn("check-publication-status=disabled\n", outputs)

    def test_environment_runner_automatically_selects_the_configured_case(self) -> None:
        source_case = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            initialize_project(workspace, project_id="agent-one")
            evidence = workspace / "evidence"
            evidence.mkdir()
            shutil.copy2(source_case, evidence / "refund.case.json")
            configure_github_component(
                workspace,
                component_id="refund-tool",
                component="tool_description",
                paths=("agent/tools/**/*.py",),
                case_file="evidence/refund.case.json",
                artifact_retention_days=21,
            )
            event_path = workspace / "event.json"
            event_path.write_bytes(_event())
            github_output = workspace / "github-output.txt"
            environment = _environment()
            environment.update(
                {
                    "GITHUB_WORKSPACE": str(workspace),
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GITHUB_STEP_SUMMARY": str(workspace / "step-summary.md"),
                    "GITHUB_OUTPUT": str(github_output),
                    "CAUSURE_CASE": "",
                    "CAUSURE_COMPONENT_PATH": "",
                    "CAUSURE_CONFIG": ".causure/config.json",
                    "CAUSURE_POLICY": "",
                    "CAUSURE_OUTPUT_DIRECTORY": ".causure/github",
                    "CAUSURE_PUBLISH_CHECK": "disabled",
                    "CAUSURE_GITHUB_TOKEN": "short-lived-token",
                    "CAUSURE_ALLOW_CONDITIONAL": "false",
                    "CAUSURE_MAXIMUM_AGE_SECONDS": "3600",
                    "CAUSURE_TIMEOUT_SECONDS": "15",
                }
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.dict(os.environ, environment, clear=True),
                patch(
                    "causure.github_action_runner.discover_github_pull_request_files",
                    return_value=(GitHubChangedFile("agent/tools/payments/refund.py", None),),
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = action_main()

            self.assertEqual(0, exit_code, stderr.getvalue())
            outputs = github_output.read_text(encoding="utf-8")
            self.assertIn("selection-mode=configured\n", outputs)
            self.assertIn("selection-status=reviewed\n", outputs)
            self.assertIn("component-id=refund-tool\n", outputs)
            self.assertIn("selected-case=evidence/refund.case.json\n", outputs)
            self.assertIn(
                "selected-component-path=agent/tools/payments/refund.py\n",
                outputs,
            )
            self.assertIn("artifact-retention-days=21\n", outputs)
            self.assertTrue((workspace / ".causure/github/review-result.json").is_file())

    def test_environment_runner_supports_a_confined_nested_repository_root(self) -> None:
        source_case = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            github_workspace = Path(directory)
            repository = github_workspace / "candidate"
            initialize_project(repository, project_id="agent-one")
            evidence = repository / "evidence"
            evidence.mkdir()
            shutil.copy2(source_case, evidence / "refund.case.json")
            configure_github_component(
                repository,
                component_id="refund-tool",
                component="tool_description",
                paths=("agent/tools/**/*.py",),
                case_file="evidence/refund.case.json",
            )
            event_path = github_workspace / "event.json"
            event_path.write_bytes(_event())
            environment = _environment()
            environment.update(
                {
                    "GITHUB_WORKSPACE": str(github_workspace),
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GITHUB_STEP_SUMMARY": str(github_workspace / "step-summary.md"),
                    "GITHUB_OUTPUT": str(github_workspace / "github-output.txt"),
                    "CAUSURE_REPOSITORY_ROOT": "candidate",
                    "CAUSURE_CASE": "",
                    "CAUSURE_COMPONENT_PATH": "",
                    "CAUSURE_CONFIG": ".causure/config.json",
                    "CAUSURE_POLICY": "",
                    "CAUSURE_OUTPUT_DIRECTORY": ".causure/github",
                    "CAUSURE_PUBLISH_CHECK": "disabled",
                    "CAUSURE_GITHUB_TOKEN": "short-lived-token",
                    "CAUSURE_ALLOW_CONDITIONAL": "false",
                    "CAUSURE_MAXIMUM_AGE_SECONDS": "3600",
                    "CAUSURE_TIMEOUT_SECONDS": "15",
                }
            )
            with (
                patch.dict(os.environ, environment, clear=True),
                patch(
                    "causure.github_action_runner.discover_github_pull_request_files",
                    return_value=(GitHubChangedFile("agent/tools/payments/refund.py", None),),
                ),
                contextlib.redirect_stdout(io.StringIO()),
                contextlib.redirect_stderr(io.StringIO()),
            ):
                exit_code = action_main()

            self.assertEqual(0, exit_code)
            self.assertTrue((repository / ".causure/github/review-result.json").is_file())

    def test_environment_runner_passes_when_no_configured_component_changed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            initialize_project(workspace, project_id="agent-one")
            configure_github_component(
                workspace,
                component_id="refund-tool",
                component="tool_description",
                paths=("agent/tools/**/*.py",),
                case_file="evidence/refund.case.json",
            )
            event_path = workspace / "event.json"
            event_path.write_bytes(_event())
            github_output = workspace / "github-output.txt"
            step_summary = workspace / "step-summary.md"
            environment = _environment()
            environment.update(
                {
                    "GITHUB_WORKSPACE": str(workspace),
                    "GITHUB_EVENT_PATH": str(event_path),
                    "GITHUB_STEP_SUMMARY": str(step_summary),
                    "GITHUB_OUTPUT": str(github_output),
                    "CAUSURE_CASE": "",
                    "CAUSURE_COMPONENT_PATH": "",
                    "CAUSURE_CONFIG": ".causure/config.json",
                    "CAUSURE_POLICY": "",
                    "CAUSURE_OUTPUT_DIRECTORY": ".causure/github",
                    "CAUSURE_PUBLISH_CHECK": "disabled",
                    "CAUSURE_GITHUB_TOKEN": "short-lived-token",
                    "CAUSURE_ALLOW_CONDITIONAL": "false",
                    "CAUSURE_MAXIMUM_AGE_SECONDS": "3600",
                    "CAUSURE_TIMEOUT_SECONDS": "15",
                }
            )
            stdout = io.StringIO()
            stderr = io.StringIO()
            with (
                patch.dict(os.environ, environment, clear=True),
                patch(
                    "causure.github_action_runner.discover_github_pull_request_files",
                    return_value=(GitHubChangedFile("docs/readme.md", None),),
                ),
                contextlib.redirect_stdout(stdout),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = action_main()

            self.assertEqual(0, exit_code, stderr.getvalue())
            outputs = github_output.read_text(encoding="utf-8")
            self.assertIn("decision=not_applicable\n", outputs)
            self.assertIn("selection-status=no_match\n", outputs)
            self.assertIn("result=not-created\n", outputs)
            self.assertIn("Not applicable", step_summary.read_text(encoding="utf-8"))
            self.assertFalse((workspace / ".causure/github").exists())

    def test_environment_runner_rejects_empty_github_component_configuration(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            initialize_project(workspace, project_id="agent-one")
            environment = {
                "GITHUB_WORKSPACE": str(workspace),
                "CAUSURE_CASE": "",
                "CAUSURE_COMPONENT_PATH": "",
                "CAUSURE_CONFIG": ".causure/config.json",
            }
            stderr = io.StringIO()
            with (
                patch.dict(os.environ, environment, clear=True),
                patch(
                    "causure.github_action_runner.discover_github_pull_request_files",
                    side_effect=AssertionError("GitHub must not be queried"),
                ),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = action_main()

            self.assertEqual(2, exit_code)
            self.assertIn("at least one GitHub component", stderr.getvalue())

    def test_environment_runner_rejects_workspace_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            environment = {
                "GITHUB_WORKSPACE": str(workspace),
                "CAUSURE_CASE": "../outside.json",
            }
            stderr = io.StringIO()
            with (
                patch.dict(os.environ, environment, clear=True),
                contextlib.redirect_stderr(stderr),
            ):
                exit_code = action_main()

            self.assertEqual(2, exit_code)
            self.assertIn("must stay within GITHUB_WORKSPACE", stderr.getvalue())

    def test_isolated_bootstrap_ignores_caller_package_shadowing(self) -> None:
        source_case = (
            PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
        )
        runner = PROJECT_ROOT / "scripts" / "run_github_action.py"
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            shutil.copy2(source_case, workspace / "case.json")
            event_path = workspace / "event.json"
            event_path.write_bytes(_event())
            (workspace / "causure.py").write_text(
                "raise SystemExit('caller package shadowed the Action')\n",
                encoding="utf-8",
            )
            environment = {
                **os.environ,
                **_environment(),
                "GITHUB_WORKSPACE": str(workspace),
                "GITHUB_EVENT_PATH": str(event_path),
                "GITHUB_STEP_SUMMARY": str(workspace / "step-summary.md"),
                "GITHUB_OUTPUT": str(workspace / "github-output.txt"),
                "CAUSURE_CASE": "case.json",
                "CAUSURE_COMPONENT_PATH": "agent/tools/refund.py",
                "CAUSURE_POLICY": "",
                "CAUSURE_OUTPUT_DIRECTORY": "causure-evidence",
                "CAUSURE_PUBLISH_CHECK": "disabled",
                "CAUSURE_GITHUB_TOKEN": "",
                "CAUSURE_ALLOW_CONDITIONAL": "false",
                "CAUSURE_MAXIMUM_AGE_SECONDS": "3600",
                "CAUSURE_TIMEOUT_SECONDS": "15",
            }

            completed = subprocess.run(
                [sys.executable, "-I", str(runner)],
                cwd=workspace,
                env=environment,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertNotIn("caller package shadowed", completed.stdout + completed.stderr)
            self.assertIn("decision=approve", (workspace / "github-output.txt").read_text())
            self.assertTrue(
                (workspace / "causure-evidence" / "github-check-run-request.json").is_file()
            )


if __name__ == "__main__":
    unittest.main()
