"""Tests for the deterministic public-snapshot release boundary."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from scripts.check_public_release import (
    LICENSE_FILES,
    REQUIRED_FILES,
    REQUIRED_GITIGNORE_PATTERNS,
    collect_candidate_paths,
    evaluate_candidate,
)
from tests.helpers import PROJECT_ROOT

_PINNED_CHECKOUT = "3d3c42e5aac5ba805825da76410c181273ba90b1"


def _workflow(ref: str = _PINNED_CHECKOUT) -> str:
    return f"""name: fixture
on:
  pull_request:
permissions:
  contents: read
jobs:
  fixture:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@{ref}
"""


def _action(ref: str = _PINNED_CHECKOUT) -> str:
    return f"""name: fixture
inputs:
  github-token:
    required: true
  config:
    required: false
  repository-root:
    required: false
runs:
  using: composite
  steps:
    - uses: actions/setup-python@{ref}
    - shell: pwsh
      env:
        CAUSURE_CONFIG: ${{{{ inputs.config }}}}
        CAUSURE_REPOSITORY_ROOT: ${{{{ inputs.repository-root }}}}
        CAUSURE_GITHUB_TOKEN: ${{{{ inputs.github-token }}}}
      run: |
        $runner = 'runner.py'
        python -I $runner
"""


def _trusted_action(ref: str = _PINNED_CHECKOUT) -> str:
    return f"""name: trusted fixture
inputs:
  github-token:
    required: true
  trusted-project:
    required: true
  candidate-root:
    required: true
  output-directory:
    required: true
runs:
  using: composite
  steps:
    - uses: actions/setup-python@{ref}
    - shell: pwsh
      env:
        CAUSURE_TRUSTED_PROJECT: ${{{{ inputs.trusted-project }}}}
        CAUSURE_CANDIDATE_ROOT: ${{{{ inputs.candidate-root }}}}
        CAUSURE_TRUSTED_OUTPUT_DIRECTORY: ${{{{ inputs.output-directory }}}}
        CAUSURE_GITHUB_TOKEN: ${{{{ inputs.github-token }}}}
      run: |
        $runner = 'runner.py'
        python -I $runner
"""


def _write_ready_candidate(root: Path) -> list[str]:
    for relative_path in sorted(REQUIRED_FILES):
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        if relative_path.startswith(".github/workflows/"):
            contents = _workflow()
        elif relative_path == "action.yml":
            contents = _action()
        elif relative_path == "trusted-case-generator/action.yml":
            contents = _trusted_action()
        elif relative_path == ".gitignore":
            contents = "\n".join(REQUIRED_GITIGNORE_PATTERNS) + "\n"
        else:
            contents = f"fixture for {relative_path}\n"
        path.write_text(contents, encoding="utf-8")

    license_path = root / "LICENSE"
    license_path.write_text("fixture license\n", encoding="utf-8")
    return [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()]


class PublicReleaseTests(unittest.TestCase):
    def test_security_workflows_fail_closed_until_the_repository_is_public(self) -> None:
        guard = "if: ${{ github.event.repository.visibility == 'public' }}"

        for relative_path in (
            ".github/workflows/codeql.yml",
            ".github/workflows/dependency-review.yml",
        ):
            with self.subTest(workflow=relative_path):
                contents = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
                self.assertIn(guard, contents)

    def test_public_text_files_have_canonical_lf_checkouts(self) -> None:
        attributes = (PROJECT_ROOT / ".gitattributes").read_text(encoding="utf-8")

        self.assertIn("* text=auto eol=lf\n", attributes)

    def test_complete_candidate_is_ready(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            candidate_paths = _write_ready_candidate(root)

            result = evaluate_candidate(root, candidate_paths)

        self.assertEqual("ready", result["status"])
        self.assertTrue(result["ready"])
        self.assertEqual([], result["errors"])
        self.assertEqual([], result["blockers"])

    def test_missing_license_remains_an_explicit_blocker(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            candidate_paths = _write_ready_candidate(root)
            license_name = next(iter(LICENSE_FILES & set(candidate_paths)))
            (root / license_name).unlink()
            candidate_paths.remove(license_name)

            result = evaluate_candidate(root, candidate_paths)

        self.assertEqual("blocked_license", result["status"])
        self.assertFalse(result["ready"])
        self.assertEqual(["license_missing"], [item["code"] for item in result["blockers"]])

    def test_tfvc_metadata_is_rejected_if_selected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            candidate_paths = _write_ready_candidate(root)
            metadata_path = root / "$tf" / "workspace.db"
            metadata_path.parent.mkdir()
            metadata_path.write_text("local metadata", encoding="utf-8")
            candidate_paths.append("$tf/workspace.db")

            result = evaluate_candidate(root, candidate_paths)

        self.assertIn("forbidden_path", [item["code"] for item in result["errors"]])

    def test_possible_api_key_is_rejected_without_echoing_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            candidate_paths = _write_ready_candidate(root)
            possible_secret = "sk-" + ("A" * 32)
            suspect_path = root / "notes.txt"
            suspect_path.write_text(f"token={possible_secret}\n", encoding="utf-8")
            candidate_paths.append("notes.txt")

            result = evaluate_candidate(root, candidate_paths)

        secret_findings = [item for item in result["errors"] if item["code"] == "secret_pattern"]
        self.assertEqual(1, len(secret_findings))
        self.assertNotIn(possible_secret, str(secret_findings))

    def test_machine_specific_user_home_is_rejected_without_echoing_it(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            candidate_paths = _write_ready_candidate(root)
            private_segment = "private-machine-user"
            suspect_path = root / "setup.txt"
            suspect_path.write_text(
                f"workspace=C:\\Users\\{private_segment}\\source\\project\n",
                encoding="utf-8",
            )
            candidate_paths.append("setup.txt")

            result = evaluate_candidate(root, candidate_paths)

        path_findings = [item for item in result["errors"] if item["code"] == "local_user_path"]
        self.assertEqual(1, len(path_findings))
        self.assertNotIn(private_segment, str(path_findings))

    def test_symbolic_action_ref_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            candidate_paths = _write_ready_candidate(root)
            workflow_path = root / ".github" / "workflows" / "ci.yml"
            workflow_path.write_text(_workflow("v6"), encoding="utf-8")

            result = evaluate_candidate(root, candidate_paths)

        self.assertIn(
            "workflow_action_unpinned",
            [item["code"] for item in result["errors"]],
        )

    def test_composite_action_requires_pins_explicit_token_and_isolated_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            candidate_paths = _write_ready_candidate(root)
            action_path = root / "action.yml"
            action_path.write_text(
                _action("v6")
                .replace("${{ inputs.config }}", "config.json")
                .replace("${{ inputs.repository-root }}", "candidate")
                .replace("${{ inputs.github-token }}", "${{ secrets.GITHUB_TOKEN }}")
                .replace("python -I $runner", "python $runner"),
                encoding="utf-8",
            )

            result = evaluate_candidate(root, candidate_paths)

        codes = {item["code"] for item in result["errors"]}
        self.assertIn("action_dependency_unpinned", codes)
        self.assertIn("action_secret_context", codes)
        self.assertIn("action_config_boundary", codes)
        self.assertIn("action_repository_boundary", codes)
        self.assertIn("action_token_boundary", codes)
        self.assertIn("action_python_not_isolated", codes)

    def test_trusted_action_requires_pins_explicit_roots_and_isolated_python(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            candidate_paths = _write_ready_candidate(root)
            action_path = root / "trusted-case-generator" / "action.yml"
            action_path.write_text(
                _trusted_action("v6")
                .replace("${{ inputs.trusted-project }}", "trusted-control")
                .replace("${{ inputs.candidate-root }}", "candidate")
                .replace("${{ inputs.github-token }}", "${{ secrets.GITHUB_TOKEN }}")
                .replace("python -I $runner", "python $runner"),
                encoding="utf-8",
            )

            result = evaluate_candidate(root, candidate_paths)

        codes = {item["code"] for item in result["errors"]}
        self.assertIn("action_dependency_unpinned", codes)
        self.assertIn("action_secret_context", codes)
        self.assertIn("action_trusted_generation_boundary", codes)
        self.assertIn("action_token_boundary", codes)
        self.assertIn("action_python_not_isolated", codes)

    def test_filesystem_source_excludes_local_source_control_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            _write_ready_candidate(root)
            git_metadata = root / ".git" / "config"
            git_metadata.parent.mkdir()
            git_metadata.write_text("fixture", encoding="utf-8")
            tfvc_metadata = root / "$tf" / "workspace.db"
            tfvc_metadata.parent.mkdir()
            tfvc_metadata.write_text("fixture", encoding="utf-8")

            candidate_paths, source = collect_candidate_paths(root, "filesystem")

        self.assertEqual("filesystem", source)
        self.assertNotIn(".git/config", candidate_paths)
        self.assertNotIn("$tf/workspace.db", candidate_paths)

    def test_current_project_is_ready_for_owner_controlled_publication(self) -> None:
        candidate_paths, source = collect_candidate_paths(PROJECT_ROOT, "auto")

        result = evaluate_candidate(
            PROJECT_ROOT,
            candidate_paths,
            candidate_source=source,
        )

        self.assertEqual([], result["errors"])
        self.assertEqual("ready", result["status"])
        self.assertTrue(result["ready"])
        self.assertEqual([], result["blockers"])


if __name__ == "__main__":
    unittest.main()
