"""Environment-only entry point for the protected case-generator Action."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from causure.adapters import MAX_CASE_GENERATION_BYTES, CaseGenerationBudget
from causure.errors import DocumentValidationError
from causure.github_review import github_context_from_environment
from causure.github_selection import (
    DEFAULT_GITHUB_PULL_TIMEOUT_SECONDS,
    discover_github_pull_request_files,
    select_configured_github_change,
)
from causure.io import InputDocumentError, read_json
from causure.onboarding import (
    PROJECT_CONFIG_NAME,
    PROJECT_DIRECTORY_NAME,
    parse_project_configuration,
)
from causure.runner import AdapterRunError
from causure.trusted_case_generation import (
    generate_configured_github_case,
    render_trusted_case_generation_summary,
)


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value or value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError(f"required trusted Action input is unset or invalid: {name}")
    return value


def _workspace_directory(workspace: Path, value: str, *, role: str) -> Path:
    candidate = Path(value)
    resolved = (
        (workspace / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    )
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{role} must stay within GITHUB_WORKSPACE") from exc
    if not resolved.is_dir():
        raise ValueError(f"{role} must identify an existing directory")
    return resolved


def _workspace_output(candidate_root: Path, value: str) -> Path:
    path = Path(value)
    resolved = (candidate_root / path).resolve() if not path.is_absolute() else path.resolve()
    try:
        resolved.relative_to(candidate_root)
    except ValueError as exc:
        raise ValueError("output-directory must stay within the candidate checkout") from exc
    return resolved


def _git_head_sha(checkout: Path) -> str:
    executable = shutil.which("git")
    if executable is None:
        raise ValueError("git is required to verify the protected and candidate checkouts")
    environment = {
        key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
        }
    )
    try:
        process = subprocess.run(
            [executable, "-C", str(checkout), "rev-parse", "--verify", "HEAD^{commit}"],
            check=False,
            capture_output=True,
            env=environment,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValueError(f"could not verify checkout identity: {type(exc).__name__}") from exc
    if process.returncode != 0:
        raise ValueError("checkout does not contain a verifiable Git HEAD")
    try:
        value = process.stdout.decode("ascii").strip().lower()
    except UnicodeDecodeError as exc:
        raise ValueError("checkout Git HEAD was not ASCII") from exc
    if len(value) not in {40, 64} or any(
        character not in "0123456789abcdef" for character in value
    ):
        raise ValueError("checkout Git HEAD was not a full commit SHA")
    return value


def _append_outputs(path: Path, values: dict[str, str]) -> None:
    for key, value in values.items():
        if not value or "\n" in value or "\r" in value:
            raise ValueError(f"trusted Action output {key} must be a non-empty single line")
    try:
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            for key, value in values.items():
                stream.write(f"{key}={value}\n")
    except OSError as exc:
        raise ValueError(f"could not write GITHUB_OUTPUT: {type(exc).__name__}") from exc


def _append_summary(path: Path, content: str) -> None:
    try:
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("## Causure trusted case generation\n\n")
            stream.write(content)
            stream.write("\n")
    except OSError as exc:
        raise ValueError(f"could not append GITHUB_STEP_SUMMARY: {type(exc).__name__}") from exc


def main() -> int:
    """Generate a case only when the exact trusted and candidate checkouts agree."""

    token = ""
    try:
        workspace = Path(_required_environment("GITHUB_WORKSPACE")).resolve()
        if not workspace.is_dir():
            raise ValueError("GITHUB_WORKSPACE must identify an existing directory")
        trusted_project = _workspace_directory(
            workspace,
            _required_environment("CAUSURE_TRUSTED_PROJECT"),
            role="trusted-project",
        )
        candidate_root = _workspace_directory(
            workspace,
            _required_environment("CAUSURE_CANDIDATE_ROOT"),
            role="candidate-root",
        )
        if trusted_project == candidate_root:
            raise ValueError("trusted-project and candidate-root must be separate checkouts")
        output_directory = _workspace_output(
            candidate_root,
            _required_environment("CAUSURE_TRUSTED_OUTPUT_DIRECTORY"),
        )
        configuration_path = trusted_project / PROJECT_DIRECTORY_NAME / PROJECT_CONFIG_NAME
        configuration = parse_project_configuration(read_json(configuration_path))
        if not configuration.github.components:
            raise ValueError("trusted project has no configured GitHub components")

        pull_request, _ = github_context_from_environment(os.environ)
        token = _required_environment("CAUSURE_GITHUB_TOKEN")
        timeout_seconds = float(
            os.environ.get(
                "CAUSURE_TRUSTED_TIMEOUT_SECONDS",
                str(DEFAULT_GITHUB_PULL_TIMEOUT_SECONDS),
            )
        )
        changed_files = discover_github_pull_request_files(
            pull_request,
            token=token,
            timeout_seconds=timeout_seconds,
        )
        selection = select_configured_github_change(
            configuration,
            changed_files,
            config_repository_path=f"{PROJECT_DIRECTORY_NAME}/{PROJECT_CONFIG_NAME}",
        )
        github_output = Path(_required_environment("GITHUB_OUTPUT"))
        step_summary = Path(_required_environment("GITHUB_STEP_SUMMARY"))
        if selection is None:
            _append_outputs(
                github_output,
                {
                    "selection-status": "no_match",
                    "component-id": "not-applicable",
                    "component-path": "not-applicable",
                    "configured-case": "not-created",
                    "generation-receipt": "not-created",
                    "report": "not-created",
                },
            )
            _append_summary(
                step_summary,
                "No configured harness component changed; no trusted adapter ran.",
            )
            return 0

        mapping = next(
            item
            for item in configuration.github.components
            if item.component_id == selection.component_id
        )
        if mapping.case_generator_adapter_id is None:
            _append_outputs(
                github_output,
                {
                    "selection-status": "existing_case",
                    "component-id": selection.component_id,
                    "component-path": selection.component_path,
                    "configured-case": selection.case_file,
                    "generation-receipt": "not-created",
                    "report": "not-created",
                },
            )
            _append_summary(
                step_summary,
                f"Component `{selection.component_id}` uses its reviewed committed case; "
                "no trusted adapter ran.",
            )
            return 0
        if pull_request.is_fork:
            raise ValueError(
                "trusted case generation is unavailable for fork pull requests; the gate "
                "fails closed without executing the adapter"
            )
        if _git_head_sha(trusted_project) != pull_request.base_sha:
            raise ValueError("trusted-project HEAD does not match pull_request.base.sha")
        if _git_head_sha(candidate_root) != pull_request.head_sha:
            raise ValueError("candidate-root HEAD does not match pull_request.head.sha")

        generated = generate_configured_github_case(
            trusted_project,
            candidate_root,
            component_id=selection.component_id,
            component_path=selection.component_path,
            repository=pull_request.base_repository.full_name,
            pull_request_number=pull_request.number,
            base_sha=pull_request.base_sha,
            head_sha=pull_request.head_sha,
            output_directory=output_directory,
            budget=CaseGenerationBudget(
                timeout_seconds=timeout_seconds,
                maximum_case_bytes=int(
                    os.environ.get(
                        "CAUSURE_TRUSTED_MAXIMUM_CASE_BYTES",
                        str(MAX_CASE_GENERATION_BYTES),
                    )
                ),
            ),
        )
        _append_outputs(
            github_output,
            {
                "selection-status": "generated",
                "component-id": selection.component_id,
                "component-path": selection.component_path,
                "configured-case": generated.configured_case_path.relative_to(
                    candidate_root
                ).as_posix(),
                "generation-receipt": generated.receipt_path.relative_to(candidate_root).as_posix(),
                "report": generated.report_path.relative_to(candidate_root).as_posix(),
            },
        )
        _append_summary(step_summary, render_trusted_case_generation_summary(generated))
        return 0
    except (
        AdapterRunError,
        DocumentValidationError,
        InputDocumentError,
        OSError,
        StopIteration,
        ValueError,
    ) as exc:
        print(f"Causure trusted generation failed: {exc}", file=sys.stderr)
        return 2
    finally:
        token = ""
