"""Environment-only entry point used by the pinned composite GitHub Action."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from causure.constants import Decision
from causure.github_action import run_github_action
from causure.github_review import github_context_from_environment
from causure.github_selection import (
    discover_github_pull_request_files,
    ensure_unchanged_github_paths,
    select_configured_github_change,
)
from causure.io import load_change_case, read_json
from causure.onboarding import (
    DEFAULT_GITHUB_ARTIFACT_RETENTION_DAYS,
    ProjectConfiguration,
    parse_project_configuration,
)

DEFAULT_PROJECT_CONFIG_PATH = ".causure/config.json"


def _required_environment(name: str) -> str:
    value = os.environ.get(name)
    if not value or value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError(f"required Action input is unset or invalid: {name}")
    return value


def _optional_environment(name: str) -> str:
    value = os.environ.get(name, "")
    if value != value.strip() or any(ord(character) < 32 for character in value):
        raise ValueError(f"Action input is invalid: {name}")
    return value


def _boolean_environment(name: str) -> bool:
    value = _required_environment(name).casefold()
    if value not in {"true", "false"}:
        raise ValueError(f"Action input {name} must be true or false")
    return value == "true"


def _workspace_path(workspace: Path, value: str, *, role: str, must_exist: bool) -> Path:
    candidate = Path(value)
    resolved = (
        (workspace / candidate).resolve() if not candidate.is_absolute() else candidate.resolve()
    )
    try:
        resolved.relative_to(workspace)
    except ValueError as exc:
        raise ValueError(f"{role} must stay within GITHUB_WORKSPACE") from exc
    if must_exist and not resolved.is_file():
        raise ValueError(f"{role} does not identify a file: {resolved}")
    return resolved


def _append_github_output(path: Path, values: dict[str, str]) -> None:
    for key, value in values.items():
        if not value or "\n" in value or "\r" in value:
            raise ValueError(f"GitHub output {key} must be a non-empty single-line value")
    try:
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            for key, value in values.items():
                stream.write(f"{key}={value}\n")
    except OSError as exc:
        raise ValueError(f"could not write GITHUB_OUTPUT: {exc}") from exc


def _append_no_match_summary(path: Path) -> None:
    summary = "\n".join(
        [
            "## Causure evidence gate",
            "",
            "**Not applicable** — this pull request does not change a configured agent "
            "harness component.",
            "",
            "The validated project configuration contained no matching path pattern.",
            "",
        ]
    )
    try:
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(summary)
    except OSError as exc:
        raise ValueError(f"could not append the GitHub step summary: {exc}") from exc


def _configuration_path(
    workspace: Path,
    value: str,
    *,
    required: bool,
) -> tuple[Path | None, str]:
    repository_value = value or DEFAULT_PROJECT_CONFIG_PATH
    path = _workspace_path(
        workspace,
        repository_value,
        role="project configuration",
        must_exist=False,
    )
    if not path.is_file():
        if required:
            raise ValueError(
                f"automatic selection requires {repository_value}; run "
                "causure init and github-configure first"
            )
        return None, repository_value
    return path, path.relative_to(workspace).as_posix()


def _load_configuration(path: Path | None) -> ProjectConfiguration | None:
    return parse_project_configuration(read_json(path)) if path is not None else None


def main() -> int:
    """Run the composite Action from explicit inputs and GitHub-provided paths."""

    token = ""
    try:
        github_workspace = Path(_required_environment("GITHUB_WORKSPACE")).resolve()
        if not github_workspace.is_dir():
            raise ValueError("GITHUB_WORKSPACE must identify an existing directory")
        repository_root_value = _optional_environment("CAUSURE_REPOSITORY_ROOT") or "."
        workspace = _workspace_path(
            github_workspace,
            repository_root_value,
            role="repository-root",
            must_exist=False,
        )
        if not workspace.is_dir():
            raise ValueError("repository-root must identify an existing directory")
        case_value = _optional_environment("CAUSURE_CASE")
        component_value = _optional_environment("CAUSURE_COMPONENT_PATH")
        explicit_case_path = (
            _workspace_path(
                workspace,
                case_value,
                role="case",
                must_exist=True,
            )
            if case_value
            else None
        )
        if bool(case_value) != bool(component_value):
            raise ValueError(
                "case and component-path must either both be set as explicit overrides or "
                "both be omitted for automatic selection"
            )
        explicit_selection = bool(case_value)
        configuration_path, configuration_repository_path = _configuration_path(
            workspace,
            _optional_environment("CAUSURE_CONFIG"),
            required=not explicit_selection,
        )
        configuration = _load_configuration(configuration_path) if not explicit_selection else None
        policy_value = _optional_environment("CAUSURE_POLICY")
        token = os.environ.get("CAUSURE_GITHUB_TOKEN", "")
        selection_mode = "explicit" if explicit_selection else "configured"
        selection_status = "reviewed"
        component_id = "explicit"
        retention_days = (
            configuration.github.artifact_retention_days
            if configuration is not None
            else DEFAULT_GITHUB_ARTIFACT_RETENTION_DAYS
        )
        if explicit_selection:
            if explicit_case_path is None:
                raise ValueError("explicit case path was not resolved")
            case_path = explicit_case_path
            component_path = component_value
            policy_path = (
                _workspace_path(workspace, policy_value, role="policy", must_exist=True)
                if policy_value
                else None
            )
        else:
            if configuration_path is None or configuration is None:
                raise ValueError("automatic selection requires a valid project configuration")
            if not configuration.github.components:
                raise ValueError(
                    "automatic selection requires at least one GitHub component; run "
                    "causure github-configure first"
                )
            pull_request, _ = github_context_from_environment(os.environ)
            changed_files = discover_github_pull_request_files(
                pull_request,
                token=token,
                timeout_seconds=float(_required_environment("CAUSURE_TIMEOUT_SECONDS")),
            )
            selection = select_configured_github_change(
                configuration,
                changed_files,
                config_repository_path=configuration_repository_path,
            )
            if selection is None:
                step_summary = Path(_required_environment("GITHUB_STEP_SUMMARY"))
                github_output = Path(_required_environment("GITHUB_OUTPUT"))
                _append_no_match_summary(step_summary)
                _append_github_output(
                    github_output,
                    {
                        "decision": "not_applicable",
                        "recommended-action": "no_review",
                        "check-published": "false",
                        "check-publication-status": "not_applicable",
                        "selection-mode": selection_mode,
                        "selection-status": "no_match",
                        "component-id": "not-applicable",
                        "selected-case": "not-applicable",
                        "selected-component-path": "not-applicable",
                        "artifact-retention-days": str(retention_days),
                        "result": "not-created",
                        "report": "not-created",
                        "publication": "not-created",
                        "verification": "not-created",
                        "check-request": "not-created",
                        "check-summary": "not-created",
                        "check-receipt": "not-published",
                    },
                )
                print("Causure: NOT APPLICABLE (no configured component changed)")
                return 0
            component_id = selection.component_id
            retention_days = selection.artifact_retention_days
            case_path = _workspace_path(
                workspace,
                selection.case_file,
                role="configured case",
                must_exist=True,
            )
            component_path = selection.component_path
            selected_case = load_change_case(case_path)
            if selected_case.proposed_change.component is not selection.component:
                raise ValueError(
                    f"configured component {selection.component_id} expects "
                    f"{selection.component.value}, but its case declares "
                    f"{selected_case.proposed_change.component.value}"
                )
            if policy_value:
                policy_path = _workspace_path(
                    workspace,
                    policy_value,
                    role="policy",
                    must_exist=True,
                )
                ensure_unchanged_github_paths(
                    changed_files,
                    (policy_path.relative_to(workspace).as_posix(),),
                )
            else:
                policy_path = _workspace_path(
                    workspace,
                    selection.policy_file,
                    role="configured policy",
                    must_exist=True,
                )
        output_directory = _workspace_path(
            workspace,
            _required_environment("CAUSURE_OUTPUT_DIRECTORY"),
            role="output directory",
            must_exist=False,
        )
        publish_mode = _required_environment("CAUSURE_PUBLISH_CHECK")
        if (
            os.environ.get("GITHUB_ACTOR", "").casefold() == "dependabot[bot]"
            and publish_mode == "auto"
        ):
            publish_mode = "disabled"
        allow_conditional = _boolean_environment("CAUSURE_ALLOW_CONDITIONAL")
        maximum_age_seconds = int(_required_environment("CAUSURE_MAXIMUM_AGE_SECONDS"))
        timeout_seconds = float(_required_environment("CAUSURE_TIMEOUT_SECONDS"))
        step_summary = _required_environment("GITHUB_STEP_SUMMARY")
        github_output = Path(_required_environment("GITHUB_OUTPUT"))
        run = run_github_action(
            case_path,
            policy_path=policy_path,
            component_path=component_path,
            output_directory=output_directory,
            environment=os.environ,
            publish_mode=publish_mode,
            token=token,
            allow_conditional=allow_conditional,
            maximum_age_seconds=maximum_age_seconds,
            timeout_seconds=timeout_seconds,
            step_summary_path=step_summary,
        )
        outputs = {
            "decision": run.decision.value,
            "recommended-action": run.recommended_action.value,
            "check-published": str(run.check_published).lower(),
            "check-publication-status": run.check_publication_status,
            "selection-mode": selection_mode,
            "selection-status": selection_status,
            "component-id": component_id,
            "selected-case": case_path.relative_to(workspace).as_posix(),
            "selected-component-path": component_path,
            "artifact-retention-days": str(retention_days),
            "result": str(run.artifacts.result),
            "report": str(run.artifacts.report),
            "publication": str(run.artifacts.publication),
            "verification": str(run.artifacts.verification),
            "check-request": str(run.artifacts.check_request),
            "check-summary": str(run.artifacts.check_summary),
            "check-receipt": (
                str(run.artifacts.check_receipt)
                if run.artifacts.check_receipt is not None
                else "not-published"
            ),
        }
        _append_github_output(github_output, outputs)
        print(
            f"Causure: {run.decision.value.upper()} "
            f"({run.recommended_action.value}); Check Run {run.check_publication_status}"
        )
        if run.decision is Decision.APPROVE:
            return 0
        if run.decision is Decision.CONDITIONAL_PASS and allow_conditional:
            return 0
        return 1
    except (OSError, ValueError) as exc:
        print(f"Causure Action error: {exc}", file=sys.stderr)
        return 2
    finally:
        token = ""


if __name__ == "__main__":
    raise SystemExit(main())
