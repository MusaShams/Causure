"""Safe first-run workflows for the Causure command line interface."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib import metadata, resources
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from causure.constants import (
    PACKAGE_VERSION,
    Component,
    Decision,
    RecommendedAction,
)
from causure.engine import review_case
from causure.io import (
    InputDocumentError,
    atomic_write_bytes,
    atomic_write_text,
    load_change_case,
    parse_json_text,
    read_json,
)
from causure.models import ChangeCase, ReviewResult, parse_change_case
from causure.policy import parse_policy
from causure.report import render_json, render_markdown

PROJECT_DIRECTORY_NAME = ".causure"
PROJECT_CONFIG_NAME = "config.json"
PROJECT_CONFIG_SCHEMA_VERSION = "3.0"
PREVIOUS_PROJECT_CONFIG_SCHEMA_VERSION = "2.0"
LEGACY_PROJECT_CONFIG_SCHEMA_VERSION = "1.0"
DEFAULT_GITHUB_ARTIFACT_RETENTION_DAYS = 30
MAX_GITHUB_ARTIFACT_RETENTION_DAYS = 90
DEMO_RESULT_SCHEMA_VERSION = "1.0"
DOCTOR_SCHEMA_VERSION = "1.0"
DEMO_REVIEWED_AT = datetime(2026, 7, 27, 21, 0, tzinfo=UTC)

_PROJECT_ID_PATTERN = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?")
_ADAPTER_ENTRY_POINT_PATTERN = re.compile(
    r"[A-Za-z_][A-Za-z0-9_.]{0,126}:[A-Za-z_][A-Za-z0-9_.]{0,126}"
)
_LEGACY_PROJECT_CONFIG_KEYS = {
    "adapter_directory",
    "artifact_directory",
    "policy_file",
    "project_id",
    "raw_trace_storage",
    "schema_version",
}
_PROJECT_CONFIG_KEYS = _LEGACY_PROJECT_CONFIG_KEYS | {
    "github",
    "trusted_adapter_entry_points",
}
_GITHUB_CONFIG_KEYS = {"artifact_retention_days", "components"}
_PREVIOUS_GITHUB_COMPONENT_KEYS = {
    "case_file",
    "component",
    "component_id",
    "paths",
}
_GITHUB_COMPONENT_KEYS = _PREVIOUS_GITHUB_COMPONENT_KEYS | {
    "case_generator_adapter_id",
}
_TRUSTED_ADAPTER_KEYS = {"adapter_id", "entry_point", "kind"}


@dataclass(frozen=True, slots=True)
class DemoStorySpec:
    """A bundled synthetic story and its expected deterministic outcome."""

    story_id: str
    title: str
    explanation: str
    resource_name: str
    expected_decision: Decision
    expected_action: RecommendedAction


@dataclass(frozen=True, slots=True)
class DemoStoryResult:
    """The reviewed outcome and portable artifact paths for one demo story."""

    spec: DemoStorySpec
    case: ChangeCase
    result: ReviewResult
    case_path: str
    report_path: str
    result_path: str


@dataclass(frozen=True, slots=True)
class DemoRun:
    """A completed deterministic synthetic demo."""

    output_directory: Path
    stories: tuple[DemoStoryResult, ...]


@dataclass(frozen=True, slots=True)
class ProjectConfiguration:
    """The deliberately small local project configuration."""

    project_id: str
    policy_file: str
    adapter_directory: str
    artifact_directory: str
    raw_trace_storage: str
    trusted_adapter_entry_points: tuple[TrustedAdapterEntryPoint, ...]
    github: GitHubProjectConfiguration


@dataclass(frozen=True, slots=True)
class TrustedAdapterEntryPoint:
    """One company-reviewed adapter registration; project data never executes it."""

    adapter_id: str
    kind: Literal["replay", "evaluator", "case_generator"]
    entry_point: str


@dataclass(frozen=True, slots=True)
class GitHubComponentConfiguration:
    """One deterministic mapping from changed repository paths to a change case."""

    component_id: str
    component: Component
    paths: tuple[str, ...]
    case_file: str
    case_generator_adapter_id: str | None = None


@dataclass(frozen=True, slots=True)
class GitHubProjectConfiguration:
    """Repository review behavior shared by the CLI and composite Action."""

    artifact_retention_days: int
    components: tuple[GitHubComponentConfiguration, ...]


@dataclass(frozen=True, slots=True)
class GitHubConfigurationUpdate:
    """One new-only GitHub component registration written to a project."""

    configuration_path: Path
    component: GitHubComponentConfiguration
    artifact_retention_days: int


@dataclass(frozen=True, slots=True)
class TrustedAdapterConfigurationUpdate:
    """One new-only trusted adapter registration written to a project."""

    configuration_path: Path
    adapter: TrustedAdapterEntryPoint
    component: GitHubComponentConfiguration | None


@dataclass(frozen=True, slots=True)
class ProjectInitialization:
    """Paths created by a successful new-only project initialization."""

    project_root: Path
    configuration_path: Path
    policy_path: Path
    adapter_directory: Path


DoctorStatus = Literal["pass", "warn", "fail"]


@dataclass(frozen=True, slots=True)
class DoctorCheck:
    """One stable, machine-readable environment diagnostic."""

    code: str
    status: DoctorStatus
    message: str


@dataclass(frozen=True, slots=True)
class DoctorReport:
    """Read-only environment diagnostic results."""

    project_root: Path
    status: Literal["ready", "ready_with_warnings", "failed"]
    checks: tuple[DoctorCheck, ...]


DEMO_STORIES = (
    DemoStorySpec(
        story_id="justified-minimal-patch",
        title="Justified minimal patch",
        explanation=(
            "The failure reproduced, an isolated tool-description correction fixed it, "
            "and the positive, negative, regression, cost, and latency controls passed."
        ),
        resource_name="approve-refund-tool-description.json",
        expected_decision=Decision.APPROVE,
        expected_action=RecommendedAction.PATCH,
    ),
    DemoStorySpec(
        story_id="overbroad-change-rejected",
        title="Attractive but overbroad change",
        explanation=(
            "The evidence identified the tool description, but the proposal changed the "
            "global prompt, exceeded the minimal surface, and failed a negative control."
        ),
        resource_name="reject-overbroad-prompt.json",
        expected_decision=Decision.REJECT,
        expected_action=RecommendedAction.DO_NOT_PATCH,
    ),
)


def _json_text(document: Any) -> str:
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def _resource_bytes(resource_name: str) -> bytes:
    try:
        return resources.files("causure").joinpath("demo").joinpath(resource_name).read_bytes()
    except (FileNotFoundError, OSError) as exc:
        raise ValueError(f"bundled demo case is unavailable: {resource_name}") from exc


def load_demo_story(spec: DemoStorySpec) -> tuple[bytes, ChangeCase, ReviewResult]:
    """Load and review one bundled story, enforcing its expected outcome."""

    raw_bytes = _resource_bytes(spec.resource_name)
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InputDocumentError(
            f"bundled demo case is not valid UTF-8: {spec.resource_name}"
        ) from exc
    document = parse_json_text(text, source=f"bundled demo/{spec.resource_name}")
    case = parse_change_case(document)
    result = review_case(case, reviewed_at=DEMO_REVIEWED_AT)
    if result.decision is not spec.expected_decision:
        raise ValueError(
            f"bundled demo story {spec.story_id} produced {result.decision.value}; "
            f"expected {spec.expected_decision.value}"
        )
    if result.recommended_action is not spec.expected_action:
        raise ValueError(
            f"bundled demo story {spec.story_id} recommended "
            f"{result.recommended_action.value}; expected {spec.expected_action.value}"
        )
    return raw_bytes, case, result


def _demo_document(stories: tuple[DemoStoryResult, ...]) -> dict[str, Any]:
    return {
        "engine_version": PACKAGE_VERSION,
        "reviewed_at": DEMO_REVIEWED_AT.isoformat().replace("+00:00", "Z"),
        "schema_version": DEMO_RESULT_SCHEMA_VERSION,
        "stories": [
            {
                "artifacts": {
                    "case": story.case_path,
                    "report": story.report_path,
                    "result": story.result_path,
                },
                "case_id": story.case.case_id,
                "decision": story.result.decision.value,
                "recommended_action": story.result.recommended_action.value,
                "story_id": story.spec.story_id,
                "summary": story.result.summary,
                "title": story.spec.title,
            }
            for story in stories
        ],
        "synthetic": True,
    }


def _demo_readme(stories: tuple[DemoStoryResult, ...]) -> str:
    lines = [
        "# Causure synthetic demo",
        "",
        "This directory was generated locally from bundled synthetic evidence. It contains no",
        "customer traces, credentials, or network-fetched content.",
        "",
        "## Outcomes",
        "",
        "| Story | Gate decision | Recommended action | Report |",
        "| --- | --- | --- | --- |",
    ]
    for story in stories:
        lines.append(
            f"| {story.spec.title} | **{story.result.decision.value.upper()}** | "
            f"**{story.result.recommended_action.value.upper()}** | "
            f"[{story.case.case_id}]({story.report_path}) |"
        )
    lines.extend(["", "## Why", ""])
    lines.extend(f"- **{story.spec.title}:** {story.spec.explanation}" for story in stories)
    lines.extend(
        [
            "",
            "`demo-result.json` is the compact machine-readable index. Each `results/` file is the",
            "canonical gate output, while each `reports/` file explains the decision for a human.",
            "The fixed synthetic review timestamp makes repeated demo output deterministic.",
            "",
            "## Next step",
            "",
            "Initialize a local project without writing configuration JSON yourself:",
            "",
            "```text",
            "causure init my-agent-project",
            "```",
            "",
            "The initialized project prints the next command. Use `causure doctor` only",
            "when you want a read-only setup diagnostic.",
            "",
        ]
    )
    return "\n".join(lines)


def run_demo(output_directory: str | Path) -> DemoRun:
    """Create a deterministic two-story demo in a new output directory."""

    loaded = tuple((spec, *load_demo_story(spec)) for spec in DEMO_STORIES)
    destination = Path(output_directory).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        destination.mkdir()
    except FileExistsError as exc:
        raise ValueError(
            f"demo output already exists; choose a new directory: {destination}"
        ) from exc
    except OSError as exc:
        raise ValueError(f"could not create demo output {destination}: {exc}") from exc

    completed = False
    try:
        stories: list[DemoStoryResult] = []
        for index, (spec, raw_bytes, case, result) in enumerate(loaded, start=1):
            stem = f"{index:02d}-{spec.story_id}"
            case_path = f"cases/{stem}.json"
            report_path = f"reports/{stem}.md"
            result_path = f"results/{stem}.json"
            atomic_write_bytes(destination / case_path, raw_bytes)
            atomic_write_text(destination / report_path, render_markdown(case, result))
            atomic_write_text(destination / result_path, render_json(result))
            stories.append(
                DemoStoryResult(
                    spec=spec,
                    case=case,
                    result=result,
                    case_path=case_path,
                    report_path=report_path,
                    result_path=result_path,
                )
            )
        frozen_stories = tuple(stories)
        atomic_write_text(destination / "README.md", _demo_readme(frozen_stories))
        atomic_write_text(
            destination / "demo-result.json",
            _json_text(_demo_document(frozen_stories)),
        )
        completed = True
        return DemoRun(output_directory=destination, stories=frozen_stories)
    finally:
        if not completed:
            shutil.rmtree(destination, ignore_errors=True)


def render_demo_summary(run: DemoRun) -> str:
    """Render the concise first-run terminal result."""

    lines = ["Causure demo completed (synthetic; no network was used):"]
    for story in run.stories:
        lines.extend(
            [
                f"  {story.result.recommended_action.value.upper()}: "
                f"{story.result.decision.value.upper()} - {story.spec.title}",
                f"    Why: {story.spec.explanation}",
                f"    Report: {run.output_directory / story.report_path}",
            ]
        )
    lines.extend(
        [
            "",
            "The gate approved the supported narrow change and blocked the plausible wrong one.",
            f"Open this local overview in your editor: {run.output_directory / 'README.md'}",
            f"Machine result: {run.output_directory / 'demo-result.json'}",
            "Next: causure init my-agent-project",
        ]
    )
    return "\n".join(lines)


def _validate_project_id(project_id: Any) -> str:
    if not isinstance(project_id, str):
        raise ValueError("project ID must be a string")
    normalized = project_id.strip()
    if not _PROJECT_ID_PATTERN.fullmatch(normalized):
        raise ValueError(
            "project ID must contain 1-64 lowercase letters, digits, or internal hyphens"
        )
    return normalized


def _derive_project_id(name: str) -> str:
    ascii_name = unicodedata.normalize("NFKD", name).encode("ascii", "ignore").decode("ascii")
    candidate = re.sub(r"[^a-z0-9]+", "-", ascii_name.lower()).strip("-")
    candidate = candidate[:64].rstrip("-")
    return _validate_project_id(candidate or "causure-project")


def _relative_project_path(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"project configuration {field_name} must be a non-empty string")
    normalized = value.strip()
    if any(ord(character) < 32 or ord(character) == 127 for character in normalized):
        raise ValueError(f"project configuration {field_name} cannot contain control characters")
    if "\\" in normalized:
        raise ValueError(f"project configuration {field_name} must use forward slashes")
    path = PurePosixPath(normalized)
    if (
        path.is_absolute()
        or path.as_posix() != normalized
        or any(part in {"", ".", ".."} for part in path.parts)
    ):
        raise ValueError(f"project configuration {field_name} must be a contained relative path")
    return normalized


def _repository_path(value: Any, field_name: str, *, allow_glob: bool = False) -> str:
    normalized = _relative_project_path(value, field_name)
    if len(normalized) > 1024:
        raise ValueError(f"project configuration {field_name} must be at most 1024 characters")
    if not allow_glob and "*" in normalized:
        raise ValueError(f"project configuration {field_name} cannot contain wildcards")
    if allow_glob:
        if any(character in normalized for character in "?[]"):
            raise ValueError(f"project configuration {field_name} supports only * and ** wildcards")
        for part in PurePosixPath(normalized).parts:
            if "**" in part and part != "**":
                raise ValueError(
                    f"project configuration {field_name} requires ** to be a whole path segment"
                )
    return normalized


def _closed_configuration_object(
    value: Any,
    *,
    field_name: str,
    required: set[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError(f"project configuration {field_name} must be an object")
    keys = set(value)
    missing = sorted(required - keys)
    unknown = sorted(keys - required)
    if missing:
        raise ValueError(
            f"project configuration {field_name} is missing field(s): " + ", ".join(missing)
        )
    if unknown:
        raise ValueError(
            f"project configuration {field_name} contains unknown field(s): " + ", ".join(unknown)
        )
    return value


def _parse_trusted_adapter_entry_points(
    value: Any,
    *,
    allow_case_generators: bool,
) -> tuple[TrustedAdapterEntryPoint, ...]:
    if not isinstance(value, list) or len(value) > 32:
        raise ValueError(
            "project configuration trusted_adapter_entry_points must be an array of at "
            "most 32 items"
        )
    parsed: list[TrustedAdapterEntryPoint] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        path = f"trusted_adapter_entry_points[{index}]"
        entry = _closed_configuration_object(
            item,
            field_name=path,
            required=_TRUSTED_ADAPTER_KEYS,
        )
        adapter_id = _validate_project_id(entry["adapter_id"])
        if adapter_id in seen:
            raise ValueError(f"project configuration adapter ID must be unique: {adapter_id}")
        seen.add(adapter_id)
        kind = entry["kind"]
        supported_kinds = (
            {"replay", "evaluator", "case_generator"}
            if allow_case_generators
            else {"replay", "evaluator"}
        )
        if not isinstance(kind, str) or kind not in supported_kinds:
            allowed = ", ".join(sorted(supported_kinds))
            raise ValueError(f"project configuration {path}.kind must be one of: {allowed}")
        entry_point = entry["entry_point"]
        if not isinstance(entry_point, str) or not _ADAPTER_ENTRY_POINT_PATTERN.fullmatch(
            entry_point
        ):
            raise ValueError(
                f"project configuration {path}.entry_point must use module.path:callable format"
            )
        parsed.append(
            TrustedAdapterEntryPoint(
                adapter_id=adapter_id,
                kind=kind,
                entry_point=entry_point,
            )
        )
    return tuple(parsed)


def _parse_github_configuration(
    value: Any,
    *,
    include_case_generators: bool,
) -> GitHubProjectConfiguration:
    github = _closed_configuration_object(
        value,
        field_name="github",
        required=_GITHUB_CONFIG_KEYS,
    )
    retention = github["artifact_retention_days"]
    if type(retention) is not int or not 1 <= retention <= MAX_GITHUB_ARTIFACT_RETENTION_DAYS:
        raise ValueError(
            "project configuration github.artifact_retention_days must be an integer from "
            f"1 to {MAX_GITHUB_ARTIFACT_RETENTION_DAYS}"
        )
    raw_components = github["components"]
    if not isinstance(raw_components, list) or len(raw_components) > 128:
        raise ValueError(
            "project configuration github.components must be an array of at most 128 items"
        )
    components: list[GitHubComponentConfiguration] = []
    seen_ids: set[str] = set()
    seen_case_files: set[str] = set()
    seen_patterns: set[str] = set()
    for index, item in enumerate(raw_components):
        path = f"github.components[{index}]"
        mapping = _closed_configuration_object(
            item,
            field_name=path,
            required=(
                _GITHUB_COMPONENT_KEYS
                if include_case_generators
                else _PREVIOUS_GITHUB_COMPONENT_KEYS
            ),
        )
        component_id = _validate_project_id(mapping["component_id"])
        if component_id in seen_ids:
            raise ValueError(
                f"project configuration GitHub component ID must be unique: {component_id}"
            )
        seen_ids.add(component_id)
        try:
            component = Component(mapping["component"])
        except (TypeError, ValueError) as exc:
            raise ValueError(
                f"project configuration {path}.component is not a supported component"
            ) from exc
        raw_paths = mapping["paths"]
        if not isinstance(raw_paths, list) or not 1 <= len(raw_paths) <= 32:
            raise ValueError(
                f"project configuration {path}.paths must contain from 1 to 32 patterns"
            )
        patterns = tuple(
            _repository_path(item, f"{path}.paths[{path_index}]", allow_glob=True)
            for path_index, item in enumerate(raw_paths)
        )
        if len(set(patterns)) != len(patterns):
            raise ValueError(f"project configuration {path}.paths must be unique")
        duplicate_pattern = next(
            (pattern for pattern in patterns if pattern in seen_patterns),
            None,
        )
        if duplicate_pattern is not None:
            raise ValueError(
                "project configuration GitHub path patterns must be unique across components: "
                + duplicate_pattern
            )
        seen_patterns.update(patterns)
        case_file = _repository_path(mapping["case_file"], f"{path}.case_file")
        if case_file in seen_case_files:
            raise ValueError(
                "project configuration GitHub case files must be unique across components: "
                + case_file
            )
        seen_case_files.add(case_file)
        generator_value = mapping["case_generator_adapter_id"] if include_case_generators else None
        case_generator_adapter_id = (
            None if generator_value is None else _validate_project_id(generator_value)
        )
        components.append(
            GitHubComponentConfiguration(
                component_id=component_id,
                component=component,
                paths=patterns,
                case_file=case_file,
                case_generator_adapter_id=case_generator_adapter_id,
            )
        )
    return GitHubProjectConfiguration(
        artifact_retention_days=retention,
        components=tuple(components),
    )


def parse_project_configuration(document: Any) -> ProjectConfiguration:
    """Parse the small first-run configuration with a closed field set."""

    if not isinstance(document, dict):
        raise ValueError("project configuration must be a JSON object")
    schema_version = document.get("schema_version")
    if schema_version == LEGACY_PROJECT_CONFIG_SCHEMA_VERSION:
        expected_keys = _LEGACY_PROJECT_CONFIG_KEYS
    elif schema_version in {
        PREVIOUS_PROJECT_CONFIG_SCHEMA_VERSION,
        PROJECT_CONFIG_SCHEMA_VERSION,
    }:
        expected_keys = _PROJECT_CONFIG_KEYS
    else:
        raise ValueError(
            "project configuration schema_version must be one of: "
            f"{LEGACY_PROJECT_CONFIG_SCHEMA_VERSION}, "
            f"{PREVIOUS_PROJECT_CONFIG_SCHEMA_VERSION}, {PROJECT_CONFIG_SCHEMA_VERSION}"
        )
    keys = set(document)
    missing = sorted(expected_keys - keys)
    unknown = sorted(keys - expected_keys)
    if missing:
        raise ValueError("project configuration is missing field(s): " + ", ".join(missing))
    if unknown:
        raise ValueError("project configuration contains unknown field(s): " + ", ".join(unknown))
    if document["raw_trace_storage"] != "disabled":
        raise ValueError("project configuration raw_trace_storage must be disabled")
    trusted_adapters = (
        _parse_trusted_adapter_entry_points(
            document["trusted_adapter_entry_points"],
            allow_case_generators=schema_version == PROJECT_CONFIG_SCHEMA_VERSION,
        )
        if schema_version != LEGACY_PROJECT_CONFIG_SCHEMA_VERSION
        else ()
    )
    github = (
        _parse_github_configuration(
            document["github"],
            include_case_generators=schema_version == PROJECT_CONFIG_SCHEMA_VERSION,
        )
        if schema_version != LEGACY_PROJECT_CONFIG_SCHEMA_VERSION
        else GitHubProjectConfiguration(
            artifact_retention_days=DEFAULT_GITHUB_ARTIFACT_RETENTION_DAYS,
            components=(),
        )
    )
    adapters_by_id = {adapter.adapter_id: adapter for adapter in trusted_adapters}
    for component in github.components:
        if component.case_generator_adapter_id is None:
            continue
        adapter = adapters_by_id.get(component.case_generator_adapter_id)
        if adapter is None or adapter.kind != "case_generator":
            raise ValueError(
                "project configuration GitHub component "
                f"{component.component_id} must reference a registered case_generator adapter"
            )
    return ProjectConfiguration(
        project_id=_validate_project_id(document["project_id"]),
        policy_file=_relative_project_path(document["policy_file"], "policy_file"),
        adapter_directory=_relative_project_path(
            document["adapter_directory"], "adapter_directory"
        ),
        artifact_directory=_relative_project_path(
            document["artifact_directory"], "artifact_directory"
        ),
        raw_trace_storage="disabled",
        trusted_adapter_entry_points=trusted_adapters,
        github=github,
    )


def _project_document(configuration: ProjectConfiguration) -> dict[str, Any]:
    return {
        "adapter_directory": configuration.adapter_directory,
        "artifact_directory": configuration.artifact_directory,
        "github": {
            "artifact_retention_days": configuration.github.artifact_retention_days,
            "components": [
                {
                    "case_file": component.case_file,
                    "case_generator_adapter_id": component.case_generator_adapter_id,
                    "component": component.component.value,
                    "component_id": component.component_id,
                    "paths": list(component.paths),
                }
                for component in configuration.github.components
            ],
        },
        "policy_file": configuration.policy_file,
        "project_id": configuration.project_id,
        "raw_trace_storage": configuration.raw_trace_storage,
        "schema_version": PROJECT_CONFIG_SCHEMA_VERSION,
        "trusted_adapter_entry_points": [
            {
                "adapter_id": adapter.adapter_id,
                "entry_point": adapter.entry_point,
                "kind": adapter.kind,
            }
            for adapter in configuration.trusted_adapter_entry_points
        ],
    }


def initialize_project(
    directory: str | Path,
    *,
    project_id: str | None = None,
) -> ProjectInitialization:
    """Create a new local configuration boundary without overwriting existing state."""

    root = Path(directory).expanduser().resolve()
    if root.exists() and not root.is_dir():
        raise ValueError(f"project path is not a directory: {root}")
    root.mkdir(parents=True, exist_ok=True)
    control = root / PROJECT_DIRECTORY_NAME
    if os.path.lexists(control):
        raise ValueError(f"Causure project already exists; no files were changed: {control}")
    control.mkdir()

    completed = False
    try:
        identifier = (
            _validate_project_id(project_id) if project_id else _derive_project_id(root.name)
        )
        configuration = ProjectConfiguration(
            project_id=identifier,
            policy_file="policy.json",
            adapter_directory="adapters",
            artifact_directory="artifacts",
            raw_trace_storage="disabled",
            trusted_adapter_entry_points=(),
            github=GitHubProjectConfiguration(
                artifact_retention_days=DEFAULT_GITHUB_ARTIFACT_RETENTION_DAYS,
                components=(),
            ),
        )
        configuration_path = control / PROJECT_CONFIG_NAME
        policy_path = control / configuration.policy_file
        adapter_directory = control / configuration.adapter_directory
        adapter_directory.mkdir()
        atomic_write_text(configuration_path, _json_text(_project_document(configuration)))
        atomic_write_text(policy_path, _json_text({"name": "causure-default-v1"}))
        atomic_write_text(
            control / ".gitignore",
            "# Generated local evidence and caches\nartifacts/\ncache/\n*.sqlite3\n*.sqlite3-*\n",
        )
        atomic_write_text(
            adapter_directory / "README.md",
            "# Trusted adapters\n\n"
            "Place company-owned replay, evaluator, and case-generator adapters here only "
            "after reviewing them as trusted code. Evidence files cannot select or execute "
            "adapters. Use "
            "`causure adapter-configure --help` to register an entry point without "
            "importing it. Run case generators only through the separately trusted "
            "`python -I -m causure case generate` workflow.\n",
        )
        atomic_write_text(
            control / "README.md",
            "# Causure project\n\n"
            "## Next step\n\n"
            "From this project root, create a redacted investigation from an "
            "OTLP/OpenInference JSON export:\n\n"
            "```text\n"
            "causure investigate <path-to-agent-traces.json>\n"
            "```\n\n"
            "Then copy the printed investigation path into "
            "`causure case create <path-to-investigation>`. Run "
            "`causure doctor .` only when you want a read-only setup diagnostic. "
            "Generated artifacts stay under `artifacts/` and are ignored by the local ignore "
            "file. Raw trace storage is disabled by default.\n\n"
            "To let the GitHub Action choose a case from changed paths without editing JSON, "
            "run `causure github-configure --help`.\n",
        )
        completed = True
        return ProjectInitialization(
            project_root=root,
            configuration_path=configuration_path,
            policy_path=policy_path,
            adapter_directory=adapter_directory,
        )
    finally:
        if not completed:
            shutil.rmtree(control, ignore_errors=True)


def configure_github_component(
    directory: str | Path,
    *,
    component_id: str,
    component: str | Component,
    paths: tuple[str, ...],
    case_file: str,
    artifact_retention_days: int | None = None,
) -> GitHubConfigurationUpdate:
    """Add one component mapping without asking a user to edit configuration JSON."""

    root = Path(directory).expanduser().resolve()
    control = root / PROJECT_DIRECTORY_NAME
    configuration_path = control / PROJECT_CONFIG_NAME
    if not configuration_path.is_file():
        raise ValueError(
            f"Causure project configuration was not found: {configuration_path}; "
            "run causure init first"
        )
    configuration = parse_project_configuration(read_json(configuration_path))
    normalized_id = _validate_project_id(component_id)
    if any(item.component_id == normalized_id for item in configuration.github.components):
        raise ValueError(f"GitHub component already exists; no files were changed: {normalized_id}")
    try:
        normalized_component = (
            component if isinstance(component, Component) else Component(component)
        )
    except ValueError as exc:
        raise ValueError(f"unsupported Causure component: {component}") from exc
    if not paths:
        raise ValueError("at least one GitHub component path pattern is required")
    normalized_paths = tuple(
        _repository_path(value, f"paths[{index}]", allow_glob=True)
        for index, value in enumerate(paths)
    )
    mapping = GitHubComponentConfiguration(
        component_id=normalized_id,
        component=normalized_component,
        paths=normalized_paths,
        case_file=_repository_path(case_file, "case_file"),
    )
    retention = (
        configuration.github.artifact_retention_days
        if artifact_retention_days is None
        else artifact_retention_days
    )
    updated = ProjectConfiguration(
        project_id=configuration.project_id,
        policy_file=configuration.policy_file,
        adapter_directory=configuration.adapter_directory,
        artifact_directory=configuration.artifact_directory,
        raw_trace_storage=configuration.raw_trace_storage,
        trusted_adapter_entry_points=configuration.trusted_adapter_entry_points,
        github=GitHubProjectConfiguration(
            artifact_retention_days=retention,
            components=configuration.github.components + (mapping,),
        ),
    )
    document = _project_document(updated)
    validated = parse_project_configuration(document)
    atomic_write_text(configuration_path, _json_text(_project_document(validated)))
    return GitHubConfigurationUpdate(
        configuration_path=configuration_path,
        component=mapping,
        artifact_retention_days=validated.github.artifact_retention_days,
    )


def render_github_configuration_summary(update: GitHubConfigurationUpdate) -> str:
    """Render the concise next step after a GitHub component is registered."""

    return "\n".join(
        [
            f"Configured GitHub component {update.component.component_id}",
            f"  Type: {update.component.component.value}",
            f"  Changed paths: {', '.join(update.component.paths)}",
            f"  Change case: {update.component.case_file}",
            f"  Evidence retention: {update.artifact_retention_days} days",
            f"  Config: {update.configuration_path}",
            "Next: add the minimal workflow from docs/github-action.md.",
        ]
    )


def configure_trusted_adapter(
    directory: str | Path,
    *,
    adapter_id: str,
    kind: str,
    entry_point: str,
    component_id: str | None = None,
) -> TrustedAdapterConfigurationUpdate:
    """Register one trusted adapter entry point without importing or executing it."""

    root = Path(directory).expanduser().resolve()
    configuration_path = root / PROJECT_DIRECTORY_NAME / PROJECT_CONFIG_NAME
    if not configuration_path.is_file():
        raise ValueError(
            f"Causure project configuration was not found: {configuration_path}; "
            "run causure init first"
        )
    configuration = parse_project_configuration(read_json(configuration_path))
    normalized_id = _validate_project_id(adapter_id)
    if any(item.adapter_id == normalized_id for item in configuration.trusted_adapter_entry_points):
        raise ValueError(f"trusted adapter already exists; no files were changed: {normalized_id}")
    if not isinstance(kind, str) or kind not in {
        "replay",
        "evaluator",
        "case_generator",
    }:
        raise ValueError("trusted adapter kind must be replay, evaluator, or case_generator")
    if not isinstance(entry_point, str) or not _ADAPTER_ENTRY_POINT_PATTERN.fullmatch(entry_point):
        raise ValueError("trusted adapter entry point must use module.path:callable format")
    adapter = TrustedAdapterEntryPoint(
        adapter_id=normalized_id,
        kind=kind,
        entry_point=entry_point,
    )
    bound_component: GitHubComponentConfiguration | None = None
    components = configuration.github.components
    if component_id is not None:
        if kind != "case_generator":
            raise ValueError("--component-id can bind only a case_generator adapter")
        normalized_component_id = _validate_project_id(component_id)
        current = next(
            (
                item
                for item in configuration.github.components
                if item.component_id == normalized_component_id
            ),
            None,
        )
        if current is None:
            raise ValueError(
                "GitHub component was not found for case-generator binding: "
                f"{normalized_component_id}"
            )
        if current.case_generator_adapter_id is not None:
            raise ValueError(
                "GitHub component already has a case generator; no files were changed: "
                f"{normalized_component_id}"
            )
        bound_component = GitHubComponentConfiguration(
            component_id=current.component_id,
            component=current.component,
            paths=current.paths,
            case_file=current.case_file,
            case_generator_adapter_id=normalized_id,
        )
        components = tuple(
            bound_component if item.component_id == normalized_component_id else item
            for item in configuration.github.components
        )
    updated = ProjectConfiguration(
        project_id=configuration.project_id,
        policy_file=configuration.policy_file,
        adapter_directory=configuration.adapter_directory,
        artifact_directory=configuration.artifact_directory,
        raw_trace_storage=configuration.raw_trace_storage,
        trusted_adapter_entry_points=configuration.trusted_adapter_entry_points + (adapter,),
        github=configuration.github,
    )
    if bound_component is not None:
        updated = ProjectConfiguration(
            project_id=updated.project_id,
            policy_file=updated.policy_file,
            adapter_directory=updated.adapter_directory,
            artifact_directory=updated.artifact_directory,
            raw_trace_storage=updated.raw_trace_storage,
            trusted_adapter_entry_points=updated.trusted_adapter_entry_points,
            github=GitHubProjectConfiguration(
                artifact_retention_days=updated.github.artifact_retention_days,
                components=components,
            ),
        )
    document = _project_document(updated)
    validated = parse_project_configuration(document)
    atomic_write_text(configuration_path, _json_text(_project_document(validated)))
    return TrustedAdapterConfigurationUpdate(
        configuration_path=configuration_path,
        adapter=adapter,
        component=bound_component,
    )


def render_trusted_adapter_configuration_summary(
    update: TrustedAdapterConfigurationUpdate,
) -> str:
    """Render the trust warning after an adapter entry point is registered."""

    lines = [
        f"Registered trusted {update.adapter.kind} adapter {update.adapter.adapter_id}",
        f"  Entry point: {update.adapter.entry_point}",
        f"  Config: {update.configuration_path}",
        "Registration does not execute the adapter. Review its code and deployment "
        "boundary before a trusted orchestrator imports it.",
    ]
    if update.component is not None:
        lines.extend(
            [
                f"  Bound GitHub component: {update.component.component_id}",
                "Next: run `python -I -m causure case generate --help` from a protected workflow.",
            ]
        )
    return "\n".join(lines)


def render_initialization_summary(initialization: ProjectInitialization) -> str:
    """Render actionable output for a new project."""

    return "\n".join(
        [
            f"Initialized Causure project at {initialization.project_root}",
            f"  Config: {initialization.configuration_path}",
            f"  Policy preset: {initialization.policy_path}",
            f"  Trusted adapters: {initialization.adapter_directory}",
            "Project is ready for a trace export.",
            f'Next: open a terminal in "{initialization.project_root}" and run:',
            "  causure investigate <path-to-agent-traces.json>",
            "Optional setup diagnostic:",
            f'  causure doctor "{initialization.project_root}"',
        ]
    )


def _check(code: str, status: DoctorStatus, message: str) -> DoctorCheck:
    return DoctorCheck(code=code, status=status, message=message)


def _installed_version() -> str | None:
    try:
        return metadata.version("causure")
    except metadata.PackageNotFoundError:
        return None


def _load_configuration(control: Path) -> ProjectConfiguration:
    return parse_project_configuration(read_json(control / PROJECT_CONFIG_NAME))


def inspect_environment(directory: str | Path) -> DoctorReport:
    """Inspect the local environment without writing files or contacting services."""

    root = Path(directory).expanduser().resolve()
    checks: list[DoctorCheck] = []

    python_version = sys.version_info
    python_ready = python_version >= (3, 11)
    checks.append(
        _check(
            "CAUSURE-DOCTOR-PYTHON",
            "pass" if python_ready else "fail",
            f"Python {python_version.major}.{python_version.minor}.{python_version.micro} "
            + (
                "meets the >=3.11 requirement"
                if python_ready
                else "is below the >=3.11 requirement"
            ),
        )
    )

    installed_version = _installed_version()
    if installed_version is None:
        checks.append(
            _check(
                "CAUSURE-DOCTOR-PACKAGE",
                "warn",
                f"running Causure {PACKAGE_VERSION} from source without installed metadata",
            )
        )
    elif installed_version != PACKAGE_VERSION:
        checks.append(
            _check(
                "CAUSURE-DOCTOR-PACKAGE",
                "fail",
                f"loaded version {PACKAGE_VERSION} differs from installed metadata "
                f"{installed_version}",
            )
        )
    else:
        checks.append(
            _check(
                "CAUSURE-DOCTOR-PACKAGE",
                "pass",
                f"Causure {PACKAGE_VERSION} package metadata matches the loaded code",
            )
        )

    try:
        outcomes = []
        for spec in DEMO_STORIES:
            load_demo_story(spec)
            outcomes.append(f"{spec.expected_decision.value}/{spec.expected_action.value}")
        checks.append(
            _check(
                "CAUSURE-DOCTOR-DEMO",
                "pass",
                "bundled synthetic stories validate with expected outcomes: " + ", ".join(outcomes),
            )
        )
    except (OSError, ValueError) as exc:
        checks.append(_check("CAUSURE-DOCTOR-DEMO", "fail", str(exc)))

    configuration: ProjectConfiguration | None = None
    control = root / PROJECT_DIRECTORY_NAME
    configuration_path = control / PROJECT_CONFIG_NAME
    if not root.exists():
        checks.append(
            _check("CAUSURE-DOCTOR-PROJECT", "fail", f"project directory does not exist: {root}")
        )
    elif not root.is_dir():
        checks.append(
            _check("CAUSURE-DOCTOR-PROJECT", "fail", f"project path is not a directory: {root}")
        )
    else:
        checks.append(
            _check("CAUSURE-DOCTOR-PROJECT", "pass", f"project directory is readable: {root}")
        )
        if not configuration_path.exists():
            checks.append(
                _check(
                    "CAUSURE-DOCTOR-CONFIG",
                    "warn",
                    f'no project configuration found; run causure init "{root}"',
                )
            )
        else:
            try:
                configuration = _load_configuration(control)
                checks.append(
                    _check(
                        "CAUSURE-DOCTOR-CONFIG",
                        "pass",
                        f"configuration is valid for project {configuration.project_id}",
                    )
                )
            except (OSError, ValueError) as exc:
                checks.append(_check("CAUSURE-DOCTOR-CONFIG", "fail", str(exc)))

    if configuration is not None:
        policy_path = control.joinpath(*PurePosixPath(configuration.policy_file).parts)
        try:
            parse_policy(read_json(policy_path))
            checks.append(
                _check(
                    "CAUSURE-DOCTOR-POLICY",
                    "pass",
                    f"policy preset is valid: {policy_path}",
                )
            )
        except (OSError, ValueError) as exc:
            checks.append(_check("CAUSURE-DOCTOR-POLICY", "fail", str(exc)))

        if not configuration.github.components:
            checks.append(
                _check(
                    "CAUSURE-DOCTOR-GITHUB",
                    "warn",
                    "no GitHub components are registered; run "
                    "causure github-configure when CI onboarding is needed",
                )
            )
        else:
            github_problem: str | None = None
            generated_at_runtime: list[str] = []
            for mapping in configuration.github.components:
                case_path = root.joinpath(*PurePosixPath(mapping.case_file).parts)
                if not case_path.exists() and mapping.case_generator_adapter_id is not None:
                    generated_at_runtime.append(mapping.component_id)
                    continue
                try:
                    case = load_change_case(case_path)
                except (OSError, ValueError) as exc:
                    github_problem = f"configured case {mapping.component_id} is invalid: {exc}"
                    break
                if case.proposed_change.component is not mapping.component:
                    github_problem = (
                        f"configured case {mapping.component_id} declares "
                        f"{case.proposed_change.component.value}, expected "
                        f"{mapping.component.value}"
                    )
                    break
            checks.append(
                _check(
                    "CAUSURE-DOCTOR-GITHUB",
                    ("fail" if github_problem else "warn" if generated_at_runtime else "pass"),
                    (
                        github_problem
                        or (
                            "runtime case generation is configured and its case is "
                            "intentionally absent until the protected workflow runs: "
                            + ", ".join(generated_at_runtime)
                            if generated_at_runtime
                            else (
                                f"{len(configuration.github.components)} GitHub component "
                                "case(s) are present and type-matched"
                            )
                        )
                    ),
                )
            )

        adapter_path = control.joinpath(*PurePosixPath(configuration.adapter_directory).parts)
        try:
            candidate_count = (
                sum(
                    1
                    for path in adapter_path.iterdir()
                    if path.name != "README.md" and not path.name.startswith(".")
                )
                if adapter_path.is_dir()
                else None
            )
        except OSError as exc:
            checks.append(_check("CAUSURE-DOCTOR-ADAPTERS", "fail", str(exc)))
        else:
            if candidate_count is None:
                checks.append(
                    _check(
                        "CAUSURE-DOCTOR-ADAPTERS",
                        "fail",
                        f"trusted adapter directory is missing: {adapter_path}",
                    )
                )
            else:
                checks.append(
                    _check(
                        "CAUSURE-DOCTOR-ADAPTERS",
                        "pass",
                        "trusted adapter directory is available "
                        f"({candidate_count} candidate file(s))",
                    )
                )

    permission_targets = [root]
    if configuration is not None:
        permission_targets.append(control)
    inaccessible = [
        path for path in permission_targets if not os.access(path, os.R_OK | os.W_OK | os.X_OK)
    ]
    if inaccessible:
        checks.append(
            _check(
                "CAUSURE-DOCTOR-PERMISSIONS",
                "fail",
                "OS permission check failed for: " + ", ".join(str(path) for path in inaccessible),
            )
        )
    elif root.exists() and root.is_dir():
        checks.append(
            _check(
                "CAUSURE-DOCTOR-PERMISSIONS",
                "pass",
                "OS reports the project paths readable and writable; no probe file was created",
            )
        )

    git = shutil.which("git")
    checks.append(
        _check(
            "CAUSURE-DOCTOR-GIT",
            "pass" if git else "warn",
            f"optional Git executable found: {git}" if git else "optional Git executable not found",
        )
    )
    docker = shutil.which("docker")
    checks.append(
        _check(
            "CAUSURE-DOCTOR-CONTAINER",
            "pass" if docker else "warn",
            (
                f"optional container executable found without contacting its daemon: {docker}"
                if docker
                else "optional Docker executable not found; process adapters and the "
                "demo still work"
            ),
        )
    )

    if any(check.status == "fail" for check in checks):
        status: Literal["ready", "ready_with_warnings", "failed"] = "failed"
    elif any(check.status == "warn" for check in checks):
        status = "ready_with_warnings"
    else:
        status = "ready"
    return DoctorReport(project_root=root, status=status, checks=tuple(checks))


def doctor_document(report: DoctorReport) -> dict[str, Any]:
    """Return the stable JSON form of a doctor report."""

    return {
        "checks": [
            {"code": check.code, "message": check.message, "status": check.status}
            for check in report.checks
        ],
        "package_version": PACKAGE_VERSION,
        "project_root": str(report.project_root),
        "schema_version": DOCTOR_SCHEMA_VERSION,
        "status": report.status,
    }


def render_doctor_json(report: DoctorReport) -> str:
    """Render a machine-readable doctor report."""

    return _json_text(doctor_document(report))


def render_doctor_text(report: DoctorReport) -> str:
    """Render concise environment diagnostics and an exact next step."""

    labels = {"pass": "PASS", "warn": "WARN", "fail": "FAIL"}
    lines = [f"Causure doctor: {report.status.upper()}"]
    lines.extend(
        f"[{labels[check.status]}] {check.code}: {check.message}" for check in report.checks
    )
    if report.status == "failed":
        lines.append("Resolve the FAIL items above, then rerun this command.")
    elif any(
        check.code == "CAUSURE-DOCTOR-CONFIG" and check.status == "warn" for check in report.checks
    ):
        lines.append(f'Next: causure init "{report.project_root}"')
    else:
        lines.append(
            "Core local review is ready. Optional adapters are only needed for real evidence runs."
        )
    return "\n".join(lines)
