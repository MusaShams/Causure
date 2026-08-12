"""Guided, no-manual-JSON change-case creation."""

from __future__ import annotations

import hashlib
import json
import math
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from causure.constants import (
    CASE_SCHEMA_VERSION,
    Component,
    Consequence,
    IncidentSeverity,
    OracleKind,
    RequirementStatus,
    ValidationKind,
)
from causure.engine import review_case
from causure.investigation_workspace import (
    VerifiedInvestigationWorkspace,
    derive_safe_identifier,
)
from causure.io import atomic_write_text, load_policy, read_json
from causure.models import ChangeCase, ReviewResult, parse_change_case, to_jsonable
from causure.onboarding import (
    PROJECT_CONFIG_NAME,
    PROJECT_DIRECTORY_NAME,
    parse_project_configuration,
)
from causure.policy import GatePolicy
from causure.report import render_json, render_markdown

CASE_SOURCE_SCHEMA_VERSION = "1.0"
_CASE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}")


@dataclass(frozen=True, slots=True)
class CaseCreationResult:
    """A generated canonical case and its immediate evidence-gate review."""

    output_directory: Path
    case: ChangeCase
    result: ReviewResult
    case_path: Path
    report_path: Path
    result_path: Path


class _Prompt:
    def __init__(
        self,
        reader: Callable[[str], str],
        writer: Callable[[str], None],
    ) -> None:
        self._reader = reader
        self._writer = writer

    def _read(self, label: str) -> str:
        try:
            return self._reader(label)
        except EOFError as exc:
            raise ValueError("case creation ended before all answers were received") from exc

    def required(self, label: str, *, default: str | None = None) -> str:
        suffix = f" [{default}]" if default is not None else ""
        while True:
            value = self._read(f"{label}{suffix}: ").strip()
            if value:
                return value
            if default is not None:
                return default
            self._writer("A non-empty answer is required.")

    def identifier(self, label: str, *, default: str) -> str:
        while True:
            value = self.required(label, default=default)
            if _CASE_ID_PATTERN.fullmatch(value):
                return value
            self._writer(
                "Use 3-128 letters, digits, periods, underscores, or hyphens; "
                "start with a letter or digit."
            )

    def yes_no(self, label: str, *, default: bool = False) -> bool:
        default_label = "Y/n" if default else "y/N"
        while True:
            value = self._read(f"{label} [{default_label}]: ").strip().lower()
            if not value:
                return default
            if value in {"y", "yes"}:
                return True
            if value in {"n", "no"}:
                return False
            self._writer("Answer yes or no.")

    def integer(
        self,
        label: str,
        *,
        default: int,
        minimum: int = 0,
        maximum: int | None = None,
    ) -> int:
        while True:
            value = self._read(f"{label} [{default}]: ").strip()
            if not value:
                return default
            try:
                converted = int(value)
            except ValueError:
                self._writer("Enter a whole number.")
                continue
            if converted < minimum or (maximum is not None and converted > maximum):
                upper = f" and at most {maximum}" if maximum is not None else ""
                self._writer(f"Enter a number of at least {minimum}{upper}.")
                continue
            return converted

    def number(
        self,
        label: str,
        *,
        minimum: float = 0.0,
        maximum: float | None = None,
    ) -> float:
        while True:
            value = self._read(f"{label}: ").strip()
            try:
                converted = float(value)
            except ValueError:
                self._writer("Enter a number.")
                continue
            if not math.isfinite(converted):
                self._writer("Enter a finite number.")
                continue
            if converted < minimum or (maximum is not None and converted > maximum):
                upper = f" through {maximum:g}" if maximum is not None else " or greater"
                self._writer(f"Enter a number from {minimum:g}{upper}.")
                continue
            return converted

    def optional_number(self, label: str) -> float | None:
        while True:
            value = self._read(f"{label} (Enter if unmeasured): ").strip()
            if not value:
                return None
            try:
                converted = float(value)
            except ValueError:
                self._writer("Enter a non-negative number or leave it blank.")
                continue
            if not math.isfinite(converted) or converted < 0:
                self._writer("Enter a finite non-negative number or leave it blank.")
                continue
            return converted

    def choice(self, label: str, values: tuple[str, ...], *, default: str) -> str:
        options = ", ".join(f"{index}={value}" for index, value in enumerate(values, start=1))
        while True:
            value = self._read(f"{label} ({options}) [{default}]: ").strip()
            if not value:
                return default
            if value.isdecimal() and 1 <= int(value) <= len(values):
                return values[int(value) - 1]
            if value in values:
                return value
            self._writer("Choose one listed number or value.")

    def strings(
        self,
        label: str,
        *,
        count: int,
    ) -> list[str]:
        values: list[str] = []
        for index in range(1, count + 1):
            while True:
                value = self.required(f"{label} {index}")
                if value not in values:
                    values.append(value)
                    break
                self._writer("That value was already entered.")
        return values


def _timestamp(value: datetime | None = None) -> str:
    instant = value or datetime.now(UTC)
    if instant.tzinfo is None:
        raise ValueError("case creation timestamp must include a timezone")
    return instant.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _metric_snapshot(prompt: _Prompt, label: str) -> dict[str, float]:
    values = {
        "p95_latency_ms": prompt.optional_number(f"{label} p95 latency in milliseconds"),
        "mean_cost_usd": prompt.optional_number(f"{label} mean cost in USD"),
        "mean_tokens": prompt.optional_number(f"{label} mean token count"),
    }
    return {name: value for name, value in values.items() if value is not None}


def collect_guided_case(
    workspace: VerifiedInvestigationWorkspace,
    *,
    reader: Callable[[str], str] = input,
    writer: Callable[[str], None] = print,
    created_at: datetime | None = None,
) -> ChangeCase:
    """Ask plain-language questions and return a canonical validated change case."""

    prompt = _Prompt(reader, writer)
    fixture_id = workspace.fixture.fixture_id
    base = fixture_id.removesuffix("-investigation")
    default_case_id = derive_safe_identifier(
        f"{base}-case",
        fallback="agent-change-case",
    )
    writer(
        f"Verified investigation {fixture_id} with "
        f"{len(workspace.selected_clusters)} selected trace cluster(s)."
    )
    writer("Selected traces are observations only; this wizard will not infer a failure or cause.")
    writer("Enter 0 for evidence sections you have not completed; the gate will request it.")

    writer("\nCase identity")
    case_id = prompt.identifier("Case ID", default=default_case_id)
    title = prompt.required(
        "Short case title",
        default=f"Agent change review for {workspace.manifest.source.artifact_id}",
    )

    writer("\nObserved incident")
    claimed_failure = prompt.required("What failure do you believe occurred?")
    expected_behavior = prompt.required("What should have happened instead?")
    observed_behavior = prompt.required("What did the selected traces show?")
    severity = prompt.choice(
        "Incident severity",
        tuple(item.value for item in IncidentSeverity),
        default=IncidentSeverity.MEDIUM.value,
    )
    requirement_status = prompt.choice(
        "Governing requirement status",
        tuple(item.value for item in RequirementStatus),
        default=RequirementStatus.UNKNOWN.value,
    )

    writer("\nFailure oracle")
    oracle_kind = prompt.choice(
        "Oracle kind",
        tuple(item.value for item in OracleKind),
        default=OracleKind.CUSTOM.value,
    )
    oracle_description = prompt.required(
        "How will correctness be decided independently of the proposed change?"
    )
    oracle_independent = prompt.yes_no(
        "Is that oracle independent of the proposed change?",
        default=False,
    )
    oracle_reference_count = prompt.integer(
        "How many oracle definition or result references do you have?",
        default=1,
        minimum=1,
        maximum=100,
    )
    oracle_refs = prompt.strings(
        "Oracle reference",
        count=oracle_reference_count,
    )

    writer("\nReproduction evidence")
    reproduction_count = prompt.integer(
        "How many completed reproduction trials do you want to add?",
        default=0,
        maximum=10_000,
    )
    reproduction_trials: list[dict[str, Any]] = []
    for index in range(1, reproduction_count + 1):
        writer(f"Reproduction trial {index}")
        reproduction_trials.append(
            {
                "id": prompt.required("Trial ID", default=f"repro-{index:02d}"),
                "reproduced": prompt.yes_no("Did the claimed failure reproduce?"),
                "evidence_ref": prompt.required("Exact reproduction evidence reference"),
            }
        )

    writer("\nCausal hypotheses")
    hypothesis_count = prompt.integer(
        "How many evidence-backed causal hypotheses do you want to add?",
        default=0,
        maximum=len(Component),
    )
    hypotheses: list[dict[str, Any]] = []
    used_components: set[str] = set()
    component_values = tuple(item.value for item in Component)
    for index in range(1, hypothesis_count + 1):
        writer(f"Hypothesis {index}")
        while True:
            component = prompt.choice(
                "Suspected component",
                component_values,
                default=Component.OTHER.value,
            )
            if component not in used_components:
                used_components.add(component)
                break
            writer("Each hypothesis must identify a different component.")
        confidence = prompt.number(
            "Evidence-backed confidence from 0 through 1",
            maximum=1.0,
        )
        reference_count = prompt.integer(
            "How many attribution evidence references?",
            default=1,
            minimum=1,
            maximum=100,
        )
        hypothesis: dict[str, Any] = {
            "component": component,
            "confidence": confidence,
            "evidence_refs": prompt.strings(
                "Attribution evidence reference",
                count=reference_count,
            ),
        }
        if prompt.yes_no("Add isolated-intervention evidence for this hypothesis?"):
            intervention_description = prompt.required("Describe the isolated intervention")
            intervention_isolated = prompt.yes_no(
                "Was the suspected component isolated?",
                default=False,
            )
            held_constant_count = prompt.integer(
                "How many important variables were held constant?",
                default=1,
                minimum=1,
                maximum=100,
            )
            held_constant = prompt.strings(
                "Held-constant variable",
                count=held_constant_count,
            )
            intervention_trial_count = prompt.integer(
                "How many completed intervention trials?",
                default=0,
                maximum=10_000,
            )
            intervention_trials: list[dict[str, Any]] = []
            for trial_index in range(1, intervention_trial_count + 1):
                writer(f"Intervention trial {trial_index}")
                intervention_trials.append(
                    {
                        "id": prompt.required(
                            "Trial ID",
                            default=f"intervention-{trial_index:02d}",
                        ),
                        "failure_resolved": prompt.yes_no(
                            "Did changing only this component resolve the failure?"
                        ),
                        "evidence_ref": prompt.required("Exact intervention evidence reference"),
                    }
                )
            hypothesis["intervention"] = {
                "description": intervention_description,
                "isolated": intervention_isolated,
                "held_constant": held_constant,
                "trials": intervention_trials,
            }
        hypotheses.append(hypothesis)

    writer("\nProposed change")
    default_component = hypotheses[0]["component"] if hypotheses else Component.OTHER.value
    proposed_component = prompt.choice(
        "Harness component to change",
        component_values,
        default=default_component,
    )
    proposed_summary = prompt.required("Describe the smallest proposed change")
    prediction = prompt.required("What exact effect do you predict?")
    unaffected_count = prompt.integer(
        "How many behaviors must remain unaffected?",
        default=1,
        minimum=1,
        maximum=1_000,
    )
    unaffected = prompt.strings("Expected unaffected behavior", count=unaffected_count)
    risk_count = prompt.integer(
        "How many known risks do you want to record?",
        default=0,
        maximum=1_000,
    )
    known_risks = prompt.strings("Known risk", count=risk_count)
    changed_surface_count = prompt.integer(
        "How many harness surfaces will change?",
        default=1,
        minimum=1,
        maximum=10_000,
    )
    change_ref = prompt.required("Reference for the proposed diff or working change")

    writer("\nNo-change alternative")
    null_statement = prompt.required(
        "Why might no harness modification be necessary?",
        default=(
            "No harness modification is necessary; the observed behavior may be transient "
            "or environmental."
        ),
    )
    null_evidence_count = prompt.integer(
        "How many evidence items currently argue against no change?",
        default=0,
        maximum=1_000,
    )
    null_evidence = prompt.strings(
        "Evidence against no change",
        count=null_evidence_count,
    )

    writer("\nValidation controls")
    validation_count = prompt.integer(
        "How many completed positive, negative, or regression cases do you want to add?",
        default=0,
        maximum=100_000,
    )
    validation_cases: list[dict[str, Any]] = []
    for index in range(1, validation_count + 1):
        writer(f"Validation case {index}")
        validation_cases.append(
            {
                "id": prompt.required("Validation case ID", default=f"control-{index:02d}"),
                "kind": prompt.choice(
                    "Control kind",
                    tuple(item.value for item in ValidationKind),
                    default=ValidationKind.REGRESSION.value,
                ),
                "critical": prompt.yes_no("Is this behavior critical?"),
                "baseline_passed": prompt.yes_no("Did the baseline pass?"),
                "candidate_passed": prompt.yes_no("Did the candidate pass?"),
                "evidence_ref": prompt.required("Exact validation evidence reference"),
            }
        )

    metrics: dict[str, Any] | None = None
    if prompt.yes_no("Add measured baseline and candidate cost/latency/token metrics?"):
        baseline_metrics = _metric_snapshot(prompt, "Baseline")
        candidate_metrics = _metric_snapshot(prompt, "Candidate")
        if not baseline_metrics and not candidate_metrics:
            writer("No metric values were entered; the metrics section will remain absent.")
        else:
            if set(baseline_metrics) != set(candidate_metrics):
                raise ValueError(
                    "baseline and candidate metrics must measure the same fields; "
                    "restart case creation and provide both sides"
                )
            metrics = {"baseline": baseline_metrics, "candidate": candidate_metrics}

    document: dict[str, Any] = {
        "schema_version": CASE_SCHEMA_VERSION,
        "case_id": case_id,
        "title": title,
        "created_at": _timestamp(created_at),
        "incident": {
            "claimed_failure": claimed_failure,
            "expected_behavior": expected_behavior,
            "observed_behavior": observed_behavior,
            "severity": severity,
            "requirement_status": requirement_status,
            "source_refs": [cluster.trace_ref for cluster in workspace.selected_clusters],
        },
        "verification": {
            "oracle": {
                "kind": oracle_kind,
                "description": oracle_description,
                "independent": oracle_independent,
                "evidence_refs": oracle_refs,
            },
            "reproduction_trials": reproduction_trials,
        },
        "attribution": {"hypotheses": hypotheses},
        "proposed_change": {
            "component": proposed_component,
            "summary": proposed_summary,
            "prediction": prediction,
            "expected_unaffected_behaviors": unaffected,
            "known_risks": known_risks,
            "changed_surface_count": changed_surface_count,
            "change_ref": change_ref,
        },
        "null_hypothesis": {
            "statement": null_statement,
            "evidence_against": null_evidence,
        },
        "validation": {"cases": validation_cases},
    }
    if metrics is not None:
        document["validation"]["metrics"] = metrics
    return parse_change_case(document)


def render_case_preview(case: ChangeCase) -> str:
    """Render a concise, pre-write summary of the guided answers."""

    return "\n".join(
        [
            "Guided case preview",
            f"Case: {case.case_id} - {case.title}",
            f"Proposed component: {case.proposed_change.component.value}",
            f"Reproduction trials supplied: {len(case.verification.reproduction_trials)}",
            f"Causal hypotheses supplied: {len(case.attribution.hypotheses)}",
            f"Validation cases supplied: {len(case.validation.cases)}",
            "Missing sections remain empty and will produce explicit evidence requests.",
        ]
    )


def load_case_policy(
    workspace: VerifiedInvestigationWorkspace,
    override_path: str | Path | None,
) -> GatePolicy:
    """Load an explicit policy, the associated project preset, or defaults."""

    if override_path is not None:
        return load_policy(override_path)
    if workspace.project_root is None:
        return GatePolicy()
    control = workspace.project_root / PROJECT_DIRECTORY_NAME
    configuration = parse_project_configuration(read_json(control / PROJECT_CONFIG_NAME))
    policy_path = control.joinpath(*PurePosixPath(configuration.policy_file).parts)
    return load_policy(policy_path)


def default_case_output(
    workspace: VerifiedInvestigationWorkspace,
    case_id: str,
) -> Path:
    """Choose a project artifact path or a standalone sibling path."""

    if workspace.project_root is not None:
        control = workspace.project_root / PROJECT_DIRECTORY_NAME
        configuration = parse_project_configuration(read_json(control / PROJECT_CONFIG_NAME))
        artifact_root = control.joinpath(*PurePosixPath(configuration.artifact_directory).parts)
        return artifact_root / "cases" / case_id
    return workspace.directory.parent / "causure-cases" / case_id


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


def _case_readme(case: ChangeCase, result: ReviewResult) -> str:
    required = [
        finding for finding in result.findings if finding.consequence is not Consequence.NONE
    ]
    lines = [
        f"# Causure case: {case.case_id}",
        "",
        f"> **{result.decision.value.upper()}** / "
        f"**{result.recommended_action.value.upper()}** - {result.summary}",
        "",
        "- `change-case.json` is the canonical portable evidence bundle.",
        "- `report.md` explains the gate decision and findings.",
        "- `review-result.json` is the machine-readable gate result.",
        "- `case-source.json` binds the case bytes to the exact investigation selection.",
        "",
    ]
    if required:
        lines.extend(["## Required next evidence or resolution", ""])
        lines.extend(f"- `{finding.code}`: {finding.message}" for finding in required)
        lines.append("")
    lines.extend(
        [
            "The wizard never invents missing trials, hypotheses, controls, or measurements.",
            "A `needs_evidence` result is a successful and expected outcome for an early case.",
            "",
        ]
    )
    return "\n".join(lines)


def create_case_workspace(
    workspace: VerifiedInvestigationWorkspace,
    case: ChangeCase,
    *,
    policy: GatePolicy | None = None,
    output_directory: str | Path | None = None,
    reviewed_at: datetime | None = None,
) -> CaseCreationResult:
    """Review and write a canonical case into a new, hash-bound output directory."""

    expected_source_refs = tuple(cluster.trace_ref for cluster in workspace.selected_clusters)
    if case.incident.source_refs != expected_source_refs:
        raise ValueError("case source references do not match the verified investigation selection")
    destination = (
        default_case_output(workspace, case.case_id)
        if output_directory is None
        else Path(output_directory).expanduser().resolve()
    )
    destination = destination.resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        destination.mkdir()
    except FileExistsError as exc:
        raise ValueError(
            f"case output already exists; choose a new directory: {destination}"
        ) from exc
    except OSError as exc:
        raise ValueError(f"could not create case output {destination}: {exc}") from exc

    completed = False
    try:
        case_text = _json_text(to_jsonable(case))
        case_bytes = case_text.encode("utf-8")
        result = review_case(case, policy, reviewed_at=reviewed_at)
        case_path = destination / "change-case.json"
        result_path = destination / "review-result.json"
        report_path = destination / "report.md"
        atomic_write_text(case_path, case_text)
        atomic_write_text(result_path, render_json(result))
        atomic_write_text(report_path, render_markdown(case, result))
        atomic_write_text(
            destination / "case-source.json",
            _json_text(
                {
                    "change_case": {
                        "byte_count": len(case_bytes),
                        "path": "change-case.json",
                        "sha256": hashlib.sha256(case_bytes).hexdigest(),
                    },
                    "investigation": {
                        "fixture_id": workspace.fixture.fixture_id,
                        "selected_cluster_ids": [
                            cluster.cluster_id for cluster in workspace.selected_clusters
                        ],
                        "selection_byte_count": len(workspace.selection_bytes),
                        "selection_sha256": hashlib.sha256(workspace.selection_bytes).hexdigest(),
                    },
                    "raw_trace_content_stored": False,
                    "schema_version": CASE_SOURCE_SCHEMA_VERSION,
                }
            ),
        )
        atomic_write_text(destination / "README.md", _case_readme(case, result))
        completed = True
        return CaseCreationResult(
            output_directory=destination,
            case=case,
            result=result,
            case_path=case_path,
            report_path=report_path,
            result_path=result_path,
        )
    finally:
        if not completed:
            shutil.rmtree(destination, ignore_errors=True)


def render_case_creation_summary(created: CaseCreationResult) -> str:
    """Render the successful guided-case terminal result."""

    required_count = sum(
        finding.consequence is not Consequence.NONE for finding in created.result.findings
    )
    return "\n".join(
        [
            f"Created canonical case at {created.output_directory}",
            f"Decision: {created.result.decision.value.upper()}",
            f"Recommended action: {created.result.recommended_action.value.upper()}",
            f"Required evidence or resolution items: {required_count}",
            f"Open report: {created.report_path}",
            "For PR automation, copy change-case.json to a reviewed repository path, then "
            "run: causure github-configure --help",
        ]
    )
