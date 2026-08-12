"""Separately trusted, candidate-nonexecuting GitHub case generation."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from causure.adapters import (
    MAX_CANDIDATE_COMPONENT_BYTES,
    CaseGenerationBudget,
    CaseGenerationRequest,
)
from causure.constants import (
    PACKAGE_VERSION,
    TRUSTED_CASE_GENERATION_RECEIPT_SCHEMA_VERSION,
)
from causure.engine import review_case
from causure.github_selection import (
    GitHubChangedFile,
    select_configured_github_change,
)
from causure.io import atomic_write_text, load_policy, read_json
from causure.models import ChangeCase, ReviewResult, to_jsonable
from causure.onboarding import (
    PROJECT_CONFIG_NAME,
    PROJECT_DIRECTORY_NAME,
    parse_project_configuration,
)
from causure.report import render_json, render_markdown
from causure.runner import CaseGenerationRunResult, ProcessAdapterRunner

MAX_TRUSTED_ADAPTER_FILES = 256
MAX_TRUSTED_ADAPTER_DIRECTORY_BYTES = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class FileIntegrity:
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class AdapterDirectoryIntegrity:
    sha256: str
    byte_count: int
    file_count: int


@dataclass(frozen=True, slots=True)
class TrustedCaseGenerationResult:
    """New canonical case, review, and minimized provenance artifacts."""

    output_directory: Path
    configured_case_path: Path
    generated_case_path: Path
    result_path: Path
    report_path: Path
    receipt_path: Path
    case: ChangeCase
    result: ReviewResult
    receipt: dict[str, Any]


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


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


def _timestamp(value: datetime | None) -> tuple[datetime, str]:
    generated_at = datetime.now(UTC) if value is None else value
    if generated_at.tzinfo is None or generated_at.utcoffset() is None:
        raise ValueError("generated_at must include a timezone")
    normalized = generated_at.astimezone(UTC).replace(microsecond=0)
    return normalized, normalized.isoformat().replace("+00:00", "Z")


def _bounded_file_integrity(path: Path, *, maximum_bytes: int) -> tuple[bytes, FileIntegrity]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"candidate component must be a regular non-symlink file: {path}")
    try:
        size = path.stat().st_size
        if size > maximum_bytes:
            raise ValueError(f"candidate component exceeds the {maximum_bytes}-byte limit: {path}")
        contents = path.read_bytes()
    except OSError as exc:
        raise ValueError(f"could not read candidate component: {type(exc).__name__}") from exc
    if len(contents) != size or len(contents) > maximum_bytes:
        raise ValueError("candidate component changed while it was being read")
    return contents, FileIntegrity(
        sha256=hashlib.sha256(contents).hexdigest(),
        byte_count=len(contents),
    )


def _adapter_directory_integrity(directory: Path) -> AdapterDirectoryIntegrity:
    root = directory.resolve(strict=True)
    if directory.is_symlink() or not root.is_dir():
        raise ValueError("trusted adapter directory must be a regular directory")
    files: list[tuple[str, bytes]] = []
    for current_root, directory_names, file_names in os.walk(root, followlinks=False):
        directory_names.sort()
        file_names.sort()
        current = Path(current_root)
        if not _is_within(current.resolve(strict=True), root):
            raise ValueError("trusted adapter directory contains an escaping directory")
        for directory_name in tuple(directory_names):
            child = current / directory_name
            if child.is_symlink() or not _is_within(child.resolve(strict=True), root):
                raise ValueError("trusted adapter directory cannot contain links")
        for file_name in file_names:
            path = current / file_name
            if path.is_symlink():
                raise ValueError("trusted adapter directory cannot contain linked files")
            resolved = path.resolve(strict=True)
            if not _is_within(resolved, root) or not resolved.is_file():
                raise ValueError("trusted adapter directory contains an invalid file")
            contents = resolved.read_bytes()
            relative = resolved.relative_to(root).as_posix()
            files.append((relative, contents))
            if len(files) > MAX_TRUSTED_ADAPTER_FILES:
                raise ValueError(
                    f"trusted adapter directory exceeds the {MAX_TRUSTED_ADAPTER_FILES}-file limit"
                )
            if sum(len(item[1]) for item in files) > MAX_TRUSTED_ADAPTER_DIRECTORY_BYTES:
                raise ValueError(
                    "trusted adapter directory exceeds the "
                    f"{MAX_TRUSTED_ADAPTER_DIRECTORY_BYTES}-byte limit"
                )
    digest = hashlib.sha256()
    total_bytes = 0
    for relative, contents in files:
        relative_bytes = relative.encode("utf-8")
        digest.update(len(relative_bytes).to_bytes(4, "big"))
        digest.update(relative_bytes)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
        total_bytes += len(contents)
    return AdapterDirectoryIntegrity(
        sha256=digest.hexdigest(),
        byte_count=total_bytes,
        file_count=len(files),
    )


def _new_path(path: str | Path, *, description: str) -> Path:
    candidate = Path(path).expanduser().resolve()
    if os.path.lexists(candidate):
        raise ValueError(f"{description} already exists; choose a new path: {candidate}")
    return candidate


def _receipt_document(
    *,
    generated_at: str,
    project_id: str,
    adapter_id: str,
    entry_point: str,
    adapter_integrity: AdapterDirectoryIntegrity,
    run: CaseGenerationRunResult,
    request: CaseGenerationRequest,
    case_path: str,
    case: ChangeCase,
    case_integrity: FileIntegrity,
) -> dict[str, Any]:
    return {
        "adapter": {
            "adapter_id": adapter_id,
            "directory_byte_count": adapter_integrity.byte_count,
            "directory_file_count": adapter_integrity.file_count,
            "directory_sha256": adapter_integrity.sha256,
            "entry_module_byte_count": run.entry_module_byte_count,
            "entry_module_path": run.entry_module_path,
            "entry_module_sha256": run.entry_module_sha256,
            "entry_point": entry_point,
            "kind": "case_generator",
        },
        "change_case": {
            "byte_count": case_integrity.byte_count,
            "case_id": case.case_id,
            "path": case_path,
            "sha256": case_integrity.sha256,
        },
        "component": {
            "byte_count": request.component_byte_count,
            "change_ref": request.expected_change_ref,
            "component": request.component.value,
            "component_id": request.component_id,
            "path": request.component_path,
            "sha256": request.component_sha256,
        },
        "execution": {
            "adapter_loaded_from_trusted_directory": True,
            "candidate_code_executed": False,
            "candidate_component_content_embedded_in_receipt": False,
            "candidate_root_stored": False,
            "maximum_case_bytes": request.budget.maximum_case_bytes,
            "timeout_seconds": request.budget.timeout_seconds,
        },
        "generated_at": generated_at,
        "generator_version": PACKAGE_VERSION,
        "project_id": project_id,
        "pull_request": {
            "base_sha": request.base_sha,
            "head_sha": request.head_sha,
            "number": request.pull_request_number,
            "repository": request.repository,
        },
        "request_id": request.request_id,
        "schema_version": TRUSTED_CASE_GENERATION_RECEIPT_SCHEMA_VERSION,
    }


def generate_configured_github_case(
    trusted_project: str | Path,
    candidate_root: str | Path,
    *,
    component_id: str,
    component_path: str,
    repository: str,
    pull_request_number: int,
    base_sha: str,
    head_sha: str,
    output_directory: str | Path,
    budget: CaseGenerationBudget | None = None,
    generated_at: datetime | None = None,
    runner: ProcessAdapterRunner | None = None,
) -> TrustedCaseGenerationResult:
    """Generate one configured case without importing or executing candidate code."""

    trusted_root = Path(trusted_project).expanduser().resolve(strict=True)
    candidate = Path(candidate_root).expanduser().resolve(strict=True)
    if not trusted_root.is_dir() or not candidate.is_dir():
        raise ValueError("trusted project and candidate roots must be directories")
    if trusted_root == candidate:
        raise ValueError("trusted project and candidate roots must be separate checkouts")

    control = trusted_root / PROJECT_DIRECTORY_NAME
    configuration_path = control / PROJECT_CONFIG_NAME
    configuration = parse_project_configuration(read_json(configuration_path))
    mapping = next(
        (item for item in configuration.github.components if item.component_id == component_id),
        None,
    )
    if mapping is None:
        raise ValueError(f"configured GitHub component was not found: {component_id}")
    if mapping.case_generator_adapter_id is None:
        raise ValueError(f"GitHub component {component_id} has no trusted case_generator adapter")
    adapter = next(
        (
            item
            for item in configuration.trusted_adapter_entry_points
            if item.adapter_id == mapping.case_generator_adapter_id
        ),
        None,
    )
    if adapter is None or adapter.kind != "case_generator":
        raise ValueError("configured case generator is missing or has the wrong kind")

    selection = select_configured_github_change(
        configuration,
        (GitHubChangedFile(path=component_path, previous_path=None),),
        config_repository_path=f"{PROJECT_DIRECTORY_NAME}/{PROJECT_CONFIG_NAME}",
    )
    if selection is None or selection.component_id != mapping.component_id:
        raise ValueError(
            f"component path does not select configured component {mapping.component_id}"
        )

    candidate_component = candidate.joinpath(*PurePosixPath(component_path).parts)
    if candidate_component.is_symlink():
        raise ValueError("candidate component cannot be a symbolic link")
    try:
        resolved_component = candidate_component.resolve(strict=True)
    except OSError as exc:
        raise ValueError("candidate component path is unavailable") from exc
    if not _is_within(resolved_component, candidate):
        raise ValueError("candidate component path escapes the candidate root")
    _, component_integrity = _bounded_file_integrity(
        resolved_component,
        maximum_bytes=MAX_CANDIDATE_COMPONENT_BYTES,
    )

    adapter_directory = control.joinpath(*PurePosixPath(configuration.adapter_directory).parts)
    adapter_root = adapter_directory.resolve(strict=True)
    if not _is_within(adapter_root, control.resolve(strict=True)):
        raise ValueError("trusted adapter directory escapes the protected project control")
    adapter_integrity = _adapter_directory_integrity(adapter_directory)

    destination = _new_path(output_directory, description="generation output directory")
    case_destination = _new_path(
        candidate.joinpath(*PurePosixPath(mapping.case_file).parts),
        description="configured generated case",
    )
    if not _is_within(case_destination, candidate):
        raise ValueError("configured generated case path escapes the candidate root")
    if _is_within(destination, adapter_root) or _is_within(case_destination, adapter_root):
        raise ValueError("generated output cannot be placed in the trusted adapter directory")
    if _is_within(case_destination, destination) or _is_within(destination, case_destination):
        raise ValueError("generation output directory and configured case path must be separate")

    execution_budget = budget or CaseGenerationBudget()
    request = CaseGenerationRequest(
        request_id=f"pr-{pull_request_number}-{head_sha[:12]}-{mapping.component_id}",
        project_id=configuration.project_id,
        repository=repository,
        pull_request_number=pull_request_number,
        base_sha=base_sha,
        head_sha=head_sha,
        component_id=mapping.component_id,
        component=mapping.component,
        component_path=component_path,
        candidate_root=str(candidate),
        component_sha256=component_integrity.sha256,
        component_byte_count=component_integrity.byte_count,
        budget=execution_budget,
    )
    adapter_run = (runner or ProcessAdapterRunner()).run_case_generation(
        adapter_directory,
        adapter.entry_point,
        request,
    )
    _, component_after = _bounded_file_integrity(
        resolved_component,
        maximum_bytes=MAX_CANDIDATE_COMPONENT_BYTES,
    )
    if component_after != component_integrity:
        raise ValueError("candidate component changed during trusted case generation")
    if _adapter_directory_integrity(adapter_directory) != adapter_integrity:
        raise ValueError("trusted adapter directory changed during case generation")

    case = adapter_run.case
    if case.proposed_change.component is not mapping.component:
        raise ValueError(
            f"generated case declares {case.proposed_change.component.value}, expected "
            f"{mapping.component.value}"
        )
    if case.proposed_change.change_ref != request.expected_change_ref:
        raise ValueError(
            "generated case change_ref does not bind the exact pull-request head and component"
        )

    normalized_time, generated_at_text = _timestamp(generated_at)
    policy_path = control.joinpath(*PurePosixPath(configuration.policy_file).parts)
    result = review_case(case, load_policy(policy_path), reviewed_at=normalized_time)
    case_text = _json_text(to_jsonable(case))
    case_bytes = case_text.encode("utf-8")
    if len(case_bytes) > execution_budget.maximum_case_bytes:
        raise ValueError("generated canonical case exceeds the configured byte limit")
    case_integrity = FileIntegrity(
        sha256=hashlib.sha256(case_bytes).hexdigest(),
        byte_count=len(case_bytes),
    )
    receipt = _receipt_document(
        generated_at=generated_at_text,
        project_id=configuration.project_id,
        adapter_id=adapter.adapter_id,
        entry_point=adapter.entry_point,
        adapter_integrity=adapter_integrity,
        run=adapter_run,
        request=request,
        case_path=mapping.case_file,
        case=case,
        case_integrity=case_integrity,
    )

    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.mkdir()
    case_written = False
    try:
        generated_case_path = destination / "change-case.json"
        result_path = destination / "review-result.json"
        report_path = destination / "report.md"
        receipt_path = destination / "trusted-case-generation.json"
        atomic_write_text(generated_case_path, case_text)
        atomic_write_text(result_path, render_json(result))
        atomic_write_text(report_path, render_markdown(case, result))
        atomic_write_text(receipt_path, _json_text(receipt))
        atomic_write_text(
            destination / "README.md",
            "\n".join(
                [
                    f"# Trusted generated case: {case.case_id}",
                    "",
                    f"Decision: **{result.decision.value.upper()}**",
                    "",
                    "- `change-case.json` is the exact generated canonical case.",
                    "- `trusted-case-generation.json` binds it to the adapter and PR head.",
                    "- `report.md` explains the deterministic review.",
                    "- `review-result.json` is the machine-readable gate decision.",
                    "",
                    "Candidate code was treated as data and was not imported or executed.",
                    "",
                ]
            ),
        )
        case_destination.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(case_destination, case_text)
        case_written = True
        return TrustedCaseGenerationResult(
            output_directory=destination,
            configured_case_path=case_destination,
            generated_case_path=generated_case_path,
            result_path=result_path,
            report_path=report_path,
            receipt_path=receipt_path,
            case=case,
            result=result,
            receipt=receipt,
        )
    finally:
        if not case_written:
            shutil.rmtree(destination, ignore_errors=True)
            try:
                case_destination.unlink(missing_ok=True)
            except OSError:
                pass


def render_trusted_case_generation_summary(generated: TrustedCaseGenerationResult) -> str:
    """Render the successful protected-generation handoff to the Action."""

    return "\n".join(
        [
            f"Generated trusted case for {generated.case.case_id}",
            f"  Decision: {generated.result.decision.value.upper()}",
            f"  Configured case: {generated.configured_case_path}",
            f"  Provenance receipt: {generated.receipt_path}",
            f"  Report: {generated.report_path}",
            "Next: run the pinned Causure Action in this same protected job.",
        ]
    )
