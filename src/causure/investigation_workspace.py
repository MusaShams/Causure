"""Guided, content-minimized local investigation workspaces."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from causure.collector import (
    DEFAULT_MAX_SPANS,
    TraceManifest,
    collect_otlp_trace_manifest,
    render_trace_manifest,
)
from causure.constants import INVESTIGATION_SELECTION_SCHEMA_VERSION
from causure.fixtures import (
    DEFAULT_MAX_CLUSTERS,
    MAX_INVESTIGATION_FIXTURE_BYTES,
    MAX_MANIFEST_DOCUMENT_BYTES,
    CandidateTraceCluster,
    InvestigationFixture,
    generate_investigation_fixture,
    parse_investigation_fixture_bytes,
    render_investigation_fixture,
)
from causure.io import (
    MAX_TRACE_DOCUMENT_BYTES,
    atomic_write_text,
    parse_json_text,
    read_json,
    read_json_with_bytes,
)
from causure.onboarding import (
    PROJECT_CONFIG_NAME,
    PROJECT_DIRECTORY_NAME,
    parse_project_configuration,
)
from causure.trace_manifest import parse_trace_manifest

MAX_INVESTIGATION_SELECTION_BYTES = 1024 * 1024
_UNSAFE_IDENTIFIER_CHARACTERS = re.compile(r"[^a-z0-9._-]+")
_SHA256_PATTERN = re.compile(r"[a-f0-9]{64}")
_CLUSTER_ID_PATTERN = re.compile(r"trace-[a-f0-9]{64}")


@dataclass(frozen=True, slots=True)
class PreparedInvestigation:
    """A redacted manifest and candidate-only fixture prepared in memory."""

    source_path: Path
    manifest: TraceManifest
    manifest_text: str
    fixture: InvestigationFixture
    fixture_text: str


@dataclass(frozen=True, slots=True)
class InvestigationWorkspace:
    """A completed local investigation workspace."""

    output_directory: Path
    selected_cluster_ids: tuple[str, ...]
    manifest_path: Path
    fixture_path: Path
    notes_path: Path


@dataclass(frozen=True, slots=True)
class VerifiedInvestigationWorkspace:
    """A hash-verified investigation workspace safe to consume downstream."""

    directory: Path
    project_root: Path | None
    selection_bytes: bytes
    manifest_bytes: bytes
    fixture_bytes: bytes
    manifest: TraceManifest
    fixture: InvestigationFixture
    selected_clusters: tuple[CandidateTraceCluster, ...]


class InvestigationWorkspaceValidationError(ValueError):
    """Raised when a local investigation workspace is incomplete or changed."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"Invalid investigation workspace at {path}: {message}")


def derive_safe_identifier(value: str, *, fallback: str, maximum: int = 128) -> str:
    """Derive an identifier accepted by the collector and fixture contracts."""

    ascii_value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode("ascii")
    identifier = _UNSAFE_IDENTIFIER_CHARACTERS.sub("-", ascii_value.lower()).strip("._-")
    identifier = identifier[:maximum].rstrip("._-")
    if len(identifier) < 3:
        identifier = fallback[:maximum].rstrip("._-")
    return identifier


def prepare_investigation(
    trace_path: str | Path,
    *,
    source_id: str | None = None,
    investigation_id: str | None = None,
    max_spans: int = DEFAULT_MAX_SPANS,
    max_clusters: int = DEFAULT_MAX_CLUSTERS,
) -> PreparedInvestigation:
    """Collect and cluster an exact OTLP JSON export without retaining raw content."""

    if str(trace_path) == "-":
        raise ValueError(
            "investigate requires a file path so generated artifacts bind exact source bytes"
        )
    source_path = Path(trace_path).expanduser().resolve()
    document, raw_bytes = read_json_with_bytes(
        source_path,
        max_bytes=MAX_TRACE_DOCUMENT_BYTES,
    )
    source_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    selected_source_id = source_id or f"trace-export-{source_sha256[:12]}"
    selected_investigation_id = investigation_id or derive_safe_identifier(
        f"{selected_source_id}-investigation",
        fallback="local-investigation",
    )
    manifest = collect_otlp_trace_manifest(
        document,
        raw_bytes=raw_bytes,
        source_id=selected_source_id,
        max_spans=max_spans,
    )
    if manifest.redaction.raw_content_included or manifest.source.source_embedded:
        raise ValueError("investigation collector unexpectedly retained raw source content")
    manifest_text = render_trace_manifest(manifest)
    manifest_document = parse_json_text(
        manifest_text,
        source="<generated-trace-manifest>",
    )
    fixture = generate_investigation_fixture(
        manifest_document,
        raw_bytes=manifest_text.encode("utf-8"),
        fixture_id=selected_investigation_id,
        max_clusters=max_clusters,
    )
    return PreparedInvestigation(
        source_path=source_path,
        manifest=manifest,
        manifest_text=manifest_text,
        fixture=fixture,
        fixture_text=render_investigation_fixture(fixture),
    )


def _list_text(values: tuple[str, ...]) -> str:
    return ", ".join(values) if values else "not retained"


def render_investigation_preview(prepared: PreparedInvestigation) -> str:
    """Render a content-free redaction and cluster preview."""

    manifest = prepared.manifest
    redaction = manifest.redaction
    lines = [
        "Causure redaction preview",
        f"Source artifact ID: {manifest.source.artifact_id}",
        f"Source bytes: {manifest.source.byte_count}",
        f"Source SHA-256: {manifest.source.sha256}",
        f"Trace clusters: {manifest.source.trace_count}",
        f"Spans: {manifest.source.span_count}",
        "Raw content included: NO",
        (
            "Attributes: "
            f"{redaction.retained_attribute_count} retained, "
            f"{redaction.redacted_attribute_count} redacted, "
            f"{redaction.dropped_attribute_count} dropped"
        ),
        "Candidate traces:",
    ]
    for index, cluster in enumerate(prepared.fixture.candidate_clusters, start=1):
        lines.extend(
            [
                (
                    f"  [{index}] {cluster.cluster_id[:22]}... - "
                    f"{cluster.span_count} span(s), {cluster.error_span_count} error span(s)"
                ),
                f"      models: {_list_text(cluster.model_identifiers)}",
                f"      providers: {_list_text(cluster.provider_identifiers)}",
            ]
        )
    lines.extend(
        [
            "No failure, requirement, or causal conclusion has been inferred.",
            "Nothing has been written yet.",
        ]
    )
    return "\n".join(lines)


def select_cluster_ids(
    prepared: PreparedInvestigation,
    selection: str,
) -> tuple[str, ...]:
    """Resolve friendly one-based indices or exact cluster IDs."""

    clusters = prepared.fixture.candidate_clusters
    normalized = selection.strip()
    if not normalized or normalized.lower() == "all":
        return tuple(cluster.cluster_id for cluster in clusters)

    available = {cluster.cluster_id for cluster in clusters}
    selected: set[str] = set()
    for raw_token in normalized.split(","):
        token = raw_token.strip()
        if not token:
            raise ValueError("cluster selection contains an empty item")
        if token.isdecimal():
            index = int(token)
            if not 1 <= index <= len(clusters):
                raise ValueError(
                    f"cluster selection index must be from 1 to {len(clusters)}: {token}"
                )
            selected.add(clusters[index - 1].cluster_id)
        elif token in available:
            selected.add(token)
        else:
            raise ValueError(f"unknown cluster selection: {token}")
    return tuple(cluster.cluster_id for cluster in clusters if cluster.cluster_id in selected)


def default_investigation_output(
    prepared: PreparedInvestigation,
    *,
    project_root: str | Path | None = None,
) -> Path:
    """Choose the configured artifact directory or a standalone local default."""

    root = Path.cwd() if project_root is None else Path(project_root)
    root = root.expanduser().resolve()
    control = root / PROJECT_DIRECTORY_NAME
    configuration_path = control / PROJECT_CONFIG_NAME
    if not configuration_path.exists():
        return root / "causure-investigation"
    configuration = parse_project_configuration(read_json(configuration_path))
    artifact_root = control.joinpath(*PurePosixPath(configuration.artifact_directory).parts)
    return artifact_root / prepared.fixture.fixture_id


def _selected_clusters(
    prepared: PreparedInvestigation,
    selected_cluster_ids: tuple[str, ...],
) -> tuple[CandidateTraceCluster, ...]:
    if not selected_cluster_ids:
        raise ValueError("at least one candidate trace must be selected")
    available = {cluster.cluster_id: cluster for cluster in prepared.fixture.candidate_clusters}
    if len(set(selected_cluster_ids)) != len(selected_cluster_ids):
        raise ValueError("selected cluster IDs must be unique")
    unknown = [cluster_id for cluster_id in selected_cluster_ids if cluster_id not in available]
    if unknown:
        raise ValueError(f"selected cluster is not present in the fixture: {unknown[0]}")
    selected_set = set(selected_cluster_ids)
    return tuple(
        cluster
        for cluster in prepared.fixture.candidate_clusters
        if cluster.cluster_id in selected_set
    )


def _artifact_subject(path: str, content: bytes) -> dict[str, Any]:
    return {
        "byte_count": len(content),
        "path": path,
        "sha256": hashlib.sha256(content).hexdigest(),
    }


def _selection_document(
    prepared: PreparedInvestigation,
    selected_cluster_ids: tuple[str, ...],
) -> dict[str, Any]:
    manifest_bytes = prepared.manifest_text.encode("utf-8")
    fixture_bytes = prepared.fixture_text.encode("utf-8")
    return {
        "candidate_only": True,
        "causal_claims_inferred": False,
        "fixture": _artifact_subject("investigation-fixture.json", fixture_bytes),
        "gate_eligible": False,
        "manifest": _artifact_subject("trace-manifest.json", manifest_bytes),
        "schema_version": INVESTIGATION_SELECTION_SCHEMA_VERSION,
        "selected_cluster_ids": list(selected_cluster_ids),
        "source": {
            "artifact_id": prepared.manifest.source.artifact_id,
            "byte_count": prepared.manifest.source.byte_count,
            "raw_content_stored": False,
            "sha256": prepared.manifest.source.sha256,
        },
    }


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


def _closed_object(
    value: Any,
    *,
    path: str,
    required: set[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvestigationWorkspaceValidationError(path, "expected an object")
    missing = sorted(required - set(value))
    if missing:
        raise InvestigationWorkspaceValidationError(path, f"missing field: {missing[0]}")
    unknown = sorted(set(value) - required)
    if unknown:
        raise InvestigationWorkspaceValidationError(path, f"unknown field: {unknown[0]}")
    return value


def _positive_integer(value: Any, *, path: str) -> int:
    if type(value) is not int or value < 1:
        raise InvestigationWorkspaceValidationError(path, "expected a positive integer")
    return value


def _string(value: Any, *, path: str, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise InvestigationWorkspaceValidationError(path, "expected a non-empty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise InvestigationWorkspaceValidationError(path, "value has an invalid format")
    return value


def _parse_artifact_subject(
    value: Any,
    *,
    path: str,
    expected_path: str,
) -> tuple[str, int]:
    subject = _closed_object(
        value,
        path=path,
        required={"byte_count", "path", "sha256"},
    )
    if subject["path"] != expected_path:
        raise InvestigationWorkspaceValidationError(
            f"{path}.path",
            f"expected {expected_path}",
        )
    return (
        _string(subject["sha256"], path=f"{path}.sha256", pattern=_SHA256_PATTERN),
        _positive_integer(subject["byte_count"], path=f"{path}.byte_count"),
    )


def _read_workspace_file(
    root: Path,
    name: str,
    *,
    maximum: int,
) -> bytes:
    path = root / name
    if path.is_symlink() or not path.is_file():
        raise InvestigationWorkspaceValidationError(name, "expected a regular file")
    try:
        if path.resolve().parent != root:
            raise InvestigationWorkspaceValidationError(name, "file escapes the workspace")
        size = path.stat().st_size
        if not 1 <= size <= maximum:
            raise InvestigationWorkspaceValidationError(
                name,
                f"expected from 1 to {maximum} bytes",
            )
        content = path.read_bytes()
    except InvestigationWorkspaceValidationError:
        raise
    except OSError as exc:
        raise InvestigationWorkspaceValidationError(name, str(exc)) from exc
    if len(content) != size:
        raise InvestigationWorkspaceValidationError(name, "file changed while being read")
    return content


def _verify_subject(
    content: bytes,
    *,
    expected_sha256: str,
    expected_byte_count: int,
    path: str,
) -> None:
    if len(content) != expected_byte_count:
        raise InvestigationWorkspaceValidationError(path, "byte count does not match")
    if hashlib.sha256(content).hexdigest() != expected_sha256:
        raise InvestigationWorkspaceValidationError(path, "SHA-256 does not match")


def _associated_project_root(workspace: Path) -> Path | None:
    for ancestor in workspace.parents:
        if ancestor.name != PROJECT_DIRECTORY_NAME:
            continue
        configuration_path = ancestor / PROJECT_CONFIG_NAME
        if not configuration_path.is_file():
            return None
        configuration = parse_project_configuration(read_json(configuration_path))
        artifact_root = ancestor.joinpath(
            *PurePosixPath(configuration.artifact_directory).parts
        ).resolve()
        try:
            workspace.relative_to(artifact_root)
        except ValueError:
            return None
        return ancestor.parent
    return None


def load_verified_investigation_workspace(
    directory: str | Path,
) -> VerifiedInvestigationWorkspace:
    """Load a generated workspace and verify every selected evidence subject."""

    requested = Path(directory).expanduser()
    if requested.is_symlink() or not requested.is_dir():
        raise InvestigationWorkspaceValidationError("$", "expected a regular directory")
    root = requested.resolve()
    selection_bytes = _read_workspace_file(
        root,
        "selection.json",
        maximum=MAX_INVESTIGATION_SELECTION_BYTES,
    )
    try:
        selection_text = selection_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvestigationWorkspaceValidationError(
            "selection.json",
            "document is not valid UTF-8",
        ) from exc
    try:
        selection_document = parse_json_text(
            selection_text,
            source="<investigation-selection>",
            max_bytes=MAX_INVESTIGATION_SELECTION_BYTES,
        )
    except ValueError as exc:
        raise InvestigationWorkspaceValidationError("selection.json", str(exc)) from exc
    selection = _closed_object(
        selection_document,
        path="$",
        required={
            "candidate_only",
            "causal_claims_inferred",
            "fixture",
            "gate_eligible",
            "manifest",
            "schema_version",
            "selected_cluster_ids",
            "source",
        },
    )
    if selection["schema_version"] != INVESTIGATION_SELECTION_SCHEMA_VERSION:
        raise InvestigationWorkspaceValidationError(
            "$.schema_version",
            f"expected {INVESTIGATION_SELECTION_SCHEMA_VERSION}",
        )
    fixed_flags = {
        "candidate_only": True,
        "causal_claims_inferred": False,
        "gate_eligible": False,
    }
    for field, expected in fixed_flags.items():
        if selection[field] is not expected:
            raise InvestigationWorkspaceValidationError(f"$.{field}", f"expected {expected}")

    manifest_sha256, manifest_byte_count = _parse_artifact_subject(
        selection["manifest"],
        path="$.manifest",
        expected_path="trace-manifest.json",
    )
    fixture_sha256, fixture_byte_count = _parse_artifact_subject(
        selection["fixture"],
        path="$.fixture",
        expected_path="investigation-fixture.json",
    )
    manifest_bytes = _read_workspace_file(
        root,
        "trace-manifest.json",
        maximum=MAX_MANIFEST_DOCUMENT_BYTES,
    )
    fixture_bytes = _read_workspace_file(
        root,
        "investigation-fixture.json",
        maximum=MAX_INVESTIGATION_FIXTURE_BYTES,
    )
    _verify_subject(
        manifest_bytes,
        expected_sha256=manifest_sha256,
        expected_byte_count=manifest_byte_count,
        path="$.manifest",
    )
    _verify_subject(
        fixture_bytes,
        expected_sha256=fixture_sha256,
        expected_byte_count=fixture_byte_count,
        path="$.fixture",
    )
    try:
        manifest_document = parse_json_text(
            manifest_bytes.decode("utf-8"),
            source="<trace-manifest>",
            max_bytes=MAX_MANIFEST_DOCUMENT_BYTES,
        )
        manifest = parse_trace_manifest(manifest_document)
        fixture = parse_investigation_fixture_bytes(fixture_bytes)
    except (UnicodeDecodeError, ValueError) as exc:
        raise InvestigationWorkspaceValidationError("$", str(exc)) from exc

    source = _closed_object(
        selection["source"],
        path="$.source",
        required={"artifact_id", "byte_count", "raw_content_stored", "sha256"},
    )
    if source["raw_content_stored"] is not False:
        raise InvestigationWorkspaceValidationError(
            "$.source.raw_content_stored",
            "expected False",
        )
    source_artifact_id = _string(source["artifact_id"], path="$.source.artifact_id")
    source_sha256 = _string(
        source["sha256"],
        path="$.source.sha256",
        pattern=_SHA256_PATTERN,
    )
    source_byte_count = _positive_integer(
        source["byte_count"],
        path="$.source.byte_count",
    )
    if (
        source_artifact_id != manifest.source.artifact_id
        or source_sha256 != manifest.source.sha256
        or source_byte_count != manifest.source.byte_count
    ):
        raise InvestigationWorkspaceValidationError(
            "$.source",
            "source subject does not match the trace manifest",
        )
    if (
        fixture.source.manifest_sha256 != hashlib.sha256(manifest_bytes).hexdigest()
        or fixture.source.trace_artifact_id != manifest.source.artifact_id
        or fixture.source.trace_source_sha256 != manifest.source.sha256
        or fixture.source.trace_count != manifest.source.trace_count
        or fixture.source.span_count != manifest.source.span_count
    ):
        raise InvestigationWorkspaceValidationError(
            "investigation-fixture.json",
            "fixture source does not match the exact trace manifest",
        )

    cluster_ids_value = selection["selected_cluster_ids"]
    if not isinstance(cluster_ids_value, list) or not cluster_ids_value:
        raise InvestigationWorkspaceValidationError(
            "$.selected_cluster_ids",
            "expected a non-empty array",
        )
    selected_ids = tuple(
        _string(
            value,
            path=f"$.selected_cluster_ids[{index}]",
            pattern=_CLUSTER_ID_PATTERN,
        )
        for index, value in enumerate(cluster_ids_value)
    )
    if len(set(selected_ids)) != len(selected_ids):
        raise InvestigationWorkspaceValidationError(
            "$.selected_cluster_ids",
            "cluster IDs must be unique",
        )
    selected_set = set(selected_ids)
    selected_clusters = tuple(
        cluster for cluster in fixture.candidate_clusters if cluster.cluster_id in selected_set
    )
    if tuple(cluster.cluster_id for cluster in selected_clusters) != selected_ids:
        raise InvestigationWorkspaceValidationError(
            "$.selected_cluster_ids",
            "IDs must exist in fixture order",
        )
    return VerifiedInvestigationWorkspace(
        directory=root,
        project_root=_associated_project_root(root),
        selection_bytes=selection_bytes,
        manifest_bytes=manifest_bytes,
        fixture_bytes=fixture_bytes,
        manifest=manifest,
        fixture=fixture,
        selected_clusters=selected_clusters,
    )


def _investigation_notes(
    prepared: PreparedInvestigation,
    selected: tuple[CandidateTraceCluster, ...],
) -> str:
    lines = [
        f"# Investigation: {prepared.fixture.fixture_id}",
        "",
        "> Candidate-only draft. Selecting a trace does not prove a failure or its cause.",
        "",
        "## Selected observations",
        "",
    ]
    for index, cluster in enumerate(selected, start=1):
        lines.extend(
            [
                f"### Observation {index}",
                "",
                f"- Cluster ID: `{cluster.cluster_id}`",
                f"- Spans: {cluster.span_count}",
                f"- Error spans: {cluster.error_span_count}",
                f"- Models: {_list_text(cluster.model_identifiers)}",
                f"- Providers: {_list_text(cluster.provider_identifiers)}",
                "",
            ]
        )
    lines.extend(
        [
            "## Investigator notes",
            "",
            "These answers are working notes, not gate evidence until confirmed and bound to",
            "replay/evaluation artifacts by the later case-creation step.",
            "",
            "### What failure do you believe occurred?",
            "",
            "_Describe the claimed failure in plain language._",
            "",
            "### What should have happened instead?",
            "",
            "_Name the expected behavior and governing requirement._",
            "",
            "### What did you observe?",
            "",
            "_Describe only what the selected traces support._",
            "",
            "### How will you independently decide whether behavior is correct?",
            "",
            "_Identify the policy, evaluator, human rubric, or other oracle._",
            "",
            "### What are the competing explanations?",
            "",
            "1. _Primary hypothesis and affected harness component_",
            "2. _Plausible alternative_",
            "3. _Environmental or transient explanation_",
            "",
            "### What is the no-change alternative?",
            "",
            "_State why no harness modification might be necessary and what evidence would "
            "refute it._",
            "",
            "### What evidence is still missing?",
            "",
        ]
    )
    lines.extend(f"- [ ] {item.replace('_', ' ')}" for item in prepared.fixture.missing_evidence)
    lines.append("")
    return "\n".join(lines)


def _workspace_readme(selected_count: int) -> str:
    return "\n".join(
        [
            "# Causure investigation workspace",
            "",
            f"This candidate-only workspace contains {selected_count} selected trace cluster(s).",
            "No raw trace payload, message content, credential, or source path is stored here.",
            "",
            "- `investigation.md` is the editable, plain-language investigator notebook.",
            "- `selection.json` records the selected cluster IDs and exact artifact hashes.",
            "- `trace-manifest.json` is the content-minimized collector output.",
            "- `investigation-fixture.json` contains every candidate cluster from that manifest.",
            "",
            "The workspace is not gate-eligible and makes no causal claim. The next product step",
            "is guided case creation and attachment of reproducible, independently evaluated",
            "intervention and control results.",
            "",
        ]
    )


def write_investigation_workspace(
    prepared: PreparedInvestigation,
    selected_cluster_ids: tuple[str, ...],
    output_directory: str | Path,
) -> InvestigationWorkspace:
    """Write only redacted, derived artifacts into a new local directory."""

    selected = _selected_clusters(prepared, selected_cluster_ids)
    normalized_cluster_ids = tuple(cluster.cluster_id for cluster in selected)
    destination = Path(output_directory).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        destination.mkdir()
    except FileExistsError as exc:
        raise ValueError(
            f"investigation output already exists; choose a new directory: {destination}"
        ) from exc
    except OSError as exc:
        raise ValueError(f"could not create investigation output {destination}: {exc}") from exc

    completed = False
    try:
        manifest_path = destination / "trace-manifest.json"
        fixture_path = destination / "investigation-fixture.json"
        notes_path = destination / "investigation.md"
        atomic_write_text(manifest_path, prepared.manifest_text)
        atomic_write_text(fixture_path, prepared.fixture_text)
        atomic_write_text(
            destination / "selection.json",
            _json_text(_selection_document(prepared, normalized_cluster_ids)),
        )
        atomic_write_text(notes_path, _investigation_notes(prepared, selected))
        atomic_write_text(destination / "README.md", _workspace_readme(len(selected)))
        completed = True
        return InvestigationWorkspace(
            output_directory=destination,
            selected_cluster_ids=normalized_cluster_ids,
            manifest_path=manifest_path,
            fixture_path=fixture_path,
            notes_path=notes_path,
        )
    finally:
        if not completed:
            shutil.rmtree(destination, ignore_errors=True)


def render_workspace_summary(workspace: InvestigationWorkspace) -> str:
    """Render the concise successful investigate result."""

    return "\n".join(
        [
            f"Created candidate-only investigation at {workspace.output_directory}",
            f"Selected trace clusters: {len(workspace.selected_cluster_ids)}",
            f"Edit investigator notes: {workspace.notes_path}",
            "No raw trace content was written.",
        ]
    )
