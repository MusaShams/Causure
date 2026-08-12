"""Deterministic, draft-only investigation fixtures from trace manifests."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from causure.collector import CollectedSpan, TraceManifest
from causure.constants import (
    INVESTIGATION_FIXTURE_SCHEMA_VERSION,
    PACKAGE_VERSION,
    SAFE_TRACE_TEXT_PATTERN,
    OpenInferenceSpanKind,
)
from causure.io import InputDocumentError, parse_json_text
from causure.models import to_jsonable
from causure.trace_manifest import parse_trace_manifest

MAX_MANIFEST_DOCUMENT_BYTES = 64 * 1024 * 1024
MAX_INVESTIGATION_FIXTURE_BYTES = 64 * 1024 * 1024
DEFAULT_MAX_CLUSTERS = 1_000
MAX_CONFIGURABLE_CLUSTERS = 10_000

_FIXTURE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_SAFE_TRACE_TEXT_PATTERN = re.compile(SAFE_TRACE_TEXT_PATTERN)
_CLUSTER_ID_PATTERN = re.compile(r"^trace-[a-f0-9]{64}$")
_TRACE_REF_PATTERN = re.compile(r"^trace-sha256://([a-f0-9]{64})/traces/([a-f0-9]{64})$")
_SPAN_REF_PATTERN = re.compile(r"^trace-sha256://([a-f0-9]{64})/spans/([a-f0-9]{64})$")
_UINT64_MAX = (1 << 64) - 1
_MODEL_ATTRIBUTE_KEYS = {
    "embedding.model_name",
    "gen_ai.request.model",
    "gen_ai.response.model",
    "llm.model_name",
}
_PROVIDER_ATTRIBUTE_KEYS = {
    "gen_ai.provider.name",
    "llm.provider",
    "llm.system",
}
_MISSING_EVIDENCE = (
    "incident_claim",
    "governing_requirement",
    "independent_oracle",
    "reproduction_outcomes",
    "causal_attribution",
    "proposed_change",
    "negative_and_regression_controls",
)


class FixtureGenerationError(ValueError):
    """Raised when a safe investigation fixture cannot be generated."""


class InvestigationFixtureValidationError(ValueError):
    """Raised when an investigation fixture violates its closed wire contract."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"Invalid investigation fixture at {path}: {message}")


@dataclass(frozen=True, slots=True)
class NamedCount:
    name: str
    count: int


@dataclass(frozen=True, slots=True)
class StatusCount:
    code: int
    count: int


@dataclass(frozen=True, slots=True)
class FixtureSource:
    manifest_sha256: str
    trace_artifact_id: str
    trace_source_sha256: str
    trace_count: int
    span_count: int


@dataclass(frozen=True, slots=True)
class CandidateTraceCluster:
    cluster_id: str
    trace_ref: str
    trace_id_sha256: str
    span_evidence_refs: tuple[str, ...]
    span_count: int
    root_span_count: int
    error_span_count: int
    span_kind_counts: tuple[NamedCount, ...]
    status_code_counts: tuple[StatusCount, ...]
    model_identifiers: tuple[str, ...]
    provider_identifiers: tuple[str, ...]
    earliest_start_time_unix_nano: str | None = field(
        default=None,
        metadata={"omit_none": True},
    )
    latest_end_time_unix_nano: str | None = field(
        default=None,
        metadata={"omit_none": True},
    )
    observed_duration_nano: str | None = field(
        default=None,
        metadata={"omit_none": True},
    )


@dataclass(frozen=True, slots=True)
class InvestigationFixture:
    schema_version: str
    generator_version: str
    fixture_id: str
    draft_only: bool
    gate_eligible: bool
    causal_claims_inferred: bool
    clustering_basis: str
    source: FixtureSource
    missing_evidence: tuple[str, ...]
    candidate_clusters: tuple[CandidateTraceCluster, ...]


def _fixture_object(
    value: Any,
    path: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InvestigationFixtureValidationError(path, "expected an object")
    allowed = required | (optional or set())
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise InvestigationFixtureValidationError(path, f"unknown field: {unknown[0]}")
    missing = sorted(required - set(value))
    if missing:
        raise InvestigationFixtureValidationError(
            path,
            f"missing required field: {missing[0]}",
        )
    return value


def _fixture_array(
    value: Any,
    path: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> list[Any]:
    if not isinstance(value, list):
        raise InvestigationFixtureValidationError(path, "expected an array")
    if len(value) < minimum or (maximum is not None and len(value) > maximum):
        if maximum is None:
            message = f"expected at least {minimum} item(s)"
        else:
            message = f"expected from {minimum} to {maximum} item(s)"
        raise InvestigationFixtureValidationError(path, message)
    return value


def _fixture_string(
    value: Any,
    path: str,
    *,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if not isinstance(value, str) or not value:
        raise InvestigationFixtureValidationError(path, "expected a non-empty string")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise InvestigationFixtureValidationError(path, "value does not match the required format")
    return value


def _fixture_integer(
    value: Any,
    path: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvestigationFixtureValidationError(path, "expected an integer")
    if value < minimum or (maximum is not None and value > maximum):
        if maximum is None:
            message = f"expected an integer of at least {minimum}"
        else:
            message = f"expected an integer from {minimum} to {maximum}"
        raise InvestigationFixtureValidationError(path, message)
    return value


def _fixture_decimal(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.isdecimal():
        raise InvestigationFixtureValidationError(
            path, "expected a canonical uint64 decimal string"
        )
    if len(value) > len(str(_UINT64_MAX)):
        raise InvestigationFixtureValidationError(path, "decimal string exceeds the uint64 range")
    number = int(value)
    if number > _UINT64_MAX or str(number) != value:
        raise InvestigationFixtureValidationError(
            path, "expected a canonical uint64 decimal string"
        )
    return value


def _parse_fixture_source(value: Any) -> FixtureSource:
    path = "$.source"
    source = _fixture_object(
        value,
        path,
        required={
            "manifest_sha256",
            "trace_artifact_id",
            "trace_source_sha256",
            "trace_count",
            "span_count",
        },
    )
    return FixtureSource(
        manifest_sha256=_fixture_string(
            source["manifest_sha256"],
            f"{path}.manifest_sha256",
            pattern=_SHA256_PATTERN,
        ),
        trace_artifact_id=_fixture_string(
            source["trace_artifact_id"],
            f"{path}.trace_artifact_id",
            pattern=_FIXTURE_ID_PATTERN,
        ),
        trace_source_sha256=_fixture_string(
            source["trace_source_sha256"],
            f"{path}.trace_source_sha256",
            pattern=_SHA256_PATTERN,
        ),
        trace_count=_fixture_integer(source["trace_count"], f"{path}.trace_count", minimum=1),
        span_count=_fixture_integer(source["span_count"], f"{path}.span_count", minimum=1),
    )


def _parse_named_counts(value: Any, path: str, span_count: int) -> tuple[NamedCount, ...]:
    parsed: list[NamedCount] = []
    for index, item in enumerate(_fixture_array(value, path, maximum=len(OpenInferenceSpanKind))):
        item_path = f"{path}[{index}]"
        count = _fixture_object(item, item_path, required={"name", "count"})
        try:
            name = OpenInferenceSpanKind(count["name"]).value
        except (TypeError, ValueError) as exc:
            allowed = ", ".join(member.value for member in OpenInferenceSpanKind)
            raise InvestigationFixtureValidationError(
                f"{item_path}.name",
                f"expected one of: {allowed}",
            ) from exc
        parsed.append(
            NamedCount(
                name=name,
                count=_fixture_integer(
                    count["count"],
                    f"{item_path}.count",
                    minimum=1,
                    maximum=span_count,
                ),
            )
        )
    result = tuple(parsed)
    if tuple(item.name for item in result) != tuple(sorted({item.name for item in result})):
        raise InvestigationFixtureValidationError(path, "span kinds must be unique and sorted")
    if sum(item.count for item in result) > span_count:
        raise InvestigationFixtureValidationError(path, "span-kind counts exceed span_count")
    return result


def _parse_status_counts(value: Any, path: str, span_count: int) -> tuple[StatusCount, ...]:
    parsed: list[StatusCount] = []
    for index, item in enumerate(_fixture_array(value, path, maximum=3)):
        item_path = f"{path}[{index}]"
        count = _fixture_object(item, item_path, required={"code", "count"})
        parsed.append(
            StatusCount(
                code=_fixture_integer(
                    count["code"],
                    f"{item_path}.code",
                    maximum=2,
                ),
                count=_fixture_integer(
                    count["count"],
                    f"{item_path}.count",
                    minimum=1,
                    maximum=span_count,
                ),
            )
        )
    result = tuple(parsed)
    if tuple(item.code for item in result) != tuple(sorted({item.code for item in result})):
        raise InvestigationFixtureValidationError(path, "status codes must be unique and sorted")
    if sum(item.count for item in result) > span_count:
        raise InvestigationFixtureValidationError(path, "status counts exceed span_count")
    return result


def _parse_identifier_array(value: Any, path: str) -> tuple[str, ...]:
    result = tuple(
        _fixture_string(item, f"{path}[{index}]", pattern=_SAFE_TRACE_TEXT_PATTERN)
        for index, item in enumerate(_fixture_array(value, path, maximum=10_000))
    )
    if result != tuple(sorted(set(result))):
        raise InvestigationFixtureValidationError(path, "values must be unique and sorted")
    return result


def _parse_fixture_cluster(
    value: Any,
    index: int,
    source: FixtureSource,
) -> CandidateTraceCluster:
    path = f"$.candidate_clusters[{index}]"
    cluster = _fixture_object(
        value,
        path,
        required={
            "cluster_id",
            "trace_ref",
            "trace_id_sha256",
            "span_evidence_refs",
            "span_count",
            "root_span_count",
            "error_span_count",
            "span_kind_counts",
            "status_code_counts",
            "model_identifiers",
            "provider_identifiers",
        },
        optional={
            "earliest_start_time_unix_nano",
            "latest_end_time_unix_nano",
            "observed_duration_nano",
        },
    )
    trace_id = _fixture_string(
        cluster["trace_id_sha256"],
        f"{path}.trace_id_sha256",
        pattern=_SHA256_PATTERN,
    )
    cluster_id = _fixture_string(
        cluster["cluster_id"],
        f"{path}.cluster_id",
        pattern=_CLUSTER_ID_PATTERN,
    )
    if cluster_id != f"trace-{trace_id}":
        raise InvestigationFixtureValidationError(
            f"{path}.cluster_id",
            "must be derived from trace_id_sha256",
        )
    trace_ref = _fixture_string(
        cluster["trace_ref"],
        f"{path}.trace_ref",
        pattern=_TRACE_REF_PATTERN,
    )
    expected_trace_ref = f"trace-sha256://{source.trace_source_sha256}/traces/{trace_id}"
    if trace_ref != expected_trace_ref:
        raise InvestigationFixtureValidationError(
            f"{path}.trace_ref",
            "does not bind the declared trace source and trace id",
        )
    span_count = _fixture_integer(cluster["span_count"], f"{path}.span_count", minimum=1)
    span_refs = tuple(
        _fixture_string(item, f"{path}.span_evidence_refs[{item_index}]", pattern=_SPAN_REF_PATTERN)
        for item_index, item in enumerate(
            _fixture_array(
                cluster["span_evidence_refs"],
                f"{path}.span_evidence_refs",
                minimum=1,
            )
        )
    )
    if len(span_refs) != span_count:
        raise InvestigationFixtureValidationError(
            f"{path}.span_evidence_refs",
            "item count must equal span_count",
        )
    if span_refs != tuple(sorted(set(span_refs))):
        raise InvestigationFixtureValidationError(
            f"{path}.span_evidence_refs",
            "span references must be unique and sorted",
        )
    prefix = f"trace-sha256://{source.trace_source_sha256}/spans/"
    if any(not item.startswith(prefix) for item in span_refs):
        raise InvestigationFixtureValidationError(
            f"{path}.span_evidence_refs",
            "span references must bind the declared trace source",
        )
    root_span_count = _fixture_integer(
        cluster["root_span_count"],
        f"{path}.root_span_count",
        maximum=span_count,
    )
    error_span_count = _fixture_integer(
        cluster["error_span_count"],
        f"{path}.error_span_count",
        maximum=span_count,
    )
    kinds = _parse_named_counts(cluster["span_kind_counts"], f"{path}.span_kind_counts", span_count)
    statuses = _parse_status_counts(
        cluster["status_code_counts"],
        f"{path}.status_code_counts",
        span_count,
    )
    status_errors = next((item.count for item in statuses if item.code == 2), 0)
    if status_errors != error_span_count:
        raise InvestigationFixtureValidationError(
            f"{path}.error_span_count",
            "must equal the status-code 2 count",
        )
    earliest = (
        None
        if "earliest_start_time_unix_nano" not in cluster
        else _fixture_decimal(
            cluster["earliest_start_time_unix_nano"],
            f"{path}.earliest_start_time_unix_nano",
        )
    )
    latest = (
        None
        if "latest_end_time_unix_nano" not in cluster
        else _fixture_decimal(
            cluster["latest_end_time_unix_nano"],
            f"{path}.latest_end_time_unix_nano",
        )
    )
    duration = (
        None
        if "observed_duration_nano" not in cluster
        else _fixture_decimal(
            cluster["observed_duration_nano"],
            f"{path}.observed_duration_nano",
        )
    )
    expected_duration = (
        str(int(latest) - int(earliest))
        if earliest is not None and latest is not None and int(latest) >= int(earliest)
        else None
    )
    if duration != expected_duration:
        raise InvestigationFixtureValidationError(
            f"{path}.observed_duration_nano",
            "must equal the declared observation window",
        )
    return CandidateTraceCluster(
        cluster_id=cluster_id,
        trace_ref=trace_ref,
        trace_id_sha256=trace_id,
        span_evidence_refs=span_refs,
        span_count=span_count,
        root_span_count=root_span_count,
        error_span_count=error_span_count,
        span_kind_counts=kinds,
        status_code_counts=statuses,
        model_identifiers=_parse_identifier_array(
            cluster["model_identifiers"],
            f"{path}.model_identifiers",
        ),
        provider_identifiers=_parse_identifier_array(
            cluster["provider_identifiers"],
            f"{path}.provider_identifiers",
        ),
        earliest_start_time_unix_nano=earliest,
        latest_end_time_unix_nano=latest,
        observed_duration_nano=duration,
    )


def parse_investigation_fixture(document: Any) -> InvestigationFixture:
    """Strictly parse a draft-only investigation fixture."""

    root = _fixture_object(
        document,
        "$",
        required={
            "schema_version",
            "generator_version",
            "fixture_id",
            "draft_only",
            "gate_eligible",
            "causal_claims_inferred",
            "clustering_basis",
            "source",
            "missing_evidence",
            "candidate_clusters",
        },
    )
    if root["schema_version"] != INVESTIGATION_FIXTURE_SCHEMA_VERSION:
        raise InvestigationFixtureValidationError(
            "$.schema_version",
            f"expected {INVESTIGATION_FIXTURE_SCHEMA_VERSION}",
        )
    if root["draft_only"] is not True:
        raise InvestigationFixtureValidationError("$.draft_only", "expected true")
    if root["gate_eligible"] is not False:
        raise InvestigationFixtureValidationError("$.gate_eligible", "expected false")
    if root["causal_claims_inferred"] is not False:
        raise InvestigationFixtureValidationError("$.causal_claims_inferred", "expected false")
    if root["clustering_basis"] != "trace_identity":
        raise InvestigationFixtureValidationError(
            "$.clustering_basis",
            "expected trace_identity",
        )
    missing_evidence = tuple(
        _fixture_string(item, f"$.missing_evidence[{index}]")
        for index, item in enumerate(
            _fixture_array(
                root["missing_evidence"],
                "$.missing_evidence",
                minimum=len(_MISSING_EVIDENCE),
                maximum=len(_MISSING_EVIDENCE),
            )
        )
    )
    if missing_evidence != _MISSING_EVIDENCE:
        raise InvestigationFixtureValidationError(
            "$.missing_evidence",
            "expected the canonical missing-evidence list",
        )
    source = _parse_fixture_source(root["source"])
    clusters = tuple(
        _parse_fixture_cluster(item, index, source)
        for index, item in enumerate(
            _fixture_array(
                root["candidate_clusters"],
                "$.candidate_clusters",
                minimum=1,
                maximum=MAX_CONFIGURABLE_CLUSTERS,
            )
        )
    )
    cluster_ids = tuple(item.cluster_id for item in clusters)
    if cluster_ids != tuple(sorted(set(cluster_ids))):
        raise InvestigationFixtureValidationError(
            "$.candidate_clusters",
            "cluster ids must be unique and sorted",
        )
    if len(clusters) != source.trace_count:
        raise InvestigationFixtureValidationError(
            "$.source.trace_count",
            "must equal the number of candidate clusters",
        )
    if sum(item.span_count for item in clusters) != source.span_count:
        raise InvestigationFixtureValidationError(
            "$.source.span_count",
            "must equal the candidate-cluster span total",
        )
    return InvestigationFixture(
        schema_version=INVESTIGATION_FIXTURE_SCHEMA_VERSION,
        generator_version=_fixture_string(
            root["generator_version"],
            "$.generator_version",
            pattern=_VERSION_PATTERN,
        ),
        fixture_id=_fixture_string(
            root["fixture_id"],
            "$.fixture_id",
            pattern=_FIXTURE_ID_PATTERN,
        ),
        draft_only=True,
        gate_eligible=False,
        causal_claims_inferred=False,
        clustering_basis="trace_identity",
        source=source,
        missing_evidence=missing_evidence,
        candidate_clusters=clusters,
    )


def parse_investigation_fixture_bytes(raw_bytes: bytes) -> InvestigationFixture:
    """Strictly parse exact UTF-8 JSON fixture bytes."""

    if (
        not isinstance(raw_bytes, bytes)
        or not 1 <= len(raw_bytes) <= MAX_INVESTIGATION_FIXTURE_BYTES
    ):
        raise InvestigationFixtureValidationError(
            "$",
            f"expected from 1 to {MAX_INVESTIGATION_FIXTURE_BYTES} bytes",
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise InvestigationFixtureValidationError("$", "document is not valid UTF-8") from exc
    try:
        document = parse_json_text(
            text,
            source="<investigation-fixture>",
            max_bytes=MAX_INVESTIGATION_FIXTURE_BYTES,
        )
    except InputDocumentError as exc:
        raise InvestigationFixtureValidationError("$", str(exc)) from exc
    return parse_investigation_fixture(document)


def _cluster_spans(
    trace_hash: str,
    spans: list[CollectedSpan],
    manifest: TraceManifest,
) -> CandidateTraceCluster:
    starts = [
        int(span.start_time_unix_nano) for span in spans if span.start_time_unix_nano is not None
    ]
    ends = [int(span.end_time_unix_nano) for span in spans if span.end_time_unix_nano is not None]
    earliest = min(starts) if starts else None
    latest = max(ends) if ends else None
    observed_duration = (
        latest - earliest
        if earliest is not None and latest is not None and latest >= earliest
        else None
    )

    span_kinds = Counter(
        str(span.attributes["openinference.span.kind"])
        for span in spans
        if "openinference.span.kind" in span.attributes
    )
    statuses = Counter(span.status_code for span in spans if span.status_code is not None)
    models = {
        str(value)
        for span in spans
        for key, value in span.attributes.items()
        if key in _MODEL_ATTRIBUTE_KEYS
    }
    providers = {
        str(value)
        for span in spans
        for key, value in span.attributes.items()
        if key in _PROVIDER_ATTRIBUTE_KEYS
    }
    return CandidateTraceCluster(
        cluster_id=f"trace-{trace_hash}",
        trace_ref=(f"trace-sha256://{manifest.source.sha256}/traces/{trace_hash}"),
        trace_id_sha256=trace_hash,
        span_evidence_refs=tuple(sorted(span.evidence_ref for span in spans)),
        span_count=len(spans),
        root_span_count=sum(span.parent_span_id_sha256 is None for span in spans),
        error_span_count=sum(span.status_code == 2 for span in spans),
        span_kind_counts=tuple(
            NamedCount(name=name, count=count) for name, count in sorted(span_kinds.items())
        ),
        status_code_counts=tuple(
            StatusCount(code=code, count=count) for code, count in sorted(statuses.items())
        ),
        model_identifiers=tuple(sorted(models)),
        provider_identifiers=tuple(sorted(providers)),
        earliest_start_time_unix_nano=(str(earliest) if earliest is not None else None),
        latest_end_time_unix_nano=(str(latest) if latest is not None else None),
        observed_duration_nano=(str(observed_duration) if observed_duration is not None else None),
    )


def generate_investigation_fixture(
    document: Any,
    *,
    raw_bytes: bytes,
    fixture_id: str,
    max_clusters: int = DEFAULT_MAX_CLUSTERS,
) -> InvestigationFixture:
    """Generate a non-gate-eligible trace triage fixture."""

    if not isinstance(raw_bytes, bytes):
        raise FixtureGenerationError("raw_bytes must be exact manifest bytes")
    try:
        decoded = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise FixtureGenerationError("trace manifest bytes are not valid UTF-8") from exc
    try:
        parsed_source = parse_json_text(
            decoded,
            source="<trace-manifest>",
            max_bytes=MAX_MANIFEST_DOCUMENT_BYTES,
        )
    except InputDocumentError as exc:
        raise FixtureGenerationError(str(exc)) from exc
    if parsed_source != document:
        raise FixtureGenerationError("parsed manifest does not match the supplied source bytes")
    if not isinstance(fixture_id, str) or not _FIXTURE_ID_PATTERN.fullmatch(fixture_id):
        raise FixtureGenerationError("fixture_id must be 3-128 safe identifier characters")
    if (
        isinstance(max_clusters, bool)
        or not isinstance(max_clusters, int)
        or not 1 <= max_clusters <= MAX_CONFIGURABLE_CLUSTERS
    ):
        raise FixtureGenerationError(
            f"max_clusters must be an integer from 1 to {MAX_CONFIGURABLE_CLUSTERS}"
        )

    manifest = parse_trace_manifest(parsed_source)
    grouped: dict[str, list[CollectedSpan]] = defaultdict(list)
    for span in manifest.spans:
        grouped[span.trace_id_sha256].append(span)
    if len(grouped) > max_clusters:
        raise FixtureGenerationError(
            f"candidate trace count exceeds configured limit {max_clusters}"
        )

    clusters = tuple(
        _cluster_spans(trace_hash, grouped[trace_hash], manifest) for trace_hash in sorted(grouped)
    )
    return InvestigationFixture(
        schema_version=INVESTIGATION_FIXTURE_SCHEMA_VERSION,
        generator_version=PACKAGE_VERSION,
        fixture_id=fixture_id,
        draft_only=True,
        gate_eligible=False,
        causal_claims_inferred=False,
        clustering_basis="trace_identity",
        source=FixtureSource(
            manifest_sha256=hashlib.sha256(raw_bytes).hexdigest(),
            trace_artifact_id=manifest.source.artifact_id,
            trace_source_sha256=manifest.source.sha256,
            trace_count=manifest.source.trace_count,
            span_count=manifest.source.span_count,
        ),
        missing_evidence=_MISSING_EVIDENCE,
        candidate_clusters=clusters,
    )


def render_investigation_fixture(fixture: InvestigationFixture) -> str:
    """Render a stable, human-inspectable investigation fixture."""

    validated = parse_investigation_fixture(to_jsonable(fixture))
    return (
        json.dumps(
            to_jsonable(validated),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
