"""Minimized, append-only Team investigation queue records."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import Enum
from typing import Any, TypeVar

from causure.constants import (
    SAFE_TRACE_TEXT_PATTERN,
    TEAM_INVESTIGATION_RECORD_SCHEMA_VERSION,
    OpenInferenceSpanKind,
    TeamInvestigationPriority,
    TeamInvestigationResolution,
    TeamInvestigationStatus,
)
from causure.fixtures import (
    CandidateTraceCluster,
    InvestigationFixture,
    InvestigationFixtureValidationError,
    parse_investigation_fixture_bytes,
)
from causure.io import InputDocumentError, parse_json_text
from causure.models import to_jsonable
from causure.team_service import TeamPrincipal

MAX_TEAM_INVESTIGATION_RECORD_BYTES = 1024 * 1024
MAX_TEAM_INVESTIGATION_SOURCE_BYTES = 8 * 1024 * 1024
MAX_TEAM_INVESTIGATION_OBSERVATIONS = 128
TEAM_INVESTIGATION_RECORD_MEDIA_TYPE = "application/vnd.causure.team-investigation-record+json"
INVESTIGATION_FIXTURE_MEDIA_TYPE = "application/vnd.causure.investigation-fixture+json"

_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/@-]{0,127}$")
_INVESTIGATION_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_OBSERVATION_ID_PATTERN = re.compile(r"^observation-[a-f0-9]{64}$")
_CLUSTER_ID_PATTERN = re.compile(r"^trace-[a-f0-9]{64}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_SAFE_TRACE_TEXT_PATTERN = re.compile(SAFE_TRACE_TEXT_PATTERN)
_UTC_TIMESTAMP_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_NO_CONTROL_PATTERN = re.compile(r"^[^\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+$")
_UINT64_MAX = (1 << 64) - 1
_EnumT = TypeVar("_EnumT", bound=Enum)


class TeamInvestigationValidationError(ValueError):
    """Raised when a minimized investigation record violates its contract."""

    def __init__(self, document_name: str, path: str, message: str) -> None:
        self.document_name = document_name
        self.path = path
        self.message = message
        super().__init__(f"Invalid {document_name} at {path}: {message}")


@dataclass(frozen=True, slots=True)
class TeamInvestigationArtifactSubject:
    media_type: str
    sha256: str
    byte_count: int


@dataclass(frozen=True, slots=True)
class TeamInvestigationNamedCount:
    name: str
    count: int


@dataclass(frozen=True, slots=True)
class TeamInvestigationStatusCount:
    code: int
    count: int


@dataclass(frozen=True, slots=True)
class TeamInvestigationObservation:
    observation_id: str
    attached_at: str
    attached_by: TeamPrincipal
    fixture: TeamInvestigationArtifactSubject
    fixture_id: str
    manifest_sha256: str
    trace_source_sha256: str
    cluster_id: str
    trace_id_sha256: str
    span_count: int
    root_span_count: int
    error_span_count: int
    span_kind_counts: tuple[TeamInvestigationNamedCount, ...]
    status_code_counts: tuple[TeamInvestigationStatusCount, ...]
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
class TeamInvestigationRecord:
    schema_version: str
    tenant_id: str
    investigation_id: str
    revision: int
    created_at: str
    updated_at: str
    title: str
    status: TeamInvestigationStatus
    priority: TeamInvestigationPriority
    opened_by: TeamPrincipal
    candidate_only: bool
    gate_eligible: bool
    causal_claims_inferred: bool
    observations: tuple[TeamInvestigationObservation, ...]
    assigned_to: TeamPrincipal | None = field(
        default=None,
        metadata={"omit_none": True},
    )
    resolution: TeamInvestigationResolution | None = field(
        default=None,
        metadata={"omit_none": True},
    )
    linked_case_id: str | None = field(
        default=None,
        metadata={"omit_none": True},
    )
    duplicate_of: str | None = field(
        default=None,
        metadata={"omit_none": True},
    )


def _object(
    value: Any,
    *,
    name: str,
    path: str,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TeamInvestigationValidationError(name, path, "expected an object")
    allowed = required | (optional or set())
    missing = sorted(required - set(value))
    if missing:
        raise TeamInvestigationValidationError(
            name,
            path,
            f"missing required field: {missing[0]}",
        )
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise TeamInvestigationValidationError(
            name,
            path,
            f"unknown field: {unknown[0]}",
        )
    return value


def _array(
    value: Any,
    *,
    name: str,
    path: str,
    minimum: int,
    maximum: int,
) -> list[Any]:
    if not isinstance(value, list) or not minimum <= len(value) <= maximum:
        raise TeamInvestigationValidationError(
            name,
            path,
            f"expected an array containing from {minimum} to {maximum} items",
        )
    return value


def _text(
    value: Any,
    *,
    name: str,
    path: str,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    selected_pattern = pattern or _NO_CONTROL_PATTERN
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= maximum
        or selected_pattern.fullmatch(value) is None
    ):
        raise TeamInvestigationValidationError(
            name,
            path,
            f"expected from 1 to {maximum} bounded characters",
        )
    return value


def _integer(
    value: Any,
    *,
    name: str,
    path: str,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise TeamInvestigationValidationError(
            name,
            path,
            f"expected an integer from {minimum} through {maximum}",
        )
    return value


def _boolean(value: Any, *, name: str, path: str) -> bool:
    if type(value) is not bool:
        raise TeamInvestigationValidationError(name, path, "expected a boolean")
    return value


def _enum(
    value: Any,
    *,
    name: str,
    path: str,
    enum_type: type[_EnumT],
) -> _EnumT:
    if not isinstance(value, str):
        raise TeamInvestigationValidationError(name, path, "expected a string enum value")
    try:
        return enum_type(value)
    except ValueError as exc:
        allowed = ", ".join(member.value for member in enum_type)
        raise TeamInvestigationValidationError(
            name,
            path,
            f"expected one of: {allowed}",
        ) from exc


def _timestamp(value: Any, *, name: str, path: str) -> str:
    result = _text(
        value,
        name=name,
        path=path,
        maximum=20,
        pattern=_UTC_TIMESTAMP_PATTERN,
    )
    try:
        parsed = datetime.fromisoformat(result.replace("Z", "+00:00"))
    except ValueError as exc:
        raise TeamInvestigationValidationError(
            name,
            path,
            "expected a whole-second UTC timestamp",
        ) from exc
    if parsed.utcoffset() is None or parsed.utcoffset().total_seconds() != 0:
        raise TeamInvestigationValidationError(
            name,
            path,
            "expected a whole-second UTC timestamp",
        )
    return result


def _decimal(value: Any, *, name: str, path: str) -> str:
    if not isinstance(value, str) or not value.isdecimal():
        raise TeamInvestigationValidationError(
            name,
            path,
            "expected a canonical uint64 decimal string",
        )
    if len(value) > len(str(_UINT64_MAX)):
        raise TeamInvestigationValidationError(name, path, "value exceeds uint64")
    number = int(value)
    if number > _UINT64_MAX or str(number) != value:
        raise TeamInvestigationValidationError(
            name,
            path,
            "expected a canonical uint64 decimal string",
        )
    return value


def _principal(value: Any, *, name: str, path: str) -> TeamPrincipal:
    obj = _object(
        value,
        name=name,
        path=path,
        required={"identity_provider", "subject_id"},
    )
    return TeamPrincipal(
        identity_provider=_text(
            obj["identity_provider"],
            name=name,
            path=f"{path}.identity_provider",
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        subject_id=_text(
            obj["subject_id"],
            name=name,
            path=f"{path}.subject_id",
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
    )


def _validated_principal(value: TeamPrincipal, *, path: str) -> TeamPrincipal:
    if not isinstance(value, TeamPrincipal):
        raise TeamInvestigationValidationError(
            "Team investigation record",
            path,
            "expected a TeamPrincipal",
        )
    return _principal(
        to_jsonable(value),
        name="Team investigation record",
        path=path,
    )


def _subject(value: Any, *, name: str, path: str) -> TeamInvestigationArtifactSubject:
    obj = _object(
        value,
        name=name,
        path=path,
        required={"media_type", "sha256", "byte_count"},
    )
    media_type = _text(
        obj["media_type"],
        name=name,
        path=f"{path}.media_type",
        maximum=255,
    )
    if media_type != INVESTIGATION_FIXTURE_MEDIA_TYPE:
        raise TeamInvestigationValidationError(
            name,
            f"{path}.media_type",
            f"expected {INVESTIGATION_FIXTURE_MEDIA_TYPE!r}",
        )
    return TeamInvestigationArtifactSubject(
        media_type=media_type,
        sha256=_text(
            obj["sha256"],
            name=name,
            path=f"{path}.sha256",
            maximum=64,
            pattern=_SHA256_PATTERN,
        ),
        byte_count=_integer(
            obj["byte_count"],
            name=name,
            path=f"{path}.byte_count",
            minimum=1,
            maximum=MAX_TEAM_INVESTIGATION_SOURCE_BYTES,
        ),
    )


def _named_counts(
    value: Any,
    *,
    name: str,
    path: str,
    span_count: int,
) -> tuple[TeamInvestigationNamedCount, ...]:
    result: list[TeamInvestigationNamedCount] = []
    for index, value_item in enumerate(
        _array(
            value,
            name=name,
            path=path,
            minimum=0,
            maximum=len(OpenInferenceSpanKind),
        )
    ):
        item_path = f"{path}[{index}]"
        item = _object(
            value_item,
            name=name,
            path=item_path,
            required={"name", "count"},
        )
        try:
            kind = OpenInferenceSpanKind(item["name"]).value
        except (TypeError, ValueError) as exc:
            allowed = ", ".join(member.value for member in OpenInferenceSpanKind)
            raise TeamInvestigationValidationError(
                name,
                f"{item_path}.name",
                f"expected one of: {allowed}",
            ) from exc
        result.append(
            TeamInvestigationNamedCount(
                name=kind,
                count=_integer(
                    item["count"],
                    name=name,
                    path=f"{item_path}.count",
                    minimum=1,
                    maximum=span_count,
                ),
            )
        )
    parsed = tuple(result)
    if tuple(item.name for item in parsed) != tuple(sorted({item.name for item in parsed})):
        raise TeamInvestigationValidationError(
            name,
            path,
            "span kinds must be unique and sorted",
        )
    if sum(item.count for item in parsed) > span_count:
        raise TeamInvestigationValidationError(name, path, "counts exceed span_count")
    return parsed


def _status_counts(
    value: Any,
    *,
    name: str,
    path: str,
    span_count: int,
) -> tuple[TeamInvestigationStatusCount, ...]:
    result: list[TeamInvestigationStatusCount] = []
    for index, value_item in enumerate(_array(value, name=name, path=path, minimum=0, maximum=3)):
        item_path = f"{path}[{index}]"
        item = _object(
            value_item,
            name=name,
            path=item_path,
            required={"code", "count"},
        )
        result.append(
            TeamInvestigationStatusCount(
                code=_integer(
                    item["code"],
                    name=name,
                    path=f"{item_path}.code",
                    minimum=0,
                    maximum=2,
                ),
                count=_integer(
                    item["count"],
                    name=name,
                    path=f"{item_path}.count",
                    minimum=1,
                    maximum=span_count,
                ),
            )
        )
    parsed = tuple(result)
    if tuple(item.code for item in parsed) != tuple(sorted({item.code for item in parsed})):
        raise TeamInvestigationValidationError(
            name,
            path,
            "status codes must be unique and sorted",
        )
    if sum(item.count for item in parsed) > span_count:
        raise TeamInvestigationValidationError(name, path, "counts exceed span_count")
    return parsed


def _identifiers(value: Any, *, name: str, path: str) -> tuple[str, ...]:
    result = tuple(
        _text(
            item,
            name=name,
            path=f"{path}[{index}]",
            maximum=128,
            pattern=_SAFE_TRACE_TEXT_PATTERN,
        )
        for index, item in enumerate(_array(value, name=name, path=path, minimum=0, maximum=10_000))
    )
    if result != tuple(sorted(set(result))):
        raise TeamInvestigationValidationError(
            name,
            path,
            "values must be unique and sorted",
        )
    return result


def _observation_id(trace_source_sha256: str, cluster_id: str) -> str:
    digest = hashlib.sha256(f"{trace_source_sha256}:{cluster_id}".encode("ascii")).hexdigest()
    return f"observation-{digest}"


def _parse_observation(
    value: Any,
    *,
    name: str,
    path: str,
) -> TeamInvestigationObservation:
    obj = _object(
        value,
        name=name,
        path=path,
        required={
            "observation_id",
            "attached_at",
            "attached_by",
            "fixture",
            "fixture_id",
            "manifest_sha256",
            "trace_source_sha256",
            "cluster_id",
            "trace_id_sha256",
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
    trace_source = _text(
        obj["trace_source_sha256"],
        name=name,
        path=f"{path}.trace_source_sha256",
        maximum=64,
        pattern=_SHA256_PATTERN,
    )
    trace_id = _text(
        obj["trace_id_sha256"],
        name=name,
        path=f"{path}.trace_id_sha256",
        maximum=64,
        pattern=_SHA256_PATTERN,
    )
    cluster_id = _text(
        obj["cluster_id"],
        name=name,
        path=f"{path}.cluster_id",
        maximum=70,
        pattern=_CLUSTER_ID_PATTERN,
    )
    if cluster_id != f"trace-{trace_id}":
        raise TeamInvestigationValidationError(
            name,
            f"{path}.cluster_id",
            "must be derived from trace_id_sha256",
        )
    observation_id = _text(
        obj["observation_id"],
        name=name,
        path=f"{path}.observation_id",
        maximum=76,
        pattern=_OBSERVATION_ID_PATTERN,
    )
    if observation_id != _observation_id(trace_source, cluster_id):
        raise TeamInvestigationValidationError(
            name,
            f"{path}.observation_id",
            "must be derived from trace source and cluster identity",
        )
    span_count = _integer(
        obj["span_count"],
        name=name,
        path=f"{path}.span_count",
        minimum=1,
        maximum=1_000_000,
    )
    root_count = _integer(
        obj["root_span_count"],
        name=name,
        path=f"{path}.root_span_count",
        minimum=0,
        maximum=span_count,
    )
    error_count = _integer(
        obj["error_span_count"],
        name=name,
        path=f"{path}.error_span_count",
        minimum=0,
        maximum=span_count,
    )
    kinds = _named_counts(
        obj["span_kind_counts"],
        name=name,
        path=f"{path}.span_kind_counts",
        span_count=span_count,
    )
    statuses = _status_counts(
        obj["status_code_counts"],
        name=name,
        path=f"{path}.status_code_counts",
        span_count=span_count,
    )
    if next((item.count for item in statuses if item.code == 2), 0) != error_count:
        raise TeamInvestigationValidationError(
            name,
            f"{path}.error_span_count",
            "must equal the status-code 2 count",
        )
    earliest = (
        None
        if "earliest_start_time_unix_nano" not in obj
        else _decimal(
            obj["earliest_start_time_unix_nano"],
            name=name,
            path=f"{path}.earliest_start_time_unix_nano",
        )
    )
    latest = (
        None
        if "latest_end_time_unix_nano" not in obj
        else _decimal(
            obj["latest_end_time_unix_nano"],
            name=name,
            path=f"{path}.latest_end_time_unix_nano",
        )
    )
    duration = (
        None
        if "observed_duration_nano" not in obj
        else _decimal(
            obj["observed_duration_nano"],
            name=name,
            path=f"{path}.observed_duration_nano",
        )
    )
    expected_duration = (
        str(int(latest) - int(earliest))
        if earliest is not None and latest is not None and int(latest) >= int(earliest)
        else None
    )
    if duration != expected_duration:
        raise TeamInvestigationValidationError(
            name,
            f"{path}.observed_duration_nano",
            "must equal the declared observation window",
        )
    return TeamInvestigationObservation(
        observation_id=observation_id,
        attached_at=_timestamp(obj["attached_at"], name=name, path=f"{path}.attached_at"),
        attached_by=_principal(obj["attached_by"], name=name, path=f"{path}.attached_by"),
        fixture=_subject(obj["fixture"], name=name, path=f"{path}.fixture"),
        fixture_id=_text(
            obj["fixture_id"],
            name=name,
            path=f"{path}.fixture_id",
            maximum=128,
            pattern=_INVESTIGATION_ID_PATTERN,
        ),
        manifest_sha256=_text(
            obj["manifest_sha256"],
            name=name,
            path=f"{path}.manifest_sha256",
            maximum=64,
            pattern=_SHA256_PATTERN,
        ),
        trace_source_sha256=trace_source,
        cluster_id=cluster_id,
        trace_id_sha256=trace_id,
        span_count=span_count,
        root_span_count=root_count,
        error_span_count=error_count,
        span_kind_counts=kinds,
        status_code_counts=statuses,
        model_identifiers=_identifiers(
            obj["model_identifiers"],
            name=name,
            path=f"{path}.model_identifiers",
        ),
        provider_identifiers=_identifiers(
            obj["provider_identifiers"],
            name=name,
            path=f"{path}.provider_identifiers",
        ),
        earliest_start_time_unix_nano=earliest,
        latest_end_time_unix_nano=latest,
        observed_duration_nano=duration,
    )


def _validate_resolution(
    *,
    name: str,
    investigation_id: str,
    status: TeamInvestigationStatus,
    resolution: TeamInvestigationResolution | None,
    linked_case_id: str | None,
    duplicate_of: str | None,
) -> None:
    if status is not TeamInvestigationStatus.CLOSED:
        if resolution is not None or linked_case_id is not None or duplicate_of is not None:
            raise TeamInvestigationValidationError(
                name,
                "$.resolution",
                "resolution and linkage fields require closed status",
            )
        return
    if resolution is None:
        raise TeamInvestigationValidationError(
            name,
            "$.resolution",
            "closed investigations require a resolution",
        )
    if resolution is TeamInvestigationResolution.CHANGE_CASE_OPENED:
        if linked_case_id is None or duplicate_of is not None:
            raise TeamInvestigationValidationError(
                name,
                "$.linked_case_id",
                "change_case_opened requires only linked_case_id",
            )
    elif resolution is TeamInvestigationResolution.DUPLICATE:
        if duplicate_of is None or linked_case_id is not None:
            raise TeamInvestigationValidationError(
                name,
                "$.duplicate_of",
                "duplicate requires only duplicate_of",
            )
        if duplicate_of == investigation_id:
            raise TeamInvestigationValidationError(
                name,
                "$.duplicate_of",
                "an investigation cannot duplicate itself",
            )
    elif linked_case_id is not None or duplicate_of is not None:
        raise TeamInvestigationValidationError(
            name,
            "$.resolution",
            "this resolution does not permit linkage fields",
        )


def parse_team_investigation_record(document: Any) -> TeamInvestigationRecord:
    """Strictly parse one minimized Team investigation queue record."""

    name = "Team investigation record"
    root = _object(
        document,
        name=name,
        path="$",
        required={
            "schema_version",
            "tenant_id",
            "investigation_id",
            "revision",
            "created_at",
            "updated_at",
            "title",
            "status",
            "priority",
            "opened_by",
            "candidate_only",
            "gate_eligible",
            "causal_claims_inferred",
            "observations",
        },
        optional={"assigned_to", "resolution", "linked_case_id", "duplicate_of"},
    )
    if root["schema_version"] != TEAM_INVESTIGATION_RECORD_SCHEMA_VERSION:
        raise TeamInvestigationValidationError(
            name,
            "$.schema_version",
            f"expected {TEAM_INVESTIGATION_RECORD_SCHEMA_VERSION!r}",
        )
    if _boolean(root["candidate_only"], name=name, path="$.candidate_only") is not True:
        raise TeamInvestigationValidationError(name, "$.candidate_only", "expected true")
    if _boolean(root["gate_eligible"], name=name, path="$.gate_eligible") is not False:
        raise TeamInvestigationValidationError(name, "$.gate_eligible", "expected false")
    if (
        _boolean(
            root["causal_claims_inferred"],
            name=name,
            path="$.causal_claims_inferred",
        )
        is not False
    ):
        raise TeamInvestigationValidationError(
            name,
            "$.causal_claims_inferred",
            "expected false",
        )
    investigation_id = _text(
        root["investigation_id"],
        name=name,
        path="$.investigation_id",
        maximum=128,
        pattern=_INVESTIGATION_ID_PATTERN,
    )
    created_at = _timestamp(root["created_at"], name=name, path="$.created_at")
    updated_at = _timestamp(root["updated_at"], name=name, path="$.updated_at")
    if updated_at < created_at:
        raise TeamInvestigationValidationError(
            name,
            "$.updated_at",
            "must be at or after created_at",
        )
    observations = tuple(
        _parse_observation(item, name=name, path=f"$.observations[{index}]")
        for index, item in enumerate(
            _array(
                root["observations"],
                name=name,
                path="$.observations",
                minimum=1,
                maximum=MAX_TEAM_INVESTIGATION_OBSERVATIONS,
            )
        )
    )
    observation_ids = tuple(item.observation_id for item in observations)
    if len(set(observation_ids)) != len(observation_ids):
        raise TeamInvestigationValidationError(
            name,
            "$.observations",
            "observation identities must be unique",
        )
    attachment_times = tuple(item.attached_at for item in observations)
    if attachment_times != tuple(sorted(set(attachment_times))):
        raise TeamInvestigationValidationError(
            name,
            "$.observations",
            "attachment times must strictly increase",
        )
    if observations[0].attached_at != created_at:
        raise TeamInvestigationValidationError(
            name,
            "$.created_at",
            "must equal the first observation attachment time",
        )
    if observations[-1].attached_at > updated_at:
        raise TeamInvestigationValidationError(
            name,
            "$.updated_at",
            "must not precede an observation attachment",
        )
    revision = _integer(
        root["revision"],
        name=name,
        path="$.revision",
        minimum=1,
        maximum=10_000,
    )
    if revision < len(observations):
        raise TeamInvestigationValidationError(
            name,
            "$.revision",
            "cannot be less than the observation count",
        )
    opened_by = _principal(root["opened_by"], name=name, path="$.opened_by")
    if observations[0].attached_by != opened_by:
        raise TeamInvestigationValidationError(
            name,
            "$.opened_by",
            "must equal the principal that attached the first observation",
        )
    status = _enum(
        root["status"],
        name=name,
        path="$.status",
        enum_type=TeamInvestigationStatus,
    )
    priority = _enum(
        root["priority"],
        name=name,
        path="$.priority",
        enum_type=TeamInvestigationPriority,
    )
    assigned_to = (
        None
        if "assigned_to" not in root
        else _principal(root["assigned_to"], name=name, path="$.assigned_to")
    )
    resolution = (
        None
        if "resolution" not in root
        else _enum(
            root["resolution"],
            name=name,
            path="$.resolution",
            enum_type=TeamInvestigationResolution,
        )
    )
    linked_case_id = (
        None
        if "linked_case_id" not in root
        else _text(
            root["linked_case_id"],
            name=name,
            path="$.linked_case_id",
            maximum=128,
            pattern=_INVESTIGATION_ID_PATTERN,
        )
    )
    duplicate_of = (
        None
        if "duplicate_of" not in root
        else _text(
            root["duplicate_of"],
            name=name,
            path="$.duplicate_of",
            maximum=128,
            pattern=_INVESTIGATION_ID_PATTERN,
        )
    )
    _validate_resolution(
        name=name,
        investigation_id=investigation_id,
        status=status,
        resolution=resolution,
        linked_case_id=linked_case_id,
        duplicate_of=duplicate_of,
    )
    return TeamInvestigationRecord(
        schema_version=TEAM_INVESTIGATION_RECORD_SCHEMA_VERSION,
        tenant_id=_text(
            root["tenant_id"],
            name=name,
            path="$.tenant_id",
            maximum=128,
            pattern=_SAFE_ID_PATTERN,
        ),
        investigation_id=investigation_id,
        revision=revision,
        created_at=created_at,
        updated_at=updated_at,
        title=_text(root["title"], name=name, path="$.title", maximum=256),
        status=status,
        priority=priority,
        opened_by=opened_by,
        candidate_only=True,
        gate_eligible=False,
        causal_claims_inferred=False,
        observations=observations,
        assigned_to=assigned_to,
        resolution=resolution,
        linked_case_id=linked_case_id,
        duplicate_of=duplicate_of,
    )


def _json_bytes(raw_bytes: bytes) -> Any:
    name = "Team investigation record"
    if not isinstance(raw_bytes, bytes):
        raise TypeError("record_bytes must be bytes")
    if not 1 <= len(raw_bytes) <= MAX_TEAM_INVESTIGATION_RECORD_BYTES:
        raise TeamInvestigationValidationError(
            name,
            "$",
            f"expected from 1 to {MAX_TEAM_INVESTIGATION_RECORD_BYTES} bytes",
        )
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TeamInvestigationValidationError(name, "$", "document is not valid UTF-8") from exc
    try:
        return parse_json_text(
            text,
            source=name,
            max_bytes=MAX_TEAM_INVESTIGATION_RECORD_BYTES,
        )
    except InputDocumentError as exc:
        raise TeamInvestigationValidationError(name, "$", str(exc)) from exc


def parse_team_investigation_record_bytes(raw_bytes: bytes) -> TeamInvestigationRecord:
    """Parse exact bounded UTF-8 Team investigation-record bytes."""

    return parse_team_investigation_record(_json_bytes(raw_bytes))


def _fixture_cluster(
    fixture_bytes: bytes,
    cluster_id: str,
) -> tuple[InvestigationFixture, CandidateTraceCluster]:
    if not isinstance(fixture_bytes, bytes):
        raise TypeError("fixture_bytes must be bytes")
    if not 1 <= len(fixture_bytes) <= MAX_TEAM_INVESTIGATION_SOURCE_BYTES:
        raise TeamInvestigationValidationError(
            "investigation fixture",
            "$",
            f"expected from 1 to {MAX_TEAM_INVESTIGATION_SOURCE_BYTES} bytes",
        )
    selected_id = _text(
        cluster_id,
        name="investigation fixture",
        path="$.selected_cluster_id",
        maximum=70,
        pattern=_CLUSTER_ID_PATTERN,
    )
    try:
        fixture = parse_investigation_fixture_bytes(fixture_bytes)
    except InvestigationFixtureValidationError as exc:
        raise TeamInvestigationValidationError(
            "investigation fixture",
            exc.path,
            exc.message,
        ) from exc
    for cluster in fixture.candidate_clusters:
        if cluster.cluster_id == selected_id:
            return fixture, cluster
    raise TeamInvestigationValidationError(
        "investigation fixture",
        "$.selected_cluster_id",
        "does not identify a candidate cluster in the supplied exact fixture",
    )


def _observation(
    fixture_bytes: bytes,
    cluster_id: str,
    *,
    attached_at: str,
    attached_by: TeamPrincipal,
) -> TeamInvestigationObservation:
    fixture, cluster = _fixture_cluster(fixture_bytes, cluster_id)
    principal = _validated_principal(attached_by, path="$.attached_by")
    instant = _timestamp(
        attached_at,
        name="Team investigation record",
        path="$.updated_at",
    )
    return TeamInvestigationObservation(
        observation_id=_observation_id(
            fixture.source.trace_source_sha256,
            cluster.cluster_id,
        ),
        attached_at=instant,
        attached_by=principal,
        fixture=TeamInvestigationArtifactSubject(
            media_type=INVESTIGATION_FIXTURE_MEDIA_TYPE,
            sha256=hashlib.sha256(fixture_bytes).hexdigest(),
            byte_count=len(fixture_bytes),
        ),
        fixture_id=fixture.fixture_id,
        manifest_sha256=fixture.source.manifest_sha256,
        trace_source_sha256=fixture.source.trace_source_sha256,
        cluster_id=cluster.cluster_id,
        trace_id_sha256=cluster.trace_id_sha256,
        span_count=cluster.span_count,
        root_span_count=cluster.root_span_count,
        error_span_count=cluster.error_span_count,
        span_kind_counts=tuple(
            TeamInvestigationNamedCount(name=item.name, count=item.count)
            for item in cluster.span_kind_counts
        ),
        status_code_counts=tuple(
            TeamInvestigationStatusCount(code=item.code, count=item.count)
            for item in cluster.status_code_counts
        ),
        model_identifiers=cluster.model_identifiers,
        provider_identifiers=cluster.provider_identifiers,
        earliest_start_time_unix_nano=cluster.earliest_start_time_unix_nano,
        latest_end_time_unix_nano=cluster.latest_end_time_unix_nano,
        observed_duration_nano=cluster.observed_duration_nano,
    )


def _bounded(record: TeamInvestigationRecord) -> TeamInvestigationRecord:
    rendered = render_team_investigation_record(record).encode("utf-8")
    if len(rendered) > MAX_TEAM_INVESTIGATION_RECORD_BYTES:
        raise TeamInvestigationValidationError(
            "Team investigation record",
            "$",
            f"derived record exceeds the {MAX_TEAM_INVESTIGATION_RECORD_BYTES}-byte limit",
        )
    return record


def create_team_investigation_record(
    fixture_bytes: bytes,
    *,
    tenant_id: str,
    investigation_id: str,
    cluster_id: str,
    title: str,
    priority: TeamInvestigationPriority | str,
    opened_at: str,
    opened_by: TeamPrincipal,
) -> TeamInvestigationRecord:
    """Open a candidate-only queue record from one exact fixture cluster."""

    try:
        resolved_priority = TeamInvestigationPriority(priority)
    except (TypeError, ValueError) as exc:
        raise TeamInvestigationValidationError(
            "Team investigation record",
            "$.priority",
            "priority is not a supported queue priority",
        ) from exc
    observation = _observation(
        fixture_bytes,
        cluster_id,
        attached_at=opened_at,
        attached_by=opened_by,
    )
    record = TeamInvestigationRecord(
        schema_version=TEAM_INVESTIGATION_RECORD_SCHEMA_VERSION,
        tenant_id=tenant_id,
        investigation_id=investigation_id,
        revision=1,
        created_at=opened_at,
        updated_at=opened_at,
        title=title,
        status=TeamInvestigationStatus.QUEUED,
        priority=resolved_priority,
        opened_by=opened_by,
        candidate_only=True,
        gate_eligible=False,
        causal_claims_inferred=False,
        observations=(observation,),
    )
    validated = parse_team_investigation_record(to_jsonable(record))
    validate_team_investigation_successor(None, validated)
    return _bounded(validated)


def attach_team_investigation_observation(
    previous: TeamInvestigationRecord,
    fixture_bytes: bytes,
    *,
    cluster_id: str,
    attached_at: str,
    attached_by: TeamPrincipal,
) -> TeamInvestigationRecord:
    """Append exactly one distinct candidate trace cluster to an open investigation."""

    if not isinstance(previous, TeamInvestigationRecord):
        raise TypeError("previous must be a TeamInvestigationRecord")
    validated_previous = parse_team_investigation_record(to_jsonable(previous))
    if len(validated_previous.observations) >= MAX_TEAM_INVESTIGATION_OBSERVATIONS:
        raise TeamInvestigationValidationError(
            "Team investigation record",
            "$.observations",
            f"supports at most {MAX_TEAM_INVESTIGATION_OBSERVATIONS} observations",
        )
    observation = _observation(
        fixture_bytes,
        cluster_id,
        attached_at=attached_at,
        attached_by=attached_by,
    )
    if any(
        item.observation_id == observation.observation_id
        for item in validated_previous.observations
    ):
        raise TeamInvestigationValidationError(
            "Team investigation record",
            "$.observations",
            "the selected trace cluster is already attached",
        )
    candidate = replace(
        validated_previous,
        revision=validated_previous.revision + 1,
        updated_at=attached_at,
        observations=validated_previous.observations + (observation,),
    )
    validated = parse_team_investigation_record(to_jsonable(candidate))
    validate_team_investigation_successor(validated_previous, validated)
    return _bounded(validated)


def transition_team_investigation_record(
    previous: TeamInvestigationRecord,
    *,
    updated_at: str,
    title: str,
    status: TeamInvestigationStatus | str,
    priority: TeamInvestigationPriority | str,
    assigned_to: TeamPrincipal | None,
    resolution: TeamInvestigationResolution | str | None = None,
    linked_case_id: str | None = None,
    duplicate_of: str | None = None,
) -> TeamInvestigationRecord:
    """Create one queue-state successor without changing attached evidence."""

    if not isinstance(previous, TeamInvestigationRecord):
        raise TypeError("previous must be a TeamInvestigationRecord")
    validated_previous = parse_team_investigation_record(to_jsonable(previous))
    try:
        resolved_status = TeamInvestigationStatus(status)
        resolved_priority = TeamInvestigationPriority(priority)
        resolved_resolution = (
            None if resolution is None else TeamInvestigationResolution(resolution)
        )
    except (TypeError, ValueError) as exc:
        raise TeamInvestigationValidationError(
            "Team investigation record",
            "$",
            "transition contains an unsupported enum value",
        ) from exc
    resolved_assignee = (
        None if assigned_to is None else _validated_principal(assigned_to, path="$.assigned_to")
    )
    candidate = replace(
        validated_previous,
        revision=validated_previous.revision + 1,
        updated_at=updated_at,
        title=title,
        status=resolved_status,
        priority=resolved_priority,
        assigned_to=resolved_assignee,
        resolution=resolved_resolution,
        linked_case_id=linked_case_id,
        duplicate_of=duplicate_of,
    )
    validated = parse_team_investigation_record(to_jsonable(candidate))
    validate_team_investigation_successor(validated_previous, validated)
    return _bounded(validated)


def validate_team_investigation_successor(
    previous: TeamInvestigationRecord | None,
    candidate: TeamInvestigationRecord,
) -> TeamInvestigationRecord:
    """Require one append-only observation or queue-state transition per revision."""

    if not isinstance(candidate, TeamInvestigationRecord):
        raise TypeError("candidate must be a TeamInvestigationRecord")
    candidate = parse_team_investigation_record(to_jsonable(candidate))
    name = "Team investigation record"
    if previous is None:
        first = candidate.observations[0]
        if (
            candidate.revision != 1
            or candidate.status is not TeamInvestigationStatus.QUEUED
            or candidate.created_at != candidate.updated_at
            or len(candidate.observations) != 1
            or first.attached_at != candidate.created_at
            or candidate.assigned_to is not None
            or candidate.resolution is not None
        ):
            raise TeamInvestigationValidationError(
                name,
                "$",
                "the first revision must be one unassigned queued observation",
            )
        return candidate
    if not isinstance(previous, TeamInvestigationRecord):
        raise TypeError("previous must be a TeamInvestigationRecord or None")
    previous = parse_team_investigation_record(to_jsonable(previous))
    if previous.status is TeamInvestigationStatus.CLOSED:
        raise TeamInvestigationValidationError(
            name,
            "$.status",
            "closed investigations are terminal",
        )
    if (
        candidate.tenant_id != previous.tenant_id
        or candidate.investigation_id != previous.investigation_id
    ):
        raise TeamInvestigationValidationError(
            name,
            "$",
            "successor tenant and investigation id must remain unchanged",
        )
    if candidate.revision != previous.revision + 1:
        raise TeamInvestigationValidationError(
            name,
            "$.revision",
            "must advance the previous revision by one",
        )
    if candidate.updated_at <= previous.updated_at:
        raise TeamInvestigationValidationError(
            name,
            "$.updated_at",
            "must advance the previous update time",
        )
    if (
        candidate.schema_version != previous.schema_version
        or candidate.created_at != previous.created_at
        or candidate.opened_by != previous.opened_by
        or candidate.candidate_only != previous.candidate_only
        or candidate.gate_eligible != previous.gate_eligible
        or candidate.causal_claims_inferred != previous.causal_claims_inferred
    ):
        raise TeamInvestigationValidationError(
            name,
            "$",
            "identity, provenance semantics, and opening metadata are immutable",
        )
    previous_observations = previous.observations
    candidate_observations = candidate.observations
    observation_added = candidate_observations != previous_observations
    if observation_added:
        if (
            len(candidate_observations) != len(previous_observations) + 1
            or candidate_observations[:-1] != previous_observations
            or candidate_observations[-1].attached_at != candidate.updated_at
        ):
            raise TeamInvestigationValidationError(
                name,
                "$.observations",
                "a successor may append exactly one immutable observation",
            )
        if (
            candidate.title,
            candidate.status,
            candidate.priority,
            candidate.assigned_to,
            candidate.resolution,
            candidate.linked_case_id,
            candidate.duplicate_of,
        ) != (
            previous.title,
            previous.status,
            previous.priority,
            previous.assigned_to,
            previous.resolution,
            previous.linked_case_id,
            previous.duplicate_of,
        ):
            raise TeamInvestigationValidationError(
                name,
                "$",
                "observation attachment cannot also change queue state",
            )
        return candidate
    allowed_statuses = {
        TeamInvestigationStatus.QUEUED: {
            TeamInvestigationStatus.QUEUED,
            TeamInvestigationStatus.INVESTIGATING,
            TeamInvestigationStatus.BLOCKED,
            TeamInvestigationStatus.CLOSED,
        },
        TeamInvestigationStatus.INVESTIGATING: {
            TeamInvestigationStatus.INVESTIGATING,
            TeamInvestigationStatus.BLOCKED,
            TeamInvestigationStatus.CLOSED,
        },
        TeamInvestigationStatus.BLOCKED: {
            TeamInvestigationStatus.BLOCKED,
            TeamInvestigationStatus.INVESTIGATING,
            TeamInvestigationStatus.CLOSED,
        },
    }
    if candidate.status not in allowed_statuses[previous.status]:
        raise TeamInvestigationValidationError(
            name,
            "$.status",
            "queue status transition is not allowed",
        )
    if (
        candidate.title,
        candidate.status,
        candidate.priority,
        candidate.assigned_to,
        candidate.resolution,
        candidate.linked_case_id,
        candidate.duplicate_of,
    ) == (
        previous.title,
        previous.status,
        previous.priority,
        previous.assigned_to,
        previous.resolution,
        previous.linked_case_id,
        previous.duplicate_of,
    ):
        raise TeamInvestigationValidationError(
            name,
            "$",
            "a queue-state successor must make a material change",
        )
    return candidate


def render_team_investigation_record(record: TeamInvestigationRecord) -> str:
    """Render one canonical, minimized Team investigation queue record."""

    validated = parse_team_investigation_record(to_jsonable(record))
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
