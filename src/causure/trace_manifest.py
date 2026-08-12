"""Strict parsing for redacted trace manifests."""

from __future__ import annotations

import math
import re
from enum import Enum
from typing import Any, TypeVar

from causure.collector import (
    CollectedSpan,
    RedactionSummary,
    TraceManifest,
    TraceSource,
)
from causure.constants import (
    OMITTED_TRACE_FIELD_GROUPS,
    SAFE_TRACE_NUMERIC_ATTRIBUTES,
    SAFE_TRACE_TEXT_ATTRIBUTES,
    SAFE_TRACE_TEXT_PATTERN,
    TRACE_MANIFEST_SCHEMA_VERSION,
    OpenInferenceSpanKind,
    RedactionStrategy,
    TraceSourceFormat,
)

_ARTIFACT_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_VERSION_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+-]{0,63}$")
_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")
_SAFE_TEXT_PATTERN = re.compile(SAFE_TRACE_TEXT_PATTERN)
_UINT64_MAX = (1 << 64) - 1
_EnumT = TypeVar("_EnumT", bound=Enum)


class TraceManifestValidationError(ValueError):
    """Raised when a redacted trace manifest violates its wire contract."""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.message = message
        super().__init__(f"Invalid trace manifest at {path}: {message}")


def _object(
    value: Any,
    path: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TraceManifestValidationError(path, "expected an object")
    allowed = required | (optional or set())
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise TraceManifestValidationError(path, f"unknown field: {unknown[0]}")
    missing = sorted(required - set(value))
    if missing:
        raise TraceManifestValidationError(path, f"missing required field: {missing[0]}")
    return value


def _array(value: Any, path: str, *, minimum: int = 0) -> list[Any]:
    if not isinstance(value, list):
        raise TraceManifestValidationError(path, "expected an array")
    if len(value) < minimum:
        raise TraceManifestValidationError(path, f"expected at least {minimum} item(s)")
    return value


def _string(value: Any, path: str, *, pattern: re.Pattern[str] | None = None) -> str:
    if not isinstance(value, str) or not value:
        raise TraceManifestValidationError(path, "expected a non-empty string")
    if pattern is not None and not pattern.fullmatch(value):
        raise TraceManifestValidationError(path, "value does not match the required format")
    return value


def _integer(
    value: Any,
    path: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TraceManifestValidationError(path, "expected an integer")
    if value < minimum or (maximum is not None and value > maximum):
        if maximum is None:
            message = f"expected an integer of at least {minimum}"
        else:
            message = f"expected an integer from {minimum} to {maximum}"
        raise TraceManifestValidationError(path, message)
    return value


def _is_nonnegative_finite_number(value: Any) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value)) and value >= 0
    except (OverflowError, ValueError):
        return False


def _enum(value: Any, path: str, enum_type: type[_EnumT]) -> _EnumT:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(member.value for member in enum_type)
        raise TraceManifestValidationError(path, f"expected one of: {allowed}") from exc


def _sha256(value: Any, path: str) -> str:
    return _string(value, path, pattern=_SHA256_PATTERN)


def _decimal(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.isdecimal():
        raise TraceManifestValidationError(path, "expected a canonical uint64 decimal string")
    if len(value) > len(str(_UINT64_MAX)):
        raise TraceManifestValidationError(path, "decimal string exceeds the uint64 range")
    number = int(value)
    if number > _UINT64_MAX or str(number) != value:
        raise TraceManifestValidationError(path, "expected a canonical uint64 decimal string")
    return value


def _parse_source(value: Any) -> TraceSource:
    path = "$.source"
    obj = _object(
        value,
        path,
        required={
            "artifact_id",
            "format",
            "media_type",
            "sha256",
            "byte_count",
            "trace_count",
            "span_count",
            "source_embedded",
        },
    )
    if obj["media_type"] != "application/json":
        raise TraceManifestValidationError(
            f"{path}.media_type",
            "expected application/json",
        )
    if obj["source_embedded"] is not False:
        raise TraceManifestValidationError(
            f"{path}.source_embedded",
            "source content must not be embedded",
        )
    return TraceSource(
        artifact_id=_string(
            obj["artifact_id"],
            f"{path}.artifact_id",
            pattern=_ARTIFACT_ID_PATTERN,
        ),
        format=_enum(obj["format"], f"{path}.format", TraceSourceFormat),
        media_type="application/json",
        sha256=_sha256(obj["sha256"], f"{path}.sha256"),
        byte_count=_integer(obj["byte_count"], f"{path}.byte_count", minimum=1),
        trace_count=_integer(obj["trace_count"], f"{path}.trace_count", minimum=1),
        span_count=_integer(obj["span_count"], f"{path}.span_count", minimum=1),
        source_embedded=False,
    )


def _parse_redaction(value: Any) -> RedactionSummary:
    path = "$.redaction"
    obj = _object(
        value,
        path,
        required={
            "strategy",
            "raw_content_included",
            "retained_attribute_count",
            "redacted_attribute_count",
            "dropped_attribute_count",
            "omitted_field_groups",
        },
    )
    if obj["raw_content_included"] is not False:
        raise TraceManifestValidationError(
            f"{path}.raw_content_included",
            "raw content must not be included",
        )
    omitted = tuple(
        _string(item, f"{path}.omitted_field_groups[{index}]")
        for index, item in enumerate(
            _array(
                obj["omitted_field_groups"],
                f"{path}.omitted_field_groups",
                minimum=len(OMITTED_TRACE_FIELD_GROUPS),
            )
        )
    )
    if omitted != OMITTED_TRACE_FIELD_GROUPS:
        raise TraceManifestValidationError(
            f"{path}.omitted_field_groups",
            "expected the canonical omitted-field list",
        )
    return RedactionSummary(
        strategy=_enum(obj["strategy"], f"{path}.strategy", RedactionStrategy),
        raw_content_included=False,
        retained_attribute_count=_integer(
            obj["retained_attribute_count"],
            f"{path}.retained_attribute_count",
        ),
        redacted_attribute_count=_integer(
            obj["redacted_attribute_count"],
            f"{path}.redacted_attribute_count",
        ),
        dropped_attribute_count=_integer(
            obj["dropped_attribute_count"],
            f"{path}.dropped_attribute_count",
        ),
        omitted_field_groups=omitted,
    )


def _parse_attribute(value: Any, path: str, key: str) -> str | int | float:
    if key in SAFE_TRACE_TEXT_ATTRIBUTES:
        text = _string(value, path)
        if key == "openinference.span.kind":
            return _enum(text, path, OpenInferenceSpanKind).value
        if not _SAFE_TEXT_PATTERN.fullmatch(text):
            raise TraceManifestValidationError(
                path,
                "text metadata does not match the safe identifier format",
            )
        return text
    if key in SAFE_TRACE_NUMERIC_ATTRIBUTES:
        if not _is_nonnegative_finite_number(value):
            raise TraceManifestValidationError(
                path,
                "numeric metadata must be a non-negative finite number",
            )
        return value
    raise TraceManifestValidationError(path, f"attribute is not allowlisted: {key}")


def _parse_span(value: Any, index: int, source_sha256: str) -> CollectedSpan:
    path = f"$.spans[{index}]"
    obj = _object(
        value,
        path,
        required={
            "evidence_ref",
            "trace_id_sha256",
            "span_id_sha256",
            "attributes",
        },
        optional={
            "parent_span_id_sha256",
            "start_time_unix_nano",
            "end_time_unix_nano",
            "duration_nano",
            "kind",
            "status_code",
        },
    )
    trace_hash = _sha256(obj["trace_id_sha256"], f"{path}.trace_id_sha256")
    span_hash = _sha256(obj["span_id_sha256"], f"{path}.span_id_sha256")
    evidence_ref = _string(obj["evidence_ref"], f"{path}.evidence_ref")
    expected_ref = f"trace-sha256://{source_sha256}/spans/{span_hash}"
    if evidence_ref != expected_ref:
        raise TraceManifestValidationError(
            f"{path}.evidence_ref",
            "reference does not match the source and span hashes",
        )

    parent_hash = None
    if "parent_span_id_sha256" in obj:
        parent_hash = _sha256(
            obj["parent_span_id_sha256"],
            f"{path}.parent_span_id_sha256",
        )
        if parent_hash == span_hash:
            raise TraceManifestValidationError(
                f"{path}.parent_span_id_sha256",
                "a span cannot be its own parent",
            )

    start = (
        _decimal(obj["start_time_unix_nano"], f"{path}.start_time_unix_nano")
        if "start_time_unix_nano" in obj
        else None
    )
    end = (
        _decimal(obj["end_time_unix_nano"], f"{path}.end_time_unix_nano")
        if "end_time_unix_nano" in obj
        else None
    )
    duration = (
        _decimal(obj["duration_nano"], f"{path}.duration_nano") if "duration_nano" in obj else None
    )
    if start is not None and end is not None:
        if int(end) < int(start):
            raise TraceManifestValidationError(path, "span end time precedes start time")
        expected_duration = str(int(end) - int(start))
        if duration != expected_duration:
            raise TraceManifestValidationError(
                f"{path}.duration_nano",
                "duration does not match the start and end timestamps",
            )
    elif duration is not None:
        raise TraceManifestValidationError(
            f"{path}.duration_nano",
            "duration requires both start and end timestamps",
        )

    attributes_obj = _object(
        obj["attributes"],
        f"{path}.attributes",
        required=set(),
        optional=set(SAFE_TRACE_TEXT_ATTRIBUTES) | set(SAFE_TRACE_NUMERIC_ATTRIBUTES),
    )
    attributes = {
        key: _parse_attribute(
            attribute_value,
            f"{path}.attributes.{key}",
            key,
        )
        for key, attribute_value in sorted(attributes_obj.items())
    }
    return CollectedSpan(
        evidence_ref=evidence_ref,
        trace_id_sha256=trace_hash,
        span_id_sha256=span_hash,
        parent_span_id_sha256=parent_hash,
        start_time_unix_nano=start,
        end_time_unix_nano=end,
        duration_nano=duration,
        kind=(_integer(obj["kind"], f"{path}.kind", maximum=5) if "kind" in obj else None),
        status_code=(
            _integer(obj["status_code"], f"{path}.status_code", maximum=2)
            if "status_code" in obj
            else None
        ),
        attributes=attributes,
    )


def parse_trace_manifest(document: Any) -> TraceManifest:
    """Validate and parse an untrusted redacted trace manifest."""

    root = _object(
        document,
        "$",
        required={
            "schema_version",
            "collector_version",
            "source",
            "redaction",
            "spans",
        },
    )
    if root["schema_version"] != TRACE_MANIFEST_SCHEMA_VERSION:
        raise TraceManifestValidationError(
            "$.schema_version",
            f"expected {TRACE_MANIFEST_SCHEMA_VERSION}",
        )
    collector_version = _string(
        root["collector_version"],
        "$.collector_version",
        pattern=_VERSION_PATTERN,
    )
    source = _parse_source(root["source"])
    redaction = _parse_redaction(root["redaction"])
    spans = tuple(
        _parse_span(span, index, source.sha256)
        for index, span in enumerate(_array(root["spans"], "$.spans", minimum=1))
    )

    if source.span_count != len(spans):
        raise TraceManifestValidationError(
            "$.source.span_count",
            "count does not match the spans array",
        )
    trace_count = len({span.trace_id_sha256 for span in spans})
    if source.trace_count != trace_count:
        raise TraceManifestValidationError(
            "$.source.trace_count",
            "count does not match the distinct trace hashes",
        )
    span_identities = {(span.trace_id_sha256, span.span_id_sha256) for span in spans}
    if len(span_identities) != len(spans):
        raise TraceManifestValidationError("$.spans", "span identities must be unique")
    evidence_refs = {span.evidence_ref for span in spans}
    if len(evidence_refs) != len(spans):
        raise TraceManifestValidationError("$.spans", "evidence references must be unique")
    retained_count = sum(len(span.attributes) for span in spans)
    if redaction.retained_attribute_count != retained_count:
        raise TraceManifestValidationError(
            "$.redaction.retained_attribute_count",
            "count does not match retained span attributes",
        )

    return TraceManifest(
        schema_version=TRACE_MANIFEST_SCHEMA_VERSION,
        collector_version=collector_version,
        source=source,
        redaction=redaction,
        spans=spans,
    )
