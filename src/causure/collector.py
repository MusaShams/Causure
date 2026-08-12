"""Safe, deterministic collection of redacted OTLP trace metadata."""

from __future__ import annotations

import hashlib
import json
import math
import re
from dataclasses import dataclass, field
from typing import Any

from causure.constants import (
    OMITTED_TRACE_FIELD_GROUPS,
    PACKAGE_VERSION,
    SAFE_TRACE_NUMERIC_ATTRIBUTES,
    SAFE_TRACE_TEXT_ATTRIBUTES,
    SAFE_TRACE_TEXT_PATTERN,
    TRACE_MANIFEST_SCHEMA_VERSION,
    OpenInferenceSpanKind,
    RedactionStrategy,
    TraceSourceFormat,
)
from causure.errors import TraceCollectionError
from causure.io import (
    MAX_TRACE_DOCUMENT_BYTES,
    InputDocumentError,
    parse_json_text,
)
from causure.models import to_jsonable

DEFAULT_MAX_SPANS = 10_000
MAX_CONFIGURABLE_SPANS = 100_000

_SOURCE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_TRACE_ID_PATTERN = re.compile(r"^[A-Fa-f0-9]{32}$")
_SPAN_ID_PATTERN = re.compile(r"^[A-Fa-f0-9]{16}$")
_SAFE_TEXT_PATTERN = re.compile(SAFE_TRACE_TEXT_PATTERN)
_UINT64_MAX = (1 << 64) - 1
_INT64_MIN = -(1 << 63)
_INT64_MAX = (1 << 63) - 1

_OPENINFERENCE_SPAN_KINDS = {member.value for member in OpenInferenceSpanKind}

_SAFE_TEXT_ATTRIBUTES = frozenset(SAFE_TRACE_TEXT_ATTRIBUTES)
_SAFE_NUMERIC_ATTRIBUTES = frozenset(SAFE_TRACE_NUMERIC_ATTRIBUTES)

_SENSITIVE_KEY_FRAGMENTS = (
    "api_key",
    "arguments",
    "authorization",
    "content",
    "cookie",
    "document",
    "input",
    "message",
    "metadata",
    "output",
    "password",
    "prompt",
    "query",
    "reasoning",
    "secret",
    "session",
    "signature",
    "tool_call",
    "url",
    "user",
)

PrimitiveAttributeValue = str | int | float | bool
SafeAttributeValue = str | int | float


@dataclass(frozen=True, slots=True)
class TraceSource:
    """Integrity metadata for a source artifact that is never embedded."""

    artifact_id: str
    format: TraceSourceFormat
    media_type: str
    sha256: str
    byte_count: int
    trace_count: int
    span_count: int
    source_embedded: bool = False


@dataclass(frozen=True, slots=True)
class RedactionSummary:
    """Auditable summary of the collector's fail-closed projection."""

    strategy: RedactionStrategy
    raw_content_included: bool
    retained_attribute_count: int
    redacted_attribute_count: int
    dropped_attribute_count: int
    omitted_field_groups: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class CollectedSpan:
    """Non-content span metadata suitable for use as an evidence reference."""

    evidence_ref: str
    trace_id_sha256: str
    span_id_sha256: str
    parent_span_id_sha256: str | None = field(
        default=None,
        metadata={"omit_none": True},
    )
    start_time_unix_nano: str | None = field(
        default=None,
        metadata={"omit_none": True},
    )
    end_time_unix_nano: str | None = field(
        default=None,
        metadata={"omit_none": True},
    )
    duration_nano: str | None = field(
        default=None,
        metadata={"omit_none": True},
    )
    kind: int | None = field(default=None, metadata={"omit_none": True})
    status_code: int | None = field(default=None, metadata={"omit_none": True})
    attributes: dict[str, SafeAttributeValue] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class TraceManifest:
    """Versioned, deterministic output from the trace collector."""

    schema_version: str
    collector_version: str
    source: TraceSource
    redaction: RedactionSummary
    spans: tuple[CollectedSpan, ...]


@dataclass(slots=True)
class _RedactionCounts:
    retained: int = 0
    redacted: int = 0
    dropped: int = 0


def _fingerprint(domain: str, value: str) -> str:
    payload = f"causure:{domain}:{value}".encode()
    return hashlib.sha256(payload).hexdigest()


def _required_object(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TraceCollectionError(path, "expected an object")
    return value


def _required_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise TraceCollectionError(path, "expected an array")
    return value


def _required_hex_id(value: Any, path: str, pattern: re.Pattern[str]) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise TraceCollectionError(path, "expected a correctly sized hexadecimal identifier")
    normalized = value.lower()
    if set(normalized) == {"0"}:
        raise TraceCollectionError(path, "all-zero identifiers are invalid")
    return normalized


def _optional_decimal(value: Any, path: str) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise TraceCollectionError(path, "expected a non-negative decimal integer")
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and value.isdecimal() and len(value) <= len(str(_UINT64_MAX)):
        number = int(value)
    else:
        raise TraceCollectionError(path, "expected a non-negative decimal integer")
    if not 0 <= number <= _UINT64_MAX:
        raise TraceCollectionError(path, "decimal integer is outside the uint64 range")
    return str(number)


def _optional_enum_integer(value: Any, path: str, *, maximum: int) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= maximum:
        raise TraceCollectionError(path, f"expected an integer enum value from 0 to {maximum}")
    return value


def _decode_primitive(value: Any) -> PrimitiveAttributeValue | None:
    if not isinstance(value, dict):
        return None
    present = [
        key for key in ("stringValue", "intValue", "doubleValue", "boolValue") if key in value
    ]
    if len(present) != 1:
        return None
    key = present[0]
    raw = value[key]
    if key == "stringValue":
        return raw if isinstance(raw, str) else None
    if key == "boolValue":
        return raw if isinstance(raw, bool) else None
    if key == "intValue":
        if isinstance(raw, bool):
            return None
        if isinstance(raw, int):
            return raw if _INT64_MIN <= raw <= _INT64_MAX else None
        if (
            isinstance(raw, str)
            and len(raw.removeprefix("-")) <= 19
            and re.fullmatch(r"-?[0-9]+", raw)
        ):
            converted_integer = int(raw)
            return converted_integer if _INT64_MIN <= converted_integer <= _INT64_MAX else None
        return None
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return None
    try:
        converted = float(raw)
    except (OverflowError, ValueError):
        return None
    return converted if math.isfinite(converted) else None


def _safe_text_value(key: str, value: PrimitiveAttributeValue | None) -> str | None:
    if not isinstance(value, str):
        return None
    if key == "openinference.span.kind":
        normalized = value.upper()
        return normalized if normalized in _OPENINFERENCE_SPAN_KINDS else None
    return value if _SAFE_TEXT_PATTERN.fullmatch(value) else None


def _safe_numeric_value(value: PrimitiveAttributeValue | None) -> int | float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if value < 0 or not math.isfinite(float(value)):
        return None
    return value


def _is_sensitive_key(key: str) -> bool:
    lowered = key.casefold()
    return any(fragment in lowered for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _is_safe_numeric_attribute(key: str) -> bool:
    return key in _SAFE_NUMERIC_ATTRIBUTES


def _filter_attributes(
    value: Any,
    path: str,
    counts: _RedactionCounts,
) -> dict[str, SafeAttributeValue]:
    attributes = _required_list(value, path)
    retained: dict[str, SafeAttributeValue] = {}
    seen: set[str] = set()
    for index, item in enumerate(attributes):
        item_path = f"{path}[{index}]"
        attribute = _required_object(item, item_path)
        key = attribute.get("key")
        if not isinstance(key, str) or not key or len(key) > 256:
            raise TraceCollectionError(f"{item_path}.key", "expected a non-empty attribute key")
        if key in seen:
            raise TraceCollectionError(item_path, "duplicate attribute key")
        seen.add(key)

        if key in _SAFE_TEXT_ATTRIBUTES:
            safe_text = _safe_text_value(key, _decode_primitive(attribute.get("value")))
            if safe_text is None:
                counts.redacted += 1
            else:
                retained[key] = safe_text
                counts.retained += 1
            continue

        if _is_safe_numeric_attribute(key):
            safe_number = _safe_numeric_value(_decode_primitive(attribute.get("value")))
            if safe_number is None:
                counts.redacted += 1
            else:
                retained[key] = safe_number
                counts.retained += 1
            continue

        if _is_sensitive_key(key):
            counts.redacted += 1
        else:
            counts.dropped += 1
    return dict(sorted(retained.items()))


def _collect_span(
    value: Any,
    path: str,
    source_sha256: str,
    counts: _RedactionCounts,
) -> tuple[CollectedSpan, str, str]:
    span = _required_object(value, path)
    trace_id = _required_hex_id(span.get("traceId"), f"{path}.traceId", _TRACE_ID_PATTERN)
    span_id = _required_hex_id(span.get("spanId"), f"{path}.spanId", _SPAN_ID_PATTERN)
    parent_id_value = span.get("parentSpanId")
    parent_id = None
    if parent_id_value not in (None, ""):
        parent_id = _required_hex_id(
            parent_id_value,
            f"{path}.parentSpanId",
            _SPAN_ID_PATTERN,
        )

    name = span.get("name")
    if not isinstance(name, str) or not name:
        raise TraceCollectionError(f"{path}.name", "expected a non-empty span name")

    start = _optional_decimal(span.get("startTimeUnixNano"), f"{path}.startTimeUnixNano")
    end = _optional_decimal(span.get("endTimeUnixNano"), f"{path}.endTimeUnixNano")
    duration = None
    if start is not None and end is not None:
        start_number = int(start)
        end_number = int(end)
        if end_number < start_number:
            raise TraceCollectionError(path, "span end time precedes its start time")
        duration = str(end_number - start_number)

    status_value = span.get("status")
    status_code = None
    if status_value is not None:
        status = _required_object(status_value, f"{path}.status")
        status_code = _optional_enum_integer(
            status.get("code"),
            f"{path}.status.code",
            maximum=2,
        )

    trace_hash = _fingerprint("trace-id", trace_id)
    span_hash = _fingerprint("span-id", f"{trace_id}:{span_id}")
    evidence_ref = f"trace-sha256://{source_sha256}/spans/{span_hash}"
    collected = CollectedSpan(
        evidence_ref=evidence_ref,
        trace_id_sha256=trace_hash,
        span_id_sha256=span_hash,
        parent_span_id_sha256=(
            _fingerprint("span-id", f"{trace_id}:{parent_id}") if parent_id is not None else None
        ),
        start_time_unix_nano=start,
        end_time_unix_nano=end,
        duration_nano=duration,
        kind=_optional_enum_integer(span.get("kind"), f"{path}.kind", maximum=5),
        status_code=status_code,
        attributes=_filter_attributes(span.get("attributes", []), f"{path}.attributes", counts),
    )
    return collected, trace_id, span_id


def collect_otlp_trace_manifest(
    document: Any,
    *,
    raw_bytes: bytes,
    source_id: str,
    max_spans: int = DEFAULT_MAX_SPANS,
) -> TraceManifest:
    """Project an OTLP JSON trace export into a redacted metadata manifest."""

    if not isinstance(raw_bytes, bytes):
        raise TraceCollectionError("$.source", "raw_bytes must be exact source bytes")
    try:
        decoded_source = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TraceCollectionError("$.source", "source bytes are not valid UTF-8") from exc
    try:
        parsed_source = parse_json_text(
            decoded_source,
            source="<trace-source>",
            max_bytes=MAX_TRACE_DOCUMENT_BYTES,
        )
    except InputDocumentError as exc:
        raise TraceCollectionError("$.source", str(exc)) from exc
    if document != parsed_source:
        raise TraceCollectionError(
            "$.source",
            "parsed document does not match the supplied source bytes",
        )

    if not _SOURCE_ID_PATTERN.fullmatch(source_id):
        raise TraceCollectionError(
            "$.source_id",
            "must match ^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$",
        )
    if (
        isinstance(max_spans, bool)
        or not isinstance(max_spans, int)
        or not 1 <= max_spans <= MAX_CONFIGURABLE_SPANS
    ):
        raise TraceCollectionError(
            "$.max_spans",
            f"must be an integer from 1 to {MAX_CONFIGURABLE_SPANS}",
        )

    root = _required_object(parsed_source, "$")
    resource_spans = _required_list(root.get("resourceSpans"), "$.resourceSpans")
    source_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    counts = _RedactionCounts()
    collected_spans: list[CollectedSpan] = []
    trace_ids: set[str] = set()
    span_keys: set[tuple[str, str]] = set()

    for resource_index, resource_span_value in enumerate(resource_spans):
        resource_path = f"$.resourceSpans[{resource_index}]"
        resource_span = _required_object(resource_span_value, resource_path)
        scope_spans = _required_list(
            resource_span.get("scopeSpans", []),
            f"{resource_path}.scopeSpans",
        )
        for scope_index, scope_span_value in enumerate(scope_spans):
            scope_path = f"{resource_path}.scopeSpans[{scope_index}]"
            scope_span = _required_object(scope_span_value, scope_path)
            spans = _required_list(scope_span.get("spans", []), f"{scope_path}.spans")
            for span_index, span_value in enumerate(spans):
                if len(collected_spans) >= max_spans:
                    raise TraceCollectionError(
                        f"{scope_path}.spans[{span_index}]",
                        f"span count exceeds configured limit {max_spans}",
                    )
                span_path = f"{scope_path}.spans[{span_index}]"
                collected, trace_id, span_id = _collect_span(
                    span_value,
                    span_path,
                    source_sha256,
                    counts,
                )
                span_key = (trace_id, span_id)
                if span_key in span_keys:
                    raise TraceCollectionError(span_path, "duplicate span identifier in trace")
                span_keys.add(span_key)
                trace_ids.add(trace_id)
                collected_spans.append(collected)

    if not collected_spans:
        raise TraceCollectionError("$.resourceSpans", "no spans were found")

    collected_spans.sort(
        key=lambda span: (
            span.trace_id_sha256,
            int(span.start_time_unix_nano or "0"),
            span.span_id_sha256,
        )
    )
    return TraceManifest(
        schema_version=TRACE_MANIFEST_SCHEMA_VERSION,
        collector_version=PACKAGE_VERSION,
        source=TraceSource(
            artifact_id=source_id,
            format=TraceSourceFormat.OTLP_JSON,
            media_type="application/json",
            sha256=source_sha256,
            byte_count=len(raw_bytes),
            trace_count=len(trace_ids),
            span_count=len(collected_spans),
        ),
        redaction=RedactionSummary(
            strategy=RedactionStrategy.METADATA_ALLOWLIST_V1,
            raw_content_included=False,
            retained_attribute_count=counts.retained,
            redacted_attribute_count=counts.redacted,
            dropped_attribute_count=counts.dropped,
            omitted_field_groups=OMITTED_TRACE_FIELD_GROUPS,
        ),
        spans=tuple(collected_spans),
    )


def render_trace_manifest(manifest: TraceManifest) -> str:
    """Render a stable, human-inspectable JSON manifest."""

    return (
        json.dumps(
            to_jsonable(manifest),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
