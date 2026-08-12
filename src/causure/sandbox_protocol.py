"""Contracts for isolated adapter workers and provider quota enforcement."""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Protocol, TypeVar, runtime_checkable
from urllib.parse import urlsplit

from causure.adapters import EvaluationOutcome, ReplayOutcome
from causure.constants import (
    SANDBOX_POLICY_SCHEMA_VERSION,
    SANDBOX_WORKER_SCHEMA_VERSION,
    QuotaEnforcement,
    SandboxNetworkMode,
    SandboxWorkerMode,
)
from causure.io import InputDocumentError, parse_json_text
from causure.models import to_jsonable

DEFAULT_SANDBOX_OUTPUT_BYTES = 1024 * 1024
MAX_SANDBOX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_SANDBOX_INPUT_BYTES = 64 * 1024

_SAFE_ID_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:+/-]{2,127}$")
_IMAGE_PATTERN = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,255}@sha256:[a-f0-9]{64}$")
_CONTAINER_NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,62}$")
_NETWORK_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{1,127}$")
_NON_ROOT_USER_PATTERN = re.compile(r"^[1-9][0-9]{0,9}:[1-9][0-9]{0,9}$")
_UTC_TIMESTAMP_PATTERN = re.compile(
    r"^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T"
    r"([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z$"
)
_EnumT = TypeVar("_EnumT", bound=Enum)


class SandboxDocumentError(ValueError):
    """Raised when a sandbox policy or worker document is malformed."""

    def __init__(self, document_name: str, path: str, message: str) -> None:
        self.document_name = document_name
        self.path = path
        self.message = message
        super().__init__(f"Invalid {document_name} at {path}: {message}")


def _valid_unicode(value: str, name: str) -> None:
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{name} must contain valid Unicode scalar values") from exc


def _text(
    value: str,
    name: str,
    *,
    minimum: int = 1,
    maximum: int = 2_048,
    pattern: re.Pattern[str] | None = None,
    allow_whitespace: bool = True,
) -> None:
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise ValueError(f"{name} must contain from {minimum} to {maximum} characters")
    _valid_unicode(value, name)
    if not value.strip():
        raise ValueError(f"{name} must not be blank")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{name} must not contain control characters")
    if not allow_whitespace and any(character.isspace() for character in value):
        raise ValueError(f"{name} must not contain whitespace")
    if pattern is not None and not pattern.fullmatch(value):
        raise ValueError(f"{name} does not match the required format")


def _finite_number(
    value: int | float,
    name: str,
    *,
    minimum: float,
    maximum: float | None = None,
) -> None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{name} must be a finite number")
    try:
        converted = float(value)
    except (OverflowError, ValueError) as exc:
        raise ValueError(f"{name} must be a finite number") from exc
    if not math.isfinite(converted) or converted < minimum:
        raise ValueError(f"{name} must be a finite number of at least {minimum}")
    if maximum is not None and converted > maximum:
        raise ValueError(f"{name} must not exceed {maximum}")


def _integer(value: int, name: str, *, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an integer")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be an integer from {minimum} to {maximum}")


def _timestamp(value: str, name: str) -> None:
    _text(
        value,
        name,
        maximum=20,
        pattern=_UTC_TIMESTAMP_PATTERN,
        allow_whitespace=False,
    )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(
            f"{name} must be a real UTC timestamp in YYYY-MM-DDTHH:MM:SSZ form"
        ) from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        raise ValueError(f"{name} must be a UTC timestamp")


def timestamp_value(value: str) -> datetime:
    """Parse a previously validated canonical UTC timestamp."""

    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _validate_proxy_url(value: str, name: str, expected_hostname: str | None) -> None:
    _text(
        value,
        name,
        maximum=2_048,
        allow_whitespace=False,
    )
    try:
        parsed_url = urlsplit(value)
        hostname = parsed_url.hostname
        port = parsed_url.port
    except ValueError as exc:
        raise ValueError(f"{name} must be a valid HTTPS URL") from exc
    expected_authority = hostname if port is None else f"{hostname}:{port}"
    if (
        parsed_url.scheme != "https"
        or not hostname
        or port == 0
        or parsed_url.netloc != expected_authority
        or (expected_hostname is not None and hostname != expected_hostname)
        or parsed_url.username is not None
        or parsed_url.password is not None
        or parsed_url.query
        or parsed_url.fragment
    ):
        hostname_requirement = (
            f" hosted by {expected_hostname}" if expected_hostname is not None else ""
        )
        raise ValueError(
            f"{name} must be an HTTPS URL{hostname_requirement} without "
            "credentials, query, or fragment"
        )


@dataclass(frozen=True, slots=True)
class SandboxPolicy:
    """Trusted, versioned limits applied to every OCI worker."""

    schema_version: str
    policy_id: str
    worker_protocol: str
    image: str
    network_mode: SandboxNetworkMode
    cpu_limit: float
    memory_mb: int
    pids_limit: int
    tmpfs_mb: int
    max_output_bytes: int = DEFAULT_SANDBOX_OUTPUT_BYTES
    user: str = "65532:65532"

    def __post_init__(self) -> None:
        if self.schema_version != SANDBOX_POLICY_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {SANDBOX_POLICY_SCHEMA_VERSION}")
        if self.worker_protocol != SANDBOX_WORKER_SCHEMA_VERSION:
            raise ValueError(f"worker_protocol must be {SANDBOX_WORKER_SCHEMA_VERSION}")
        _text(self.policy_id, "policy_id", maximum=128, pattern=_SAFE_ID_PATTERN)
        _text(
            self.image,
            "image",
            maximum=328,
            pattern=_IMAGE_PATTERN,
            allow_whitespace=False,
        )
        if not isinstance(self.network_mode, SandboxNetworkMode):
            raise ValueError("network_mode must be a SandboxNetworkMode")
        _finite_number(
            self.cpu_limit,
            "cpu_limit",
            minimum=0.1,
            maximum=64,
        )
        _integer(self.memory_mb, "memory_mb", minimum=64, maximum=65_536)
        _integer(self.pids_limit, "pids_limit", minimum=8, maximum=4_096)
        _integer(self.tmpfs_mb, "tmpfs_mb", minimum=1, maximum=4_096)
        _integer(
            self.max_output_bytes,
            "max_output_bytes",
            minimum=1_024,
            maximum=MAX_SANDBOX_OUTPUT_BYTES,
        )
        _text(
            self.user,
            "user",
            maximum=21,
            pattern=_NON_ROOT_USER_PATTERN,
            allow_whitespace=False,
        )


@dataclass(frozen=True, slots=True)
class QuotaReservation:
    """Hard provider budget requested before any networked worker starts."""

    case_id: str
    max_cost_usd: float
    max_concurrency: int
    max_operations: int
    timeout_seconds: float

    def __post_init__(self) -> None:
        _text(self.case_id, "case_id")
        _finite_number(self.max_cost_usd, "max_cost_usd", minimum=0)
        _integer(
            self.max_concurrency,
            "max_concurrency",
            minimum=1,
            maximum=64,
        )
        _integer(
            self.max_operations,
            "max_operations",
            minimum=1,
            maximum=10_000,
        )
        _finite_number(
            self.timeout_seconds,
            "timeout_seconds",
            minimum=0.001,
            maximum=86_400,
        )


@dataclass(frozen=True, slots=True)
class QuotaLease:
    """Scoped credential and limits issued by a provider quota controller."""

    lease_id: str
    lease_token: str = field(repr=False)
    enforcement: QuotaEnforcement = QuotaEnforcement.PROVIDER_HARD_LIMIT
    proxy_url: str = ""
    proxy_container_name: str = ""
    network_name: str = ""
    expires_at: str = ""
    max_cost_usd: float = 0
    max_concurrency: int = 1
    max_operations: int = 1

    def __post_init__(self) -> None:
        _text(self.lease_id, "lease_id", maximum=128, pattern=_SAFE_ID_PATTERN)
        _text(
            self.lease_token,
            "lease_token",
            minimum=16,
            maximum=8_192,
            allow_whitespace=False,
        )
        if self.enforcement is not QuotaEnforcement.PROVIDER_HARD_LIMIT:
            raise ValueError("enforcement must be provider_hard_limit")
        _text(
            self.proxy_container_name,
            "proxy_container_name",
            maximum=63,
            pattern=_CONTAINER_NAME_PATTERN,
            allow_whitespace=False,
        )
        _text(
            self.network_name,
            "network_name",
            maximum=128,
            pattern=_NETWORK_NAME_PATTERN,
            allow_whitespace=False,
        )
        _validate_proxy_url(
            self.proxy_url,
            "proxy_url",
            self.proxy_container_name,
        )
        _timestamp(self.expires_at, "expires_at")
        _finite_number(self.max_cost_usd, "max_cost_usd", minimum=0)
        _integer(
            self.max_concurrency,
            "max_concurrency",
            minimum=1,
            maximum=64,
        )
        _integer(
            self.max_operations,
            "max_operations",
            minimum=1,
            maximum=10_000,
        )


@dataclass(frozen=True, slots=True)
class QuotaSettlement:
    """Authoritative provider accounting returned while revoking a lease."""

    lease_id: str
    status: str
    actual_cost_usd: float
    completed_operations: int

    def __post_init__(self) -> None:
        _text(self.lease_id, "lease_id", maximum=128, pattern=_SAFE_ID_PATTERN)
        if self.status != "settled":
            raise ValueError("status must be settled")
        _finite_number(self.actual_cost_usd, "actual_cost_usd", minimum=0)
        _integer(
            self.completed_operations,
            "completed_operations",
            minimum=0,
            maximum=10_000,
        )


@dataclass(frozen=True, slots=True)
class QuotaReceipt:
    """Non-secret quota evidence returned with a successful sandbox run."""

    lease_id: str
    enforcement: QuotaEnforcement
    expires_at: str
    max_cost_usd: float
    max_concurrency: int
    max_operations: int
    actual_cost_usd: float
    completed_operations: int

    def __post_init__(self) -> None:
        _text(self.lease_id, "lease_id", maximum=128, pattern=_SAFE_ID_PATTERN)
        if self.enforcement is not QuotaEnforcement.PROVIDER_HARD_LIMIT:
            raise ValueError("enforcement must be provider_hard_limit")
        _timestamp(self.expires_at, "expires_at")
        _finite_number(self.max_cost_usd, "max_cost_usd", minimum=0)
        _integer(self.max_concurrency, "max_concurrency", minimum=1, maximum=64)
        _integer(self.max_operations, "max_operations", minimum=1, maximum=10_000)
        _finite_number(self.actual_cost_usd, "actual_cost_usd", minimum=0)
        _integer(
            self.completed_operations,
            "completed_operations",
            minimum=0,
            maximum=10_000,
        )
        if self.actual_cost_usd > self.max_cost_usd:
            raise ValueError("actual_cost_usd must not exceed max_cost_usd")
        if self.completed_operations > self.max_operations:
            raise ValueError("completed_operations must not exceed max_operations")


@runtime_checkable
class ProviderQuotaController(Protocol):
    """Company implementation backed by a hard provider/proxy quota."""

    def reserve(self, reservation: QuotaReservation) -> QuotaLease: ...

    def settle(
        self,
        lease_id: str,
        *,
        completed_operations: int,
    ) -> QuotaSettlement: ...

    def cancel(self, lease_id: str, *, reason_code: str) -> None: ...


@dataclass(frozen=True, slots=True)
class WorkerQuotaAccess:
    lease_id: str
    lease_token: str = field(repr=False)
    proxy_url: str = ""

    def __post_init__(self) -> None:
        _text(self.lease_id, "lease_id", maximum=128, pattern=_SAFE_ID_PATTERN)
        _text(
            self.lease_token,
            "lease_token",
            minimum=16,
            maximum=8_192,
            allow_whitespace=False,
        )
        _validate_proxy_url(self.proxy_url, "proxy_url", None)


@dataclass(frozen=True, slots=True)
class SandboxWorkerBudget:
    timeout_seconds: float
    max_concurrency: int
    max_cases: int
    max_cost_usd: float | None = None

    def __post_init__(self) -> None:
        _finite_number(
            self.timeout_seconds,
            "timeout_seconds",
            minimum=0.001,
            maximum=86_400,
        )
        if self.max_concurrency != 1:
            raise ValueError("worker max_concurrency must be 1")
        if self.max_cases != 1:
            raise ValueError("worker max_cases must be 1")
        if self.max_cost_usd is not None:
            _finite_number(self.max_cost_usd, "max_cost_usd", minimum=0)


@dataclass(frozen=True, slots=True)
class SandboxWorkerRequest:
    """One reference sent to one isolated container over standard input."""

    schema_version: str
    mode: SandboxWorkerMode
    case_id: str
    input_ref: str
    budget: SandboxWorkerBudget
    baseline_ref: str | None = field(default=None, metadata={"omit_none": True})
    candidate_ref: str | None = field(default=None, metadata={"omit_none": True})
    seed: int | None = field(default=None, metadata={"omit_none": True})
    evaluator_ref: str | None = field(default=None, metadata={"omit_none": True})
    quota: WorkerQuotaAccess | None = field(
        default=None,
        metadata={"omit_none": True},
        repr=False,
    )

    def __post_init__(self) -> None:
        if self.schema_version != SANDBOX_WORKER_SCHEMA_VERSION:
            raise ValueError(f"schema_version must be {SANDBOX_WORKER_SCHEMA_VERSION}")
        if not isinstance(self.mode, SandboxWorkerMode):
            raise ValueError("mode must be a SandboxWorkerMode")
        _text(self.case_id, "case_id")
        _text(self.input_ref, "input_ref")
        if not isinstance(self.budget, SandboxWorkerBudget):
            raise ValueError("budget must be a SandboxWorkerBudget")
        if self.quota is not None and not isinstance(self.quota, WorkerQuotaAccess):
            raise ValueError("quota must be WorkerQuotaAccess")
        if self.mode is SandboxWorkerMode.REPLAY:
            if (
                self.baseline_ref is None
                or self.candidate_ref is None
                or self.seed is None
                or self.evaluator_ref is not None
            ):
                raise ValueError(
                    "replay worker requires baseline_ref, candidate_ref, and seed only"
                )
            _text(self.baseline_ref, "baseline_ref")
            _text(self.candidate_ref, "candidate_ref")
            if (
                isinstance(self.seed, bool)
                or not isinstance(self.seed, int)
                or self.seed < 0
                or self.seed > 2**63 - 1
            ):
                raise ValueError("seed must be a signed 64-bit non-negative integer")
        elif (
            self.evaluator_ref is None
            or self.baseline_ref is not None
            or self.candidate_ref is not None
            or self.seed is not None
        ):
            raise ValueError("evaluation worker requires evaluator_ref only")
        else:
            _text(self.evaluator_ref, "evaluator_ref")


def render_sandbox_policy(policy: SandboxPolicy) -> str:
    """Render a stable sandbox deployment policy."""

    if not isinstance(policy, SandboxPolicy):
        raise ValueError("policy must be a SandboxPolicy")
    return (
        json.dumps(
            to_jsonable(policy),
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )


def render_sandbox_worker_request(request: SandboxWorkerRequest) -> bytes:
    """Serialize a bounded worker request, including an optional secret lease."""

    if not isinstance(request, SandboxWorkerRequest):
        raise ValueError("request must be a SandboxWorkerRequest")
    payload = json.dumps(
        to_jsonable(request),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(payload) > MAX_SANDBOX_INPUT_BYTES:
        raise ValueError(f"sandbox worker request exceeds {MAX_SANDBOX_INPUT_BYTES} bytes")
    return payload


def render_sandbox_worker_response(
    mode: SandboxWorkerMode,
    *,
    case_id: str,
    input_ref: str,
    outcome: ReplayOutcome | EvaluationOutcome,
) -> bytes:
    """Render the one-outcome response expected from a container image."""

    if not isinstance(mode, SandboxWorkerMode):
        raise ValueError("mode must be a SandboxWorkerMode")
    if mode is SandboxWorkerMode.REPLAY and not isinstance(outcome, ReplayOutcome):
        raise ValueError("replay worker response requires ReplayOutcome")
    if mode is SandboxWorkerMode.EVALUATION and not isinstance(
        outcome,
        EvaluationOutcome,
    ):
        raise ValueError("evaluation worker response requires EvaluationOutcome")
    _text(case_id, "case_id")
    _text(input_ref, "input_ref")
    return json.dumps(
        {
            "schema_version": SANDBOX_WORKER_SCHEMA_VERSION,
            "mode": mode.value,
            "case_id": case_id,
            "input_ref": input_ref,
            "outcome": to_jsonable(outcome),
        },
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _object(
    value: Any,
    path: str,
    document_name: str,
    *,
    required: set[str],
    optional: set[str] | None = None,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise SandboxDocumentError(document_name, path, "expected an object")
    allowed = required | (optional or set())
    unknown = sorted(set(value) - allowed)
    if unknown:
        raise SandboxDocumentError(
            document_name,
            path,
            f"unknown field: {unknown[0]}",
        )
    missing = sorted(required - set(value))
    if missing:
        raise SandboxDocumentError(
            document_name,
            path,
            f"missing required field: {missing[0]}",
        )
    return value


def _enum(
    value: Any,
    path: str,
    document_name: str,
    enum_type: type[_EnumT],
) -> _EnumT:
    try:
        return enum_type(value)
    except (TypeError, ValueError) as exc:
        allowed = ", ".join(member.value for member in enum_type)
        raise SandboxDocumentError(
            document_name,
            path,
            f"expected one of: {allowed}",
        ) from exc


def _required_text(
    value: Any,
    path: str,
    document_name: str,
    *,
    maximum: int = 2_048,
    pattern: re.Pattern[str] | None = None,
) -> str:
    try:
        _text(value, path, maximum=maximum, pattern=pattern)
    except ValueError as exc:
        raise SandboxDocumentError(document_name, path, str(exc)) from exc
    return value


def _required_number(
    value: Any,
    path: str,
    document_name: str,
    *,
    minimum: float,
    maximum: float | None = None,
) -> int | float:
    try:
        _finite_number(
            value,
            path,
            minimum=minimum,
            maximum=maximum,
        )
    except ValueError as exc:
        raise SandboxDocumentError(document_name, path, str(exc)) from exc
    return value


def _required_integer(
    value: Any,
    path: str,
    document_name: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    try:
        _integer(value, path, minimum=minimum, maximum=maximum)
    except ValueError as exc:
        raise SandboxDocumentError(document_name, path, str(exc)) from exc
    return value


def parse_sandbox_policy(document: Any) -> SandboxPolicy:
    """Strictly parse a trusted OCI sandbox deployment policy."""

    name = "sandbox policy"
    root = _object(
        document,
        "$",
        name,
        required={
            "schema_version",
            "policy_id",
            "worker_protocol",
            "image",
            "network_mode",
            "cpu_limit",
            "memory_mb",
            "pids_limit",
            "tmpfs_mb",
            "max_output_bytes",
            "user",
        },
    )
    if root["schema_version"] != SANDBOX_POLICY_SCHEMA_VERSION:
        raise SandboxDocumentError(
            name,
            "$.schema_version",
            f"expected {SANDBOX_POLICY_SCHEMA_VERSION}",
        )
    if root["worker_protocol"] != SANDBOX_WORKER_SCHEMA_VERSION:
        raise SandboxDocumentError(
            name,
            "$.worker_protocol",
            f"expected {SANDBOX_WORKER_SCHEMA_VERSION}",
        )
    try:
        return SandboxPolicy(
            schema_version=SANDBOX_POLICY_SCHEMA_VERSION,
            policy_id=_required_text(
                root["policy_id"],
                "$.policy_id",
                name,
                maximum=128,
                pattern=_SAFE_ID_PATTERN,
            ),
            worker_protocol=SANDBOX_WORKER_SCHEMA_VERSION,
            image=_required_text(
                root["image"],
                "$.image",
                name,
                maximum=328,
                pattern=_IMAGE_PATTERN,
            ),
            network_mode=_enum(
                root["network_mode"],
                "$.network_mode",
                name,
                SandboxNetworkMode,
            ),
            cpu_limit=float(
                _required_number(
                    root["cpu_limit"],
                    "$.cpu_limit",
                    name,
                    minimum=0.1,
                    maximum=64,
                )
            ),
            memory_mb=_required_integer(
                root["memory_mb"],
                "$.memory_mb",
                name,
                minimum=64,
                maximum=65_536,
            ),
            pids_limit=_required_integer(
                root["pids_limit"],
                "$.pids_limit",
                name,
                minimum=8,
                maximum=4_096,
            ),
            tmpfs_mb=_required_integer(
                root["tmpfs_mb"],
                "$.tmpfs_mb",
                name,
                minimum=1,
                maximum=4_096,
            ),
            max_output_bytes=_required_integer(
                root["max_output_bytes"],
                "$.max_output_bytes",
                name,
                minimum=1_024,
                maximum=MAX_SANDBOX_OUTPUT_BYTES,
            ),
            user=_required_text(
                root["user"],
                "$.user",
                name,
                maximum=21,
                pattern=_NON_ROOT_USER_PATTERN,
            ),
        )
    except ValueError as exc:
        raise SandboxDocumentError(name, "$", str(exc)) from exc


def _parse_finite_outcome_number(
    value: Any,
    path: str,
    document_name: str,
    *,
    maximum: float | None = None,
) -> float:
    converted = _required_number(
        value,
        path,
        document_name,
        minimum=0,
        maximum=maximum,
    )
    return float(converted)


def parse_sandbox_worker_request(
    raw_bytes: bytes,
    *,
    max_bytes: int = MAX_SANDBOX_INPUT_BYTES,
) -> SandboxWorkerRequest:
    """Parse one bounded worker request from standard input."""

    name = "sandbox worker request"
    if not isinstance(raw_bytes, bytes) or not raw_bytes:
        raise SandboxDocumentError(name, "$", "expected non-empty UTF-8 JSON bytes")
    if len(raw_bytes) > max_bytes:
        raise SandboxDocumentError(name, "$", f"exceeds the {max_bytes}-byte limit")
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SandboxDocumentError(name, "$", "expected valid UTF-8") from exc
    try:
        document = parse_json_text(text, source="<sandbox-worker>", max_bytes=max_bytes)
    except InputDocumentError as exc:
        raise SandboxDocumentError(name, "$", str(exc)) from exc

    root = _object(
        document,
        "$",
        name,
        required={
            "schema_version",
            "mode",
            "case_id",
            "input_ref",
            "budget",
        },
        optional={
            "baseline_ref",
            "candidate_ref",
            "seed",
            "evaluator_ref",
            "quota",
        },
    )
    if root["schema_version"] != SANDBOX_WORKER_SCHEMA_VERSION:
        raise SandboxDocumentError(
            name,
            "$.schema_version",
            f"expected {SANDBOX_WORKER_SCHEMA_VERSION}",
        )
    mode = _enum(root["mode"], "$.mode", name, SandboxWorkerMode)
    replay_fields = {"baseline_ref", "candidate_ref", "seed"}
    evaluation_fields = {"evaluator_ref"}
    if mode is SandboxWorkerMode.REPLAY:
        missing = sorted(replay_fields - set(root))
        if missing:
            raise SandboxDocumentError(
                name,
                "$",
                f"missing required field: {missing[0]}",
            )
        forbidden = evaluation_fields & set(root)
    else:
        missing = sorted(evaluation_fields - set(root))
        if missing:
            raise SandboxDocumentError(
                name,
                "$",
                f"missing required field: {missing[0]}",
            )
        forbidden = replay_fields & set(root)
    if forbidden:
        raise SandboxDocumentError(
            name,
            "$",
            f"field is not valid for {mode.value} mode: {sorted(forbidden)[0]}",
        )

    budget_document = _object(
        root["budget"],
        "$.budget",
        name,
        required={"timeout_seconds", "max_concurrency", "max_cases"},
        optional={"max_cost_usd"},
    )
    max_cost = None
    if "max_cost_usd" in budget_document:
        max_cost = float(
            _required_number(
                budget_document["max_cost_usd"],
                "$.budget.max_cost_usd",
                name,
                minimum=0,
            )
        )
    budget = SandboxWorkerBudget(
        timeout_seconds=float(
            _required_number(
                budget_document["timeout_seconds"],
                "$.budget.timeout_seconds",
                name,
                minimum=0.001,
                maximum=86_400,
            )
        ),
        max_concurrency=_required_integer(
            budget_document["max_concurrency"],
            "$.budget.max_concurrency",
            name,
            minimum=1,
            maximum=1,
        ),
        max_cases=_required_integer(
            budget_document["max_cases"],
            "$.budget.max_cases",
            name,
            minimum=1,
            maximum=1,
        ),
        max_cost_usd=max_cost,
    )

    quota = None
    if "quota" in root:
        quota_document = _object(
            root["quota"],
            "$.quota",
            name,
            required={"lease_id", "lease_token", "proxy_url"},
        )
        try:
            quota = WorkerQuotaAccess(
                lease_id=_required_text(
                    quota_document["lease_id"],
                    "$.quota.lease_id",
                    name,
                    maximum=128,
                    pattern=_SAFE_ID_PATTERN,
                ),
                lease_token=_required_text(
                    quota_document["lease_token"],
                    "$.quota.lease_token",
                    name,
                    maximum=8_192,
                ),
                proxy_url=_required_text(
                    quota_document["proxy_url"],
                    "$.quota.proxy_url",
                    name,
                ),
            )
        except ValueError as exc:
            raise SandboxDocumentError(name, "$.quota", str(exc)) from exc

    common = {
        "schema_version": SANDBOX_WORKER_SCHEMA_VERSION,
        "mode": mode,
        "case_id": _required_text(root["case_id"], "$.case_id", name),
        "input_ref": _required_text(root["input_ref"], "$.input_ref", name),
        "budget": budget,
        "quota": quota,
    }
    try:
        if mode is SandboxWorkerMode.REPLAY:
            return SandboxWorkerRequest(
                **common,
                baseline_ref=_required_text(
                    root["baseline_ref"],
                    "$.baseline_ref",
                    name,
                ),
                candidate_ref=_required_text(
                    root["candidate_ref"],
                    "$.candidate_ref",
                    name,
                ),
                seed=_required_integer(
                    root["seed"],
                    "$.seed",
                    name,
                    minimum=0,
                    maximum=2**63 - 1,
                ),
            )
        return SandboxWorkerRequest(
            **common,
            evaluator_ref=_required_text(
                root["evaluator_ref"],
                "$.evaluator_ref",
                name,
            ),
        )
    except ValueError as exc:
        raise SandboxDocumentError(name, "$", str(exc)) from exc


def parse_sandbox_worker_response(
    raw_bytes: bytes,
    *,
    expected_mode: SandboxWorkerMode,
    expected_case_id: str,
    expected_input_ref: str,
    max_bytes: int,
) -> ReplayOutcome | EvaluationOutcome:
    """Parse one bounded, untrusted container response."""

    name = "sandbox worker response"
    if not isinstance(raw_bytes, bytes) or not raw_bytes:
        raise SandboxDocumentError(name, "$", "expected non-empty UTF-8 JSON bytes")
    if len(raw_bytes) > max_bytes:
        raise SandboxDocumentError(name, "$", f"exceeds the {max_bytes}-byte limit")
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise SandboxDocumentError(name, "$", "expected valid UTF-8") from exc
    try:
        document = parse_json_text(text, source="<sandbox-worker>", max_bytes=max_bytes)
    except InputDocumentError as exc:
        raise SandboxDocumentError(name, "$", str(exc)) from exc
    root = _object(
        document,
        "$",
        name,
        required={
            "schema_version",
            "mode",
            "case_id",
            "input_ref",
            "outcome",
        },
    )
    if root["schema_version"] != SANDBOX_WORKER_SCHEMA_VERSION:
        raise SandboxDocumentError(
            name,
            "$.schema_version",
            f"expected {SANDBOX_WORKER_SCHEMA_VERSION}",
        )
    mode = _enum(root["mode"], "$.mode", name, SandboxWorkerMode)
    if mode is not expected_mode:
        raise SandboxDocumentError(name, "$.mode", "does not match the invocation")
    case_id = _required_text(root["case_id"], "$.case_id", name)
    input_ref = _required_text(root["input_ref"], "$.input_ref", name)
    if case_id != expected_case_id:
        raise SandboxDocumentError(name, "$.case_id", "does not match the invocation")
    if input_ref != expected_input_ref:
        raise SandboxDocumentError(name, "$.input_ref", "does not match the invocation")

    path = "$.outcome"
    if mode is SandboxWorkerMode.REPLAY:
        outcome = _object(
            root["outcome"],
            path,
            name,
            required={
                "trial_id",
                "reproduced",
                "evidence_ref",
                "latency_ms",
                "cost_usd",
            },
        )
        if type(outcome["reproduced"]) is not bool:
            raise SandboxDocumentError(name, f"{path}.reproduced", "expected a boolean")
        try:
            return ReplayOutcome(
                trial_id=_required_text(
                    outcome["trial_id"],
                    f"{path}.trial_id",
                    name,
                ),
                reproduced=outcome["reproduced"],
                evidence_ref=_required_text(
                    outcome["evidence_ref"],
                    f"{path}.evidence_ref",
                    name,
                ),
                latency_ms=_parse_finite_outcome_number(
                    outcome["latency_ms"],
                    f"{path}.latency_ms",
                    name,
                ),
                cost_usd=_parse_finite_outcome_number(
                    outcome["cost_usd"],
                    f"{path}.cost_usd",
                    name,
                ),
            )
        except ValueError as exc:
            raise SandboxDocumentError(name, path, str(exc)) from exc

    outcome = _object(
        root["outcome"],
        path,
        name,
        required={
            "validation_case_id",
            "passed",
            "evidence_ref",
            "latency_ms",
            "cost_usd",
        },
        optional={"score"},
    )
    if type(outcome["passed"]) is not bool:
        raise SandboxDocumentError(name, f"{path}.passed", "expected a boolean")
    score = None
    if "score" in outcome:
        score = _parse_finite_outcome_number(
            outcome["score"],
            f"{path}.score",
            name,
            maximum=1,
        )
    try:
        return EvaluationOutcome(
            validation_case_id=_required_text(
                outcome["validation_case_id"],
                f"{path}.validation_case_id",
                name,
            ),
            passed=outcome["passed"],
            evidence_ref=_required_text(
                outcome["evidence_ref"],
                f"{path}.evidence_ref",
                name,
            ),
            latency_ms=_parse_finite_outcome_number(
                outcome["latency_ms"],
                f"{path}.latency_ms",
                name,
            ),
            cost_usd=_parse_finite_outcome_number(
                outcome["cost_usd"],
                f"{path}.cost_usd",
                name,
            ),
            score=score,
        )
    except ValueError as exc:
        raise SandboxDocumentError(name, path, str(exc)) from exc
