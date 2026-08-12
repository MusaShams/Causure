"""Typed contracts for company-owned replay and evaluation adapters."""

from __future__ import annotations

import math
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Protocol, runtime_checkable

from causure.constants import Component
from causure.models import ChangeCase

_MAX_TEXT_LENGTH = 2_048
MAX_CASE_GENERATION_BYTES = 5 * 1024 * 1024
MAX_CANDIDATE_COMPONENT_BYTES = 2 * 1024 * 1024

_SAFE_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{2,127}")
_GIT_COMMIT_PATTERN = re.compile(r"[a-f0-9]{40}|[a-f0-9]{64}")
_REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_SHA256_PATTERN = re.compile(r"[a-f0-9]{64}")


def _is_finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > _MAX_TEXT_LENGTH:
        raise ValueError(f"{name} must not exceed {_MAX_TEXT_LENGTH} characters")
    if any(ord(character) < 32 for character in value):
        raise ValueError(f"{name} must not contain control characters")


def _require_unique_refs(values: tuple[str, ...], name: str) -> None:
    if not isinstance(values, tuple):
        raise ValueError(f"{name} must be an immutable tuple")
    if not values:
        raise ValueError(f"{name} must contain at least one reference")
    for index, value in enumerate(values):
        _require_text(value, f"{name}[{index}]")
    if len(set(values)) != len(values):
        raise ValueError(f"{name} must contain unique references")


@dataclass(frozen=True, slots=True)
class ExecutionBudget:
    """Mandatory limits supplied to every external adapter invocation."""

    timeout_seconds: float = 60.0
    max_concurrency: int = 4
    max_cases: int = 100
    max_cost_usd: float | None = None

    def __post_init__(self) -> None:
        if not _is_finite_number(self.timeout_seconds) or self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be a positive finite number")
        if (
            isinstance(self.max_concurrency, bool)
            or not isinstance(self.max_concurrency, int)
            or not 1 <= self.max_concurrency <= 64
        ):
            raise ValueError("max_concurrency must be an integer from 1 to 64")
        if (
            isinstance(self.max_cases, bool)
            or not isinstance(self.max_cases, int)
            or not 1 <= self.max_cases <= 10_000
        ):
            raise ValueError("max_cases must be an integer from 1 to 10000")
        if self.max_cost_usd is not None and (
            not _is_finite_number(self.max_cost_usd) or self.max_cost_usd < 0
        ):
            raise ValueError("max_cost_usd must be a non-negative finite number")


@dataclass(frozen=True, slots=True)
class CaseGenerationBudget:
    """Limits for one separately trusted canonical-case generator."""

    timeout_seconds: float = 60.0
    maximum_case_bytes: int = MAX_CASE_GENERATION_BYTES

    def __post_init__(self) -> None:
        if not _is_finite_number(self.timeout_seconds) or not 0 < self.timeout_seconds <= 3600:
            raise ValueError("timeout_seconds must be greater than zero and at most 3600")
        if (
            isinstance(self.maximum_case_bytes, bool)
            or not isinstance(self.maximum_case_bytes, int)
            or not 1 <= self.maximum_case_bytes <= MAX_CASE_GENERATION_BYTES
        ):
            raise ValueError(
                f"maximum_case_bytes must be an integer from 1 to {MAX_CASE_GENERATION_BYTES}"
            )


@dataclass(frozen=True, slots=True)
class CaseGenerationRequest:
    """Bounded GitHub candidate identity supplied to trusted generator code."""

    request_id: str
    project_id: str
    repository: str
    pull_request_number: int
    base_sha: str
    head_sha: str
    component_id: str
    component: Component
    component_path: str
    candidate_root: str
    component_sha256: str
    component_byte_count: int
    budget: CaseGenerationBudget

    def __post_init__(self) -> None:
        for value, name in (
            (self.request_id, "request_id"),
            (self.project_id, "project_id"),
            (self.component_id, "component_id"),
        ):
            _require_text(value, name)
            if _SAFE_ID_PATTERN.fullmatch(value) is None:
                raise ValueError(f"{name} must use the safe identifier format")
        _require_text(self.repository, "repository")
        if len(self.repository) > 255 or _REPOSITORY_PATTERN.fullmatch(self.repository) is None:
            raise ValueError("repository must use owner/name format")
        if (
            isinstance(self.pull_request_number, bool)
            or not isinstance(self.pull_request_number, int)
            or self.pull_request_number < 1
        ):
            raise ValueError("pull_request_number must be a positive integer")
        for value, name in ((self.base_sha, "base_sha"), (self.head_sha, "head_sha")):
            if not isinstance(value, str) or _GIT_COMMIT_PATTERN.fullmatch(value) is None:
                raise ValueError(f"{name} must be a full lowercase Git commit SHA")
        if len(self.base_sha) != len(self.head_sha):
            raise ValueError("base_sha and head_sha must use the same object format")
        if not isinstance(self.component, Component):
            raise ValueError("component must be a Component")
        _require_text(self.component_path, "component_path")
        component_path = PurePosixPath(self.component_path)
        if (
            "\\" in self.component_path
            or component_path.is_absolute()
            or component_path.as_posix() != self.component_path
            or any(part in {"", ".", ".."} for part in component_path.parts)
        ):
            raise ValueError("component_path must be a contained repository-relative path")
        _require_text(self.candidate_root, "candidate_root")
        if len(self.candidate_root) > 4096 or not Path(self.candidate_root).is_absolute():
            raise ValueError("candidate_root must be a bounded absolute path")
        if (
            not isinstance(self.component_sha256, str)
            or _SHA256_PATTERN.fullmatch(self.component_sha256) is None
        ):
            raise ValueError("component_sha256 must be a lowercase SHA-256 digest")
        if (
            isinstance(self.component_byte_count, bool)
            or not isinstance(self.component_byte_count, int)
            or not 0 <= self.component_byte_count <= MAX_CANDIDATE_COMPONENT_BYTES
        ):
            raise ValueError(
                f"component_byte_count must be from 0 to {MAX_CANDIDATE_COMPONENT_BYTES}"
            )
        if not isinstance(self.budget, CaseGenerationBudget):
            raise ValueError("budget must be a CaseGenerationBudget")

    @property
    def expected_change_ref(self) -> str:
        """Canonical URI that generated evidence must use for this candidate."""

        return (
            f"github://{self.repository}/pull/{self.pull_request_number}/head/"
            f"{self.head_sha}/{self.component_path}"
        )


@dataclass(frozen=True, slots=True)
class ReplayRequest:
    case_id: str
    trace_refs: tuple[str, ...]
    baseline_ref: str
    candidate_ref: str
    seed: int
    budget: ExecutionBudget

    def __post_init__(self) -> None:
        _require_text(self.case_id, "case_id")
        _require_unique_refs(self.trace_refs, "trace_refs")
        _require_text(self.baseline_ref, "baseline_ref")
        _require_text(self.candidate_ref, "candidate_ref")
        if isinstance(self.seed, bool) or not isinstance(self.seed, int) or self.seed < 0:
            raise ValueError("seed must be a non-negative integer")
        if not isinstance(self.budget, ExecutionBudget):
            raise ValueError("budget must be an ExecutionBudget")


@dataclass(frozen=True, slots=True)
class ReplayOutcome:
    trial_id: str
    reproduced: bool
    evidence_ref: str
    latency_ms: float
    cost_usd: float

    def __post_init__(self) -> None:
        _require_text(self.trial_id, "trial_id")
        _require_text(self.evidence_ref, "evidence_ref")
        if type(self.reproduced) is not bool:
            raise ValueError("reproduced must be a boolean")
        for value, name in (
            (self.latency_ms, "latency_ms"),
            (self.cost_usd, "cost_usd"),
        ):
            if not _is_finite_number(value) or value < 0:
                raise ValueError(f"{name} must be a non-negative finite number")


@dataclass(frozen=True, slots=True)
class EvaluationRequest:
    case_id: str
    replay_refs: tuple[str, ...]
    evaluator_ref: str
    budget: ExecutionBudget

    def __post_init__(self) -> None:
        _require_text(self.case_id, "case_id")
        _require_unique_refs(self.replay_refs, "replay_refs")
        _require_text(self.evaluator_ref, "evaluator_ref")
        if not isinstance(self.budget, ExecutionBudget):
            raise ValueError("budget must be an ExecutionBudget")


@dataclass(frozen=True, slots=True)
class EvaluationOutcome:
    validation_case_id: str
    passed: bool
    evidence_ref: str
    latency_ms: float
    cost_usd: float
    score: float | None = None

    def __post_init__(self) -> None:
        _require_text(self.validation_case_id, "validation_case_id")
        _require_text(self.evidence_ref, "evidence_ref")
        if type(self.passed) is not bool:
            raise ValueError("passed must be a boolean")
        for value, name in (
            (self.latency_ms, "latency_ms"),
            (self.cost_usd, "cost_usd"),
        ):
            if not _is_finite_number(value) or value < 0:
                raise ValueError(f"{name} must be a non-negative finite number")
        if self.score is not None and (
            not _is_finite_number(self.score) or not 0 <= self.score <= 1
        ):
            raise ValueError("score must be a finite number from 0 to 1")


@runtime_checkable
class ReplayAdapter(Protocol):
    """Adapter implemented outside the deterministic gate and collector."""

    def replay(self, request: ReplayRequest) -> Sequence[ReplayOutcome]: ...


@runtime_checkable
class EvaluatorAdapter(Protocol):
    """Adapter implemented outside the deterministic gate and collector."""

    def evaluate(self, request: EvaluationRequest) -> Sequence[EvaluationOutcome]: ...


@runtime_checkable
class CaseGeneratorAdapter(Protocol):
    """Reviewed callable loaded only by the separately trusted generator workflow."""

    def __call__(
        self,
        request: CaseGenerationRequest,
    ) -> ChangeCase | Mapping[str, object]: ...
