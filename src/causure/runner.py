"""Process-bounded execution for company-owned evidence adapters."""

from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import math
import multiprocessing
import os
import re
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Any, Literal

from causure.adapters import (
    MAX_CASE_GENERATION_BYTES,
    CaseGenerationRequest,
    EvaluationOutcome,
    EvaluationRequest,
    EvaluatorAdapter,
    ReplayAdapter,
    ReplayOutcome,
    ReplayRequest,
)
from causure.models import ChangeCase, parse_change_case, to_jsonable

_PROCESS_STOP_GRACE_SECONDS = 1.0
_MAX_TRUSTED_ADAPTER_MODULE_BYTES = 2 * 1024 * 1024
_ENTRY_POINT_PATTERN = re.compile(r"[A-Za-z_][A-Za-z0-9_.]{0,126}:[A-Za-z_][A-Za-z0-9_.]{0,126}")


class AdapterRunError(RuntimeError):
    """Base error with a stable, non-sensitive machine code."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


class AdapterTimeoutError(AdapterRunError):
    """Raised after the adapter child exceeds its wall-clock budget."""


class AdapterBudgetError(AdapterRunError):
    """Raised when case, outcome, or cost limits are exceeded."""


class AdapterProtocolError(AdapterRunError):
    """Raised when an adapter returns malformed outcomes."""


class AdapterExecutionError(AdapterRunError):
    """Raised when the isolated adapter process cannot complete."""


@dataclass(frozen=True, slots=True)
class ReplayRunResult:
    case_id: str
    total_cost_usd: float
    outcomes: tuple[ReplayOutcome, ...]


@dataclass(frozen=True, slots=True)
class EvaluationRunResult:
    case_id: str
    total_cost_usd: float
    outcomes: tuple[EvaluationOutcome, ...]


@dataclass(frozen=True, slots=True)
class CaseGenerationRunResult:
    """Validated case plus the exact trusted entry-module identity."""

    case: ChangeCase
    entry_module_path: str
    entry_module_sha256: str
    entry_module_byte_count: int


def _validate_outcome_sequence(
    outcomes: Any,
    *,
    outcome_type: type,
    max_cases: int,
    identity_field: str,
) -> tuple[Any, ...]:
    if isinstance(outcomes, (str, bytes)) or not isinstance(
        outcomes,
        Sequence,
    ):
        raise AdapterProtocolError(
            "invalid_outcome_sequence",
            "adapter outcomes must be a sequence",
        )
    converted = tuple(outcomes)
    if not converted:
        raise AdapterProtocolError(
            "empty_outcomes",
            "adapter must return at least one outcome",
        )
    if len(converted) > max_cases:
        raise AdapterBudgetError(
            "outcome_limit_exceeded",
            "adapter returned more outcomes than the case budget allows",
        )
    if any(not isinstance(outcome, outcome_type) for outcome in converted):
        raise AdapterProtocolError(
            "invalid_outcome_type",
            "adapter returned an unsupported outcome type",
        )
    identities = [getattr(outcome, identity_field) for outcome in converted]
    if len(set(identities)) != len(identities):
        raise AdapterProtocolError(
            "duplicate_outcome_identity",
            "adapter outcome identities must be unique",
        )
    return converted


def _enforce_cost_limit(
    costs: Sequence[float],
    maximum: float | None,
) -> float:
    try:
        total = math.fsum(costs)
    except OverflowError as exc:
        raise AdapterBudgetError(
            "reported_cost_overflow",
            "adapter reported a cost total outside the finite numeric range",
        ) from exc
    if not math.isfinite(total):
        raise AdapterBudgetError(
            "reported_cost_overflow",
            "adapter reported a cost total outside the finite numeric range",
        )
    if maximum is not None and total > maximum:
        raise AdapterBudgetError(
            "cost_limit_exceeded",
            "adapter outcomes exceed the configured cost budget",
        )
    return total


def _execute_replay(
    adapter: ReplayAdapter,
    request: ReplayRequest,
) -> ReplayRunResult:
    outcomes = _validate_outcome_sequence(
        adapter.replay(request),
        outcome_type=ReplayOutcome,
        max_cases=request.budget.max_cases,
        identity_field="trial_id",
    )
    typed_outcomes = tuple(outcomes)
    total_cost = _enforce_cost_limit(
        [outcome.cost_usd for outcome in typed_outcomes],
        request.budget.max_cost_usd,
    )
    return ReplayRunResult(
        case_id=request.case_id,
        total_cost_usd=total_cost,
        outcomes=typed_outcomes,
    )


def _execute_evaluation(
    adapter: EvaluatorAdapter,
    request: EvaluationRequest,
) -> EvaluationRunResult:
    outcomes = _validate_outcome_sequence(
        adapter.evaluate(request),
        outcome_type=EvaluationOutcome,
        max_cases=request.budget.max_cases,
        identity_field="validation_case_id",
    )
    typed_outcomes = tuple(outcomes)
    total_cost = _enforce_cost_limit(
        [outcome.cost_usd for outcome in typed_outcomes],
        request.budget.max_cost_usd,
    )
    return EvaluationRunResult(
        case_id=request.case_id,
        total_cost_usd=total_cost,
        outcomes=typed_outcomes,
    )


def _adapter_child(
    mode: Literal["replay", "evaluation"],
    adapter: Any,
    request: ReplayRequest | EvaluationRequest,
    connection: Connection,
) -> None:
    try:
        with (
            open(os.devnull, "w", encoding="utf-8") as sink,
            contextlib.redirect_stdout(sink),
            contextlib.redirect_stderr(sink),
        ):
            if mode == "replay":
                result = _execute_replay(adapter, request)
            else:
                result = _execute_evaluation(adapter, request)
        connection.send(("ok", result))
    except AdapterBudgetError as exc:
        connection.send(("budget", exc.code))
    except AdapterProtocolError as exc:
        connection.send(("protocol", exc.code))
    except BaseException as exc:
        connection.send(("execution", type(exc).__name__))
    finally:
        connection.close()


def _path_is_within(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
    except ValueError:
        return False
    return True


def _load_trusted_case_generator(
    adapter_directory: Path,
    entry_point: str,
    candidate_root: Path,
) -> tuple[Any, Path, bytes]:
    module_name, attribute_path = entry_point.split(":", 1)
    trusted_root = adapter_directory.resolve(strict=True)
    candidate_root = candidate_root.resolve(strict=True)
    retained_paths: list[str] = []
    for raw_path in sys.path:
        if not raw_path:
            continue
        try:
            resolved = Path(raw_path).resolve()
        except OSError:
            continue
        if _path_is_within(resolved, candidate_root):
            continue
        retained_paths.append(raw_path)
    sys.path[:] = [str(trusted_root), *retained_paths]
    sys.dont_write_bytecode = True
    importlib.invalidate_caches()
    module = importlib.import_module(module_name)
    origin_value = getattr(module, "__file__", None)
    if not isinstance(origin_value, str):
        raise AdapterExecutionError(
            "adapter_import_outside_trust_root",
            "trusted case generator must resolve to a file in the configured adapter directory",
        )
    unresolved_origin = Path(origin_value)
    if unresolved_origin.is_symlink():
        raise AdapterExecutionError(
            "adapter_module_invalid",
            "trusted case generator module must not be a symbolic link",
        )
    origin = unresolved_origin.resolve(strict=True)
    if not _path_is_within(origin, trusted_root):
        raise AdapterExecutionError(
            "adapter_import_outside_trust_root",
            "trusted case generator must resolve to a file in the configured adapter directory",
        )
    if origin.suffix != ".py" or not origin.is_file():
        raise AdapterExecutionError(
            "adapter_module_invalid",
            "trusted case generator module must be a regular Python source file",
        )
    module_bytes = origin.read_bytes()
    if len(module_bytes) > _MAX_TRUSTED_ADAPTER_MODULE_BYTES:
        raise AdapterBudgetError(
            "adapter_module_too_large",
            "trusted case generator module exceeds the source-size limit",
        )
    target: Any = module
    for attribute in attribute_path.split("."):
        target = getattr(target, attribute)
    if not callable(target):
        raise AdapterProtocolError(
            "case_generator_not_callable",
            "trusted case generator entry point must be callable",
        )
    return target, origin, module_bytes


def _coerce_generated_case(payload: Any, maximum_case_bytes: int) -> ChangeCase:
    if isinstance(payload, ChangeCase):
        case = payload
    elif isinstance(payload, Mapping):
        case = parse_change_case(dict(payload))
    else:
        raise AdapterProtocolError(
            "invalid_generated_case_type",
            "trusted case generator must return a ChangeCase or mapping",
        )
    try:
        case_bytes = (
            json.dumps(
                to_jsonable(case),
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise AdapterProtocolError(
            "invalid_generated_case_encoding",
            "trusted case generator returned a case that cannot be encoded",
        ) from exc
    if len(case_bytes) > maximum_case_bytes:
        raise AdapterBudgetError(
            "generated_case_too_large",
            "trusted case generator exceeded the case-size limit",
        )
    return case


def _case_generator_child(
    adapter_directory: str,
    entry_point: str,
    request: CaseGenerationRequest,
    connection: Connection,
) -> None:
    try:
        with (
            open(os.devnull, "w", encoding="utf-8") as sink,
            contextlib.redirect_stdout(sink),
            contextlib.redirect_stderr(sink),
        ):
            generator, module_path, module_bytes = _load_trusted_case_generator(
                Path(adapter_directory),
                entry_point,
                Path(request.candidate_root),
            )
            case = _coerce_generated_case(
                generator(request),
                request.budget.maximum_case_bytes,
            )
            if module_path.read_bytes() != module_bytes:
                raise AdapterExecutionError(
                    "adapter_source_changed",
                    "trusted case generator source changed during execution",
                )
            result = CaseGenerationRunResult(
                case=case,
                entry_module_path=module_path.relative_to(
                    Path(adapter_directory).resolve(strict=True)
                ).as_posix(),
                entry_module_sha256=hashlib.sha256(module_bytes).hexdigest(),
                entry_module_byte_count=len(module_bytes),
            )
        connection.send(("ok", result))
    except AdapterBudgetError as exc:
        connection.send(("budget", exc.code))
    except AdapterProtocolError as exc:
        connection.send(("protocol", exc.code))
    except AdapterExecutionError as exc:
        connection.send(("execution", exc.code))
    except BaseException:
        connection.send(("execution", "adapter_raised"))
    finally:
        connection.close()


def _stop_process(process: multiprocessing.Process) -> None:
    if process.is_alive():
        process.terminate()
        process.join(_PROCESS_STOP_GRACE_SECONDS)
    if process.is_alive():
        process.kill()
        process.join(_PROCESS_STOP_GRACE_SECONDS)


class ProcessAdapterRunner:
    """Run a trusted, picklable adapter behind a killable process boundary."""

    def __init__(self) -> None:
        self._context = multiprocessing.get_context("spawn")

    def _invoke(
        self,
        mode: Literal["replay", "evaluation"],
        adapter: Any,
        request: ReplayRequest | EvaluationRequest,
    ) -> ReplayRunResult | EvaluationRunResult:
        references = (
            request.trace_refs if isinstance(request, ReplayRequest) else request.replay_refs
        )
        if len(references) > request.budget.max_cases:
            raise AdapterBudgetError(
                "case_limit_exceeded",
                "request contains more references than the case budget allows",
            )

        receiver, sender = self._context.Pipe(duplex=False)
        process = self._context.Process(
            target=_adapter_child,
            args=(mode, adapter, request, sender),
            daemon=True,
        )
        try:
            try:
                process.start()
            except Exception as exc:
                raise AdapterExecutionError(
                    "adapter_not_startable",
                    "adapter must be importable and picklable for process execution",
                ) from exc
            finally:
                sender.close()

            deadline = time.monotonic() + request.budget.timeout_seconds
            remaining = max(0.0, deadline - time.monotonic())
            if not receiver.poll(remaining):
                _stop_process(process)
                raise AdapterTimeoutError(
                    "timeout_exceeded",
                    "adapter exceeded its wall-clock timeout",
                )
            try:
                status, payload = receiver.recv()
            except (EOFError, OSError) as exc:
                _stop_process(process)
                raise AdapterExecutionError(
                    "adapter_process_failed",
                    "adapter process exited without a result",
                ) from exc

            remaining = max(0.0, deadline - time.monotonic())
            process.join(remaining)
            if process.is_alive():
                _stop_process(process)
                raise AdapterTimeoutError(
                    "timeout_exceeded",
                    "adapter exceeded its wall-clock timeout",
                )
            if status == "ok":
                return payload
            if status == "budget":
                raise AdapterBudgetError(
                    payload,
                    "adapter exceeded an execution budget",
                )
            if status == "protocol":
                raise AdapterProtocolError(
                    payload,
                    "adapter violated the outcome protocol",
                )
            raise AdapterExecutionError(
                "adapter_raised",
                f"adapter failed with exception type {payload}",
            )
        finally:
            receiver.close()
            if process.is_alive():
                _stop_process(process)
            if process.pid is not None and not process.is_alive():
                process.close()

    def run_replay(
        self,
        adapter: ReplayAdapter,
        request: ReplayRequest,
    ) -> ReplayRunResult:
        """Run one replay request within its declared process budget."""

        if not isinstance(request, ReplayRequest):
            raise AdapterProtocolError(
                "invalid_replay_request",
                "request must be a ReplayRequest",
            )
        if not isinstance(adapter, ReplayAdapter):
            raise AdapterProtocolError(
                "missing_replay_method",
                "adapter does not implement ReplayAdapter",
            )
        result = self._invoke("replay", adapter, request)
        if not isinstance(result, ReplayRunResult):
            raise AdapterProtocolError(
                "invalid_replay_result",
                "adapter runner returned an invalid replay result",
            )
        return result

    def run_evaluation(
        self,
        adapter: EvaluatorAdapter,
        request: EvaluationRequest,
    ) -> EvaluationRunResult:
        """Run one evaluation request within its declared process budget."""

        if not isinstance(request, EvaluationRequest):
            raise AdapterProtocolError(
                "invalid_evaluation_request",
                "request must be an EvaluationRequest",
            )
        if not isinstance(adapter, EvaluatorAdapter):
            raise AdapterProtocolError(
                "missing_evaluate_method",
                "adapter does not implement EvaluatorAdapter",
            )
        result = self._invoke("evaluation", adapter, request)
        if not isinstance(result, EvaluationRunResult):
            raise AdapterProtocolError(
                "invalid_evaluation_result",
                "adapter runner returned an invalid evaluation result",
            )
        return result

    def run_case_generation(
        self,
        adapter_directory: str | Path,
        entry_point: str,
        request: CaseGenerationRequest,
    ) -> CaseGenerationRunResult:
        """Load one configured generator only from its trusted root and run it."""

        if not isinstance(request, CaseGenerationRequest):
            raise AdapterProtocolError(
                "invalid_case_generation_request",
                "request must be a CaseGenerationRequest",
            )
        if request.budget.maximum_case_bytes > MAX_CASE_GENERATION_BYTES:
            raise AdapterBudgetError(
                "generated_case_limit_invalid",
                "case generation limit exceeds the supported maximum",
            )
        if not isinstance(entry_point, str) or _ENTRY_POINT_PATTERN.fullmatch(entry_point) is None:
            raise AdapterProtocolError(
                "invalid_case_generator_entry_point",
                "case generator entry point must use module.path:callable format",
            )
        try:
            trusted_root = Path(adapter_directory).expanduser().resolve(strict=True)
            candidate_root = Path(request.candidate_root).resolve(strict=True)
        except OSError as exc:
            raise AdapterExecutionError(
                "adapter_path_unavailable",
                "trusted adapter or candidate directory is unavailable",
            ) from exc
        if not trusted_root.is_dir() or not candidate_root.is_dir():
            raise AdapterExecutionError(
                "adapter_path_unavailable",
                "trusted adapter and candidate roots must be directories",
            )

        receiver, sender = self._context.Pipe(duplex=False)
        process = self._context.Process(
            target=_case_generator_child,
            args=(str(trusted_root), entry_point, request, sender),
            daemon=True,
        )
        try:
            try:
                process.start()
            except Exception as exc:
                raise AdapterExecutionError(
                    "adapter_not_startable",
                    "trusted case generator process could not start",
                ) from exc
            finally:
                sender.close()

            deadline = time.monotonic() + request.budget.timeout_seconds
            if not receiver.poll(max(0.0, deadline - time.monotonic())):
                _stop_process(process)
                raise AdapterTimeoutError(
                    "timeout_exceeded",
                    "trusted case generator exceeded its wall-clock timeout",
                )
            try:
                status, payload = receiver.recv()
            except (EOFError, OSError) as exc:
                _stop_process(process)
                raise AdapterExecutionError(
                    "adapter_process_failed",
                    "trusted case generator exited without a result",
                ) from exc

            process.join(max(0.0, deadline - time.monotonic()))
            if process.is_alive():
                _stop_process(process)
                raise AdapterTimeoutError(
                    "timeout_exceeded",
                    "trusted case generator exceeded its wall-clock timeout",
                )
            if status == "budget":
                raise AdapterBudgetError(payload, "trusted case generator exceeded a budget")
            if status == "protocol":
                raise AdapterProtocolError(
                    payload,
                    "trusted case generator returned an invalid case",
                )
            if status == "execution":
                raise AdapterExecutionError(
                    payload,
                    "trusted case generator could not complete",
                )
            if status != "ok" or not isinstance(payload, CaseGenerationRunResult):
                raise AdapterProtocolError(
                    "invalid_case_generation_result",
                    "trusted case generator returned an invalid result envelope",
                )
            return payload
        finally:
            receiver.close()
            if process.is_alive():
                _stop_process(process)
            if process.pid is not None and not process.is_alive():
                process.close()
