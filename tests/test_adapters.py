"""Replay and evaluator extension-point contracts."""

from __future__ import annotations

import unittest

from causure.adapters import (
    EvaluationOutcome,
    EvaluationRequest,
    EvaluatorAdapter,
    ExecutionBudget,
    ReplayAdapter,
    ReplayOutcome,
    ReplayRequest,
)


class _ReplayImplementation:
    def replay(self, request: ReplayRequest) -> tuple[ReplayOutcome, ...]:
        return (
            ReplayOutcome(
                trial_id=f"{request.case_id}-trial",
                reproduced=True,
                evidence_ref="artifact://replay/one",
                latency_ms=12.5,
                cost_usd=0.01,
            ),
        )


class _EvaluatorImplementation:
    def evaluate(self, request: EvaluationRequest) -> tuple[EvaluationOutcome, ...]:
        return (
            EvaluationOutcome(
                validation_case_id=f"{request.case_id}-positive",
                passed=True,
                evidence_ref="artifact://evaluation/one",
                latency_ms=8.5,
                cost_usd=0.002,
                score=0.95,
            ),
        )


class AdapterContractTests(unittest.TestCase):
    def test_budget_rejects_unbounded_or_invalid_values(self) -> None:
        invalid = (
            {"timeout_seconds": 0},
            {"timeout_seconds": float("inf")},
            {"timeout_seconds": 10**1000},
            {"max_concurrency": 0},
            {"max_concurrency": 65},
            {"max_cases": 0},
            {"max_cost_usd": -0.01},
            {"max_cost_usd": 10**1000},
        )
        for values in invalid:
            with self.subTest(values=values):
                with self.assertRaises(ValueError):
                    ExecutionBudget(**values)

    def test_requests_require_unique_evidence_references(self) -> None:
        budget = ExecutionBudget()
        with self.assertRaisesRegex(ValueError, "unique"):
            ReplayRequest(
                case_id="case-001",
                trace_refs=("trace://one", "trace://one"),
                baseline_ref="agent://baseline",
                candidate_ref="agent://candidate",
                seed=1,
                budget=budget,
            )
        with self.assertRaisesRegex(ValueError, "at least one"):
            EvaluationRequest(
                case_id="case-001",
                replay_refs=(),
                evaluator_ref="evaluator://refund-policy",
                budget=budget,
            )

    def test_requests_require_an_execution_budget(self) -> None:
        with self.assertRaisesRegex(ValueError, "ExecutionBudget"):
            ReplayRequest(
                case_id="case-001",
                trace_refs=("trace://one",),
                baseline_ref="agent://baseline",
                candidate_ref="agent://candidate",
                seed=1,
                budget=None,  # type: ignore[arg-type]
            )
        with self.assertRaisesRegex(ValueError, "immutable tuple"):
            EvaluationRequest(
                case_id="case-001",
                replay_refs=["replay://one"],  # type: ignore[arg-type]
                evaluator_ref="evaluator://refund-policy",
                budget=ExecutionBudget(),
            )

    def test_all_request_references_are_bounded_and_single_line(self) -> None:
        values = (
            ("trace://one\nprivate", "control characters"),
            ("x" * 2_049, "2048"),
        )
        for reference, message in values:
            with self.subTest(message=message):
                with self.assertRaisesRegex(ValueError, message):
                    ReplayRequest(
                        case_id="case-001",
                        trace_refs=(reference,),
                        baseline_ref="agent://baseline",
                        candidate_ref="agent://candidate",
                        seed=1,
                        budget=ExecutionBudget(),
                    )

    def test_outcomes_reject_invalid_measurements(self) -> None:
        with self.assertRaisesRegex(ValueError, "latency_ms"):
            ReplayOutcome(
                trial_id="trial-1",
                reproduced=True,
                evidence_ref="artifact://replay/one",
                latency_ms=-1,
                cost_usd=0,
            )
        with self.assertRaisesRegex(ValueError, "score"):
            EvaluationOutcome(
                validation_case_id="positive-1",
                passed=True,
                evidence_ref="artifact://evaluation/one",
                latency_ms=1,
                cost_usd=0,
                score=1.1,
            )

    def test_structural_protocols_accept_company_implementations(self) -> None:
        self.assertIsInstance(_ReplayImplementation(), ReplayAdapter)
        self.assertIsInstance(_EvaluatorImplementation(), EvaluatorAdapter)


if __name__ == "__main__":
    unittest.main()
