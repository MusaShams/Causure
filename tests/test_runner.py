"""Process-bounded adapter runner contracts."""

from __future__ import annotations

import time
import unittest

from causure.adapters import (
    EvaluationOutcome,
    EvaluationRequest,
    ExecutionBudget,
    ReplayOutcome,
    ReplayRequest,
)
from causure.runner import (
    AdapterBudgetError,
    AdapterExecutionError,
    AdapterProtocolError,
    AdapterTimeoutError,
    ProcessAdapterRunner,
)


class SuccessfulReplayAdapter:
    def replay(self, request: ReplayRequest) -> tuple[ReplayOutcome, ...]:
        return tuple(
            ReplayOutcome(
                trial_id=f"trial-{index}",
                reproduced=True,
                evidence_ref=f"artifact://replay/{index}",
                latency_ms=10 + index,
                cost_usd=0.02,
            )
            for index, _ in enumerate(request.trace_refs, start=1)
        )


class SuccessfulEvaluatorAdapter:
    def evaluate(
        self,
        request: EvaluationRequest,
    ) -> tuple[EvaluationOutcome, ...]:
        return tuple(
            EvaluationOutcome(
                validation_case_id=f"validation-{index}",
                passed=True,
                evidence_ref=f"artifact://evaluation/{index}",
                latency_ms=5 + index,
                cost_usd=0.01,
                score=0.9,
            )
            for index, _ in enumerate(request.replay_refs, start=1)
        )


class SlowReplayAdapter:
    def replay(self, request: ReplayRequest) -> tuple[ReplayOutcome, ...]:
        time.sleep(2)
        return SuccessfulReplayAdapter().replay(request)


class ExpensiveReplayAdapter:
    def replay(self, request: ReplayRequest) -> tuple[ReplayOutcome, ...]:
        return (
            ReplayOutcome(
                trial_id="expensive",
                reproduced=True,
                evidence_ref="artifact://replay/expensive",
                latency_ms=1,
                cost_usd=5,
            ),
        )


class OverflowCostReplayAdapter:
    def replay(self, request: ReplayRequest) -> tuple[ReplayOutcome, ...]:
        return tuple(
            ReplayOutcome(
                trial_id=f"overflow-{index}",
                reproduced=True,
                evidence_ref=f"artifact://replay/overflow-{index}",
                latency_ms=1,
                cost_usd=1e308,
            )
            for index in range(2)
        )


class DuplicateReplayAdapter:
    def replay(self, request: ReplayRequest) -> tuple[ReplayOutcome, ...]:
        outcome = ReplayOutcome(
            trial_id="duplicate",
            reproduced=True,
            evidence_ref="artifact://replay/duplicate",
            latency_ms=1,
            cost_usd=0,
        )
        return (outcome, outcome)


class FailingReplayAdapter:
    def replay(self, request: ReplayRequest) -> tuple[ReplayOutcome, ...]:
        raise RuntimeError("private adapter detail must not cross the boundary")


class AdapterRunnerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.runner = ProcessAdapterRunner()

    @staticmethod
    def replay_request(**budget_values) -> ReplayRequest:
        return ReplayRequest(
            case_id="case-001",
            trace_refs=("trace://one", "trace://two"),
            baseline_ref="agent://baseline",
            candidate_ref="agent://candidate",
            seed=7,
            budget=ExecutionBudget(
                timeout_seconds=budget_values.get("timeout_seconds", 10),
                max_concurrency=2,
                max_cases=budget_values.get("max_cases", 2),
                max_cost_usd=budget_values.get("max_cost_usd", 0.1),
            ),
        )

    def test_runs_replay_and_evaluation_in_child_processes(self) -> None:
        replay = self.runner.run_replay(
            SuccessfulReplayAdapter(),
            self.replay_request(),
        )
        evaluation = self.runner.run_evaluation(
            SuccessfulEvaluatorAdapter(),
            EvaluationRequest(
                case_id="case-001",
                replay_refs=tuple(outcome.evidence_ref for outcome in replay.outcomes),
                evaluator_ref="evaluator://policy",
                budget=ExecutionBudget(
                    timeout_seconds=10,
                    max_concurrency=2,
                    max_cases=2,
                    max_cost_usd=0.1,
                ),
            ),
        )

        self.assertEqual(2, len(replay.outcomes))
        self.assertAlmostEqual(0.04, replay.total_cost_usd)
        self.assertEqual(2, len(evaluation.outcomes))
        self.assertAlmostEqual(0.02, evaluation.total_cost_usd)

    def test_terminates_an_adapter_that_exceeds_timeout(self) -> None:
        with self.assertRaisesRegex(
            AdapterTimeoutError,
            "wall-clock timeout",
        ):
            self.runner.run_replay(
                SlowReplayAdapter(),
                self.replay_request(timeout_seconds=0.05),
            )

    def test_enforces_case_and_cost_budgets(self) -> None:
        with self.assertRaisesRegex(AdapterBudgetError, "case budget"):
            self.runner.run_replay(
                SuccessfulReplayAdapter(),
                self.replay_request(max_cases=1),
            )
        with self.assertRaisesRegex(AdapterBudgetError, "execution budget"):
            self.runner.run_replay(
                ExpensiveReplayAdapter(),
                self.replay_request(max_cost_usd=0.1),
            )

    def test_rejects_duplicate_outcome_identities(self) -> None:
        with self.assertRaisesRegex(
            AdapterProtocolError,
            "outcome protocol",
        ):
            self.runner.run_replay(
                DuplicateReplayAdapter(),
                self.replay_request(),
            )

    def test_rejects_an_overflowing_reported_cost_total(self) -> None:
        with self.assertRaises(AdapterBudgetError) as raised:
            self.runner.run_replay(
                OverflowCostReplayAdapter(),
                self.replay_request(max_cost_usd=None),
            )

        self.assertEqual("reported_cost_overflow", raised.exception.code)

    def test_adapter_error_does_not_expose_exception_message(self) -> None:
        with self.assertRaises(AdapterExecutionError) as raised:
            self.runner.run_replay(
                FailingReplayAdapter(),
                self.replay_request(),
            )

        self.assertEqual("adapter_raised", raised.exception.code)
        self.assertNotIn("private adapter detail", str(raised.exception))

    def test_rejects_request_for_the_wrong_runner_mode(self) -> None:
        evaluation_request = EvaluationRequest(
            case_id="case-001",
            replay_refs=("artifact://replay/one",),
            evaluator_ref="evaluator://policy",
            budget=ExecutionBudget(max_cases=1),
        )

        with self.assertRaisesRegex(
            AdapterProtocolError,
            "request must be a ReplayRequest",
        ) as raised:
            self.runner.run_replay(SuccessfulReplayAdapter(), evaluation_request)  # type: ignore[arg-type]

        self.assertEqual("invalid_replay_request", raised.exception.code)


if __name__ == "__main__":
    unittest.main()
