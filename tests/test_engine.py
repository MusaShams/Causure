"""Decision-engine behavior."""

from __future__ import annotations

import unittest
from datetime import datetime

from causure.constants import Consequence, Decision, RecommendedAction
from causure.engine import review_case
from causure.models import document_sha256, parse_change_case
from causure.policy import GatePolicy, parse_policy
from tests.helpers import load_example


class ReviewCaseTests(unittest.TestCase):
    def test_approves_a_reproducible_minimal_change(self) -> None:
        case = parse_change_case(load_example())

        result = review_case(case)

        self.assertEqual(Decision.APPROVE, result.decision)
        self.assertEqual(RecommendedAction.PATCH, result.recommended_action)
        self.assertTrue(all(finding.consequence is Consequence.NONE for finding in result.findings))
        self.assertEqual(1.0, result.metrics["negative_pass_rate"])

    def test_rejects_an_overbroad_patch_with_negative_transfer(self) -> None:
        case = parse_change_case(load_example("reject-overbroad-prompt.json"))

        result = review_case(case)

        self.assertEqual(Decision.REJECT, result.decision)
        self.assertEqual(RecommendedAction.DO_NOT_PATCH, result.recommended_action)
        reject_codes = {
            finding.code for finding in result.findings if finding.consequence is Consequence.REJECT
        }
        self.assertEqual(
            {"CAUSURE-ATT-003", "CAUSURE-MIN-001", "CAUSURE-VAL-002"},
            reject_codes,
        )

    def test_requests_evidence_when_reproduction_trials_are_insufficient(self) -> None:
        document = load_example()
        document["verification"]["reproduction_trials"] = document["verification"][
            "reproduction_trials"
        ][:1]

        result = review_case(parse_change_case(document))

        self.assertEqual(Decision.NEEDS_EVIDENCE, result.decision)
        self.assertEqual(RecommendedAction.COLLECT_EVIDENCE, result.recommended_action)
        self.assertIn(
            "CAUSURE-VER-002",
            {
                finding.code
                for finding in result.findings
                if finding.consequence is Consequence.NEEDS_EVIDENCE
            },
        )

    def test_routes_ambiguous_requirements_to_a_human(self) -> None:
        document = load_example()
        document["incident"]["requirement_status"] = "ambiguous"

        result = review_case(parse_change_case(document))

        self.assertEqual(Decision.HUMAN_REVIEW, result.decision)
        self.assertEqual(RecommendedAction.ESCALATE, result.recommended_action)

    def test_returns_conditional_pass_for_nonblocking_cost_growth(self) -> None:
        document = load_example()
        document["validation"]["metrics"]["candidate"]["mean_cost_usd"] = 0.0144

        result = review_case(parse_change_case(document))

        self.assertEqual(Decision.CONDITIONAL_PASS, result.decision)
        cost_finding = next(
            finding for finding in result.findings if finding.code == "CAUSURE-MET-001"
        )
        self.assertEqual(Consequence.CONDITIONAL, cost_finding.consequence)

    def test_can_make_metric_regressions_blocking(self) -> None:
        document = load_example()
        document["validation"]["metrics"]["candidate"]["p95_latency_ms"] = 1200
        policy = parse_policy({"name": "blocking-metrics", "block_on_metric_regression": True})

        result = review_case(parse_change_case(document), policy)

        self.assertEqual(Decision.REJECT, result.decision)
        latency_finding = next(
            finding for finding in result.findings if finding.code == "CAUSURE-MET-002"
        )
        self.assertEqual(Consequence.REJECT, latency_finding.consequence)

    def test_rejects_an_intervention_that_does_not_resolve_the_failure(self) -> None:
        document = load_example()
        trials = document["attribution"]["hypotheses"][0]["intervention"]["trials"]
        for trial in trials:
            trial["failure_resolved"] = False

        result = review_case(parse_change_case(document))

        self.assertEqual(Decision.REJECT, result.decision)
        intervention_finding = next(
            finding for finding in result.findings if finding.code == "CAUSURE-ATT-005"
        )
        self.assertEqual(Consequence.REJECT, intervention_finding.consequence)

    def test_strict_policy_exposes_missing_production_evidence(self) -> None:
        case = parse_change_case(load_example())
        policy = parse_policy(
            {
                "name": "strict",
                "min_reproduction_trials": 5,
                "min_intervention_trials": 5,
                "min_positive_controls": 3,
                "min_negative_controls": 3,
                "min_regression_controls": 20,
            }
        )

        result = review_case(case, policy)

        self.assertEqual(Decision.NEEDS_EVIDENCE, result.decision)

    def test_result_digest_is_stable_for_the_same_case(self) -> None:
        case = parse_change_case(load_example())

        self.assertEqual(document_sha256(case), document_sha256(case))
        self.assertEqual(64, len(document_sha256(case)))

    def test_naive_review_timestamp_is_rejected(self) -> None:
        case = parse_change_case(load_example())

        with self.assertRaisesRegex(ValueError, "timezone"):
            review_case(case, GatePolicy(), reviewed_at=datetime(2026, 7, 27))


if __name__ == "__main__":
    unittest.main()
