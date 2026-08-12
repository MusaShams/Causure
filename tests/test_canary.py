"""Adversarial tests for evidence-bound canary outcome comparison."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from datetime import UTC, datetime

from causure.canary import (
    CanaryDecision,
    CanaryMetricStatus,
    CanaryValidationError,
    compare_canary_outcomes,
    parse_canary_observation_bytes,
    parse_canary_policy_bytes,
    parse_canary_result,
    parse_canary_result_bytes,
    render_canary_markdown,
    render_canary_result,
)
from causure.engine import review_case
from causure.io import load_change_case
from causure.models import document_sha256
from causure.report import render_json
from tests.helpers import PROJECT_ROOT


def _json_bytes(document: object) -> bytes:
    return (
        json.dumps(
            document,
            allow_nan=False,
            ensure_ascii=False,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    ).encode("utf-8")


def _policy_document() -> dict:
    return {
        "schema_version": "1.0",
        "policy_id": "company-canary-v1",
        "declared_at": "2026-07-29T12:00:00Z",
        "confidence_level": 0.95,
        "maximum_looks": 3,
        "minimum_observation_seconds": 3600,
        "minimum_sample_size_per_cohort": 1000,
        "evaluator_ref": "attestation://evaluators/refund-v4",
        "assignment_unit": "principal",
        "assignment_method": "deterministic_hash",
        "require_sticky_assignment": True,
        "metrics": [
            {
                "metric_id": "task_success",
                "direction": "higher",
                "maximum_degradation": 0.02,
            },
            {
                "metric_id": "safety_violation",
                "direction": "lower",
                "maximum_degradation": 0.005,
            },
        ],
    }


def _artifacts(
    *,
    policy_document: dict | None = None,
    baseline_sample_count: int = 10_000,
    candidate_sample_count: int = 10_000,
    baseline_events: tuple[int, int] = (9000, 50),
    candidate_events: tuple[int, int] = (9150, 40),
) -> tuple[bytes, bytes, bytes, bytes, dict]:
    case_path = PROJECT_ROOT / "examples" / "change-cases" / "approve-refund-tool-description.json"
    case_bytes = case_path.read_bytes()
    case = load_change_case(case_path)
    review = review_case(
        case,
        reviewed_at=datetime(2026, 7, 29, 12, 30, tzinfo=UTC),
    )
    review_bytes = render_json(review).encode("utf-8")
    policy = policy_document or _policy_document()
    policy_bytes = _json_bytes(policy)
    observation = {
        "schema_version": "1.0",
        "comparison_id": "refund-canary-001",
        "look_number": 1,
        "observed_at": "2026-07-29T15:00:00Z",
        "change": {
            "case_id": case.case_id,
            "change_ref": case.proposed_change.change_ref,
            "change_case_sha256": document_sha256(case),
            "review_result_sha256": hashlib.sha256(review_bytes).hexdigest(),
        },
        "policy": {
            "policy_id": policy["policy_id"],
            "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
        },
        "window": {
            "started_at": "2026-07-29T13:00:00Z",
            "ended_at": "2026-07-29T15:00:00Z",
        },
        "evaluator_ref": "attestation://evaluators/refund-v4",
        "assignment": {
            "method": "deterministic_hash",
            "unit": "principal",
            "sticky": True,
            "cross_cohort_contamination_detected": False,
        },
        "baseline": {
            "deployment_ref": "deployment://refund/baseline-v17",
            "sample_count": baseline_sample_count,
            "evidence_ref": "artifact://canary/refund-baseline-001",
            "metrics": [
                {"metric_id": "task_success", "event_count": baseline_events[0]},
                {"metric_id": "safety_violation", "event_count": baseline_events[1]},
            ],
        },
        "candidate": {
            "deployment_ref": "deployment://refund/candidate-v18",
            "sample_count": candidate_sample_count,
            "evidence_ref": "artifact://canary/refund-candidate-001",
            "metrics": [
                {"metric_id": "task_success", "event_count": candidate_events[0]},
                {"metric_id": "safety_violation", "event_count": candidate_events[1]},
            ],
        },
    }
    return _json_bytes(observation), policy_bytes, case_bytes, review_bytes, observation


def _compare(
    observation_bytes: bytes,
    policy_bytes: bytes,
    case_bytes: bytes,
    review_bytes: bytes,
):
    return compare_canary_outcomes(
        observation_bytes,
        policy_bytes,
        case_bytes,
        review_bytes,
        compared_at=datetime(2026, 7, 29, 16, 0, tzinfo=UTC),
    )


class CanaryComparisonTests(unittest.TestCase):
    def test_committed_policy_example_matches_the_runtime_contract(self) -> None:
        path = PROJECT_ROOT / "examples" / "canary" / "company-canary-policy.json"

        policy = parse_canary_policy_bytes(path.read_bytes())

        self.assertEqual("company-canary-v1", policy.policy_id)
        self.assertEqual(
            ("task_success", "safety_violation"),
            tuple(metric.metric_id for metric in policy.metrics),
        )

    def test_promotes_only_when_every_metric_is_noninferior(self) -> None:
        observation, policy, case, review, _ = _artifacts()

        result = _compare(observation, policy, case, review)

        self.assertIs(CanaryDecision.PROMOTE, result.decision)
        self.assertEqual(
            {CanaryMetricStatus.NONINFERIOR},
            {metric.status for metric in result.metrics},
        )
        self.assertEqual(hashlib.sha256(observation).hexdigest(), result.observation_sha256)
        self.assertEqual(hashlib.sha256(policy).hexdigest(), result.policy_sha256)
        self.assertEqual("attestation://evaluators/refund-v4", result.evaluator_ref)
        self.assertEqual("deterministic_hash", result.assignment_method.value)
        self.assertEqual("principal", result.assignment_unit.value)
        rendered = render_canary_result(result)
        self.assertEqual("promote", json.loads(rendered)["decision"])
        markdown = render_canary_markdown(result)
        self.assertIn("> **PROMOTE**", markdown)
        self.assertIn("Exact artifact bindings", markdown)
        self.assertNotIn("artifact://canary/refund-baseline-001", markdown)

    def test_rolls_back_a_conclusive_success_rate_regression(self) -> None:
        artifacts = _artifacts(candidate_events=(8000, 40))

        result = _compare(*artifacts[:4])

        self.assertIs(CanaryDecision.ROLLBACK, result.decision)
        task_success = next(
            metric for metric in result.metrics if metric.metric_id == "task_success"
        )
        self.assertIs(CanaryMetricStatus.REGRESSION, task_success.status)
        self.assertLess(task_success.confidence_upper, -task_success.maximum_degradation)

    def test_rolls_back_a_conclusive_lower_is_better_regression(self) -> None:
        artifacts = _artifacts(candidate_events=(9150, 500))

        result = _compare(*artifacts[:4])

        self.assertIs(CanaryDecision.ROLLBACK, result.decision)
        safety = next(metric for metric in result.metrics if metric.metric_id == "safety_violation")
        self.assertIs(CanaryMetricStatus.REGRESSION, safety.status)
        self.assertGreater(safety.confidence_lower, safety.maximum_degradation)

    def test_familywise_interval_widens_for_more_predeclared_looks(self) -> None:
        one_look_policy = _policy_document()
        one_look_policy["maximum_looks"] = 1
        one_look = _artifacts(policy_document=one_look_policy)
        one_look_result = _compare(*one_look[:4])

        ten_look_policy = _policy_document()
        ten_look_policy["maximum_looks"] = 10
        ten_look = _artifacts(policy_document=ten_look_policy)
        ten_look_result = _compare(*ten_look[:4])

        one_metric = one_look_result.metrics[0]
        ten_metric = ten_look_result.metrics[0]
        one_width = one_metric.confidence_upper - one_metric.confidence_lower
        ten_width = ten_metric.confidence_upper - ten_metric.confidence_lower
        self.assertGreater(ten_width, one_width)

    def test_continues_when_valid_minimum_evidence_is_statistically_inconclusive(
        self,
    ) -> None:
        policy_document = _policy_document()
        policy_document["metrics"] = [
            {
                "metric_id": "task_success",
                "direction": "higher",
                "maximum_degradation": 0.0,
            }
        ]
        observation, policy, case, review, document = _artifacts(
            policy_document=policy_document,
            baseline_events=(9000, 0),
            candidate_events=(9000, 0),
        )
        document["baseline"]["metrics"] = document["baseline"]["metrics"][:1]
        document["candidate"]["metrics"] = document["candidate"]["metrics"][:1]
        observation = _json_bytes(document)

        result = _compare(observation, policy, case, review)

        self.assertIs(CanaryDecision.CONTINUE, result.decision)
        self.assertIs(CanaryMetricStatus.INCONCLUSIVE, result.metrics[0].status)

        document["look_number"] = policy_document["maximum_looks"]
        final = _compare(_json_bytes(document), policy, case, review)
        self.assertIs(CanaryDecision.NEEDS_EVIDENCE, final.decision)
        self.assertIn("new prospective plan", final.summary)

    def test_requires_window_assignment_and_sample_contract_before_deciding(self) -> None:
        scenarios = {
            "short window": lambda document: document["window"].update(
                {"started_at": "2026-07-29T14:30:01Z"}
            ),
            "unsticky": lambda document: document["assignment"].update({"sticky": False}),
            "contaminated": lambda document: document["assignment"].update(
                {"cross_cohort_contamination_detected": True}
            ),
            "small baseline": lambda document: (
                document["baseline"].update({"sample_count": 100}),
                document["baseline"]["metrics"][0].update({"event_count": 90}),
                document["baseline"]["metrics"][1].update({"event_count": 1}),
            ),
        }
        for label, mutate in scenarios.items():
            with self.subTest(label=label):
                observation, policy, case, review, document = _artifacts()
                mutate(document)
                result = _compare(_json_bytes(document), policy, case, review)
                self.assertIs(CanaryDecision.NEEDS_EVIDENCE, result.decision)

    def test_exact_policy_case_and_review_bindings_cannot_be_substituted(self) -> None:
        scenarios = {
            "policy bytes": lambda document: document["policy"].update({"policy_sha256": "0" * 64}),
            "case digest": lambda document: document["change"].update(
                {"change_case_sha256": "0" * 64}
            ),
            "review digest": lambda document: document["change"].update(
                {"review_result_sha256": "0" * 64}
            ),
            "change ref": lambda document: document["change"].update(
                {"change_ref": "tfvc://$/ProofBeforePatch/changes/substituted"}
            ),
            "evaluator ref": lambda document: document.update(
                {"evaluator_ref": "attestation://evaluators/substituted-v1"}
            ),
            "assignment unit": lambda document: document["assignment"].update({"unit": "request"}),
            "assignment method": lambda document: document["assignment"].update(
                {"method": "randomized"}
            ),
            "unplanned look": lambda document: document.update({"look_number": 4}),
        }
        for label, mutate in scenarios.items():
            with self.subTest(label=label):
                _, policy, case, review, document = _artifacts()
                mutate(document)
                with self.assertRaises(CanaryValidationError):
                    _compare(_json_bytes(document), policy, case, review)

    def test_rejected_review_cannot_be_relabelled_as_a_canary(self) -> None:
        _, policy, case, review, document = _artifacts()
        review_document = json.loads(review)
        review_document["decision"] = "reject"
        review_document["recommended_action"] = "do_not_patch"
        rejected_review = _json_bytes(review_document)
        document["change"]["review_result_sha256"] = hashlib.sha256(rejected_review).hexdigest()

        with self.assertRaisesRegex(
            CanaryValidationError,
            "only an approved or conditional patch",
        ):
            _compare(_json_bytes(document), policy, case, rejected_review)

    def test_policy_and_review_must_predate_observation_window(self) -> None:
        policy_document = _policy_document()
        policy_document["declared_at"] = "2026-07-29T13:00:01Z"
        observation, policy, case, review, _ = _artifacts(policy_document=policy_document)
        with self.assertRaisesRegex(CanaryValidationError, "before the observation window"):
            _compare(observation, policy, case, review)

        _, policy, case, review, document = _artifacts()
        review_document = json.loads(review)
        review_document["reviewed_at"] = "2026-07-29T13:00:01Z"
        late_review = _json_bytes(review_document)
        document["change"]["review_result_sha256"] = hashlib.sha256(late_review).hexdigest()
        with self.assertRaisesRegex(CanaryValidationError, "before the observation window"):
            _compare(_json_bytes(document), policy, case, late_review)

    def test_metric_sets_counts_and_deployment_identity_are_closed(self) -> None:
        mutations = {
            "missing metric": lambda document: document["candidate"]["metrics"].pop(),
            "unknown metric": lambda document: document["candidate"]["metrics"].append(
                {"metric_id": "unplanned_metric", "event_count": 0}
            ),
            "count overflow": lambda document: document["candidate"]["metrics"][0].update(
                {"event_count": document["candidate"]["sample_count"] + 1}
            ),
            "same deployment": lambda document: document["candidate"].update(
                {"deployment_ref": document["baseline"]["deployment_ref"]}
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                _, policy, case, review, document = _artifacts()
                mutate(document)
                with self.assertRaises(CanaryValidationError):
                    _compare(_json_bytes(document), policy, case, review)

    def test_parsers_reject_unknown_duplicate_and_nonfinite_input(self) -> None:
        _, policy, _, _, document = _artifacts()
        policy_document = json.loads(policy)
        policy_document["unknown"] = True
        with self.assertRaises(CanaryValidationError):
            parse_canary_policy_bytes(_json_bytes(policy_document))

        duplicate = policy.replace(
            b'"policy_id": "company-canary-v1",',
            b'"policy_id": "company-canary-v1",\n  "policy_id": "duplicate",',
        )
        with self.assertRaises(CanaryValidationError):
            parse_canary_policy_bytes(duplicate)

        invalid_number = copy.deepcopy(document)
        invalid_number["candidate"]["sample_count"] = float("inf")
        raw = json.dumps(invalid_number, allow_nan=True).encode()
        with self.assertRaises(CanaryValidationError):
            parse_canary_observation_bytes(raw)

    def test_comparison_is_stable_for_the_same_exact_artifacts_and_time(self) -> None:
        artifacts = _artifacts()

        first = _compare(*artifacts[:4])
        second = _compare(*artifacts[:4])

        self.assertEqual(first, second)
        self.assertEqual(render_canary_result(first), render_canary_result(second))

    def test_result_parser_round_trips_and_rechecks_derived_fields(self) -> None:
        artifacts = _artifacts()
        result = _compare(*artifacts[:4])
        rendered = render_canary_result(result)

        self.assertEqual(result, parse_canary_result(json.loads(rendered)))
        self.assertEqual(result, parse_canary_result_bytes(rendered.encode("utf-8")))

        changed = json.loads(rendered)
        changed["metrics"][0]["observed_difference"] += 0.01
        with self.assertRaisesRegex(CanaryValidationError, "candidate_rate minus"):
            parse_canary_result(changed)

        changed = json.loads(rendered)
        changed["checks"].append(changed["checks"][0])
        with self.assertRaisesRegex(CanaryValidationError, "exactly 6 checks"):
            parse_canary_result(changed)

        changed = json.loads(rendered)
        changed["candidate_deployment_ref"] = changed["baseline_deployment_ref"]
        with self.assertRaisesRegex(CanaryValidationError, "must differ"):
            parse_canary_result(changed)


if __name__ == "__main__":
    unittest.main()
