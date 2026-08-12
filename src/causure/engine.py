"""Deterministic evidence-gate decision engine."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from causure.constants import (
    ENGINE_VERSION,
    RESULT_SCHEMA_VERSION,
    CheckStatus,
    Consequence,
    Decision,
    RecommendedAction,
    RequirementStatus,
    ValidationKind,
)
from causure.models import ChangeCase, Finding, ReviewResult, document_sha256
from causure.policy import GatePolicy


def _rate(successes: int, attempts: int) -> float | None:
    return round(successes / attempts, 6) if attempts else None


def _change_ratio(baseline: float | None, candidate: float | None) -> float | None:
    if baseline is None or candidate is None:
        return None
    if baseline == 0:
        return 0.0 if candidate == 0 else None
    return round((candidate - baseline) / baseline, 6)


def _decision_for(findings: list[Finding]) -> tuple[Decision, RecommendedAction]:
    consequences = {finding.consequence for finding in findings}
    if Consequence.HUMAN_REVIEW in consequences:
        return Decision.HUMAN_REVIEW, RecommendedAction.ESCALATE
    if Consequence.REJECT in consequences:
        return Decision.REJECT, RecommendedAction.DO_NOT_PATCH
    if Consequence.NEEDS_EVIDENCE in consequences:
        return Decision.NEEDS_EVIDENCE, RecommendedAction.COLLECT_EVIDENCE
    if Consequence.CONDITIONAL in consequences:
        return Decision.CONDITIONAL_PASS, RecommendedAction.PATCH
    return Decision.APPROVE, RecommendedAction.PATCH


def _summary_for(decision: Decision) -> str:
    return {
        Decision.APPROVE: (
            "The proposed change is supported by reproducible, attributable evidence and "
            "passed the configured controls."
        ),
        Decision.CONDITIONAL_PASS: (
            "The proposed change passed the safety gate with non-blocking conditions that "
            "must be accepted or resolved before deployment."
        ),
        Decision.REJECT: (
            "The proposed change is contradicted by the evidence or creates an unacceptable "
            "regression. Do not apply it."
        ),
        Decision.NEEDS_EVIDENCE: (
            "The current evidence is insufficient to justify a change. Gather the requested "
            "evidence before patching."
        ),
        Decision.HUMAN_REVIEW: (
            "The incident depends on an ambiguous or conflicting requirement and requires a "
            "human decision before any patch."
        ),
    }[decision]


def review_case(
    case: ChangeCase,
    policy: GatePolicy | None = None,
    *,
    reviewed_at: datetime | None = None,
) -> ReviewResult:
    """Review a parsed change case against a deterministic gate policy."""

    policy = policy or GatePolicy()
    findings: list[Finding] = []
    metrics: dict[str, int | float | None] = {}

    def add(
        code: str,
        status: CheckStatus,
        consequence: Consequence,
        message: str,
        **details: Any,
    ) -> None:
        findings.append(
            Finding(
                code=code,
                status=status,
                consequence=consequence,
                message=message,
                details=details,
            )
        )

    requirement_status = case.incident.requirement_status
    if requirement_status is RequirementStatus.CLEAR:
        add(
            "CAUSURE-REQ-001",
            CheckStatus.PASS,
            Consequence.NONE,
            "The incident is tied to a clear requirement.",
            requirement_status=requirement_status.value,
        )
    elif requirement_status in {
        RequirementStatus.AMBIGUOUS,
        RequirementStatus.CONFLICTING,
    }:
        add(
            "CAUSURE-REQ-001",
            CheckStatus.FAIL,
            Consequence.HUMAN_REVIEW,
            "The governing requirement is ambiguous or conflicting.",
            requirement_status=requirement_status.value,
        )
    else:
        add(
            "CAUSURE-REQ-001",
            CheckStatus.FAIL,
            Consequence.NEEDS_EVIDENCE,
            "The governing requirement has not been established.",
            requirement_status=requirement_status.value,
        )

    oracle = case.verification.oracle
    if policy.require_independent_oracle and not oracle.independent:
        add(
            "CAUSURE-VER-001",
            CheckStatus.FAIL,
            Consequence.NEEDS_EVIDENCE,
            "The failure oracle is not independent from the proposed change.",
            oracle_kind=oracle.kind.value,
        )
    else:
        add(
            "CAUSURE-VER-001",
            CheckStatus.PASS,
            Consequence.NONE,
            "The failure oracle meets the policy's independence requirement.",
            oracle_kind=oracle.kind.value,
            independent=oracle.independent,
        )

    reproduction_trials = case.verification.reproduction_trials
    reproduction_count = sum(trial.reproduced for trial in reproduction_trials)
    reproduction_rate = _rate(reproduction_count, len(reproduction_trials))
    metrics["reproduction_trials"] = len(reproduction_trials)
    metrics["reproduction_rate"] = reproduction_rate
    if len(reproduction_trials) < policy.min_reproduction_trials:
        add(
            "CAUSURE-VER-002",
            CheckStatus.FAIL,
            Consequence.NEEDS_EVIDENCE,
            "There are too few reproduction trials to adjudicate the claimed failure.",
            actual_trials=len(reproduction_trials),
            required_trials=policy.min_reproduction_trials,
        )
    elif reproduction_rate is not None and reproduction_rate < policy.min_reproduction_rate:
        add(
            "CAUSURE-VER-002",
            CheckStatus.FAIL,
            Consequence.REJECT,
            "The claimed failure did not reproduce at the policy's required rate.",
            actual_rate=reproduction_rate,
            required_rate=policy.min_reproduction_rate,
        )
    else:
        add(
            "CAUSURE-VER-002",
            CheckStatus.PASS,
            Consequence.NONE,
            "The claimed failure reproduced at the required rate.",
            actual_rate=reproduction_rate,
            required_rate=policy.min_reproduction_rate,
        )

    hypotheses = sorted(
        case.attribution.hypotheses,
        key=lambda hypothesis: hypothesis.confidence,
        reverse=True,
    )
    top_hypothesis = hypotheses[0] if hypotheses else None
    runner_up_confidence = hypotheses[1].confidence if len(hypotheses) > 1 else 0.0
    attribution_margin = (
        round(top_hypothesis.confidence - runner_up_confidence, 6) if top_hypothesis else None
    )
    metrics["attribution_confidence"] = top_hypothesis.confidence if top_hypothesis else None
    metrics["attribution_margin"] = attribution_margin

    if top_hypothesis is None:
        add(
            "CAUSURE-ATT-001",
            CheckStatus.FAIL,
            Consequence.NEEDS_EVIDENCE,
            "No causal hypotheses were supplied.",
        )
    elif top_hypothesis.confidence < policy.min_attribution_confidence:
        add(
            "CAUSURE-ATT-001",
            CheckStatus.FAIL,
            Consequence.NEEDS_EVIDENCE,
            "The leading causal hypothesis is below the confidence threshold.",
            component=top_hypothesis.component.value,
            actual_confidence=top_hypothesis.confidence,
            required_confidence=policy.min_attribution_confidence,
        )
    else:
        add(
            "CAUSURE-ATT-001",
            CheckStatus.PASS,
            Consequence.NONE,
            "The leading causal hypothesis meets the confidence threshold.",
            component=top_hypothesis.component.value,
            actual_confidence=top_hypothesis.confidence,
        )

    if top_hypothesis is not None:
        if attribution_margin is not None and attribution_margin < policy.min_attribution_margin:
            add(
                "CAUSURE-ATT-002",
                CheckStatus.FAIL,
                Consequence.NEEDS_EVIDENCE,
                "Competing causal hypotheses are not sufficiently separated.",
                actual_margin=attribution_margin,
                required_margin=policy.min_attribution_margin,
            )
        else:
            add(
                "CAUSURE-ATT-002",
                CheckStatus.PASS,
                Consequence.NONE,
                "The leading causal hypothesis is separated from alternatives.",
                actual_margin=attribution_margin,
            )

        if top_hypothesis.component is not case.proposed_change.component:
            add(
                "CAUSURE-ATT-003",
                CheckStatus.FAIL,
                Consequence.REJECT,
                "The proposed change targets a different component than the leading cause.",
                attributed_component=top_hypothesis.component.value,
                proposed_component=case.proposed_change.component.value,
            )
        else:
            add(
                "CAUSURE-ATT-003",
                CheckStatus.PASS,
                Consequence.NONE,
                "The proposed change targets the leading attributed component.",
                component=top_hypothesis.component.value,
            )

        intervention = top_hypothesis.intervention
        if intervention is None:
            add(
                "CAUSURE-ATT-004",
                CheckStatus.FAIL,
                Consequence.NEEDS_EVIDENCE,
                "The leading hypothesis has no isolated intervention evidence.",
            )
        else:
            if policy.require_isolated_intervention and not intervention.isolated:
                add(
                    "CAUSURE-ATT-004",
                    CheckStatus.FAIL,
                    Consequence.NEEDS_EVIDENCE,
                    "The attribution intervention did not isolate the suspected component.",
                )
            else:
                add(
                    "CAUSURE-ATT-004",
                    CheckStatus.PASS,
                    Consequence.NONE,
                    "The attribution intervention meets the isolation requirement.",
                    isolated=intervention.isolated,
                )

            intervention_successes = sum(trial.failure_resolved for trial in intervention.trials)
            intervention_rate = _rate(intervention_successes, len(intervention.trials))
            metrics["intervention_trials"] = len(intervention.trials)
            metrics["intervention_success_rate"] = intervention_rate
            if len(intervention.trials) < policy.min_intervention_trials:
                add(
                    "CAUSURE-ATT-005",
                    CheckStatus.FAIL,
                    Consequence.NEEDS_EVIDENCE,
                    "There are too few intervention trials to support causal attribution.",
                    actual_trials=len(intervention.trials),
                    required_trials=policy.min_intervention_trials,
                )
            elif (
                intervention_rate is not None
                and intervention_rate < policy.min_intervention_success_rate
            ):
                add(
                    "CAUSURE-ATT-005",
                    CheckStatus.FAIL,
                    Consequence.REJECT,
                    "The isolated intervention did not resolve the failure reliably.",
                    actual_rate=intervention_rate,
                    required_rate=policy.min_intervention_success_rate,
                )
            else:
                add(
                    "CAUSURE-ATT-005",
                    CheckStatus.PASS,
                    Consequence.NONE,
                    "The isolated intervention resolved the failure at the required rate.",
                    actual_rate=intervention_rate,
                )

    null_evidence_count = len(case.null_hypothesis.evidence_against)
    metrics["null_hypothesis_evidence"] = null_evidence_count
    if null_evidence_count == 0:
        add(
            "CAUSURE-NULL-001",
            CheckStatus.FAIL,
            Consequence.NEEDS_EVIDENCE,
            "The null hypothesis was declared but no evidence against it was supplied.",
        )
    else:
        add(
            "CAUSURE-NULL-001",
            CheckStatus.PASS,
            Consequence.NONE,
            "The case includes evidence against making no change.",
            evidence_items=null_evidence_count,
        )

    changed_surfaces = case.proposed_change.changed_surface_count
    metrics["changed_surfaces"] = changed_surfaces
    if changed_surfaces > policy.max_changed_surfaces:
        add(
            "CAUSURE-MIN-001",
            CheckStatus.FAIL,
            Consequence.REJECT,
            "The proposal changes more harness surfaces than the minimality policy permits.",
            actual_surfaces=changed_surfaces,
            maximum_surfaces=policy.max_changed_surfaces,
        )
    else:
        add(
            "CAUSURE-MIN-001",
            CheckStatus.PASS,
            Consequence.NONE,
            "The proposal is within the configured minimal-change boundary.",
            changed_surfaces=changed_surfaces,
        )

    positive_cases = [
        validation_case
        for validation_case in case.validation.cases
        if validation_case.kind is ValidationKind.POSITIVE
    ]
    positive_passes = sum(validation_case.candidate_passed for validation_case in positive_cases)
    positive_rate = _rate(positive_passes, len(positive_cases))
    demonstrated_fixes = sum(
        not validation_case.baseline_passed and validation_case.candidate_passed
        for validation_case in positive_cases
    )
    metrics["positive_controls"] = len(positive_cases)
    metrics["positive_pass_rate"] = positive_rate
    if len(positive_cases) < policy.min_positive_controls:
        add(
            "CAUSURE-VAL-001",
            CheckStatus.FAIL,
            Consequence.NEEDS_EVIDENCE,
            "There are too few positive controls.",
            actual_controls=len(positive_cases),
            required_controls=policy.min_positive_controls,
        )
    elif demonstrated_fixes == 0:
        add(
            "CAUSURE-VAL-001",
            CheckStatus.FAIL,
            Consequence.NEEDS_EVIDENCE,
            "The positive controls do not demonstrate a baseline failure becoming a pass.",
        )
    elif positive_rate is not None and positive_rate < policy.min_positive_pass_rate:
        add(
            "CAUSURE-VAL-001",
            CheckStatus.FAIL,
            Consequence.REJECT,
            "The candidate did not fix enough positive controls.",
            actual_rate=positive_rate,
            required_rate=policy.min_positive_pass_rate,
        )
    else:
        add(
            "CAUSURE-VAL-001",
            CheckStatus.PASS,
            Consequence.NONE,
            "The candidate fixed the positive controls at the required rate.",
            actual_rate=positive_rate,
            demonstrated_fixes=demonstrated_fixes,
        )

    negative_cases = [
        validation_case
        for validation_case in case.validation.cases
        if validation_case.kind is ValidationKind.NEGATIVE
    ]
    eligible_negative_cases = [
        validation_case for validation_case in negative_cases if validation_case.baseline_passed
    ]
    negative_passes = sum(
        validation_case.candidate_passed for validation_case in eligible_negative_cases
    )
    negative_rate = _rate(negative_passes, len(eligible_negative_cases))
    metrics["negative_controls"] = len(eligible_negative_cases)
    metrics["negative_pass_rate"] = negative_rate
    if len(eligible_negative_cases) < policy.min_negative_controls:
        add(
            "CAUSURE-VAL-002",
            CheckStatus.FAIL,
            Consequence.NEEDS_EVIDENCE,
            "There are too few valid negative controls with a passing baseline.",
            actual_controls=len(eligible_negative_cases),
            required_controls=policy.min_negative_controls,
        )
    elif negative_rate is not None and negative_rate < policy.min_negative_pass_rate:
        add(
            "CAUSURE-VAL-002",
            CheckStatus.FAIL,
            Consequence.REJECT,
            "The candidate activates or restricts behavior in negative-control scenarios.",
            actual_rate=negative_rate,
            required_rate=policy.min_negative_pass_rate,
            failed_cases=[
                validation_case.case_id
                for validation_case in eligible_negative_cases
                if not validation_case.candidate_passed
            ],
        )
    else:
        add(
            "CAUSURE-VAL-002",
            CheckStatus.PASS,
            Consequence.NONE,
            "The candidate passed the negative controls.",
            actual_rate=negative_rate,
        )

    regression_cases = [
        validation_case
        for validation_case in case.validation.cases
        if validation_case.kind is ValidationKind.REGRESSION
    ]
    eligible_regression_cases = [
        validation_case for validation_case in regression_cases if validation_case.baseline_passed
    ]
    regression_passes = sum(
        validation_case.candidate_passed for validation_case in eligible_regression_cases
    )
    regression_rate = _rate(regression_passes, len(eligible_regression_cases))
    critical_regressions = [
        validation_case.case_id
        for validation_case in eligible_regression_cases
        if validation_case.critical and not validation_case.candidate_passed
    ]
    metrics["regression_controls"] = len(eligible_regression_cases)
    metrics["regression_pass_rate"] = regression_rate
    if len(eligible_regression_cases) < policy.min_regression_controls:
        add(
            "CAUSURE-VAL-003",
            CheckStatus.FAIL,
            Consequence.NEEDS_EVIDENCE,
            "There are too few valid regression controls with a passing baseline.",
            actual_controls=len(eligible_regression_cases),
            required_controls=policy.min_regression_controls,
        )
    elif critical_regressions and not policy.allow_critical_regressions:
        add(
            "CAUSURE-VAL-003",
            CheckStatus.FAIL,
            Consequence.REJECT,
            "The candidate creates at least one critical regression.",
            failed_cases=critical_regressions,
        )
    elif regression_rate is not None and regression_rate < policy.min_regression_pass_rate:
        add(
            "CAUSURE-VAL-003",
            CheckStatus.FAIL,
            Consequence.REJECT,
            "The candidate did not pass enough regression controls.",
            actual_rate=regression_rate,
            required_rate=policy.min_regression_pass_rate,
            failed_cases=[
                validation_case.case_id
                for validation_case in eligible_regression_cases
                if not validation_case.candidate_passed
            ],
        )
    else:
        add(
            "CAUSURE-VAL-003",
            CheckStatus.PASS,
            Consequence.NONE,
            "The candidate passed the regression controls.",
            actual_rate=regression_rate,
        )

    metric_comparison = case.validation.metrics
    if metric_comparison is None:
        metrics["cost_change_ratio"] = None
        metrics["latency_change_ratio"] = None
        if policy.require_metrics_for_approval:
            add(
                "CAUSURE-MET-001",
                CheckStatus.WARNING,
                Consequence.CONDITIONAL,
                "Cost and latency metrics were not supplied.",
            )
    else:
        cost_ratio = _change_ratio(
            metric_comparison.baseline.mean_cost_usd,
            metric_comparison.candidate.mean_cost_usd,
        )
        latency_ratio = _change_ratio(
            metric_comparison.baseline.p95_latency_ms,
            metric_comparison.candidate.p95_latency_ms,
        )
        token_ratio = _change_ratio(
            metric_comparison.baseline.mean_tokens,
            metric_comparison.candidate.mean_tokens,
        )
        metrics["cost_change_ratio"] = cost_ratio
        metrics["latency_change_ratio"] = latency_ratio
        metrics["token_change_ratio"] = token_ratio

        metric_consequence = (
            Consequence.REJECT if policy.block_on_metric_regression else Consequence.CONDITIONAL
        )
        metric_status = (
            CheckStatus.FAIL if policy.block_on_metric_regression else CheckStatus.WARNING
        )

        if cost_ratio is None:
            if policy.require_metrics_for_approval:
                add(
                    "CAUSURE-MET-001",
                    CheckStatus.WARNING,
                    Consequence.CONDITIONAL,
                    "Comparable mean-cost metrics were not supplied.",
                )
        elif cost_ratio > policy.max_cost_increase_ratio:
            add(
                "CAUSURE-MET-001",
                metric_status,
                metric_consequence,
                "The candidate exceeds the allowed cost increase.",
                actual_ratio=cost_ratio,
                maximum_ratio=policy.max_cost_increase_ratio,
            )
        else:
            add(
                "CAUSURE-MET-001",
                CheckStatus.PASS,
                Consequence.NONE,
                "The candidate is within the allowed cost increase.",
                actual_ratio=cost_ratio,
            )

        if latency_ratio is None:
            if policy.require_metrics_for_approval:
                add(
                    "CAUSURE-MET-002",
                    CheckStatus.WARNING,
                    Consequence.CONDITIONAL,
                    "Comparable p95-latency metrics were not supplied.",
                )
        elif latency_ratio > policy.max_latency_increase_ratio:
            add(
                "CAUSURE-MET-002",
                metric_status,
                metric_consequence,
                "The candidate exceeds the allowed latency increase.",
                actual_ratio=latency_ratio,
                maximum_ratio=policy.max_latency_increase_ratio,
            )
        else:
            add(
                "CAUSURE-MET-002",
                CheckStatus.PASS,
                Consequence.NONE,
                "The candidate is within the allowed latency increase.",
                actual_ratio=latency_ratio,
            )

    decision, recommended_action = _decision_for(findings)
    timestamp = reviewed_at or datetime.now(UTC)
    if timestamp.tzinfo is None:
        raise ValueError("reviewed_at must include a timezone")
    return ReviewResult(
        schema_version=RESULT_SCHEMA_VERSION,
        engine_version=ENGINE_VERSION,
        policy_name=policy.name,
        case_id=case.case_id,
        case_title=case.title,
        component=case.proposed_change.component,
        input_sha256=document_sha256(case),
        reviewed_at=timestamp.isoformat().replace("+00:00", "Z"),
        decision=decision,
        recommended_action=recommended_action,
        summary=_summary_for(decision),
        metrics=metrics,
        findings=tuple(findings),
    )
