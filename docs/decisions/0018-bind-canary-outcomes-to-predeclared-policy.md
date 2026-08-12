# ADR 0018: Bind canary outcomes to a predeclared comparison policy

## Status

Accepted for the `0.4.0a10` alpha.

## Context

ProofBeforePatch can decide whether a proposed harness change is justified before
deployment, but the change-control loop also needs evidence after a candidate reaches a
canary. A raw comparison such as “success increased by 1%” is not enough. It can be based
on a substituted change, a policy selected after seeing outcomes, too little exposure,
contaminated cohorts, repeated unplanned looks, or ordinary binomial sampling variation.

The product does not control a company's traffic router, evaluator, deployment system, or
artifact registry. It can still define a closed artifact boundary that makes those
assumptions explicit and refuses to turn an unbound observation into a promotion claim.

## Decision

Add a separate canary policy, observation, and comparison-result contract.

- The observation binds the exact policy bytes, exact review-result bytes, canonical
  change case, case ID, and proposed change reference.
- Only a review whose decision is `approve` or `conditional_pass` and whose recommended
  action is `patch` can enter comparison. This is technical eligibility, not deployment
  authority.
- The policy must declare its timestamp, family-wise confidence level, maximum number of
  planned looks, minimum window, minimum samples per cohort, exact evaluator reference,
  assignment unit and method, sticky-assignment requirement, binary
  outcome metrics, direction, and maximum tolerated degradation.
- One observation supplies distinct baseline/candidate deployment references, one shared
  evaluator reference, assignment declarations, cohort evidence references, sample
  counts, and event counts. Metric sets must match policy exactly.
- Each proportion receives a Wilson score interval. A Bonferroni allocation covers both
  cohorts, every declared metric, and every planned look before the candidate-minus-
  baseline difference interval is formed. This is intentionally conservative.
- `promote` requires every metric to be noninferior. A conclusive out-of-bound regression
  returns `rollback`. A valid non-final look that remains inconclusive returns `continue`.
  Invalid/insufficient design evidence, or an inconclusive final planned look, returns
  `needs_evidence`.
- The comparison produces JSON and Markdown, stable codes/messages, exact artifact
  digests, and a nonzero CLI exit unless promotion succeeds (or an operator explicitly
  allows `continue`).

## Consequences

Teams can bind a post-deployment result to the exact change that passed review and can
precommit tolerances before exposure. Planned repeated looks do not silently reuse a
single-look confidence claim. Higher-is-better and lower-is-better binary rates cover
outcomes such as task success, policy violations, fallback rate, escalation rate, and
request failure.

The engine does not fetch evidence references, prove randomization, prove that one
evaluator was applied to both cohorts, or execute promotion/rollback. Those remain trusted
integration claims. A policy timestamp is not proof of chronology by itself; production
systems must commit, attest, or authority-sign the exact policy before the window.

The interval assumes independent binomial observations. Sticky principal/session
assignment can create correlated samples, aggregate rates can hide segment regressions,
and evaluator drift can invalidate comparison. Deployments must choose the assignment
unit and effective sample-size policy accordingly, retain segment and raw aggregate
evidence outside this bounded document, and keep independent operational safety rollback
controls.

Continuous latency/cost distributions, survival outcomes, covariate adjustment, automatic
sample-size planning, and alpha-spending methods less conservative than Bonferroni remain
future extensions. A new policy is required after the declared final look; extending the
plan after seeing results would be post-hoc threshold selection.
