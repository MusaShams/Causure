# Post-deployment canary outcome comparison

Causure can now close the initial change-control loop with a bounded comparison
between one baseline deployment and one candidate deployment. The comparison answers a
narrow question:

> Given this exact reviewed change, this policy declared before exposure, and these two
> aggregate cohorts, is every predeclared binary outcome rate noninferior?

It does not deploy, route traffic, fetch telemetry, or automatically promote or roll back
a release.

## Artifacts

The workflow uses four exact inputs:

1. The reviewed change case.
2. Its machine-readable review result.
3. A canary policy committed before the observation window.
4. A canary observation produced after one planned look.

The observation binds the canonical change-case digest from the review result plus the
SHA-256 of the exact review-result and policy bytes. Whitespace changes to the policy or
review result therefore require a new observation binding.

Export the closed schemas with:

```powershell
$env:PYTHONPATH = "src"

python -m causure schema canary-policy `
  --output canary-policy.schema.json
python -m causure schema canary-observation `
  --output canary-observation.schema.json
python -m causure schema canary-result `
  --output canary-result.schema.json
```

The committed forms are the
[policy](../schemas/canary-policy.schema.json),
[observation](../schemas/canary-observation.schema.json), and
[result](../schemas/canary-result.schema.json) schemas. A synthetic starting policy is
available at
[`examples/canary/company-canary-policy.json`](../examples/canary/company-canary-policy.json).
Copy it into protected change control and replace its timestamp, evaluator reference,
assignment unit, thresholds, and look plan before deployment.

## Predeclare the policy

The policy fixes:

- a stable policy ID and whole-second UTC declaration time;
- one evaluator artifact reference and one assignment unit;
- one randomized or deterministic-hash assignment method;
- whether assignment must remain sticky;
- a family-wise confidence level;
- a maximum of 1–100 planned looks;
- minimum observation duration and sample size per cohort; and
- 1–50 binary outcome metrics, their preferred direction, and absolute maximum tolerated
  degradation.

`event_count` means the number of samples for which the named binary event occurred. For a
higher-is-better metric it could mean successful completion. For a lower-is-better metric
it could mean a policy violation or request failure. Every metric uses the cohort's full
`sample_count` as its denominator; missing or selectively evaluated samples need a
different predeclared population rather than an omitted denominator.

Commit, attest, or authority-sign the exact policy before the window. The self-reported
`declared_at` timestamp alone is not proof that thresholds were chosen prospectively.
Likewise, the evaluator reference should identify immutable or attested evaluator logic,
not a mutable URL or label.

## Produce the reviewed change binding

Write the machine result when reviewing the change:

```powershell
python -m causure review `
  .\change-case.json `
  --format markdown `
  --output .\review-report.md `
  --result-output .\review-result.json `
  --quiet
```

The review result contains the canonical change-case `input_sha256`. Compute the other
exact-byte bindings with:

```powershell
$caseSha = (Get-Content .\review-result.json -Raw |
  ConvertFrom-Json).input_sha256
$reviewSha = (Get-FileHash .\review-result.json -Algorithm SHA256).Hash.ToLowerInvariant()
$policySha = (Get-FileHash .\canary-policy.json -Algorithm SHA256).Hash.ToLowerInvariant()
```

Only an `approve` or `conditional_pass` review whose recommended action is `patch` is
eligible. This is a technical prerequisite; it does not replace the organization's merge,
deployment, or approval authority. Supply the review result from a protected/verified
Azure publication or separately attest it; an exact digest binds bytes but does not
authenticate who produced them.

## Record one planned look

A canary observation contains no raw prompts, messages, model output, principal IDs, or
per-request records. It carries:

- the comparison/look number and observation window;
- exact change and policy bindings;
- the same evaluator reference declared in policy;
- assignment method, unit, stickiness, and detected-contamination declaration;
- distinct baseline/candidate deployment references;
- one bounded evidence reference per cohort;
- sample counts; and
- an exact metric set with aggregate event counts.

The assignment unit and evaluator must match policy. A look number beyond the predeclared
maximum is rejected. The window must be positive, no longer than 30 days, and complete by
`observed_at`.

References are bounded opaque identifiers. Causure never dereferences them. The
producer must separately preserve and authenticate the aggregate evidence to which they
refer.

## Compare

```powershell
python -m causure canary-compare `
  .\canary-observation.json `
  --policy .\canary-policy.json `
  --case .\change-case.json `
  --review-result .\review-result.json `
  --output .\canary-report.md `
  --result-output .\canary-result.json
```

The command returns:

- `0` only for `promote`;
- `1` for `continue`, `rollback`, or `needs_evidence`; and
- `2` for invalid configuration, parsing, chronology, or artifact binding.

`--allow-continue` changes only the `continue` process exit to `0`; it does not relabel the
machine decision. This option is intended for a pipeline stage that safely leaves the
canary running, not a production-promotion gate.

## Decision semantics

For each cohort proportion, the engine computes a Wilson score interval using the
[NIST formula](https://www.itl.nist.gov/div898/handbook/prc/section2/prc241.htm).
It allocates the policy's total error probability conservatively across both cohorts,
every metric, and every planned look. The candidate-minus-baseline interval is then:

```text
[candidate lower - baseline upper, candidate upper - baseline lower]
```

For higher-is-better metrics, the whole interval must remain at or above the negative
degradation allowance. For lower-is-better metrics, it must remain at or below the
positive allowance.

- `promote`: every metric is noninferior and the window, assignment, and sample contract
  is met.
- `rollback`: at least one metric is conclusively outside its degradation allowance.
- `continue`: the design minimums are met, at least one metric is inconclusive, and a
  predeclared look remains.
- `needs_evidence`: design minimums are not met, or the final planned look remains
  inconclusive.

A new prospective policy is required after the final planned look. Increasing
`maximum_looks`, changing a tolerance, replacing the evaluator, or changing the assignment
unit after observing outcomes is not continuation of the original claim.

## Trust and limits

The result establishes a deterministic relationship among supplied artifacts. It does not
prove that:

- traffic assignment was actually randomized, deterministic, sticky, or uncontaminated;
- baseline and candidate populations were exchangeable;
- the predeclared evaluator processed every sample identically;
- samples are independent at the chosen assignment unit;
- a cohort evidence reference is authentic or retained;
- aggregate success hides no segment-specific regression; or
- the candidate caused the observed difference.

Sticky principal, session, or tenant assignment can make request-level samples correlated,
so raw request count may overstate effective sample size. Set the policy's minimum using
the deployment's independent assignment unit and preserve segment analyses outside this
bounded first contract.

Keep independent operational rollback controls for safety, availability, latency, and
cost. This alpha compares binary rates only; it does not model continuous distributions,
survival outcomes, covariate adjustment, or heterogeneous treatment effects.

See [ADR 0018](decisions/0018-bind-canary-outcomes-to-predeclared-policy.md) for the
decision and residual-risk boundary.
