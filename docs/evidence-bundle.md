# Evidence bundle guide

The change-case JSON file is the portable contract between an investigation system and the
Causure gate. The canonical machine definition is
[`schemas/change-case.schema.json`](../schemas/change-case.schema.json).

## Design rules

- Keep raw prompts, customer messages, credentials, and personal data out of the bundle.
- Use opaque evidence references such as artifact IDs, trace IDs, or content hashes.
- Make the oracle independent from the candidate change.
- Record individual trials instead of only aggregate percentages.
- Include plausible competing causes.
- Hold other variables constant during an attribution intervention.
- Predeclare the predicted effect and unaffected behavior.
- Test when the change should **not** activate.

## Sections

### Incident

`incident` records the claim being adjudicated. `requirement_status` is deliberately
explicit:

- `clear`: the gate may decide automatically.
- `ambiguous` or `conflicting`: the gate returns `human_review`.
- `unknown`: the gate returns `needs_evidence`.

### Verification

`verification.oracle` describes how failure is judged. `independent` means the oracle was not
created or changed as part of the candidate patch.

`reproduction_trials` stores each attempt:

```json
{
  "id": "repro-01",
  "reproduced": true,
  "evidence_ref": "trace://replay/refund-01"
}
```

### Attribution

Each hypothesis names one component, a confidence, evidence references, and optionally an
intervention. Confidence is supporting metadata; it does not replace intervention trials.

The leading intervention should change only the suspected component and list what was held
constant.

### Proposed change

The proposal must identify:

- One target component.
- A concrete summary.
- A falsifiable prediction.
- Expected unaffected behavior.
- Known risks.
- The number of changed surfaces.
- A source-control or change-management reference.

The default policy permits one changed surface.

### Null hypothesis

The null hypothesis should state why no harness change might be necessary. Examples include
a transient API error, evaluator defect, ambiguous requirement, or irreproducible anomaly.
The bundle then lists the evidence against doing nothing.

### Validation

Validation cases have three kinds:

- `positive`: baseline fails and candidate should pass.
- `negative`: baseline passes and the new rule should not activate or restrict behavior.
- `regression`: baseline passes and an existing capability must remain intact.

Negative and regression controls with a failing baseline do not count toward policy minimums.

### Metrics

The current engine compares:

- Mean cost in USD.
- p95 latency in milliseconds.
- Mean token count.

Token change is reported but does not have a default blocking threshold. Missing comparable
cost or latency metrics produce a conditional pass under the default policy.

## Evidence references

References are opaque strings. The alpha does not dereference them or automatically verify
the referenced artifact.

The trace collector now emits a separate, versioned
[redacted trace manifest](trace-collection.md) with an exact source hash, source byte and
span counts, a redaction summary, and content-addressed span references. It deliberately
does not include storage locations, authorization tokens, or raw trace content.

An [investigation fixture](investigation-fixtures.md) can group that manifest by trace
identity and summarize safe metadata for triage. Its schema fixes `draft_only` to true,
`gate_eligible` to false, and `causal_claims_inferred` to false. It is not an incomplete
change case that can be progressively trusted: an investigator must deliberately assemble a
new change-case document with independently established claims and evidence.
The Team [investigation queue](team-investigation-queue.md) can bind selected clusters to
attributable operational work and typed closure while preserving that candidate-only
boundary.

A detached [artifact attestation](artifact-attestations.md) can now bind any exact artifact
to a trusted producer, validity window, retention requirement, and current key-revocation
state. Signing a change case does not recursively verify the opaque references inside it;
each referenced artifact still needs its own registry record or attestation.

Post-deployment evidence is deliberately separate from the change-case schema. A
[canary comparison](canary-outcome-comparison.md) binds aggregate baseline/candidate
binary outcomes to the canonical change case, exact review-result bytes, and an exact
policy declared before exposure. It does not rewrite the original gate decision: the
result is a separate `promote`, `continue`, `rollback`, or `needs_evidence` receipt.

The Team [change-case dashboard](team-change-case-dashboard.md) can join minimized
summaries of these lifecycle artifacts. It retains their exact content subjects rather
than copying raw evidence references, report Markdown, approval justification, or canary
observations into the browser-facing index.

A production artifact registry still needs:

- Content hash.
- Storage location.
- Access policy.
- Enforced retention and deletion time.
- Redaction status.
- Producer identity backed by protected trust and key custody.

Do not replace an opaque reference with a user-controlled URL. Doing so would create both
integrity and server-side request-forgery risk.
