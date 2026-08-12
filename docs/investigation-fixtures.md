# Investigation fixtures

An investigation fixture turns a validated redacted trace manifest into a deterministic
queueing and triage artifact. It helps a company decide what to investigate without
pretending that telemetry alone establishes a failure, a cause, or a justified patch.

## Generate a fixture

```powershell
$env:PYTHONPATH = "src"

python -m causure fixture `
  causure-trace-manifest.json `
  --fixture-id refund-investigation `
  --output causure-investigation-fixture.json
```

The input must be a UTF-8 file. Standard input is rejected because the fixture records the
SHA-256 of the exact manifest bytes. The input and output paths must differ.

Export the contract with:

```powershell
python -m causure schema investigation-fixture
```

The committed form is
[`schemas/investigation-fixture.schema.json`](../schemas/investigation-fixture.schema.json).

## What it contains

The generator reparses the manifest against a strict closed contract and creates one
candidate cluster for each fingerprinted trace identity. A cluster contains:

- A content-addressed trace reference and the manifest's span evidence references.
- Span, root-span, and error-span counts.
- OpenInference kind and OTLP status-code counts.
- Allowlisted model and provider identifiers already present in the redacted manifest.
- The earliest start, latest end, and observed trace window when timestamps are available.

Clusters and nested values use stable sorting, so the same exact manifest bytes, fixture ID,
and generator version render identically.

## What it refuses to claim

Every generated artifact is structurally fixed to:

```json
{
  "draft_only": true,
  "gate_eligible": false,
  "causal_claims_inferred": false,
  "clustering_basis": "trace_identity"
}
```

It also lists the evidence that remains absent:

- Incident claim.
- Governing requirement.
- Independent oracle.
- Reproduction outcomes.
- Causal attribution.
- Proposed change.
- Negative and regression controls.

Trace co-occurrence is not causality. A fixture cannot be passed to `validate` or `review`,
renamed into a change case, or used as proof that a patch is necessary. Evidence assembly is
a separate, deliberate step.

## Bounds and residual risk

- Manifest input is limited to 64 MiB.
- The default cluster limit is 1,000 and may be set no higher than 10,000.
- Duplicate JSON keys and malformed or internally inconsistent manifest fields fail closed.
- The source manifest and its underlying trace source are both bound by SHA-256.

The fixture retains operational metadata from the manifest. An upstream system can still put
sensitive text into an allowlisted model/provider field, and SHA-256 does not authenticate
the producer. Inspect fixtures before broad distribution and apply retention controls.

`parse_investigation_fixture` and `parse_investigation_fixture_bytes` expose the same strict
closed validation used by downstream Team ingestion. They reject duplicate keys, unknown
fields, inconsistent counts, changed trace/source subjects, and malformed references rather
than treating generated JSON as implicitly trusted.

An investigator can select a cluster from the exact fixture and place it in the
[Team investigation queue](team-investigation-queue.md). That workflow preserves the
candidate-only boundary: queueing, recurrence, assignment, and prioritization are not causal
evidence and do not make the fixture gate-eligible.
