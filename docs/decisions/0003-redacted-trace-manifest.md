# ADR 0003: Keep raw traces outside the gate

- Status: Accepted
- Date: 2026-07-28

## Context

Production agent traces can contain prompts, customer conversations, retrieved documents,
tool arguments, credentials, signed URLs, account identifiers, and evaluator reasoning.
Copying those traces into a portable approval bundle would enlarge the confidentiality and
retention boundary of every CI run.

The gate still needs stable provenance for later replay, evaluation, and audit.

## Decision

ProofBeforePatch will collect a deterministic metadata manifest rather than embed raw
traces.

The collector:

- Hashes the exact source bytes.
- Fingerprints high-entropy trace and span identifiers with domain separation.
- Omits span names and raw content-bearing OTLP fields.
- Retains only constrained model, provider, kind, token, and cost metadata.
- Emits content-addressed evidence references.
- Runs without network access or artifact dereferencing.

The manifest is not a change case and cannot change gate policy. Replay and evaluator
integrations remain company-owned adapters outside the deterministic core.

## Consequences

Teams can prove which trace artifact a manifest describes without duplicating its contents
in the approval record. Manifests are smaller and safer to publish as CI artifacts.

The original source must remain available in a separately authorized store for replay or
investigation. SHA-256 provides integrity, not producer authentication. Allowlisted metadata
can still be misused by an upstream producer, so manifests remain sensitive operational
records and require inspection and retention controls.
