# ADR 0004: Bound adapters with a spawned process

- Status: Accepted
- Date: 2026-07-28

## Context

Company replay and evaluator integrations may hang, crash, emit malformed outcomes, exceed
the requested case count, or report more cost than an investigation budget allows. Running
them in the deterministic gate process would make those failures part of the approval
engine's availability and confidentiality boundary.

The Python package cannot itself provide portable Windows/Linux filesystem, network, memory,
CPU, and provider-account isolation.

## Decision

ProofBeforePatch will invoke trusted company adapters in one fresh `spawn` child process per
request.

The parent enforces the declared wall-clock deadline and input-reference count. The child
validates outcome type, count, identity uniqueness, and aggregate reported cost before
returning a result. Adapter stdout, stderr, and exception messages do not cross the process
boundary.

The API and documentation call this a process-bounded runner, not a sandbox. Evidence files
cannot select executable commands or adapter implementations.

## Consequences

A hung adapter can be terminated without wedging the deterministic gate, and malformed or
over-budget results fail closed with stable, non-sensitive codes. The `spawn` model also
makes the process boundary consistent on Windows.

Adapters must be importable and picklable, and script callers need a standard main guard.
The runner cannot constrain adapter-internal concurrency, inherited permissions, already
submitted remote work, or unreported spend. Production deployments therefore still require
an OS/container sandbox, least-privilege credentials, provider-enforced quotas, and remote
cancellation.
