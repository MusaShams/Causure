# ADR 0008: Keep signed approvals and exceptions separate from gate decisions

- Status: Accepted
- Date: 2026-07-28

## Context

The Azure publication and pre-approval verification receipt bind exact artifacts and build
identity, but they do not authenticate a human. Azure build variables identify the build
service and requester, not the person who later approved an action. Letting a pipeline copy
one of those values into an approval field would produce self-asserted identity.

A policy exception also has different semantics from the deterministic evidence decision.
Mutating `reject` into `approve` would erase what the gate found, make audit reconstruction
ambiguous, and allow a loosely scoped exception to hide unaccepted findings.

## Decision

ProofBeforePatch will use a separate signed `ApprovalAssertion`.

A protected organizational authority authenticates and authorizes a human, then signs:

- a stable identity-provider subject, authentication method, source event ID, and event
  time;
- an `approve` or `exception` action;
- the exact byte digest and size of the Azure publication and its pre-approval verification
  receipt;
- an issue time, exclusive expiration, assertion ID, authority/key ID, and required
  revocation-list ID; and
- for an exception, a bounded justification and the canonical set of every
  decision-affecting finding code.

An `approve` assertion is valid only when the deterministic decision is already `approve`.
An `exception` assertion is valid only for a non-approval and must cover every finding with
a non-`none` consequence. Assertion lifetime is limited to 24 hours and expiration must
also fall within 24 hours of the bound verification. Authentication must follow that
verification, and issuance must follow authentication within 15 minutes.

A protected trust store binds each authority key to its permitted actions and validity
window. A separately protected, freshness-bounded revocation list supports compromise and
retirement semantics.

The verifier authenticates the signature and policy, rechecks the current Azure TFVC build,
reconstructs the bound pre-approval receipt from the exact result and report, and emits a
separate successful receipt.

Both actions carry `gate_effect: record_only`. The original decision is never rewritten.
The CLI writes a verified exception receipt but returns the original non-approval exit
status.

## Consequences

An auditor can distinguish the deterministic evidence decision, the authenticated human
action, and any explicit policy exception. Identity/action tampering, artifact
substitution, stale assertions, stale revocation state, unauthorized authority actions,
partial exceptions, and build reuse fail closed.

Trust moves to the organizational approval authority and its protected key/action policy.
The bundled issuer command cannot authenticate a human by itself; it is an adapter for a
service that has already done so. Putting the authority private key in the verifier
pipeline collapses the separation and defeats the control.

The implementation does not query Azure approvals, manage organizational roles, enforce
KMS/HSM custody, guarantee assertion-ID uniqueness, or decide whether a recorded exception
authorizes deployment. A hosted workflow may add those controls without changing the
deterministic gate result.
