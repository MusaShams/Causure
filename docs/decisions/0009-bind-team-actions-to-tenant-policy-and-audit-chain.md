# ADR 0009: Bind Team actions to protected tenant policy and a per-tenant audit chain

- Status: Accepted
- Date: 2026-07-28

## Context

A hosted ProofBeforePatch service will handle evidence, investigations, policies,
approvals, and exports for more than one organization. Accepting a tenant ID or role list
from a request would make isolation self-asserted. Recording only successful actions would
also hide denied access attempts and failed privileged operations.

An append-only database or object-lock service can prevent mutation, but the deterministic
library does not control production storage. A hash chain can make mutation, deletion,
reordering, and cross-tenant substitution detectable, but it cannot make writable storage
immutable by itself.

## Decision

The Team service foundation will use a protected `TeamAccessPolicy` snapshot for each
tenant. The policy binds:

- one tenant ID and monotonically managed policy revision;
- stable principals identified by both identity-provider ID and subject ID;
- fixed investigator, policy-administrator, and approver roles; and
- named retention classes with a minimum number of days.

Roles grant a closed set of actions. The caller does not supply its role. The service looks
up exact principal membership in the protected policy and emits a complete allow or deny
decision. The decision binds the exact policy bytes, revision, tenant, action, resource,
assigned roles, granting roles, reason, and decision time.

Every allowed, denied, or failed service action can become a `TeamAuditEvent`. An event:

- embeds the authorization decision;
- hashes the acted-on payload rather than copying sensitive payload content;
- records a policy-backed retention deadline;
- expires its authorization decision after 15 minutes; and
- hashes its canonical entry while linking the previous event hash.

Each tenant has an independent sequence beginning at one. Appending to a production ledger
must compare-and-swap the expected tenant head so two writers cannot create competing
successors.

An audit export is intentionally a complete sequence beginning at one. It requires a fresh,
allowed `audit_export` decision for the export ID, carries the entire verified event chain,
must end at a head digest supplied by the protected tenant ledger, and retains the latest
deadline of its events or the current default retention minimum, whichever is later.
Verification rechecks the exact export bytes, the complete chain, the export authorization,
and the retention floor before emitting a receipt.

The hash chain and verification receipt are tamper-evident integrity controls. A hosted
deployment must put the authoritative head and export in access-controlled, immutable or
WORM-capable storage. It must also protect current and historical policy snapshots against
tampering and rollback.

## Consequences

Cross-tenant predecessors, client-supplied roles, forged allow decisions, action/resource
confusion, stale authorization reuse, shortened retention, chain mutation, gaps,
reordering, duplicate event or decision IDs, partial exports, and unauthorized exports
fail closed.

The first service milestone remains usable without choosing an HTTP framework or database.
Those deployment choices can change without changing the domain contracts.

The local CLI is not an identity provider, membership database, transaction manager, rate
limiter, or immutable store. Anyone who can replace the protected policy or authoritative
ledger head can fabricate a new internally consistent history. A production service must
authenticate the principal, select the tenant server-side, serialize appends, enforce
retention in storage, and anchor or sign exported heads where independent non-repudiation
is required.
