# ADR 0019: Bind a minimized change-case index to successful audit events

- Status: Accepted
- Date: 2026-08-03
- Release: `0.4.0a11`

## Context

The first Team console could show who recorded an action and the payload's content
subject, but it could not answer the operational question that motivated the product:
what evidence justified this change, what did the gate decide, was it delivered and
approved, and what happened during canary evaluation?

Copying complete change cases, reports, assertions, or observations into browser-facing
audit events would weaken the existing minimization boundary. Keeping only unrelated
hashes would preserve privacy but leave no durable model that could safely join the
stages. Reconstructing every page from external artifacts would also make availability,
pagination, and point-in-time review dependent on several other systems.

## Decision

Add a separate immutable `TeamCaseRecord` projection and a version-2 SQLite case index.
The projection is derived only from exact supplied artifacts and cross-checks their case,
review, TFVC/build, approval, and canary bindings before it is accepted. It retains:

- bounded operational summaries and enum/count fields;
- exact media type, SHA-256, and byte count subjects for every supplied artifact; and
- the tenant, case ID, monotonic revision, and publication time.

It deliberately excludes raw incident behavior, evidence references, intervention
descriptions, report Markdown, approval justification, assertion bytes, and canary
observation evidence references.

Each accepted record is inserted in the same SQLite transaction as one authorized,
successful `investigation_write` audit event. That event's payload subject must match the
exact case-record bytes, occurrence time, tenant, and case resource. A failed case insert
therefore leaves neither an event nor a head advance. Reads revalidate both retained byte
streams and their semantic binding.

Case revisions are append-only. The canonical change/review and their derived summaries
cannot change. Delivery and approval may appear once and then become immutable. Canary
looks may advance only under the declared comparison progression rules, and every advance
must bind a new exact result subject.

Reuse the existing investigator permission for publication and current Team membership
for reads. Do not accept a client role, tenant, revision, event ID, decision ID, or
timestamp. Serve bounded JSON and script-free server-rendered HTML from the same
application models.

## Consequences

- Companies get one practical read model for evidence, gate findings, Azure delivery,
  approval, canary outcome, retention, and audit navigation.
- The browser and case table do not need access to source artifact bodies.
- A digest substitution that preserves a visually identical summary is rejected during
  revision validation.
- Existing version-1 stores receive an additive, transactional version-2 migration when
  `initialize()` runs. Operators should still take and test a backup before upgrade.
- Publication receipts are historical evidence. Ingestion validates their closed
  structure and exact cross-bindings but does not contact Azure, recheck a current build,
  refresh revocations, authenticate the issuer live, or operate a deployment. Integrators
  must perform those checks at the action boundary before publication.
- Minimized titles, summaries, change references, build identifiers, and stable opaque
  subjects can still be sensitive. Producers remain responsible for redaction and data
  classification.
- SQLite triggers and hashes remain single-host tamper evidence, not WORM retention or an
  independently anchored audit system.

## Alternatives rejected

- Store all source artifacts in the audit ledger: excessive disclosure and duplication.
- Rebuild every page from remote artifact stores: wider availability and authorization
  boundary, with no stable pagination snapshot.
- Store summaries without exact subjects: visually useful but unable to detect source
  substitution.
- Introduce a new dashboard-specific role immediately: unnecessary policy migration for
  the first pilot; the existing investigation-write/read boundaries already express the
  intended ownership.
