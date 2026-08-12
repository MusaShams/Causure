# ADR 0010: Use SQLite for the first transactional Team store

- Status: Accepted
- Date: 2026-07-29

## Context

The Team domain contracts already define exact-policy authorization, hash-chained events,
and complete exports. Flat files and the artifact-building CLI do not serialize concurrent
writers, own an authoritative tenant head, preserve policy history as a queryable unit, or
atomically bind an event insert to a head advance.

The first usable company-facing pilot needs those properties without forcing an HTTP
framework, cloud account, or external database into the zero-runtime-dependency package.
It must also preserve exact document bytes rather than silently normalizing them into
relational fields.

## Decision

Add a standard-library `SQLiteTeamStore` for local and single-host deployments.

The store will:

1. Retain exact policy, event, and export BLOBs with protected SHA-256 and byte counts.
2. Keep a forward-only active policy pointer and historical snapshots for every tenant.
3. Begin write operations with `BEGIN IMMEDIATE`.
4. Require an expected head for every append and atomically insert the successor and
   advance the per-tenant head.
5. Reproduce an event decision against the exact historical policy subject recorded in
   that event.
6. Recheck a complete chain while holding a stable snapshot before persisting an export.
7. Enforce per-tenant event, decision, digest, export, and export-decision uniqueness.
8. Add triggers that reject ordinary mutation or deletion of retained records and prevent
   ordinary head or policy rollback.
9. Use WAL, full synchronous writes, foreign keys, a bounded busy timeout, and SQLite's
   online backup API.

The schema has its own integer version and application ID. This alpha refuses an unknown
or newer schema rather than guessing at a migration.

## Consequences

The project now has a real compare-and-swap ledger suitable for one host. Stale concurrent
writers fail without leaving partial events, old authorizations remain reproducible after
a policy advance, and operators can create consistent database backups.

SQLite is not the multi-host production database. WAL assumes a reliable local filesystem
and does not work over a network filesystem. Long complete-export transactions serialize
writers, and the initial 10,000-event complete-export cap also bounds the local ledger.

Triggers and absent delete methods reduce accidental mutation; they are not WORM
retention. A database or filesystem administrator can bypass or remove them. Hosted
identity, server-side tenant routing, rate limits, managed immutable retention, independent
head anchoring, backup encryption, and disaster-recovery qualification remain separate
deployment responsibilities.

## Alternatives considered

- **Continue with files only.** Rejected because atomic replacement of independent files
  cannot safely compare and advance one shared head across writers.
- **Require PostgreSQL immediately.** Deferred because it would add deployment and runtime
  dependencies before the service/API boundary is settled. The store interface and tests
  establish behavior that a later service database must preserve.
- **Store only decoded relational fields.** Rejected because historical authorization and
  export verification bind exact bytes, including their digest and byte count.
- **Describe SQLite triggers as immutable retention.** Rejected because a database owner
  can remove the triggers or the file. Regulatory retention requires a separately
  qualified immutable or WORM-capable layer.
