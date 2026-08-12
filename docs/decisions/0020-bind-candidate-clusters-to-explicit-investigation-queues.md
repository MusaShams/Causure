# ADR 0020: Bind candidate clusters to explicit investigation queues

- Status: Accepted
- Date: 2026-08-03
- Release: `0.4.0a12`

## Context

Investigation fixtures already grouped redacted spans by trace identity, but they stopped
at a portable draft artifact. A company still needed a usable place to decide which
candidate warranted attention, collect repeated observations, assign ownership, record an
abstention, or link completed work to the separate evidence-gated change process.

Automatically treating a recurring cluster as an incident or cause would repeat the
failure ProofBeforePatch is intended to prevent: operational activity would be mistaken
for causal proof. Storing complete fixtures in the Team dashboard would also expose trace
and span references beyond the existing minimized read boundary. A mutable ticket row,
meanwhile, would make it difficult to show who changed the queue state and which exact
candidate evidence was considered at that point.

## Decision

Add a separate immutable `TeamInvestigationRecord` projection and a version-3 SQLite
investigation index. Opening and attachment require exact, strictly parsed fixture bytes
and an explicit selected cluster. A record retains only exact fixture subjects and bounded
cluster metadata; it excludes the fixture body, trace reference, span evidence references,
and raw telemetry.

Every record is structurally fixed as candidate-only, non-gate-eligible, and free of
inferred causal claims. The first revision is queued, unassigned, and has one observation.
Each successor either appends one immutable observation or makes one material queue-state
transition. Closed records are terminal and require a typed resolution, including explicit
`not_a_failure`, `no_change_required`, and `insufficient_evidence` abstention paths.

Use the existing investigator permission for mutation and current Team membership for
reads. An assignee must be a current investigator. A `change_case_opened` resolution must
reference an existing tenant-local case; a `duplicate` must reference an existing
tenant-local canonical investigation and cannot form a duplicate chain.

Insert each accepted record in the same SQLite transaction as one authorized successful
`investigation_write` audit event whose payload subject matches the exact record bytes.
Require compare-and-swap checks for both the investigation revision and tenant ledger
head. Serve bounded JSON and script-free HTML from the same minimized application models.

## Consequences

- Companies get a practical triage queue without converting telemetry correlation into an
  incident, diagnosis, or patch recommendation.
- Every attachment, assignment, priority/status change, and terminal disposition remains
  attributable through an immutable record revision and audit event.
- Source fixtures remain in a separately authorized artifact store while their exact bytes
  can be verified by media type, SHA-256, and byte count.
- Duplicate and change-case links cannot point across tenants or to absent records under
  the supported write path.
- Existing version-1 or version-2 stores receive an additive transactional version-3
  migration; retained historical BLOBs are not rewritten.
- A fixture digest detects substitution but does not authenticate its producer. Counts,
  timestamps, titles, identifiers, and fingerprints can still be sensitive.
- SQLite triggers and hashes remain single-host tamper evidence, not WORM retention or an
  independently anchored audit system.

## Alternatives rejected

- Automatically open or merge queue items from clusters: removes accountable human
  judgment and assigns significance to a non-causal grouping heuristic.
- Promote a queue item directly into a gate-eligible change case: bypasses incident,
  requirement, reproduction, attribution, intervention, and control evidence.
- Store full fixture bodies in the Team database or HTML: unnecessarily broadens the
  disclosure and retention boundary.
- Use one mutable ticket row: loses exact historical state and weakens event binding.
- Permit free-text closure only: makes abstention, duplication, and change-case linkage
  difficult to validate or analyze consistently.
