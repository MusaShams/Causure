# Transactional SQLite Team store

The SQLite Team store is the first durable persistence layer beneath the Team domain
contracts. It is intended for local evaluation, a single-host service, and company pilots
that need real concurrent-writer protection without adding a database dependency.

It stores exact historical policy, event, export, minimized case-record, and minimized
investigation-record bytes. It also owns the authoritative per-tenant ledger head, so a
caller cannot label its own event or export prefix as current. The implementation uses
only Python's standard `sqlite3` module.

This is not a hosted identity service or a WORM archive. Put it behind authenticated,
server-side tenant routing before exposing it to users.

## Guarantees

`SQLiteTeamStore` provides these boundaries:

- Initialization refuses a non-empty foreign database and records an application ID and
  schema version.
- Access policies are retained as exact BLOBs with SHA-256 and byte count. Revisions are
  forward-only per tenant; an identical retry is idempotent, while different bytes at the
  same policy ID and revision fail.
- Every write transaction starts with `BEGIN IMMEDIATE`. SQLite therefore admits one
  writer before the store reads and compares the current head.
- `append_event` requires the caller's expected head. The event must be the immediate
  successor, its ID and authorization-decision ID must be unused in that tenant, and its
  embedded decision is reproduced against the exact historical policy it records.
- The event insert and tenant-head advance commit or roll back together. A stale writer
  receives `head_conflict` and leaves no partial row or fork.
- `append_case_record` additionally requires the exact case record to match an authorized
  successful investigation event's tenant, resource, occurrence time, and payload
  subject. The event, record, and head commit or roll back together.
- Case rows are append-only per `(tenant, case)`. Reads revalidate retained record/event
  bytes and their binding; list snapshots return only each case's latest revision.
- `append_investigation_record` likewise requires an authorized successful investigation
  event whose tenant, resource, occurrence time, and payload subject exactly bind the
  record. The event, record, and head commit or roll back together.
- Investigation rows are append-only per `(tenant, investigation)`. Reads revalidate exact
  record/event bytes and return only the latest revision; status and priority filters run
  after latest-revision selection.
- Complete exports run inside the same write-transaction boundary, end at the protected
  current head, recheck each event against its historical policy, require an export
  authorization from the active policy, and persist the exact rendered export bytes.
- Database triggers reject ordinary `UPDATE` or `DELETE` statements against policies,
  events, exports, case records, investigation records, and schema metadata. Other
  triggers prevent a head rewind, skipped sequence, active-policy rollback, invalid
  record/event binding, missing tenant-local case link, and missing duplicate target
  through ordinary SQL.
- `team-store-backup` uses SQLite's online backup API and refuses to overwrite an existing
  destination.

The store enables foreign keys, WAL journal mode, `synchronous=FULL`, a bounded busy
timeout, and read-only query connections. `BEGIN IMMEDIATE` and WAL behavior are described
in the official [SQLite transaction](https://www.sqlite.org/lang_transaction.html) and
[write-ahead logging](https://www.sqlite.org/wal.html) documentation.

## Initialize and put a policy

Keep runtime databases outside the source tree. The `.tfignore` patterns are a safety net,
not a deployment location policy.

```powershell
python -m causure team-store-init C:\CausureData\team.sqlite3

python -m causure team-store-policy-put `
  C:\CausureData\team.sqlite3 `
  .\team-access-policy.json

python -m causure team-store-head `
  C:\CausureData\team.sqlite3 `
  --tenant-id tenant-acme
```

Schema version 3 adds the immutable investigation index. Running `team-store-init` or
calling `SQLiteTeamStore.initialize()` performs an additive migration in one
`BEGIN IMMEDIATE` transaction:

- a structurally valid version-1 database receives both the version-2 case index and the
  version-3 investigation index, then records `migrated_to_v2_at` and
  `migrated_to_v3_at`; and
- a structurally valid version-2 database receives the investigation index and records
  `migrated_to_v3_at`.

The migration does not rewrite historical policy, event, export, or case BLOBs.

Even though the migration is additive and transactional, drain writers and create a
tested non-overwriting backup before installing the new package. After migration, compare
the tenant policy bytes and head with protected records and exercise restore on a separate
path. An incompatible or partially modified earlier schema is rejected rather than
repaired heuristically.

A newly registered tenant returns sequence `0` and a null event digest. A higher policy
revision becomes active, while all earlier exact bytes remain retrievable:

```powershell
python -m causure team-store-policy-get `
  C:\CausureData\team.sqlite3 `
  --tenant-id tenant-acme `
  --policy-id access-acme `
  --revision 7 `
  --sha256 $recordedPolicySha256 `
  --byte-count $recordedPolicyByteCount `
  --output .\historical-policy-7.json
```

Supply SHA-256 and byte count together when resolving a recorded policy subject. The
output is written as the original bytes, not reparsed and reformatted JSON.

## Compare-and-swap append

Create the event with the Team domain command, then offer it to the authoritative store.
The explicit `--expect-empty` flag is required for a genesis event:

```powershell
python -m causure team-store-append `
  C:\CausureData\team.sqlite3 `
  .\audit-event-1.json `
  --expect-empty `
  --output .\tenant-head.json
```

For later events, read the protected store head, create an event whose predecessor is that
event, and pass the same digest as the expected compare-and-swap value:

```powershell
$head = Get-Content .\tenant-head.json -Raw | ConvertFrom-Json

python -m causure team-store-event-get `
  C:\CausureData\team.sqlite3 `
  --tenant-id tenant-acme `
  --sequence $head.sequence `
  --output .\authoritative-previous-event.json

python -m causure team-store-append `
  C:\CausureData\team.sqlite3 `
  .\audit-event-2.json `
  --expected-head-sha256 $head.event_sha256 `
  --output .\tenant-head-2.json
```

If another writer commits first, discard the uncommitted successor, reload the protected
head and predecessor event, and create a new event at the next sequence. Do not retry the
same stale event unchanged.

The lower-level Python API makes the expected value mandatory. Joined case publication
uses `append_case_record(event_bytes, case_record_bytes, ...)`, while candidate queue
mutation uses
`append_investigation_record(event_bytes, investigation_record_bytes, ...)`, under the
same CAS rule:

```python
from causure import SQLiteTeamStore

store = SQLiteTeamStore(r"C:\CausureData\team.sqlite3")
head = store.append_event(
    event_bytes,
    expected_head_sha256=current_head.event_sha256,
)
```

## Complete export and backup

The export authorization must be a fresh allowed `audit_export` decision for the requested
export ID and must bind the tenant's active policy:

```powershell
python -m causure team-store-export `
  C:\CausureData\team.sqlite3 `
  .\export-authorization.json `
  --export-id audit-export-17 `
  --output .\audit-export-17.json

python -m causure team-store-backup `
  C:\CausureData\team.sqlite3 `
  D:\ProtectedBackups\team-2026-07-29.sqlite3
```

The backup is a transactionally consistent database snapshot. Recovery is intentionally
an operator action: restore a backup to a new path, open it with `SQLiteTeamStore`, compare
every tenant head with an independently retained head or export, and only then redirect
service traffic. The command never overwrites an existing backup or live database.

Run backups on a tested schedule, copy them to access-controlled storage outside the
database host, encrypt them according to company policy, and exercise restore drills.
Creating one backup successfully is not disaster-recovery qualification.

## Security and deployment boundary

SQLite triggers constrain the normal API and ordinary SQL mistakes. A database owner can
drop triggers, replace the database, rewrite both events and heads, or delete the file.
The hash chain will not expose a rewrite when the same principal controls every anchor.
These safeguards are not an immutable-retention claim. Use immutable or WORM-capable
storage and independently anchor or sign heads when that threat is in scope.

Retention deadlines remain verified metadata. The store offers no event, policy, or export
delete API and its triggers reject ordinary deletion, but it does not make the underlying
filesystem enforce a retention lock, perform expiry, or prove regulatory preservation.

WAL requires all processes to access the database through a reliable local filesystem on
the same host. Do not place a production database on an SMB/NFS share, use a synced folder
such as OneDrive as database replication, or let multiple hosts open the same file. Move
to a qualified service database before multi-host deployment.

The initial complete-export format and local ledger are capped at 10,000 events per
tenant. The [trusted-identity HTTP boundary](team-http-api.md) now supplies closed
single-host routing, the [evidence console](team-evidence-console.md) reads bounded event
pages, and the [change-case dashboard](team-change-case-dashboard.md) reads latest
immutable case revisions in explicit snapshots. The
[investigation queue](team-investigation-queue.md) reads latest candidate-only revisions
and their audit events through the same snapshot boundary. Segmented exports, durable
distributed queue backpressure, a shared service database, and managed retention remain
later service layers.

See [ADR 0010](decisions/0010-use-sqlite-for-the-first-transactional-team-store.md),
the [Team service foundation](team-service-foundation.md), and the
[threat model](threat-model.md).
