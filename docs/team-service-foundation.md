# Team service foundation

The Team service foundation supplies the security-sensitive domain contracts beneath the
integration API, read-only evidence console, minimized full change-case dashboard, and
candidate-only investigation queue. It provides deterministic tenant authorization,
retention-bound audit events, complete audit exports, and verification receipts without
coupling the domain contracts to an HTTP framework or database.

The optional `SQLiteTeamStore` supplies exact historical persistence and a transactional
single-host ledger. It does not authenticate a user. It does not make local files
immutable. A hosted service must still put these contracts behind its own identity
provider, server-side tenant routing, and retention-enforcing object store.

`TeamApplicationService` and `TeamWSGIApplication` now supply that typed trusted-identity
integration boundary above the single-host store. They remain separate from company
credential validation and production hosting. The closed `team-serve` command now provides
one loopback-only, single-process Entra/Waitress composition, but still requires a trusted
same-host HTTPS edge and deployment qualification; see the
[Team HTTP API guide](team-http-api.md) and
[single-host service guide](team-service-hosting.md), the
[native Windows service guide](team-windows-service.md), and the
[evidence-console guide](team-evidence-console.md), plus the
[change-case dashboard guide](team-change-case-dashboard.md) and
[investigation-queue guide](team-investigation-queue.md).

## Authorization model

The service receives a stable identity-provider ID and subject ID from a trusted
authentication layer. It selects the tenant and current access policy server-side. Roles
are looked up from that protected policy; they are never accepted from a client request.

| Role | Granted actions |
| --- | --- |
| `investigator` | `evidence_read`, `investigation_write` |
| `policy_administrator` | `evidence_read`, `policy_write`, `audit_export` |
| `approver` | `evidence_read`, `approval_issue` |

Actions also have closed resource types. For example, `approval_issue` can address only an
`approval`, while `policy_write` can address only a `gate_policy`. An invalid pairing is a
malformed request, not a discretionary denial.

A protected policy snapshot has this shape:

```json
{
  "schema_version": "1.0",
  "tenant_id": "tenant-acme",
  "policy_id": "access-acme",
  "revision": 7,
  "effective_at": "2026-07-28T00:00:00Z",
  "default_retention_class_id": "audit-365",
  "memberships": [
    {
      "principal": {
        "identity_provider": "entra:contoso",
        "subject_id": "alice-investigator"
      },
      "roles": ["investigator"]
    }
  ],
  "retention_classes": [
    {
      "class_id": "audit-365",
      "minimum_days": 365
    }
  ]
}
```

The [committed access-policy schema](../schemas/team-access-policy.schema.json) is closed.
Membership principals and retention class IDs must be unique. The surrounding service
must make policy revisions monotonic and preserve historical exact bytes so old audit
decisions remain reconstructable.

A synthetic [Team access policy](../examples/team/acme-access-policy.json) and
[action payload](../examples/team/investigation-action.json) are available for local
integration tests.

Create a decision with:

```powershell
python -m causure team-authorize .\team-access-policy.json `
  --decision-id auth-investigation-17 `
  --identity-provider entra:contoso `
  --subject-id alice-investigator `
  --action investigation_write `
  --resource-type investigation `
  --resource-id investigation-17 `
  --output .\authorization.json
```

An allowed decision returns exit code 0. A denied decision is still written as structured
JSON and returns exit code 1. Invalid policy or request input returns exit code 2.

The decision binds the SHA-256 and byte count of the exact policy file. Reformatting or
otherwise replacing that file causes later authorization verification to fail, even when
its decoded fields look equivalent.

## Audit append

An audit event embeds its authorization decision and hashes the exact acted-on payload.
Raw payload content is not copied into the event. The caller records whether an authorized
action `succeeded` or `failed`; a denied decision can only produce a `denied` event.

```powershell
python -m causure team-audit-append `
  .\team-access-policy.json `
  .\authorization.json `
  .\action-payload.json `
  --payload-media-type application/json `
  --event-id audit-event-1 `
  --outcome succeeded `
  --output .\audit-event-1.json
```

For sequence two and later, pass the current tenant head:

```powershell
python -m causure team-audit-append `
  .\team-access-policy.json `
  .\authorization-2.json `
  .\action-payload-2.json `
  --payload-media-type application/json `
  --event-id audit-event-2 `
  --outcome failed `
  --previous-event .\audit-event-1.json `
  --output .\audit-event-2.json
```

The authorization decision must be no more than 15 minutes old. The event sequence,
tenant, time, predecessor digest, decision, outcome, payload subject, and retention
requirement are included in the canonical event hash.

The CLI computes a successor but does not own shared state. A hosted service must append
with an atomic compare-and-swap against the expected tenant head. If another writer wins,
the losing request must reload the head and create a new successor; it must not store a
fork.

## Complete export and verification

An export requires a separate allowed `audit_export` decision from a policy administrator.
Its resource ID must equal the export ID.

```powershell
$authoritativeHead = (
  Get-Content .\audit-event-2.json -Raw | ConvertFrom-Json
).event_sha256

python -m causure team-audit-export `
  .\team-access-policy.json `
  .\export-authorization.json `
  .\audit-event-1.json `
  .\audit-event-2.json `
  --export-id audit-export-17 `
  --authoritative-head-sha256 $authoritativeHead `
  --output .\audit-export-17.json

python -m causure team-audit-verify `
  .\team-access-policy.json `
  .\audit-export-17.json `
  --output .\audit-export-verification.json
```

The initial format deliberately requires a full, contiguous sequence beginning at one.
The head digest must come from the protected current tenant-ledger record, not from a
client assertion. That prevents an accidentally truncated prefix from being labeled as the
current complete export.
Verification rejects changed event content, a changed event hash, gaps, reordering,
duplicate event IDs, duplicate authorization decision IDs, cross-tenant events, a wrong
head, a shortened retention deadline, a changed access-policy file, or an unauthorized
export.

The export receipt binds the SHA-256 and byte count of the exact export file. It is audit
metadata, not a digital signature.

`team-audit-verify` must receive the exact historical policy bytes bound to the export
authorization. If the tenant has since advanced its policy revision, retrieve that
snapshot by the policy subject recorded in the export rather than substituting the new
policy.

Full-chain verification checks every event's structure, self-hash, tenant, sequence, and
embedded decision consistency. It does not fetch all historical policy snapshots.
Auditors that must reproduce every past role decision should resolve each event's recorded
policy subject from protected history and call `verify_team_audit_event` with that exact
snapshot.

## Transactional SQLite persistence

The [SQLite Team-store guide](team-sqlite-store.md) describes the local and single-host
persistence option. `team-store-policy-put` preserves exact policy revisions,
`team-store-append` performs an atomic compare-and-swap against the protected tenant head,
`team-store-export` creates an export at a transactionally stable complete head, and
`team-store-backup` creates a consistent online backup.

Schema version 3 stores exact minimized `TeamCaseRecord` and `TeamInvestigationRecord`
bytes. The application publishes each revision with its authorized successful
investigation event in one transaction. Latest case and investigation reads bind the
active policy, current head, record bytes, and event bytes to one snapshot; see the
[change-case dashboard guide](team-change-case-dashboard.md) and
[investigation-queue guide](team-investigation-queue.md).

The store rechecks each event against the exact historical policy it records and enforces
tenant-local event, decision, and export uniqueness. Database triggers prevent ordinary
updates, deletes, head rewinds, and policy rollback. These controls protect the supported
API and catch operator mistakes; a database owner can remove them, so they are not an
immutable-retention claim.

## Production boundary

Before exposing these operations through an API:

1. Authenticate the principal with organizational SSO and take the identity-provider
   subject from validated server-side claims.
2. Resolve the tenant from protected routing or membership state; never trust a
   client-selected tenant without an independent membership check.
3. Generate decision, event, and export timestamps from a trusted server clock; the CLI
   timestamp options exist for deterministic integration and testing.
4. Protect the SQLite database or replacement service database from unauthorized change,
   replacement, and rollback.
5. Keep SQLite on a reliable local filesystem on one host, or replace it with a qualified
   service database that preserves the same compare-and-swap behavior.
6. Store authoritative events and exports in append-only or WORM-capable storage and
   enforce every recorded retention deadline.
7. Rate-limit both allowed and denied requests, and ensure a denial flood cannot exhaust
   the audit store.
8. Anchor or sign export heads when auditors require producer authentication or
   non-repudiation in addition to tamper evidence.
9. Keep raw payloads in a separate least-privilege store; events should retain only their
   content subject unless policy explicitly requires more.
10. Reverify time-sensitive Azure/build, approval/revocation, and deployment facts at the
    action boundary; a stored dashboard receipt is point-in-time evidence, not live
    authorization.
11. If using `team-serve`, keep its protected configuration and three distinct absolute
    data/control paths access-controlled, run one process on canonical loopback, and put a
    trusted same-host HTTPS edge with aggregate deadlines/limits and token-log redaction in
    front of it.

See [ADR 0009](decisions/0009-bind-team-actions-to-tenant-policy-and-audit-chain.md) for
the design rationale and [the threat model](threat-model.md) for the remaining trust
assumptions.
