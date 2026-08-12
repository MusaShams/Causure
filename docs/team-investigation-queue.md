# Team investigation queue

The Team investigation queue turns trace-identity clusters into explicit, attributable
work without treating telemetry as a failure report, causal explanation, or reason to
change an agent. An investigator chooses a cluster, opens a queue item, may attach more
candidate observations, and closes it with a typed resolution. The queue never creates a
change case automatically.

The JSON API is available under `/v1/team/investigations`. The script-free overview and
detail pages are `/team/investigations` and
`/team/investigations/{investigation_id}`. Every read still requires current Team
membership; every mutation requires the `investigator` role and trusted request-integrity
proof described in the [Team HTTP API guide](team-http-api.md).

## Candidate-only boundary

Opening or attaching an observation reparses the exact supplied investigation-fixture
bytes against the strict closed contract and selects one exact `cluster_id`. Every stored
record is fixed to:

```json
{
  "candidate_only": true,
  "gate_eligible": false,
  "causal_claims_inferred": false
}
```

The store retains the fixture media type, SHA-256, byte count, fixture and source subjects,
the selected trace fingerprint, bounded counts, allowlisted model/provider identifiers,
and optional observation times. It does **not** retain the fixture body, `trace_ref`,
`span_evidence_refs`, raw trace content, prompts, messages, or tool arguments. An exact
fixture subject lets an authorized external artifact store resolve and verify the source
without widening the dashboard's data boundary.

Queue membership is operational correlation only. It does not establish that an incident
occurred, that grouped observations share a cause, that a proposed intervention is
necessary, or that a change is safe. A linked change case must independently satisfy the
normal evidence and review contracts.

## Open an investigation

HTTP fixture bodies use canonical unpadded base64url. This PowerShell helper preserves the
exact file bytes:

```powershell
function ConvertTo-UnpaddedBase64Url([string] $Path) {
  [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path)).TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$fixtureBase64Url = ConvertTo-UnpaddedBase64Url `
  .\causure-investigation-fixture.json
```

Select the cluster ID from the parsed fixture and POST this closed body to
`/v1/team/investigations`:

```json
{
  "investigation_id": "investigation-refund-001",
  "fixture": {
    "base64url": "<canonical-unpadded-base64url>"
  },
  "cluster_id": "trace-<64-lowercase-hex-characters>",
  "title": "Unexpected refund-tool behavior",
  "priority": "high",
  "expected_revision": 0,
  "expected_head_sha256": null
}
```

`expected_revision` must be `0` for creation. `expected_head_sha256` is null only when the
tenant ledger is empty; otherwise use the current head returned by `/v1/team/summary` or a
prior mutation. The successful `201` response contains the immutable revision-1 record,
its audit event, and the new tenant head. Revision 1 is always `queued`, unassigned, and
contains exactly one observation.

The optional `retention_class_id` selects one class from the current protected policy.
Omitting it uses the policy default. The client cannot supply the tenant, actor, event ID,
decision ID, record revision, or timestamp.

## Attach an observation

POST another exact fixture and selected cluster to
`/v1/team/investigations/{investigation_id}/observations`:

```json
{
  "fixture": {
    "base64url": "<canonical-unpadded-base64url>"
  },
  "cluster_id": "trace-<64-lowercase-hex-characters>",
  "expected_revision": 1,
  "expected_head_sha256": "<current-tenant-head-sha256>"
}
```

An attachment creates one new record revision and appends exactly one immutable
observation. It cannot also change title, status, priority, assignment, or resolution.
Earlier observations must remain byte-for-byte equivalent, and one investigation is
limited to 128 observations.

## Transition and close queue state

POST the complete desired queue state to
`/v1/team/investigations/{investigation_id}/transition`:

```json
{
  "title": "Refund-tool cluster under investigation",
  "status": "investigating",
  "priority": "critical",
  "assigned_to": {
    "identity_provider": "entra:contoso",
    "subject_id": "alice-investigator"
  },
  "expected_revision": 2,
  "expected_head_sha256": "<current-tenant-head-sha256>"
}
```

`assigned_to` may be null. A non-null principal must currently have the `investigator`
role in this tenant; the service does not trust a client role claim. Each transition must
make a material title, status, priority, assignment, or resolution change.

Allowed status progression is:

| Current | Next |
| --- | --- |
| `queued` | `queued`, `investigating`, `blocked`, or `closed` |
| `investigating` | `investigating`, `blocked`, or `closed` |
| `blocked` | `blocked`, `investigating`, or `closed` |
| `closed` | Terminal; no successor is accepted |

A closed item requires exactly one resolution:

| Resolution | Required linkage | Meaning |
| --- | --- | --- |
| `change_case_opened` | `linked_case_id` | References an existing case in the same tenant |
| `duplicate` | `duplicate_of` | References an existing canonical, non-duplicate investigation |
| `not_a_failure` | None | Investigation found no qualifying failure |
| `no_change_required` | None | A failure may exist, but no agent change is justified |
| `insufficient_evidence` | None | Available evidence cannot support a stronger conclusion |

An investigation cannot duplicate itself, duplicate chains are rejected, and linkage
fields are forbidden for incompatible resolutions. Closure is an explicit investigator
decision, not an inferred cluster label.

## Concurrency, atomicity, and reads

Every mutation supplies both the expected investigation revision and expected tenant
head. A stale value returns `409`; reload the detail and tenant head, reconsider the
desired change, and submit a newly based request. Do not blindly retry a stale body.

The exact new record bytes and one authorized successful `investigation_write` event are
inserted with the head advance in one SQLite transaction. The event payload subject must
match those record bytes. A bad fixture, invalid successor, missing link target, policy
race, or head race leaves no record, event, or head advance. Unauthorized mutation
attempts record only a minimized digest-bound denial event, not the supplied fixture or
title.

`GET /v1/team/investigations` returns only the latest revision for each investigation and
supports strict `limit`, exclusive `before_sequence`, `status`, and `priority` query
parameters. Status and priority filters are applied after latest-revision selection, so a
closed item cannot reappear as an older open revision. The JSON and HTML detail routes
return the latest revision and its publishing event.

## Contracts and limits

The committed closed contracts are:

- [investigation record](../schemas/team-investigation-record.schema.json)
- [open request](../schemas/team-http-investigation-open-request.schema.json)
- [observation request](../schemas/team-http-investigation-attach-request.schema.json)
- [transition request](../schemas/team-http-investigation-transition-request.schema.json)
- [page response](../schemas/team-http-investigation-page.schema.json)
- [detail response](../schemas/team-http-investigation-detail.schema.json)

Source fixtures are limited to 8 MiB at this boundary and retained record bytes to 1 MiB.
JSON is duplicate-key rejecting, UTF-8, closed to unknown fields, and bounded by the
general HTTP body limit. Titles are limited to 256 characters. The queue renderer escapes
all displayed values, emits no JavaScript or forms, and receives no raw fixture body.

## SQLite schema-version 3 upgrade

`SQLiteTeamStore.initialize()` and `team-store-init` upgrade a structurally valid store in
one `BEGIN IMMEDIATE` transaction:

- version 1 receives the additive case and investigation indexes and records both
  `migrated_to_v2_at` and `migrated_to_v3_at`;
- version 2 receives the additive investigation index and records
  `migrated_to_v3_at`; and
- existing policy, event, export, and case BLOBs are not rewritten.

Drain writers, make a tested non-overwriting backup, and exercise restore on a separate
path before upgrading. An incompatible or partially modified schema fails closed rather
than being repaired heuristically.

SQLite remains a single-host pilot store, not WORM retention or an independent audit
anchor. Stable titles, actor IDs, source digests, model/provider identifiers, counts, and
timestamps may still be sensitive even without raw traces. Redact before fixture
generation, restrict tenant membership, keep source fixtures in a least-privilege artifact
store, and independently authenticate or attest them when producer provenance matters.

See [ADR 0020](decisions/0020-bind-candidate-clusters-to-explicit-investigation-queues.md)
for the design decision and the [threat model](threat-model.md) for remaining deployment
requirements.
