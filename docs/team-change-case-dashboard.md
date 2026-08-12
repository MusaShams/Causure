# Team change-case dashboard

The change-case dashboard is the company-facing read model that joins the lifecycle of a
reviewed agent-system change without copying its raw evidence into the browser. It sits
beside the lower-level [tenant evidence console](team-evidence-console.md): the console
answers “what happened in the ledger?”, while this view answers “why was this change
proposed, what gates did it pass, and what happened afterward?”

## What the dashboard joins

One latest case revision can show:

1. a minimized change-case summary, causal hypotheses, intervention counts, prediction,
   and validation counts;
2. the deterministic review decision, recommended action, and finding statuses;
3. an exact Azure publication/verification summary for the TFVC target and build;
4. a point-in-time organizational approval or exception receipt; and
5. an exact canary comparison summary and bounded metric intervals.

Every stage retains its exact media type, SHA-256, and byte count. The record itself is
the exact payload subject of a successful, authorized audit event. The full source files
remain in the organization's protected artifact system.

## Routes

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/team/cases` | Server-rendered latest case revisions |
| `GET` | `/team/cases/{case_id}` | Server-rendered joined case detail |
| `GET` | `/v1/team/cases` | Bounded newest-first JSON case page |
| `GET` | `/v1/team/cases/{case_id}` | Latest joined JSON case detail |
| `POST` | `/v1/team/cases` | Authorize and atomically publish one revision |

Collection routes accept only `limit` and `before_sequence`. The limit defaults to 50 and
is capped at 100. The cursor is exclusive and refers to the publishing audit-event
sequence. Detail routes reject every query parameter.

The committed contracts are the [case record](../schemas/team-case-record.schema.json),
[publication request](../schemas/team-http-case-publication-request.schema.json),
[case page](../schemas/team-http-case-page.schema.json), and
[case detail](../schemas/team-http-case-detail.schema.json) schemas.

## Publish exact artifacts

The POST body carries canonical unpadded base64url for each exact file. A change case and
review result are required. Azure publication and verification must appear together; an
approval verification additionally requires that pair. A canary result is independent of
the Azure/approval pair but must bind the same canonical case, change reference, and exact
review-result digest.

This PowerShell example constructs the request without putting a tenant, role, revision,
event ID, decision ID, or timestamp in client input:

```powershell
function ConvertTo-Base64Url([string] $Path) {
  $value = [Convert]::ToBase64String([IO.File]::ReadAllBytes($Path))
  return $value.TrimEnd('=').Replace('+', '-').Replace('/', '_')
}

$head = Invoke-RestMethod `
  -Uri 'https://causure.example/v1/team/summary' `
  -Headers @{ Authorization = "Bearer $accessToken" }

$body = @{
  case_id = 'refund-tool-description-001'
  change_case = @{ base64url = ConvertTo-Base64Url '.\change-case.json' }
  review_result = @{ base64url = ConvertTo-Base64Url '.\review-result.json' }
  azure_publication = @{ base64url = ConvertTo-Base64Url '.\azure-publication.json' }
  azure_verification = @{ base64url = ConvertTo-Base64Url '.\azure-verification.json' }
  approval_verification = @{ base64url = ConvertTo-Base64Url '.\approval-verification.json' }
  expected_head_sha256 = $head.head.event_sha256
} | ConvertTo-Json -Depth 4 -Compress

Invoke-RestMethod `
  -Method Post `
  -Uri 'https://causure.example/v1/team/cases' `
  -ContentType 'application/json; charset=utf-8' `
  -Headers @{ Authorization = "Bearer $accessToken" } `
  -Body $body
```

For an empty tenant head, `expected_head_sha256` is `null`. A competing writer produces
`409 head_conflict`; reload the head and source state before creating a new request.
Never retry stale bytes blindly.

The trusted host must set the internal request-integrity signal only after validating its
bearer request or session/CSRF boundary. The bare WSGI application does not authenticate a
browser or infer that a header is trustworthy.

## Revision rules

- The first accepted record is revision 1; the server chooses every revision.
- The exact change case, exact review result, canonical case hash, review report subject,
  and derived base summaries cannot be replaced after their stage is recorded.
- Delivery and approval evidence can be added, not removed or rewritten.
- An unchanged canary summary must retain the same exact result subject.
- A continuing comparison must advance its look and exact result subject. A new
  comparison can follow only an outcome that requires rollback or new evidence.
- A successor must add or advance evidence and have a later publication timestamp.

These checks execute both in the application and inside the store transaction. The case
row and audit event either commit together or both roll back.

## Privacy and trust boundary

The minimized record does not retain raw incident behavior, source/evidence references,
intervention descriptions, report Markdown, approval justification, or observation
evidence references. It does retain human-readable title/change/review/prediction text,
stable actor IDs from verified approval receipts, TFVC/build identifiers, and hashes.
Treat those fields as internal sensitive metadata and redact personal/customer content
before publication.

Displayed Azure, approval, and canary data is point-in-time evidence, not a live grant or
deployment command. Before an integration publishes a revision, it must separately:

- run the Azure verification against the current protected TFVC build;
- verify approval signature, authority permissions, expiry, and fresh revocations at the
  action boundary;
- authenticate and authorize the publishing investigator through the host; and
- ensure the canary observation/policy came from protected systems and that independent
  rollback controls remain available.

The dashboard ingestion path does not fetch URLs or opaque references and does not contact
Azure, Entra, an approval authority, telemetry, or a deployment system.

## Store upgrade and operations

`SQLiteTeamStore.initialize()` automatically migrates a valid version-1 database through
the additive version-2 case index to current schema version 3 in one immediate transaction;
a valid version-2 store receives the additive investigation index without rewriting case
BLOBs. Before deploying the current package:

1. stop or drain writers;
2. create a non-overwriting online backup and copy it to protected storage;
3. run `team-store-init` once with the new package;
4. confirm readiness, policy bytes, ledger head, and an empty or expected case page; and
5. exercise restore on a separate path before returning traffic.

The database must remain on one reliable local filesystem. The case index has ordinary
SQL update/delete guards, but a database owner can remove them. Production retention,
multi-host writes, independent head anchoring, and disaster-recovery qualification still
require a stronger service/storage deployment. These controls are not WORM retention.

See [ADR 0019](decisions/0019-bind-minimized-case-index-to-audit-events.md), the
[Team HTTP guide](team-http-api.md), [SQLite store guide](team-sqlite-store.md), and
[threat model](threat-model.md). Candidate clusters remain separate in the
[investigation queue](team-investigation-queue.md) until an investigator explicitly links
a completed item to a case.
