# Trusted-identity Team HTTP API

Causure now supplies a framework-neutral application service and a closed WSGI
JSON/HTML boundary over `SQLiteTeamStore`. This is an integration-ready, single-host pilot
boundary for a company host that already has authentication middleware. It is not an
identity provider, an OIDC implementation, a production HTTP server, or a shared
multi-host deployment.

The optional `team-serve` command now provides one closed single-process composition of
the concrete Entra adapter, managed refresh, local admission, and pinned Waitress. It is a
loopback service behind a required trusted same-host HTTPS edge, not a replacement for the
edge or a production qualification. See the
[single-host Team service launcher](team-service-hosting.md) and its
[closed host schema](../schemas/team-host-config.schema.json). Windows pilots can place
that same launcher under the [native SCM adapter](team-windows-service.md).

The boundary is deliberately split in two:

1. `TeamApplicationService` accepts only an `AuthenticatedTeamIdentity`, resolves current
   roles from the active protected tenant policy, supplies server IDs and timestamps, and
   performs compare-and-swap state transitions.
2. `TeamWSGIApplication` handles closed HTTP routes, JSON, and read-only HTML, but it never parses
   `Authorization`, `REMOTE_USER`, tenant headers, or role headers.

`EntraTeamIdentityMiddleware` is an optional concrete implementation of the first hosting
layer for Microsoft Entra v2.0 access tokens. The bare Team application remains
identity-provider neutral. See the
[Microsoft Entra bearer-host guide](team-entra-bearer-host.md) and its protected
[trust-store schema](../schemas/entra-trust-store.schema.json).

`TeamAdmissionControlMiddleware` is an optional outer process-local backstop. Place it
outside authentication so excess concurrency or rate is rejected before authorization
headers are parsed or signatures are verified.

The [Team HTTP action request schema](../schemas/team-http-action-request.schema.json)
describes the only client-controlled body that can record an action. The domain event,
authorization, export, and verification contracts remain separately versioned.
The joined case boundary has separate closed
[publication-request](../schemas/team-http-case-publication-request.schema.json),
[record](../schemas/team-case-record.schema.json),
[page](../schemas/team-http-case-page.schema.json), and
[detail](../schemas/team-http-case-detail.schema.json) contracts.
The candidate-only investigation boundary likewise has separate closed
[record](../schemas/team-investigation-record.schema.json),
[open](../schemas/team-http-investigation-open-request.schema.json),
[observation](../schemas/team-http-investigation-attach-request.schema.json),
[transition](../schemas/team-http-investigation-transition-request.schema.json),
[page](../schemas/team-http-investigation-page.schema.json), and
[detail](../schemas/team-http-investigation-detail.schema.json) contracts.

## Required hosting contract

A production host must put trusted authentication and request-integrity middleware in
front of the WSGI application. That middleware must:

- validate the credential using the organization's identity provider, including the
  expected issuer, audience, expiry, signature, and other deployment-required claims;
- derive a stable opaque identity-provider subject and select the tenant server-side;
- create the exact `AuthenticatedTeamIdentity` type and place it at
  `causure.authenticated_team_identity` in the WSGI environment;
- never copy a client-supplied tenant or role into that object;
- strip or overwrite identity-like headers at every untrusted proxy boundary;
- set `causure.request_integrity_verified` to the exact boolean `True` for a
  state-changing request only after it has validated the bearer-token request or enforced
  the deployment's cookie/session and CSRF protections; and
- keep raw credentials and sensitive claims out of application logs.

These lower-case, implementation-prefixed keys are WSGI server extension values, not HTTP
headers. [PEP 3333](https://peps.python.org/pep-3333/) permits server-defined environment
variables with a unique lower-case prefix. A client cannot authenticate by sending a
similarly named header.

Missing trusted identity produces `401` plus `WWW-Authenticate:
Causure-External`. A valid identity that lacks a current policy grant produces
`403`. This follows the authentication/authorization distinction in
[RFC 9110](https://www.rfc-editor.org/rfc/rfc9110.html).

## Constructing the application

The host constructs one store, application service, and WSGI callable:

```python
from causure import (
    SQLiteTeamStore,
    TeamApplicationService,
    TeamWSGIApplication,
)

store = SQLiteTeamStore(r"C:\CausureData\team.sqlite3")
store.initialize()

service = TeamApplicationService(store)
application = TeamWSGIApplication(service)
```

Pass `application` to a qualified production WSGI host and wrap it in the organization's
authentication/integrity middleware. Python's `wsgiref` package is useful as a WSGI
reference and test utility; it is not a production HTTP server for this deployment.
Policy provisioning remains a protected operator workflow through the store API or
`team-store-policy-put`; it is intentionally absent from this first network boundary.

For the bundled Entra adapter, parse a protected trust snapshot, build an
`EntraAccessTokenVerifier`, and pass the Team application through
`EntraTeamIdentityMiddleware`. The resulting outer callable must be the one exposed by the
WSGI host. The adapter adds bearer validation and trust readiness; it does not supply the
production server or automatic metadata/key refresh.

For the supported one-process path, `team-serve` performs that composition and owns the
managed refresh worker lifecycle. Its closed configuration fixes exact Waitress `3.0.2`,
canonical loopback, external `https` state, database/trust paths, refresh-policy subject,
and admission limits. It places admission outside Entra outside the Team application and
trusts no `Forwarded` or `X-Forwarded-*` header. The edge must be the sole intended
loopback caller and must terminate the real external TLS connection.

## Routes

| Method | Path | Authentication | Result |
| --- | --- | --- | --- |
| `GET` | `/healthz` | None | Process liveness and package version |
| `GET` | `/readyz` | None | Store/schema readiness; Entra trust/key readiness when wrapped |
| `GET` | `/` or `/team` | Current tenant member | Read-only server-rendered evidence console |
| `GET` | `/team/cases` | Current tenant member | Read-only latest change-case cards |
| `GET` | `/team/cases/{case_id}` | Current tenant member | Joined change-case detail |
| `GET` | `/team/investigations` | Current tenant member | Read-only latest investigation queue |
| `GET` | `/team/investigations/{investigation_id}` | Current tenant member | Candidate-only investigation detail |
| `GET` | `/team.css` | None | Non-sensitive console stylesheet |
| `GET` | `/v1/team/summary` | Current tenant member | Active policy metadata, caller roles, and tenant head |
| `GET` | `/v1/team/events` | Current tenant member | Bounded newest-first event-summary page |
| `GET` | `/v1/team/events/{sequence}` | Current tenant member | Exact stored audit-event bytes |
| `GET` | `/v1/team/cases` | Current tenant member | Bounded latest case-revision page |
| `GET` | `/v1/team/cases/{case_id}` | Current tenant member | Latest joined case detail |
| `GET` | `/v1/team/investigations` | Current tenant member | Bounded latest investigation-revision page |
| `GET` | `/v1/team/investigations/{investigation_id}` | Current tenant member | Latest investigation detail |
| `POST` | `/v1/team/actions` | Current identity plus request-integrity proof | CAS-recorded allowed, failed, or denied action |
| `POST` | `/v1/team/cases` | Investigator plus request-integrity proof | Atomic case revision and audit event |
| `POST` | `/v1/team/investigations` | Investigator plus request-integrity proof | Open an atomic candidate-only queue record |
| `POST` | `/v1/team/investigations/{investigation_id}/observations` | Investigator plus request-integrity proof | Attach one fixture cluster atomically |
| `POST` | `/v1/team/investigations/{investigation_id}/transition` | Investigator plus request-integrity proof | Transition or close queue state atomically |
| `POST` | `/v1/team/audit-exports` | Policy administrator plus request-integrity proof | Exact persisted complete audit-export bytes |

Only `/`, `/team`, `/team/cases`, `/team/investigations`, `/v1/team/events`,
`/v1/team/cases`, and `/v1/team/investigations` accept the strict `limit` and
`before_sequence` pagination query described in the
[evidence-console guide](team-evidence-console.md); every other route rejects query
parameters. Investigation collections also accept one strict `status` and `priority`
filter. POST requests require an exact decimal `Content-Length`, UTF-8
`application/json`, a body no larger than 24 MiB, no duplicate JSON keys, and no unknown
fields. Responses include `Cache-Control: no-store`, content-sniffing/framing/referrer
protection, and a restrictive Content Security Policy.

### Record an action

The action route never accepts a tenant, role, decision ID, event ID, or timestamp. Those
values come from trusted hosting context, active policy, or the server:

```json
{
  "action": "investigation_write",
  "resource": {
    "type": "investigation",
    "id": "investigation-17"
  },
  "outcome": "succeeded",
  "payload": {
    "media_type": "application/json",
    "base64url": "eyJzdGF0dXMiOiJvcGVuZWQifQ"
  },
  "expected_head_sha256": null
}
```

`expected_head_sha256` is `null` only for a tenant with no events. A subsequent writer
must use the current lowercase head digest from the summary or prior response. A stale
writer receives `409` and must reload before retrying.

Clients may report only `succeeded` or `failed`. The service derives `denied` from the
current protected policy, appends that denial to the same ledger, and returns `403` with
the recorded decision/event/head. The event stores a SHA-256 content subject for the
decoded payload; it does not copy payload bytes into the audit event.

This endpoint records the caller's claimed outcome. It does not perform or authorize the
external side effect described by that outcome. The trusted integration that owns the
investigation, policy, approval, or evidence operation must order its own action and audit
recording deliberately, handle partial failure, and avoid claiming success before the
side effect is known. Causure can make the claim attributable and tamper-evident;
it cannot prove an external system actually did what the payload says.

### Publish a joined change-case revision

The case route accepts an exact change case and review result as canonical unpadded
base64url. Azure publication and verification are an optional inseparable pair. Approval
verification requires that pair, while an optional canary result must bind the same
canonical case, change reference, and exact review-result digest. The route accepts no
tenant, role, revision, event/decision ID, or timestamp.

An allowed investigator request derives a minimized record, validates every supplied
cross-artifact binding, and inserts that record with its successful `investigation_write`
event in one transaction. The event payload subject matches the exact record bytes. A bad
revision or competing head leaves no partial event, case row, or head advance. A current
member without the investigator grant receives a recorded denial event and `403`, but no
case record.

The case index retains bounded summaries and exact artifact subjects, not raw incident
behavior, evidence references, report Markdown, approval justification, or canary
observation evidence. Delivery and approval may be added once; continuing canary looks
must advance prospectively and bind a new exact result. See the
[change-case dashboard guide](team-change-case-dashboard.md) for the PowerShell request,
revision rules, and store-upgrade procedure.

Azure and approval fields are point-in-time receipts. The publishing integration must run
current Azure/build, signature/authority, expiry, and revocation checks before submitting
them. This ingestion route does not contact Azure, an approval service, telemetry, or a
deployment controller and does not turn a receipt into a live authorization.

### Investigate candidate trace clusters

The investigation routes accept exact, canonical unpadded base64url fixture bytes plus an
explicit selected cluster. Opening always creates one unassigned `queued` observation.
Later revisions either append exactly one immutable observation or make one material
title/status/priority/assignment/resolution transition; a single revision cannot do both.

Every record remains `candidate_only`, non-gate-eligible, and free of inferred causal
claims. The Team store retains exact fixture subjects and bounded cluster summaries, not
the fixture body, trace references, span evidence references, prompts, messages, or tool
arguments. Closing requires a typed resolution. `change_case_opened` and `duplicate`
links must resolve inside the same tenant, and a non-null assignee must currently be an
investigator.

The client supplies the expected current investigation revision and tenant-head digest.
The exact successor record, its authorized successful `investigation_write` event, and
the head advance commit or roll back together. A denied request records a minimized
digest-bound denial event without retaining the supplied fixture or title. See the
[investigation-queue guide](team-investigation-queue.md) for complete bodies, transition
rules, resolution/linkage semantics, pagination filters, and schema-version 3 migration.

### Read events and export

Event reads first check membership against the current active policy, then distinguish a
missing sequence for an authorized member. This prevents an outsider from using the route
as an event-existence oracle.

The event collection route returns at most 100 newest-first summaries. Its active policy,
head, and event bytes come from one read transaction. It includes content subjects but
never payload bodies and uses an exclusive `next_before_sequence` cursor when older events
remain. The HTML console uses this exact application-service result rather than a separate
browser authorization/data path.

The export request body is exactly `{}`. The service creates its authorization decision,
export ID, and timestamp, verifies the full historical chain inside one store snapshot,
persists the exact bytes, and returns those stored bytes. An investigator receives `403`
with the denied export authorization; an allowed policy administrator receives `201`.

## Process-local admission control

The admission wrapper defaults to:

- 64 non-blocking active-request slots;
- a global bucket of 600 requests per 60 seconds;
- a per-source bucket of 120 requests per 60 seconds;
- at most 4,096 tracked source keys; and
- idle-source pruning after 600 seconds.

A slot remains owned until the WSGI response iterable finishes, raises, or is closed.
Rate and source state use a monotonic clock. A backward/invalid clock or invalid trusted
source resolver fails closed with `503 admission_control_unavailable`; a full semaphore
returns `503 server_busy`; and an empty token bucket returns `429 rate_limited`. Every
admission response is generic, non-cacheable, includes bounded `Retry-After`, and never
echoes a credential or source key.

The default source resolver normalizes `REMOTE_ADDR` as an IP address. It intentionally
ignores `Forwarded`, `X-Forwarded-For`, and every other HTTP header. Behind a proxy, either
accept conservative proxy-wide grouping or pass a custom resolver that reads only
authenticated connection metadata set by trusted server code. Never configure the WSGI
server or resolver to copy an untrusted forwarding header.

Source tracking is capped and least-recently-used entries can be evicted, so the
per-source bucket is a fairness control. The global bucket is the hard process-local
ceiling. `/healthz` bypasses admission for liveness. `/readyz` bypasses traffic capacity
to avoid attack-driven self-eviction, but validates the admission clock before delegating
to store and identity readiness.

Each WSGI worker has independent buckets and concurrency slots. Multiply the configured
values by the maximum worker count when estimating host capacity. These controls do not
bound TCP connections, slow request bodies, work performed by a reverse proxy, or traffic
across hosts. Keep authoritative distributed rate/concurrency and body/deadline controls
at the trusted edge. Monitor the wrapper's bounded `status` counts without logging source
keys.

See [ADR 0017](decisions/0017-add-preauthentication-admission-control.md) for the ordering
and trust decision.

## Error and retry behavior

- `400`: closed-contract, encoding, query, or client-value failure.
- `401`: trusted authentication context is absent; the Entra wrapper also uses this for
  an invalid bearer token.
- `403`: membership/action denial or missing request-integrity proof; the Entra wrapper
  also uses this for an authenticated client with insufficient API grant.
- `404`: route not found, or an authorized member requested a missing event, case, or
  investigation.
- `405`: method rejected; the response includes `Allow`.
- `409`: stale head or another semantic state conflict.
- `411`, `413`, `415`: missing length, oversized body, or unsupported media type.
- `429`: the outer admission token bucket rejected the request before authentication.
- `503`: the store or wrapped identity trust is unavailable; responses include a bounded
  `Retry-After`. The outer admission layer also uses this for concurrency saturation or
  an invalid admission clock/source integration.
- `500`: invalid trusted middleware/server integration or an unexpected internal fault.

Internal exception text is not returned. The WSGI error stream receives only a stable
generic line for an unexpected exception.

## Pilot deployment checklist

- Terminate TLS only at a trusted edge and preserve the authenticated request signal to
  the WSGI process over a protected hop.
- Use one application host and a reliable local filesystem for SQLite. Do not place the
  database on SMB/NFS or synchronize it as replication.
- Configure edge body limits at or below the application maximum, connection/request
  timeouts, distributed rate limits, concurrency/backpressure, and abuse monitoring.
- Put `TeamAdmissionControlMiddleware` outside authentication as a local backstop; size
  every process-local limit against the worker count and monitor rejection/active counts.
- Trust `REMOTE_ADDR` only when the server derives it from the protected connection.
  Ignore untrusted forwarding headers or use a reviewed resolver over authenticated edge
  metadata.
- Keep access policies and the SQLite file outside the web root with least-privilege
  filesystem permissions.
- Protect backups off-host and rehearse restore to a new path.
- Log stable request/tenant/subject references only where policy permits; never log bearer
  tokens, cookies, payload bodies, or raw identity claims.
- Put retained audit artifacts into storage that really enforces required retention. The
  SQLite mutation guards are not WORM.
- Test authentication bypass, proxy header stripping, tenant confusion, CSRF/bearer
  integrity, stale writers, policy changes during a request, backup/restore, and denial
  audit behavior in the exact deployment.

Public HTTPS/signed-installer or orchestrator packaging, qualified distributed edge controls, a shared
service database, immutable object retention, additional OIDC/SSO adapters, and live Entra
deployment qualification remain later product layers. The optional native Windows service
supplies process supervision, not the missing edge or qualification. The bundled loopback
launcher is not a production HTTP server deployment merely because it uses a
production-quality WSGI implementation.
