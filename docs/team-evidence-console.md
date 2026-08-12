# Read-only Team evidence console

The first company-facing console is a bounded, server-rendered view of the authenticated
tenant's Team audit ledger. It makes the trusted-identity API inspectable without adding a
JavaScript application, a second authorization model, or browser-side access to raw
payloads.

This remains the initial operational evidence console and ledger view rather than the full
change-case dashboard itself. The joined dashboard is now a separate view documented in
the [change-case dashboard guide](team-change-case-dashboard.md); candidate triage is a
separate [investigation queue](team-investigation-queue.md). This console answers:

- Which tenant and active policy revision am I viewing?
- Which roles does the current policy assign to me?
- What is the authoritative ledger sequence and head digest?
- Which allowed, failed, and denied actions were recorded most recently?
- Who performed each action, against which resource, under which policy?
- What payload content subject and retention deadline are bound to each event?

It intentionally does not render the underlying change case, causal hypotheses,
intervention results, affected workflows, Azure review report, approval assertion, or
post-deployment canary comparison. Those minimized lifecycle summaries are joined at
`/team/cases`; this lower-level console stays payload-free and ledger-oriented.

## Routes

After trusted hosting middleware injects `AuthenticatedTeamIdentity`, open `/` or `/team`.
Both paths render the same read-only page. `/team.css` is a non-sensitive static
stylesheet; it contains no tenant data.

The machine-readable companion is:

```text
GET /v1/team/events?limit=50&before_sequence=321
```

Its committed response contract is the
[Team HTTP event-page schema](../schemas/team-http-event-page.schema.json).

`limit` defaults to 50 and must be from 1 through 100. `before_sequence` is an exclusive,
newest-first cursor. The response returns `next_before_sequence` only when older events
remain. Query parsing accepts only those two ASCII decimal fields, rejects duplicates and
unknown fields, and never accepts a tenant or subject selector.

## Consistency and authorization

One SQLite read transaction supplies:

1. the active tenant policy bytes;
2. the authoritative ledger head; and
3. at most `limit + 1` newest matching event rows.

The application resolves the caller's roles from that same policy snapshot before it
returns anything. An outsider receives `403` before learning whether events exist.
Returned summaries must be contiguous, newest-first, tenant-matched, digest-matched, and
cursor-consistent. The page never scans or returns more than 100 event summaries.

The protected head remains the current tenant head even when the user is paging through
older events. That lets a reviewer tell the difference between the page range and current
ledger state.

## Privacy and browser safety

The console renders audit metadata and content subjects only:

- event/decision IDs and digests;
- stable opaque principal IDs;
- action and resource identifiers;
- authorization result and reason;
- outcome and occurrence time;
- payload media type, byte count, and SHA-256; and
- policy and retention subjects.

Payload bodies are never loaded into the event-page model and are never rendered. Keep
personal data out of principal/resource IDs and media types even though output is HTML
escaped.

The renderer uses semantic HTML, no JavaScript, no forms, and an external same-origin
stylesheet. Responses deny framing, disable referrers and caching, disallow all content by
default, and permit styles only from the same origin. The layout is keyboard-readable,
printable, and responsive down to a 390-pixel viewport without horizontal overflow.

These controls reduce browser attack surface; they do not replace the authentication,
TLS, proxy, rate-limit, session/CSRF, and retention requirements in the
[Team HTTP deployment guide](team-http-api.md).

## Operational use

- Treat the console as an authenticated internal operational surface.
- Use opaque subject and resource IDs where possible.
- Keep the default page size unless a reviewer needs a narrower printable range.
- Use the exact-event API or a verified audit export for forensic preservation; the
  summary page is a view, not a signed artifact.
- Monitor `401`, `403`, invalid-query, store-busy, and internal-error rates without logging
  credentials or payload bodies.
- Test the console behind the exact production proxy/SSO topology, including tenant
  confusion, membership revocation, CSP headers, mobile layout, and paging.

The change-case dashboard binds minimized case, review, approval, and deployment outcomes
to these audit resources while preserving the same server-side tenant and
payload-minimization boundaries. Use this console or verified exports when the audit
sequence itself, rather than one change lifecycle, is the primary question.
