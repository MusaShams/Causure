# ADR 0012: Render bounded event summaries in the first dashboard

- Status: Accepted
- Date: 2026-07-29

## Context

The trusted-identity API is usable by an integration, but company reviewers also need a
human-readable operational surface. A browser dashboard can easily create new risks by
loading payload bodies, duplicating authorization in JavaScript, exposing unbounded tenant
history, or rendering a policy/event from different database moments.

The broader product vision eventually needs change-case evidence, causal hypotheses,
approvals, and canary outcomes. Those records do not yet share one durable service model.

## Decision

Build the first console as a server-rendered, read-only view of bounded Team event
summaries.

- Use the same typed trusted identity and current-policy membership check as the JSON API.
- Read active policy, current head, and the newest event page in one SQLite transaction.
- Cap a page at 100 and use an exclusive sequence cursor for older events.
- Return/render audit metadata and payload content subjects, never payload bodies.
- Escape every displayed value, ship no JavaScript or forms, and use a restrictive
  Content Security Policy with a same-origin static stylesheet.
- Keep the complete exact event and audit export as the forensic contracts; the HTML page
  is not a signed or independently verifiable artifact.
- Describe this as an initial evidence console rather than claiming the full
  change-case-centric dashboard is complete.

## Consequences

- A company can inspect tenant activity immediately after embedding the WSGI application
  behind its authentication middleware.
- JSON and HTML consumers share one application authorization and pagination path.
- The browser never receives raw acted-on payloads through this feature.
- The view is useful for operations and audit navigation but cannot yet explain why a
  proposed harness change was causally justified.
- Search, filtering, cross-tenant views, live updates, mutation controls, and full
  change-case drill-down remain later work.

## Alternatives considered

- **Build a client-side single-page application first.** Rejected because it adds a
  separate token/data flow and larger dependency/supply-chain surface before the service
  model requires it.
- **Render complete event documents or payload bodies.** Rejected because the summary
  task needs metadata/content subjects, not sensitive evidence content.
- **Load policy, head, and events through separate reads.** Rejected because a reviewer
  could see mixed membership and ledger states during concurrent policy or event changes.
- **Call this the completed evidence dashboard.** Rejected because the original product
  workflow also requires durable change cases, causal evidence, approvals, and deployment
  outcomes.
