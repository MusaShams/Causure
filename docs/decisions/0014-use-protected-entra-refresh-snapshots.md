# ADR 0014: Use protected Entra refresh snapshots and request-path reload

## Status

Accepted for the `0.4.0a6` single-host alpha.

## Context

The first Microsoft Entra adapter deliberately consumed an offline trust snapshot. That
kept network access and token-controlled URLs out of bearer validation, but a company
deployment still needed a concrete way to discover current signing keys, survive rollover,
and replace trust without exposing a partial file.

The refresh boundary is security-sensitive. OpenID metadata can redirect, environmental
proxy settings can silently reroute traffic, remote JSON can be oversized or ambiguous,
and Microsoft scopes individual signing keys with an `issuer` property. A failed refresh
must not destroy still-valid last-known-good trust. A stale or rolled-back file must not
silently extend trust.

## Decision

Add a separate, explicit `entra-trust-refresh` operation and a file-reloading verifier.

- Select every issuer, discovery URL, JWKS URL, Team tenant, API audience, client
  allowlist, accepted grant, token-lifetime limit, snapshot ID, and snapshot TTL from a
  closed protected configuration.
- Require exact tenant-specific v2.0 issuers and a JWKS URL on the same protected origin.
- Fetch only those derived/configured HTTPS URLs with platform certificate and hostname
  verification, no environment proxy, no redirects, bounded time and response size, and
  strict status/content metadata.
- Require strict duplicate-free UTF-8 JSON. Verify the discovery issuer and JWKS URI
  exactly, reduce only public RSA signing keys suitable for `RS256`, and scope each key by
  its exact or `{tenantid}`-templated Entra signing-key issuer.
- Fetch and validate all configured tenants before producing one snapshot.
- Atomically install only a valid, newer snapshot with the same `store_id`. Refuse to
  overwrite an invalid existing file.
- Let request workers reload a newer valid file while retaining a still-fresh
  last-known-good verifier after a missing, corrupt, cross-store, stale, or rolled-back
  candidate. The original snapshot expiration remains authoritative.
- Keep network retrieval out of the WSGI request path.

## Consequences

A single-host operator can bootstrap and periodically refresh tenant-partitioned Entra
trust without restarting the WSGI application. Failed network or candidate-file updates
leave the installed snapshot intact, and request workers never accept a partially written
snapshot.

The command is a one-shot primitive, not a scheduler. The host must run it at startup and
periodically with one writer, monitor age and failures, protect both configuration and
snapshot, and qualify its actual Entra tenants and network path. This release also does
not perform Microsoft's bounded refresh-on-unknown-`kid` behavior; unknown keys fail until
the next successful scheduled refresh. Rate limiting, a production HTTP host, live
rollover exercises, and independently protected anti-rollback storage remain deployment
work.
