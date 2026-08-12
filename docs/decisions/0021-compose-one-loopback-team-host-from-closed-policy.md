# ADR 0021: Compose one loopback Team host from closed policy

- Status: Accepted
- Date: 2026-08-03
- Release: 0.4.0a13

## Context

The Team store, application, Entra verifier, managed refresh lifecycle, and admission
middleware existed as separate security-sensitive primitives. A company could assemble
them, but an omitted wrapper, wrong middleware order, mutable dependency, public bind, or
trusted forwarding header could silently weaken the boundary. The project needed one
usable single-host path without implying that a local SQLite process is a qualified
multi-host platform.

## Decision

ProofBeforePatch will ship `team-serve` and `team_host.py` as one closed, single-process
composition boundary.

1. A duplicate-rejecting versioned JSON document supplies every database, server,
   identity-refresh, and admission field. Unknown fields, relative/colliding paths, and
   inconsistent limits fail closed.
2. The Entra refresh configuration is bound by exact byte count, SHA-256, and `store_id`
   before database initialization. The writable trust snapshot remains bound by its
   `store_id`, not a frozen digest, because managed refresh must replace it atomically.
3. The only server is exact Waitress `3.0.2`, installed through the `service` extra. It may
   bind only to canonical `127.0.0.1` or `::1` and asserts an external `https` scheme for a
   required trusted same-host edge.
4. Waitress trusts no proxy and no forwarding header. The edge must strip those headers,
   and the launcher clears them again. The application never derives scheme, tenant,
   identity, role, or source partition from client-controlled forwarding metadata.
5. Middleware order is fixed as process-local admission control, Entra bearer validation,
   then the Team WSGI application. Excess traffic is rejected before bearer parsing.
6. One `ManagedEntraAccessTokenVerifier` refreshes synchronously at startup, owns one
   bounded background worker, and closes through a context-managed server lifecycle.
7. Threads, connections, backlog, idle channel timeout, header bytes, and application body
   bytes are bounded. Tracebacks and channel request lookahead are disabled.

## Consequences

- Operators receive one tested command and schema instead of maintaining security-critical
  composition code.
- A config or dependency drift fails startup rather than silently changing host behavior.
- The loopback hop and local process boundary are trusted. The edge remains responsible
  for TLS, public host policy, complete deadlines, aggregate limits, source identity, and
  log redaction.
- Default per-source admission is inappropriate behind a same-host proxy because every
  caller normally has the edge's `REMOTE_ADDR`; the guide recommends the global bucket
  unless a reviewed socket-derived resolver exists.
- This launcher intentionally runs one process on one host. Same-host multi-process
  election, multi-host refresh/storage, service-manager packaging, live Entra testing,
  immutable retention, and disaster recovery remain separate qualification work.

## Alternatives considered

- **Document manual WSGI composition only.** Rejected because middleware order, shutdown,
  and server hardening would remain easy to omit.
- **Bind publicly and terminate TLS in the Python process.** Rejected because certificate
  lifecycle and public edge controls belong to established organizational infrastructure.
- **Trust `X-Forwarded-*` from loopback.** Rejected because Waitress can promote proxy
  headers into WSGI state; fixed trusted state and no forwarded-header trust are simpler
  to audit.
- **Launch coordinated multi-process refresh workers.** Deferred because this command is a
  deliberately bounded one-process product surface; process managers and multi-host
  topology require separate lifecycle and capacity qualification.
