# ADR 0015: Use one owned Entra refresh worker with asynchronous unknown-key recovery

## Status

Accepted for the `0.4.0a7` single-host alpha.

## Context

The one-shot refresh command and atomic reloader provide safe primitives, but an operator
still has to arrange startup and periodic execution. Microsoft also recommends refreshing
when a token presents an unfamiliar signing-key ID, no more frequently than every five
minutes.

A synchronous unknown-key fetch can make an unauthenticated request wait on external
network I/O. Because the token has not yet passed signature, audience, actor, time, or
grant validation, an attacker who knows an allowed tenant ID could repeatedly exercise
that latency path. Multiple request threads must not launch duplicate refreshes or race as
snapshot writers.

## Decision

Add `ManagedEntraAccessTokenVerifier` as an explicit, single-process lifecycle owner.

- `start()` performs one synchronous all-tenant refresh. If it fails, startup may continue
  only with a fresh local snapshot whose `store_id` matches the protected refresh
  configuration.
- A managed candidate must pass verifier clock, dependency, freshness, and RSA-key
  readiness before it is installed.
- One daemon worker performs the next refresh hourly after success and retries a failed
  refresh after five minutes by default.
- The managed verifier delegates token validation to the atomic file reloader.
- Only a strict `signing_key_unknown` result reached after the existing parser has selected
  an already trusted tenant may request an early refresh.
- Unknown-key requests coalesce into one pending operation and cannot schedule another
  network attempt until at least five minutes after the preceding attempt began.
- The triggering request is not retried and receives the ordinary invalid-token response.
  The worker fetches only protected configured URLs; a later request can use the new key
  after a successful atomic install.
- Expose bounded, non-sensitive status: running/in-progress state, completed-attempt count,
  last reason, stable error code, and last successful snapshot timestamp.
- Require explicit `close()` or context-manager shutdown. Fail readiness if the lifecycle
  was not started, was closed, or its worker is no longer alive.

## Consequences

Single-process hosts gain managed startup, periodic rollover handling, failure retry, and
bounded unknown-key recovery without placing network latency in an unauthenticated request
thread. Existing last-known-good expiry and atomic rollback protections remain unchanged.

The first request carrying a legitimately new key can fail once. This is an intentional
availability/security tradeoff and differs from Microsoft's synchronous hot-path example.
The unknown-key trigger is still attacker-exercisable once per five-minute window, so
outbound requests and status must be monitored.

This class is one writer for one process. A multi-process or multi-host deployment must
elect a single refresh owner or keep using an external scheduler with reload-only workers;
it must not instantiate one manager per WSGI worker against the same file. Cross-process
coordination, jitter, production HTTP abuse controls, and live Entra qualification remain
future deployment work.
