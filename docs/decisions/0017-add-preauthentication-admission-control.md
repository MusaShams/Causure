# ADR 0017: Add process-local pre-authentication admission control

## Status

Accepted for the `0.4.0a9` single-host alpha.

## Context

The Entra adapter rejects malformed or invalid bearer tokens safely, but signature and
claim verification still consume CPU before a caller is authenticated. Documentation that
merely tells each deployment to add rate limits leaves middleware ordering, concurrency
cleanup, forwarded-header trust, and bounded source tracking unspecified.

ProofBeforePatch cannot provide an organization-wide rate limit from one WSGI process.
It can provide a deterministic local backstop that rejects excess work before bearer
parsing while keeping the deployment boundary honest.

## Decision

Add `TeamAdmissionControlMiddleware` as the outermost application wrapper.

- A non-blocking bounded semaphore rejects excess active work with `503 server_busy`.
  Ownership of the slot lasts until the returned WSGI iterable completes, raises, or is
  explicitly closed.
- A global token bucket is always enabled. An optional per-source bucket provides local
  fairness; both use a validated monotonic clock and return bounded `429 rate_limited`
  responses with `Retry-After`.
- The default source is a normalized `REMOTE_ADDR` socket value. The middleware never
  reads `Forwarded`, `X-Forwarded-For`, or another client header. A custom resolver is a
  trusted host integration and must derive a bounded opaque key only from protected server
  context.
- Source state is capped and idle-pruned with least-recently-used eviction. The global
  bucket remains the hard local ceiling when high-cardinality sources force eviction.
- `/healthz` bypasses admission for process liveness. `/readyz` bypasses traffic capacity
  so an attack cannot cause self-eviction, but it validates the admission clock before
  delegating to store and identity readiness.
- Error bodies are generic, non-cacheable, carry the existing browser hardening headers,
  add HSTS on HTTPS, and never include source keys, credentials, or exception text.
- Status exposes only active/tracked counts, admitted/rejected totals, and a stable
  integration error code.

## Consequences

Requests rejected by admission never reach authorization-header parsing, token
verification, Team authorization, or storage. Concurrent updates to token buckets and
counters are serialized, and a broken application or streaming response cannot leak a
concurrency slot.

Limits are process-local. A host with four workers has four independent buckets and
semaphores, so the configured aggregate can be up to four times a per-process value.
Source eviction also makes the per-source bucket a fairness control rather than an
identity or billing boundary. A trusted edge or API gateway must still enforce
organization-wide connection, body, request-rate, and distributed concurrency policy.

`REMOTE_ADDR` is trustworthy only to the extent that the WSGI server derives it from the
protected socket/proxy hop. Deployments behind a reverse proxy must either accept
proxy-wide grouping or inject a reviewed custom resolver from authenticated connection
metadata. Copying an untrusted forwarding header into `REMOTE_ADDR` defeats that
assumption.
