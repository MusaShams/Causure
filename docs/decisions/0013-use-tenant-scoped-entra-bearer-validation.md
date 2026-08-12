# ADR 0013: Use tenant-scoped Entra bearer validation at the Team host boundary

## Status

Accepted for the `0.4.0a5` single-host alpha.

## Context

`TeamWSGIApplication` intentionally accepts only a typed trusted identity. That keeps raw
credentials, tenant selection, and identity-provider behavior outside the Team domain,
but companies still need a concrete adapter before they can exercise the boundary with
their identity platform.

Microsoft Entra access tokens require more than signature checking. A resource server must
bind audience, tenant, subject, actor, issuer, time, and permissions. Multi-tenant key
caches also need to keep identically named keys in separate issuer/tenant partitions.
Signing keys can roll without notice, while a token-controlled key URL would introduce
server-side request forgery and key-confusion risks.

## Decision

Supply an optional Microsoft Entra v2.0 bearer middleware in front of the existing Team
WSGI application.

- Accept only compact `JWT`/`RS256` access tokens for a configured API audience.
- Select protected trust by canonical `tid`, then select `kid` only inside that tenant.
- Bind the exact tenant-specific issuer, audience, client allowlist, token lifetime, and
  accepted delegated scopes/application roles in a closed trust snapshot.
- Use `(tid, oid)` as the stable identity and continue resolving Team roles solely from
  the active Team policy.
- Require `scp` for delegated tokens; require `idtyp=app` plus `roles` for app-only
  tokens. Validate `azp` in both profiles.
- Reject duplicate JSON members, noncanonical compact segments, remote/embedded JOSE key
  headers, algorithm substitution, stale trust, and mismatched token profiles.
- Use pinned PyJWT and cryptography packages for signature verification.
- Treat the bearer header as request-integrity evidence for the current request, remove it
  before invoking the Team application, and never translate identity-like HTTP headers.
- Keep metadata/JWKS retrieval out of the request path. Consume a tenant-scoped snapshot
  produced and atomically installed by a separate trusted refresher.

## Consequences

Companies can connect the Team API to Microsoft Entra without teaching the domain or HTTP
application to trust raw headers. The adapter has deterministic offline tests, bounded
inputs, RFC bearer challenges, tenant-partitioned rollover keys, and readiness failure
when trust is stale.

The snapshot is now a high-value protected policy input. This release supports multiple
current keys but does not implement discovery, automatic refresh, live revocation, token
acquisition, browser sessions, rate limiting, or a production WSGI host. A deployment must
add and qualify those controls before describing the integration as production-ready.

Future identity-provider adapters can produce the same `AuthenticatedTeamIdentity`
without changing Team authorization or storage, but they must define equally strict and
mutually exclusive credential profiles.
