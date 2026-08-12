# ADR 0011: Require typed host identity at the Team HTTP boundary

- Status: Accepted
- Date: 2026-07-29

## Context

The transactional Team store makes a single-host pilot possible, but a network boundary
introduces identity-confusion and tenant-confusion risks. A library cannot safely infer
which proxy authenticated a request, which header was stripped, whether a bearer token was
validated for the correct issuer/audience, or whether a cookie-backed POST passed CSRF
checks.

Accepting a tenant, role, decision ID, event ID, or timestamp in the JSON request would
also let a caller cross a security boundary the domain model deliberately keeps
server-owned.

## Decision

Add two framework-neutral layers:

1. `TeamApplicationService` accepts an exact `AuthenticatedTeamIdentity`, derives roles
   only from the active protected policy, creates IDs/timestamps server-side, and uses the
   SQLite store's compare-and-swap and active-policy checks.
2. `TeamWSGIApplication` exposes a closed JSON API but does not authenticate credentials.
   It accepts identity only through the
   `proofbeforepatch.authenticated_team_identity` WSGI extension populated by trusted
   hosting middleware.

State-changing requests additionally require the exact boolean WSGI extension
`proofbeforepatch.request_integrity_verified`. The hosting middleware sets it only after
validating the deployment's bearer request or cookie/session plus CSRF requirements.

Raw `Authorization`, `REMOTE_USER`, tenant, and role headers are never interpreted by the
application. Event reads check current membership before exposing event existence.
Application writes require that the authorization's policy is still active when the event
and head commit, closing policy-revocation races.

## Consequences

- The application can be embedded behind company-specific SSO without coupling the core
  to one identity provider or web framework.
- Client-controlled identity/tenant/role claims cannot silently become trusted context.
- The host adapter becomes an explicit security-critical component that must be reviewed
  and tested in its real proxy and identity-provider topology.
- This repository does not yet provide a turnkey hosted service. Operators still need a
  production WSGI host, credential-validation middleware, TLS, rate limits, protected
  storage, and deployment qualification.
- The action route records a claimed external result; it cannot prove or atomically
  perform the external side effect.

## Alternatives considered

- **Parse bearer tokens in the WSGI application.** Rejected for this layer because issuer,
  audience, tenant routing, key discovery, session policy, and claim mapping are
  organization-specific and require a maintained identity integration.
- **Trust reverse-proxy identity and role headers directly.** Rejected because a
  misconfigured proxy/header path can turn attacker-controlled text into authorization.
- **Accept tenant and role in JSON.** Rejected because both are authorization inputs, not
  client data.
- **Delay all HTTP work until a shared database and dashboard exist.** Rejected because
  the typed application boundary is independently useful for a controlled single-host
  pilot and gives later hosts one testable contract.
