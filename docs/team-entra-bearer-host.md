# Microsoft Entra bearer host adapter

Causure `0.4.0a15` includes an optional WSGI middleware that validates Microsoft
Entra v2.0 access tokens and supplies the exact typed identity required by
`TeamWSGIApplication`. It is a resource-server adapter: it accepts a bearer token already
issued for the Causure API. It does not run an authorization-code flow, acquire
tokens, create browser sessions, provision app registrations, or contact Microsoft Entra
on a request path.

Install the optional dependencies with:

```powershell
python -m pip install "causure[entra]"
```

The extra pins PyJWT and its cryptography backend. The adapter follows Microsoft's
requirements to validate the intended API audience, tenant, subject, actor, signature,
issuer, and API grant. Microsoft explicitly warns against using mutable display claims
such as email, UPN, or preferred username for authorization. See
[Secure applications and APIs by validating claims](https://learn.microsoft.com/en-us/entra/identity-platform/claims-validation)
and the
[access-token claims reference](https://learn.microsoft.com/en-us/entra/identity-platform/access-token-claims-reference).

For the bundled one-process Team launcher, install `causure[service]` instead;
that extra includes these Entra dependencies plus exact Waitress `3.0.2`. See the
[single-host service guide](team-service-hosting.md).

For native Windows SCM supervision, use `causure[windows-service]` and follow the
[Windows service guide](team-windows-service.md). SCM running is not Entra readiness; the
trusted edge must still gate traffic on `/readyz`.

## Trust snapshot

The middleware consumes a protected, closed
[Entra trust-store contract](../schemas/entra-trust-store.schema.json). It never fetches a
URL selected by a token and never accepts tenant, audience, issuer, client, scope, role, or
key configuration from an HTTP request.

Each tenant entry binds:

- one canonical Entra directory tenant ID to one Causure Team tenant ID;
- the exact tenant-specific HTTPS v2.0 issuer and API client-ID audience;
- an allowlist of client application IDs;
- accepted delegated API scopes and/or app-only application roles;
- a deployment-selected maximum token lifetime; and
- one or more RSA `RS256` signing keys, each selected by `kid` only inside that tenant.

The snapshot also carries `refreshed_at` and `expires_at`. Its validity window must be
positive and no longer than 24 hours. Readiness and protected requests fail closed after
expiry or when the snapshot is implausibly future-dated.

An abbreviated document looks like:

```json
{
  "schema_version": "1.0",
  "store_id": "entra-production",
  "refreshed_at": "2026-07-29T11:00:00Z",
  "expires_at": "2026-07-29T23:00:00Z",
  "tenants": [
    {
      "entra_tenant_id": "11111111-1111-4111-8111-111111111111",
      "team_tenant_id": "tenant-acme",
      "issuer": "https://login.microsoftonline.com/11111111-1111-4111-8111-111111111111/v2.0",
      "audience": "33333333-3333-4333-8333-333333333333",
      "allowed_client_ids": [
        "44444444-4444-4444-8444-444444444444"
      ],
      "accepted_delegated_scopes": [
        "Causure.Access"
      ],
      "accepted_application_roles": [
        "Causure.Service"
      ],
      "max_token_lifetime_seconds": 7200,
      "keys": [
        {
          "kid": "tenant-key-id",
          "kty": "RSA",
          "use": "sig",
          "alg": "RS256",
          "n": "<canonical unpadded base64url RSA modulus>",
          "e": "AQAB"
        }
      ]
    }
  ]
}
```

The committed schema describes shape; `parse_entra_trust_store_bytes` also enforces
cross-field semantics that JSON Schema cannot express, including the issuer/tenant
binding, refresh window, canonical base64url integers, RSA strength, unique tenants,
unique per-tenant `kid` values, and at least one accepted grant.

## Protected discovery and key refresh

The one-shot trusted refresher uses a closed
[refresh configuration](../schemas/entra-refresh-config.schema.json) that selects every network
location and every authorization value before the process starts. Begin with the synthetic
[example configuration](../examples/team/acme-entra-refresh.json), replace every ID and
grant with the reviewed values for the deployment, then keep the resulting file writable
only by its configuration administrators and refresher identity.

Bootstrap or update the snapshot with:

```powershell
causure entra-trust-refresh `
  C:\CausureConfig\entra-refresh.json `
  C:\CausureConfig\entra-trust.json `
  --timeout-seconds 10
```

The command:

1. derives each discovery URL from an exact tenant-specific v2.0 issuer;
2. makes direct HTTPS `GET` requests with platform certificate and hostname verification,
   no environment proxy, no redirects, and bounded time and body sizes;
3. requires the discovery document's `issuer` and `jwks_uri` to equal the protected
   configuration;
4. parses duplicate-free UTF-8 JSON, rejects private JWK material, and reduces only public
   RSA verification keys compatible with `RS256`;
5. accepts a key only when its Microsoft `issuer` scope is the configured exact issuer or
   the same issuer after substituting the configured tenant into `{tenantid}`;
6. validates every configured tenant before constructing one complete snapshot; and
7. atomically installs only a valid snapshot whose `store_id` matches and whose
   `refreshed_at` advances the existing file.

This command is the CLI's explicit network boundary. It never follows a `jku`, `x5u`, or
other JOSE URL from a bearer token. It refuses to overwrite an invalid existing snapshot;
quarantine and investigate that file before an administrator performs a reviewed recovery.
Run only one writer against a given output and use a local filesystem—not a network share
or synced-folder replication mechanism—for the atomic replacement boundary.

Microsoft recommends tenant-specific discovery, independently cached keys per tenant, a
refresh at startup, and periodic background refresh. Its current rollover guidance
recommends hourly refresh for a 24-hour key cache and also recommends a rate-limited
refresh attempt for an unfamiliar key. See
[Signing key rollover in the Microsoft identity platform](https://learn.microsoft.com/en-us/entra/identity-platform/signing-key-rollover)
and
[access-token issuer validation](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens#validate-the-issuer).
Either schedule the command at startup and hourly or use the managed single-process
lifecycle below. Alert on failure and snapshot age, and set `snapshot_ttl_seconds` long
enough to tolerate a bounded provider outage without exceeding 24 hours. The command
itself remains a one-shot primitive.

## Managed single-process lifecycle

`ManagedEntraAccessTokenVerifier` performs one synchronous startup refresh, then owns one
background worker. After success the worker refreshes hourly by default. After failure it
retries in five minutes while a still-fresh last-known-good snapshot remains usable.

If the startup fetch fails, the manager starts only when the existing local snapshot is
fresh and has the same `store_id` as the protected refresh configuration. If neither is
true, startup fails closed. Readiness also fails if the manager was not started, was
closed, or its worker stopped unexpectedly. Before installation, every managed candidate
also passes the verifier's clock, dependency, freshness, and RSA-key readiness checks.

An unfamiliar `kid` reached after strict token parsing and selection of an already trusted
tenant can wake the worker. Concurrent events coalesce, and the global trigger cannot
start another refresh until at least five minutes after the preceding attempt began. The
request that triggered refresh is not retried: it receives the ordinary
`401 invalid_token` response. A later request can succeed after the worker atomically
installs and reloads a snapshot containing the new key. No HTTP request thread waits on
discovery or JWKS network I/O, and the token still cannot select a URL.

## Coordinated local-host lifecycle

`CoordinatedEntraAccessTokenVerifier` is the default lifecycle for a multi-process host
whose workers share one protected snapshot on the same machine and supported local
volume. Every process owns an atomic reloader and a small supervision thread. Exactly one
process obtains a non-blocking OS file lock and creates the managed network refresher;
followers do not contact Entra during ordinary startup or verification.

When a follower reaches `signing_key_unknown` for an already trusted tenant, it uses
exclusive file creation to publish one bounded request marker. Concurrent signals
coalesce. The owner polls the marker and schedules the request through the managed global
five-minute cooldown, then consumes it. The triggering request still fails once and never
waits on network I/O. If Windows temporarily denies marker deletion while a follower's
creation handle is closing, the owner retries only consumption and does not schedule the
same marker twice.

If the owner exits, the OS releases its lock and one follower promotes itself, performs a
guarded startup refresh, and becomes the only writer. Ownership is checked before network
work and immediately before installation. A follower waits up to 30 seconds by default
for an owner that is still bootstrapping a usable first snapshot. It never falls back to
doing an unowned fetch.

Create and start each coordinated verifier after the WSGI worker process has forked.
Objects inherited from a parent process fail closed. All workers must use the same exact
snapshot, owner-lock, and request-marker paths, and the service identity must control their
parent directory. Never delete, rotate, or replace a live owner-lock file.

This is local file coordination, not a distributed lease. Do not use it across hosts,
Kubernetes pods with independent filesystems, network shares, distributed filesystems, or
synced folders. For those deployments, run the one-shot command from one external
scheduler and use `ReloadingEntraAccessTokenVerifier` in request workers, or supply a
separately reviewed distributed coordinator.

See [ADR 0016](decisions/0016-use-local-file-election-for-entra-refresh.md) for the exact
ownership scope and rejected distributed-lease claim.

## Constructing the WSGI stack

For one process on one host, prefer the closed `team-serve` composition. It validates an
exact refresh-configuration subject, starts one `ManagedEntraAccessTokenVerifier`, places
admission outside Entra outside the Team application, binds only canonical loopback, and
closes the refresh worker when the server exits. Its Waitress configuration trusts no
proxy header; `wsgi.url_scheme` comes from fixed protected host policy and can be `https`
only because a trusted same-host HTTPS edge is required.

The following lower-level example remains useful when an organization owns a different
qualified WSGI lifecycle or needs same-host multi-process coordination:

```python
from pathlib import Path

from causure import (
    CoordinatedEntraAccessTokenVerifier,
    EntraTeamIdentityMiddleware,
    SQLiteTeamStore,
    TeamApplicationService,
    TeamAdmissionControlMiddleware,
    TeamWSGIApplication,
    load_entra_refresh_configuration,
)

store = SQLiteTeamStore(r"C:\CausureData\team.sqlite3")
store.initialize()

refresh_configuration = load_entra_refresh_configuration(
    Path(r"C:\CausureConfig\entra-refresh.json")
)
verifier = CoordinatedEntraAccessTokenVerifier(
    refresh_configuration,
    Path(r"C:\CausureConfig\entra-trust.json"),
    owner_lock_path=Path(r"C:\CausureConfig\entra-refresh-owner.lock"),
    refresh_request_path=Path(r"C:\CausureConfig\entra-refresh-request"),
)
verifier.start()

team = TeamWSGIApplication(TeamApplicationService(store))
authenticated = EntraTeamIdentityMiddleware(team, verifier)
application = TeamAdmissionControlMiddleware(authenticated)
```

Register `verifier.close` with the host's bounded shutdown hook. Pass `application`, not
the unwrapped `team` or `authenticated`, to the production WSGI host. The Entra
middleware:

- leaves `/healthz`, `/readyz`, and `/team.css` unauthenticated;
- adds trust/dependency checks to `/readyz`;
- requires `wsgi.url_scheme == "https"` on every protected route by default;
- reads only one `Authorization: Bearer <JWT>` credential;
- strips any preexisting trusted-identity/integrity environment values;
- validates the token and maps only `(tid, oid)` to the Team identity;
- removes the raw bearer value before calling the Team application;
- sets the exact request-integrity boolean because header-carried bearer authentication
  is not ambient cookie authentication; and
- adds HSTS to HTTPS responses unless the inner application already supplied it.

The outer admission wrapper acquires a non-blocking concurrency slot, then applies its
global and bounded per-source token buckets before the Entra middleware can parse
`Authorization`. It ignores forwarding headers by default. `/healthz` bypasses admission;
`/readyz` bypasses traffic capacity but validates the admission clock before continuing to
the Entra/store readiness checks. Its limits are independent in every WSGI process and do
not replace authoritative edge controls.

The coordinated verifier exposes bounded running/owner state, ownership-acquisition count,
request-pending state, stable coordination error, and the local owner's nested managed
status. The managed status includes in-progress state, completed attempt count, last
reason, stable refresh error, and last successful snapshot timestamp. Monitor both without
logging configuration, paths, or tokens. The underlying
`ReloadingEntraAccessTokenVerifier` adopts only a valid, newer snapshot with the same
`store_id`. A missing, corrupt, cross-store, stale, or rolled-back candidate leaves the
still-fresh last-known-good verifier in service. It never extends that verifier's original
`expires_at`.

Use exactly one `ManagedEntraAccessTokenVerifier` only for a genuinely single-process
host; `team-serve` enforces that intended topology by launching one Waitress process. For
a same-host multi-process server, instantiate one coordinated verifier per
post-fork worker against the same protected local paths; election ensures only one of
their private managers can write. For multiple hosts, run one external scheduler and give
request workers a `ReloadingEntraAccessTokenVerifier`, or provide reviewed distributed
ownership.

Do not call this adapter a qualified production Entra integration until the deployment
has exercised real startup, periodic, outage, rollover, first-request failure, recovery,
shutdown, abuse-control, and multi-process ownership behavior.

The adapter intentionally ignores `X-Forwarded-Proto`. A reviewed edge/WSGI integration
must set `wsgi.url_scheme` from protected connection metadata rather than copying an
untrusted forwarding header. The bundled launcher goes further: it trusts no proxy or
forwarding header and clears untrusted proxy headers at the Waitress boundary.

## Accepted token profiles

Only compact, signed Entra v2.0 JWT access tokens are accepted:

- JOSE `typ` is exactly `JWT`, `alg` is exactly `RS256`, and `kid` selects a configured
  tenant-local key.
- Embedded or remote key-selection headers (`jwk`, `jku`, `x5u`, `x5c`), critical
  extensions, and unencoded-payload mode are rejected.
- Header and claims JSON must be strict UTF-8 with no duplicate members; every compact
  segment must use canonical unpadded base64url.
- `iss`, scalar `aud`, `tid`, `oid`, `azp`, integer `iat`, integer `nbf`, integer `exp`,
  and `ver=2.0` are required.
- Signature, exact issuer, exact audience, tenant mapping, client allowlist, not-before,
  expiration, clock skew, and maximum token lifetime are checked.
- A delegated token must carry an accepted value in the space-delimited `scp` claim. If
  `idtyp` is present it must be `user`.
- An app-only token must omit `scp`, carry `idtyp=app`, and contain an accepted value in
  the `roles` array.

The principal becomes:

```text
tenant_id        = configured Team tenant ID
identity_provider = "entra:" + verified tid
subject_id       = verified oid
```

Email, UPN, display name, preferred username, groups, raw roles, and client-supplied
tenant headers never become Team identity or Team role assignments. Current Team roles
still come only from the protected active Team access policy.

## HTTP behavior

The adapter uses OAuth bearer response semantics from
[RFC 6750](https://www.rfc-editor.org/rfc/rfc6750.html):

- missing credentials: `401` with a bare `Bearer` challenge;
- malformed, expired, incorrectly signed, wrong-tenant, wrong-audience, or otherwise
  invalid token: `401` with `error="invalid_token"`;
- authenticated but disallowed client/scope/role: `403` with
  `error="insufficient_scope"`; and
- stale/future trust or missing crypto dependency: `503` with `Retry-After: 60`.

Bodies and challenges are generic and never echo a token or detailed verification
failure. Responses are non-cacheable. JWT algorithm and key selection follow the
cross-token-confusion guidance in
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html).

## Deployment qualification checklist

- Register a dedicated API audience; never accept Microsoft Graph or another API's token.
- Configure tenant-specific discovery for every allowed directory and test sovereign or
  external-tenant issuer forms used by the deployment.
- Restrict client IDs, delegated scopes, and app roles to least privilege.
- Configure the optional `idtyp` claim for app-only access and verify it appears as `app`.
- Protect the trust snapshot and refresher identity with least-privilege filesystem and
  network permissions; monitor refresh age and atomic reload failures.
- Run exactly one refresh owner per snapshot: one managed verifier for one process; one
  coordinated verifier per post-fork worker for same-host processes; or one external
  scheduler with reload-only workers for multi-host service. Register bounded shutdown.
- When using `team-serve`, run exactly one process, bind only its configured loopback
  address, keep the host configuration protected, and place a trusted same-host HTTPS
  edge in front of it. Do not add a prefork wrapper or enable forwarding-header trust.
- Keep configuration, snapshot, owner lock, and request marker in one protected local
  control-plane directory. Never use shared/synced storage or delete a live lock file.
- Monitor coordinated owner transitions, pending markers, managed refresh age/failures,
  and the rate-limited unknown-key trigger. Treat repeated wakeups as potentially hostile
  even though they coalesce.
- Terminate TLS at a trusted edge, protect the hop to WSGI, and derive
  `wsgi.url_scheme` from trusted server state.
- Redact `Authorization` at the edge, WSGI server, reverse proxy, APM, exception tracker,
  and access logs—not only inside the Team application.
- Put `TeamAdmissionControlMiddleware` outside the Entra middleware, size its per-process
  rate/concurrency limits against worker count, and keep distributed connection/body/rate
  controls at the trusted edge.
- Test real tokens for delegated users, guest users, service principals, consent changes,
  key rollover, unknown keys, expired trust, clock drift, client removal, and revoked
  grants.
- Review Team policy membership separately. A cryptographically valid token authenticates
  a principal; it does not itself grant a Causure Team role.

PyJWT and this adapter validate token structure and configured claims but cannot provide
instant token revocation, compromise detection, Conditional Access enforcement, or proof
that the protected trust snapshot was refreshed correctly. Those remain identity-provider
and deployment responsibilities.
