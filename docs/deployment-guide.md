# Deployment guide

Causure `0.4.0a18` is a public alpha. Start with the local CLI or GitHub review path. The
Team service, Windows service, and quota proxy are reference deployments for controlled
pilots, not a hosted multi-tenant platform.

## Choose a mode

| Mode | Use it for | Required infrastructure | Boundary |
|---|---|---|---|
| Local CLI | Demo, trace investigation, case creation, and evidence review | Python 3.11+ | Recommended first evaluation path |
| GitHub Action | Evidence-gated pull-request review | GitHub Actions and protected repository configuration | Publishes recommendations; never merges or deploys |
| Team service | Internal single-host API and read-only evidence surfaces | One trusted host, Waitress, SQLite, and a trusted HTTPS/authentication edge | Reference implementation; loopback only |
| Windows service | Native supervision of the single-host Team service | Qualified Windows image, pywin32, service identity, and edge configuration | Pilot packaging; unsigned |
| Quota proxy pilot | Bound OpenAI-compatible provider spending before connected evaluation | Docker, protected state, explicit TLS routes, and provider credentials | Non-streaming text reference; not a general billing platform |

## Recommended evaluation path

1. Install the release wheel and run `causure demo` offline.
2. Use `causure init`, `causure investigate`, and `causure case create` with a synthetic or
   sanitized OTLP/OpenInference export.
3. Exercise the GitHub workflow with synthetic cases in a non-production repository.
4. Qualify company replay and evaluator adapters against explicit time, cost, data, and
   execution boundaries.
5. Consider a Team or quota-proxy pilot only after the local evidence workflow is useful.

The [getting-started guide](getting-started.md) covers steps 1–2. The
[GitHub Action guide](github-action.md) covers step 3.

## Single-host Team reference

`causure team-serve` composes the Team API into one exact-version, loopback-only Waitress
process. It deliberately trusts no forwarding header and does not terminate public TLS.
Place it behind a trusted same-host edge that validates credentials, strips untrusted
identity headers, applies request limits, and injects only server-derived identity.

Read these guides before evaluating it:

- [Team service foundation](team-service-foundation.md)
- [Single-host service launcher](team-service-hosting.md)
- [Team HTTP API](team-http-api.md)
- [Microsoft Entra bearer host](team-entra-bearer-host.md)
- [SQLite store](team-sqlite-store.md)
- [Windows service adapter](team-windows-service.md)

Do not place the SQLite file on a network share or synchronized folder, run multiple service
processes against it, or describe its mutation guards as immutable retention.

## Provider-connected evaluation

Connected replay or evaluation must acquire a provider-backed quota lease before worker
launch. The included OpenAI-compatible controller/proxy and split-edge Docker pilot
demonstrate reservation, bounded credential flow, and settlement for the documented text
request surface.

See [OpenAI-compatible quota proxy](openai-compatible-quota-proxy.md) and
[quota pilot](openai-quota-pilot.md). Unmodeled billing surfaces, streaming, invoice
reconciliation, and production orchestrator qualification remain outside the current claim.

## Required production controls

A production deployment still needs controls that Causure does not currently ship as a
supported platform:

- a qualified shared relational authority and protected object storage;
- storage-enforced immutable or WORM retention and independent ledger anchoring;
- production TLS termination, secret management, edge rate limits, and observability;
- multi-host coordination, backups, disaster recovery, upgrades, and key rotation;
- generalized SSO onboarding and separation of producer, approver, and policy authority;
- an independent security review and qualification on the exact target environment.

The [threat model](threat-model.md) is authoritative for trust assumptions and residual
risks. The [productization roadmap](productization-roadmap.md) tracks the work required to
move from the current alpha to a supported enterprise deployment.
