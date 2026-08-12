# ADR 0025: package a split-edge OpenAI-compatible quota pilot

- Status: accepted
- Date: 2026-08-09
- Release: 0.4.0a17

## Context

ADR 0024 supplied a conservative controller, WSGI proxy, and transactional quota ledger,
but deliberately stopped before a host, TLS edge, image, or orchestrator composition.
Companies could inspect the logic but still had to invent the security-critical deployment
boundary before trying it.

A single public listener would make the protected administrative lease API reachable from
the worker network. Putting the provider key in a worker-side proxy would collapse the
credential boundary. Trusting forwarding headers or using a mutable image tag would also
turn deployment convenience into an enforcement bypass.

## Decision

Ship a one-host Docker pilot with three non-root, read-only containers:

1. A quota core owns the provider key, admin token, fixed provider transport, Waitress host,
   and persistent SQLite volume. It joins only an internal backend and a dedicated
   provider-egress bridge.
2. A worker Caddy edge joins the fixed internal worker network and backend. It exposes only
   health, readiness, and `/v1/responses` over TLS.
3. An admin Caddy edge joins the backend and a loopback-published admin-control bridge. It
   exposes only health, readiness, and `/admin/v1/leases*` over TLS.

Fix `wsgi.url_scheme` to HTTPS at the core and trust no forwarding headers. Remove all
forwarding identity headers at both edges. Give neither edge the provider key, admin bearer
token, lease token, Docker socket, or provider-egress network.

Generate new protected state rather than editing it. Bind the generated host configuration
to exact quota bytes, import the provider key from a protected file, generate a separate
admin token, and issue a short-lived pilot server certificate from an ephemeral CA whose
private key is not retained.

Build from exact Python and Caddy image digests. Build the local project wheel offline,
pass its SHA-256 into a network-disabled core build, and verify the exact Waitress wheel
inside the image. Remove Caddy's inherited low-port file capability before running it with
all capabilities dropped and `no-new-privileges`.

Retain a self-cleaning local qualification for TLS health, route separation, worker-network
exclusivity, direct-provider TCP denial, non-root/read-only runtime settings, and lease
persistence across a core restart. The qualification must not send a provider API request
or claim invoice reconciliation.

## Consequences

A company can now prepare protected state, build content-addressed local images, launch the
fixed topology, connect a real `OpenAIQuotaController`, and exercise sandbox preflight
without designing the first host boundary from scratch.

The provider key remains confined to the core. A worker sees only its scoped lease token
and a worker-only TLS edge. The admin API is absent from that edge, and the worker route is
absent from the loopback admin edge.

Docker Desktop cannot publish a host port from an internal-only bridge. The pilot's admin
edge therefore has a distinct non-internal control bridge. It has no provider or admin
credential, but that bridge can permit outbound traffic. Production must replace this
local compromise with explicit ingress and egress policy.

Compose bind-mounted secret/config file modes are enforced by host ACLs rather than Swarm
metadata. Docker daemon administrators, the host kernel, prepared-state owner, network
administrators, model/pricing configuration, and provider behavior remain trusted.

The retained receipt is offline local evidence only. Live-provider accounting and invoice
reconciliation, production TLS/secret management, registry admission, orchestrator network
mutation resistance, ambiguous-operation reconciliation, and disaster recovery remain
open qualification gates.
