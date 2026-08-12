# ADR 0024: add one conservative OpenAI-compatible quota reference

- Status: accepted
- Date: 2026-08-09
- Release: 0.4.0a16

## Context

The sandbox contract already required a provider hard-quota controller and a dedicated TLS
proxy, but every deployment had to invent both. That left the highest-risk connected-mode
boundary as an interface without a usable reference.

A generic SDK wrapper is insufficient. The controller must reserve before worker launch;
the proxy must own provider credentials, serialize cost/operation/concurrency admission
before forwarding, and refuse a clean receipt when provider cost is ambiguous.

## Decision

Ship one provider-specific reference for the OpenAI-compatible Responses shape, limited to
non-streaming text operations and exact protected model configuration.

Use a local SQLite WAL ledger with `BEGIN IMMEDIATE` to serialize lease admission. Store
only hashes of high-entropy lease tokens. Use integer nanodollar ceiling arithmetic. Hold
the full configured maximum billable input cost plus the request's explicit maximum output
cost before forwarding; do not rely on a local tokenizer estimate.

Separate the admin bearer credential, worker lease credential, and provider API key. The
fixed upstream and admin clients require verified HTTPS and reject redirects and
environment proxies. Treat provider non-success or missing/out-of-bound accounting as
worst-case uncertain liability and make the lease un-settleable.

Keep provider prices and model bounds in a strict, secret-free protected configuration.
Do not ship real credentials, current-price claims, a TLS edge, container image, or managed
orchestrator deployment in this decision.

## Consequences

Companies now have a concrete controller, proxy boundary, transactional store, schema,
and adversarial test base. Workers still cannot receive a provider key.

Admission is intentionally conservative: even a small request must fit a lease sized for
the configured model's maximum billable input. Flat token prices are the only modeled
billing contract. Streaming, stateful, multimodal, tool-fee, tiered-price, and asynchronous
surfaces remain closed.

Unit and in-process integration tests are not live-provider or Docker qualification. The
roadmap retains a separate managed deployment and exact-provider hard-spend gate.
