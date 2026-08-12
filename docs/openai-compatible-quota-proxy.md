# OpenAI-compatible quota proxy

Causure `0.4.0a18` includes its first provider-specific quota reference: a closed
controller/proxy for one non-streaming, text-only OpenAI-compatible Responses API. It is
intended to make the sandbox lease contract concrete without giving a worker a real
provider credential. The release also packages that reference as a split-edge, one-host
[Docker pilot](openai-quota-pilot.md).

This is a reference implementation and local integration boundary, not a qualified hosted
service. The unit suite does not prove a live provider's model identity, prices, token
accounting, TLS edge, Docker network, or billing behavior. Those facts must be protected
and qualified before `provider_hard_limit` is a production claim.

## Supported surface

The worker-facing route is exactly `POST /v1/responses`. A request must:

- carry the lease token as its bearer credential and the lease ID in
  `X-Causure-Lease-Id`;
- select an exact model identifier present in protected configuration;
- set `store` to `false`;
- be non-streaming;
- provide bounded text input and an explicit `max_output_tokens` no larger than the
  configured model maximum; and
- contain only the closed top-level fields accepted by `OpenAIQuotaWSGIApplication`.

The first surface deliberately excludes chat completions, images, audio, files, remote
content, conversations, prompts, background jobs, streaming, built-in tools, arbitrary
endpoints, and provider-side continuation. A function definition is also excluded in this
version. These surfaces can add token classes, per-call fees, retained state, asynchronous
work, or costs that cannot be revoked synchronously.

The official [Responses API reference](https://platform.openai.com/docs/api-reference/responses)
documents `max_output_tokens` as an upper bound that includes visible and reasoning output
tokens, and a completed response reports `input_tokens`, `output_tokens`, and cached-input
details. The proxy nevertheless treats the exact provider behavior as a deployment fact,
not something made true by matching an API shape. Provider model pages also show that
prices, context limits, and supported billing features vary by model; protected
configuration must reflect the exact selected contract.

## Components

- `OpenAIQuotaConfiguration` is the closed, non-secret deployment and pricing snapshot.
- `SQLiteOpenAIQuotaStore` serializes leases and provider operations with
  `BEGIN IMMEDIATE` on one local filesystem.
- `OpenAIQuotaWSGIApplication` exposes separate protected admin routes and the worker
  Responses route.
- `HTTPSOpenAIResponsesTransport` owns the real provider key and calls one fixed verified
  HTTPS URL without redirects or an environment proxy.
- `HTTPSOpenAIQuotaAdminClient` calls the protected admin API with a separate credential,
  also without redirects or an environment proxy.
- `OpenAIQuotaController` implements the sandbox `ProviderQuotaController` protocol.

The provider key, admin token, and lease tokens are never part of the configuration JSON.
The SQLite store retains only SHA-256 of each high-entropy lease token. A token is absent
from object representations, settlements, health/readiness output, and non-secret lease
snapshots.

## Configuration

Start from the deliberately non-operational
[reference configuration](../examples/quota/openai-compatible-reference.json) and validate
it against the [configuration schema](../schemas/openai-quota-config.schema.json). Its
`.invalid` endpoint, placeholder model, and punitive placeholder rates are intentional;
copying it unchanged must not send a useful provider request.

For every allowed model, protect and review:

- an immutable or operationally pinned model revision rather than a moving alias;
- the maximum billable input-token count for one accepted request;
- the maximum output-token count accepted by the provider;
- regular, cached-input, and output USD prices per million tokens; and
- any provider rule that changes those rates by context length, cache write, service tier,
  or another billing dimension.

The first implementation supports one flat set of text-token rates per model. Do not use a
model with threshold pricing, cache-write premiums, tool fees, scale-tier credits, or
another unmodeled billing dimension. Setting a rate to a familiar list price is not enough:
the configured rates must be the exact applicable protected rates, and regular input must
be the maximum billable input rate. Cached input may be configured at the same maximum
rate when a discount cannot be proven. Regular input and output rates cannot be zero.

The proxy preauthorizes every request against the model's full configured maximum billable
input, not a local tokenizer estimate, plus the request's explicit output maximum. This is
deliberately conservative. A small lease may reject a small prompt because the provider
has no independently enforceable preflight token-count contract. An optimized bound needs
its own provider-backed qualification before replacing this behavior.

## Secure composition

The application is framework-neutral WSGI. A hosting process can compose it as follows;
`secret_manager.read(...)` is a placeholder for the company's secret delivery system, not
an API supplied by this project:

```python
from causure import (
    HTTPSOpenAIResponsesTransport,
    OpenAIQuotaWSGIApplication,
    SQLiteOpenAIQuotaStore,
    load_openai_quota_configuration,
)

configuration = load_openai_quota_configuration("openai-quota.json")
store = SQLiteOpenAIQuotaStore("/var/lib/causure/quota.sqlite3")
store.initialize()
upstream = HTTPSOpenAIResponsesTransport(
    configuration,
    secret_manager.read("provider-api-key"),
)
application = OpenAIQuotaWSGIApplication(
    configuration,
    store,
    secret_manager.read("quota-admin-token"),
    upstream,
)
```

Host the WSGI application only behind a trusted HTTPS boundary that fixes
`wsgi.url_scheme` to `https` without trusting client forwarding headers. Keep admin access
on a separately authorized path or listener at the edge. The repository now ships one
digest-pinned, split-edge Docker pilot with a fixed worker network, separate worker/admin
routes, protected-file state preparation, and a self-cleaning local qualification. That
pilot is an integration starting point, not a general orchestrator or production edge.

The sandbox-side process uses the separate admin credential:

```python
from causure import HTTPSOpenAIQuotaAdminClient, OpenAIQuotaController

controller = OpenAIQuotaController(
    HTTPSOpenAIQuotaAdminClient(
        "https://quota-admin.internal.example",
        secret_manager.read("quota-admin-token"),
    )
)
```

Pass that controller to `SandboxedAdapterRunner.run_replay(...)` or
`run_evaluation(...)`. The returned lease points workers at the configured internal proxy.

A worker using an OpenAI-compatible client configures the lease token as the temporary API
key, the lease proxy URL as its base URL, and the lease ID as a fixed request header. The
real provider key must never exist in the worker image, request, environment, or evidence:

```python
client = OpenAI(
    api_key=request.quota.lease_token,
    base_url=request.quota.proxy_url,
    default_headers={
        "X-Causure-Lease-Id": request.quota.lease_id,
    },
)
response = client.responses.create(
    model="company-qualified-exact-model-revision",
    input="bounded text input",
    max_output_tokens=256,
    store=False,
    stream=False,
)
```

The OpenAI SDK is illustrative and is not a Causure dependency. Pin and review the
worker's actual compatible client.

## Admission and accounting sequence

1. The controller creates a cost/concurrency/operation lease before Docker preflight.
2. The proxy validates the worker credential, lease state, expiry, route, model, request
   shape, and output cap.
3. One SQLite write transaction atomically checks operation count, in-flight concurrency,
   and remaining nanodollar liability, then holds the request's maximum cost.
4. Only after that commit does the fixed transport replace the lease credential with the
   provider key and forward the request.
5. A successful response must match the exact model and carry bounded provider usage.
   Exact fixed-point ceiling arithmetic releases the maximum hold and records token-derived
   cost.
6. Settlement succeeds only when the sandbox completion count equals all and only
   successfully accounted provider operations, with no request in flight or uncertain.
7. Cancellation immediately rejects new work. Existing in-flight work can still finish;
   container termination is not remote cancellation.

A timeout, transport error, non-200 provider response, missing usage, model mismatch, or
out-of-bound token count is ambiguous after forwarding. The proxy fails the lease, converts
the operation's complete maximum hold into uncertain liability, and refuses clean
settlement. It does not silently assign zero cost. Reconciliation with the provider's
organization usage/cost records is operational work outside this first synchronous API.

## Hosting and storage boundaries

The store is single-host SQLite WAL state. Put it on a protected local filesystem, not an
SMB/NFS share or synced folder. Protect the database, WAL/SHM files, parent directory,
configuration, TLS material, and both secret sources from workers. Back up and reconcile
terminal lease/accounting records according to company retention policy.

The health endpoint proves only that the process can answer. Readiness runs a SQLite quick
check. Neither endpoint contacts the provider, validates current prices, or proves the TLS
edge and Docker network.

The [split-edge pilot guide](openai-quota-pilot.md) covers exact local image construction,
state ACLs, TLS trust, route separation, restart testing, teardown, and the retained
no-provider qualification receipt. Before a live company pilot, independently test the
exact provider/model/configuration with:

- successful and rejected calls at every cost, operation, concurrency, and expiry edge;
- response token counts and invoice/cost reconciliation, including caching;
- connection loss before send, during send, and after provider completion;
- cancellation while a call is in flight;
- worker attempts to reach provider DNS/IP directly or attach another container;
- proxy restart with an operation left in `forwarding`;
- TLS trust failure, redirect, environment-proxy injection, and credential redaction; and
- the exact worker digest, container engine, internal network, and trusted edge.

Until that evidence is retained for the exact deployment, describe this as the shipped
OpenAI-compatible reference implementation—not as a qualified hard-spend deployment.
