# Trace collection

The `collect` command turns an OTLP JSON trace export into a small, deterministic manifest
that can be inspected, retained, and referenced without copying raw production content into
an evidence bundle.

It is the first collection boundary in Causure. It does not decide whether a patch
is justified, run a replay, call a model, or convert telemetry into a gate-ready change case.

## Supported input

The initial importer accepts an
[OTLP JSON](https://opentelemetry.io/docs/specs/otlp/) trace export with OpenInference
semantic attributes. OpenInference builds on OpenTelemetry and defines agent-oriented span
kinds and model metadata; see the
[OpenInference specification](https://arize-ai.github.io/openinference/spec/) and
[semantic conventions](https://arize-ai.github.io/openinference/spec/semantic_conventions.html).

The collector expects the standard `resourceSpans -> scopeSpans -> spans` structure. Trace
IDs must be 32 hexadecimal characters, span IDs must be 16 hexadecimal characters, OTLP
enum fields must be integers, and nanosecond timestamps must fit in an unsigned 64-bit
integer.

Source constraints are intentionally bounded:

- The source must be a UTF-8 file no larger than 16 MiB.
- The default span limit is 10,000.
- An operator may lower the limit or raise it to at most 100,000 with `--max-spans`.
- Standard input is rejected because the manifest promises a hash of exact file bytes.
- Duplicate JSON keys, duplicate attribute keys, and duplicate span identities fail closed.

## Run the collector

```powershell
$env:PYTHONPATH = "src"

python -m causure collect `
  examples\traces\refund-openinference-otlp.json `
  --source-id refund-openinference-fixture `
  --output causure-trace-manifest.json
```

The committed fixture deliberately includes fake private-looking values in span names,
messages, events, links, resource attributes, status messages, and arbitrary attributes.
Those values are useful for proving that the output boundary excludes them.

Export the matching integration contract with:

```powershell
python -m causure schema trace-manifest
```

The committed form is
[`schemas/trace-manifest.schema.json`](../schemas/trace-manifest.schema.json).

## What the manifest retains

The source record contains:

- A non-sensitive operator-supplied artifact ID.
- The exact SHA-256 of the source file and its byte count.
- Trace and span counts.
- The source format and media type.
- An explicit `source_embedded: false` marker.

Each span contains domain-separated SHA-256 fingerprints of its trace identity and
trace-scoped span identity, timing and duration, numeric OTLP kind and status codes, and a
content-addressed evidence reference:

```text
trace-sha256://<source-sha256>/spans/<trace-scoped-span-sha256>
```

Only these text metadata keys can be retained, and their values must be short,
whitespace-free identifiers:

- `embedding.model_name`
- `gen_ai.operation.name`
- `gen_ai.provider.name`
- `gen_ai.request.model`
- `gen_ai.response.model`
- `llm.model_name`
- `llm.provider`
- `llm.system`
- `openinference.span.kind`, restricted to known OpenInference span kinds

Only non-negative numeric values can be retained for an explicit set of current token and
cost keys:

- `gen_ai.usage.input_tokens` and `gen_ai.usage.output_tokens`, plus their legacy
  `prompt_tokens` and `completion_tokens` names.
- `llm.token_count.prompt`, `completion`, and `total`, plus the documented `audio`,
  `reasoning`, `cache_read`, and `cache_write` detail keys.
- `llm.cost.prompt`, `completion`, and `total`, plus the documented `audio`, `input`,
  `output`, `reasoning`, `cache_input`, `cache_read`, and `cache_write` detail keys.

There are no wildcard attribute namespaces. New telemetry keys require an explicit
collector and schema update. Everything else is omitted. The manifest records how many span
attributes were retained, redacted because their key or value looked sensitive, or dropped
because they were not allowlisted.

## What the manifest excludes

Causure never copies these groups from the trace export:

- Raw span names.
- Resource and instrumentation-scope attributes.
- Span events and links.
- Status messages.
- Prompt, input, output, message, reasoning, tool-call, query, session, user, credential,
  URL, and arbitrary attribute content.
- The source document itself.

Trace and span IDs are fingerprinted rather than copied. Span names are omitted rather than
hashed because names can have low entropy or contain personal data, making unsalted hashes
susceptible to guessing.

## Generate an investigation draft

The fixture generator strictly validates the committed manifest contract, hashes the exact
manifest bytes, and groups safe span metadata by trace identity:

```powershell
python -m causure fixture `
  causure-trace-manifest.json `
  --fixture-id refund-investigation `
  --output causure-investigation-fixture.json
```

The result is useful for an investigation queue, but it deliberately does not claim that a
failure occurred, infer a cause, propose a patch, or satisfy the evidence gate. See
[investigation fixtures](investigation-fixtures.md).

## Trust boundary and next step

A redacted manifest proves which source bytes were collected and supplies stable references.
On its own it does not prove who produced the manifest or source. A detached
[artifact attestation](artifact-attestations.md) can authenticate the manifest producer;
raw-trace origin is established only when organizational trust authorizes that producer as
the collector. Neither mechanism proves that a trace represents a genuine failure or that a
proposed change caused an improvement.

Company-owned implementations can use the typed `ReplayAdapter` and `EvaluatorAdapter`
protocols in `causure.adapters`. Every request carries an `ExecutionBudget` with
timeout, concurrency, case-count, and optional cost limits. `ProcessAdapterRunner` can
invoke trusted adapters behind a spawned, killable process boundary; see the
[adapter-runner guide](adapter-runner.md).

This does not make arbitrary adapter code safe. The child inherits the invoking account's
network and filesystem permissions, internal concurrency remains cooperative, and reported
cost can be checked only after an adapter returns. Production deployments still need an
OS/container sandbox and provider-enforced quotas.

Replay and evaluation results still need to be assembled into the existing change-case
contract before the deterministic gate can approve, reject, abstain, or require human review.

## Residual privacy risk

An allowlist reduces accidental disclosure but cannot prove that an upstream producer did
not place sensitive data into a normally safe model/provider field. Treat the manifest as
sensitive operational metadata, inspect it before broad distribution, and keep the raw trace
in a separately controlled store with an appropriate retention policy.
