# Architecture

Causure starts as a narrow control plane, not another agent runtime.

```text
raw OTLP trace artifact
          |
          v
redacting collector ------> trace manifest + content hashes
                                  |
                                  v
                         draft fixture generator
                                  |
                                  v
                       candidate incident clusters
                    |             |                 |
                    |             |                 +--> digest-pinned OCI workers
                    |             |                                  |
                    |             |                                  v
                    |             |                         sandboxed runner
                    |             |                         |              |
                    |             |                         v              v
                    |             |                    no network    hard-quota proxy
                    |             |
                    |             +--> company replay/evaluator adapters
                    |                              |
                    |                              v
                    |                    process-bounded runner
                    |                              |
                    +------------------------------+
                                    |
              investigator claims, requirements, and hypotheses
                                    |
                                    v
                           evidence assembly
                                    |
                                    v
                           change case (JSON)
                                    |
                         +----------+-----------+
                         |                      |
                         v                      v
               detached attestation    protected producer trust
                         |              + current revocations
                         +----------+-----------+
                                    |
                                    v
                    optional provenance verification
                                    |
                                    v
                  structural validation ---- policy override
                           |                       |
                           +-----------+-----------+
                                       v
                              deterministic gate
                                       |
                           +-----------+-----------+
                           |                       |
                           v                       v
                    JSON review result       Markdown report
                           |                       |
                           +-----------+-----------+
                                       v
                          Azure TFVC publication
                                       |
                              exact-byte recheck
                                       |
                                       v
                       build summary + audit artifacts
                                       |
                       +---------------+----------------+
                       |                                |
                       v                                v
              signed approval assertion       protected authority trust
                       |                       + current revocations
                       +---------------+----------------+
                                       |
                                       v
                         approval-chain verification
                                       |
                                       v
                    unchanged CI gate / audit boundary
                                       |
                                       v
                     protected tenant access policy
                                       |
                                       v
                       deterministic role decision
                                       |
                                       v
                    per-tenant hash-chained audit log
                                       |
                                       v
                    policy-authorized complete export
                                       |
                                       v
                    exact-byte verification receipt
```

## Components

### Evidence model

`models.py` parses untrusted JSON into immutable domain objects. Structural validation is
separate from evidentiary sufficiency: a case with one reproduction trial can be structurally
valid while still receiving `needs_evidence`.

Unknown properties, duplicate IDs, duplicate hypothesis components, unsupported schema
versions, invalid enums, naive timestamps, and malformed numeric ranges are rejected.

### Trace collector

`collector.py` parses bounded OTLP JSON and emits a deterministic metadata manifest. It
hashes the exact source artifact, fingerprints trace-scoped identifiers, retains only a
small model/token/cost allowlist, and omits span names and raw content-bearing fields. It
does not fetch artifacts or create a change case.

`trace_manifest.py` strictly reparses a redacted manifest before downstream use.
`fixtures.py` then groups spans by trace identity and emits deterministic candidate clusters.
The artifact is permanently marked draft-only and lists the substantive evidence still
missing. It cannot be submitted as a change case.

`adapters.py` defines company-owned replay, evaluator, and canonical case-generator
protocols. Replay/evaluator requests require timeout, concurrency, case-count, and optional
cost budgets. A generation request instead binds the exact GitHub base/head/component
identity, component digest and size, candidate root, expected change reference, timeout, and
maximum canonical output. `runner.py` invokes a trusted, importable adapter in a spawned
child process and enforces the relevant wall-clock, input/output, protocol, and reported
aggregate-cost boundaries.

The runner is a failure and resource-accounting boundary, not a security sandbox. Child
code inherits the invoking user's filesystem and network access. Internal concurrency is
cooperative, and a provider-side quota is required to stop spend before outcomes are
returned.

### Sandboxed adapter execution

`sandbox_protocol.py` defines closed policies and one-reference worker request/response
contracts. `sandbox.py` schedules those requests in digest-pinned Linux containers through
`DockerCliSandboxRuntime`.

The parent enforces worker concurrency. Runtime preflight confirms the exact local image,
rejects declared image volumes, and applies a non-root/read-only container with CPU, memory,
PID, temporary-filesystem, output, and wall-clock limits. Offline work uses no container
network.

Connected work is a separate fail-closed mode. A trusted provider quota controller must
reserve a hard cost/operation/concurrency lease before runtime preflight. The runtime
accepts only the lease's internal network and requires that its only pre-attached container
be the named TLS quota proxy. The scoped token is sent inside the bounded worker request,
not through arguments or environment variables. Validated work is settled against
authoritative provider accounting; failures cancel the lease.

`openai_quota.py` supplies one deliberately narrow OpenAI-compatible reference controller,
WSGI proxy boundary, direct HTTPS clients, and transactional SQLite lease ledger. It
supports non-streaming text Responses only, holds the full configured model-maximum input
cost plus explicit output maximum before forwarding, and refuses clean settlement after
ambiguous provider accounting.

`openai_quota_host.py` adds a closed exact-version Waitress host whose configuration binds
quota bytes, secret-file locations, local SQLite, listener bounds, and a fixed HTTPS scheme
without forwarding-header trust. `openai_quota_pilot.py` creates new protected state with a
generated admin token and short-lived pilot TLS chain. The deployment assets compose that
core with mutually exclusive worker/admin Caddy edges, an internal worker network, an
internal backend, a provider-egress bridge, and a Docker Desktop loopback-control bridge.
The core alone receives the provider and admin credentials; no provider credential is
shipped by the project.

This is a one-host company pilot with a retained no-provider local qualification, not a
managed production deployment. The Docker daemon, Linux host, protected state ACLs,
model/pricing configuration, controller, proxy, provider behavior, and orchestration
permissions remain trusted deployment components. See the
[sandboxed adapter-runner guide](sandboxed-adapter-runner.md) and
[OpenAI-compatible quota guide](openai-compatible-quota-proxy.md), plus the
[split-edge pilot guide](openai-quota-pilot.md).

### Artifact attestations

`attestations.py` creates and verifies detached Ed25519 producer attestations. A signature
binds the exact artifact digest and byte count to a producer/key identity, validity window,
retention class and deadline, and required revocation-list identity.

Producer identity is established by a protected trust store that binds a key ID to one
producer and key-validity window. A separately protected revocation list is freshness-
bounded at verification time. Compromise revocations invalidate all signatures; retirement
revocations preserve signatures issued before the cutoff.

The attestation, trust-store, and revocation-list parsers are strict, closed contracts; the
successful verification receipt also has a closed output schema. Ed25519 operations use the
pinned optional `cryptography` extra and are loaded only when called. Artifact storage,
retention enforcement, trust-policy integrity, and private-key custody stay outside the
deterministic gate.

Attestation verification is an optional integration boundary rather than a new decision
rule. An organization that requires provenance must sequence `verify-attestation` before
`review` in the same protected pipeline stage.

### Policy

`policy.py` defines versioned defaults and accepts sparse overrides. Policies can increase
sample sizes, confidence thresholds, control counts, or make cost and latency regressions
blocking. Unknown policy keys fail closed.

### Decision engine

`engine.py` evaluates checks in this order:

1. Requirement clarity.
2. Oracle independence.
3. Failure reproduction.
4. Attribution confidence and separation.
5. Proposed-component alignment.
6. Isolated-intervention support.
7. Evidence against the null hypothesis.
8. Patch minimality.
9. Positive controls.
10. Negative controls.
11. Regression controls.
12. Cost and latency.

Every check emits a stable finding code, status, consequence, message, and structured
details. The final decision follows a fixed precedence:

```text
human_review > reject > needs_evidence > conditional_pass > approve
```

That ordering is intentional. A patch with a proven harmful regression is rejected even if
other parts of the bundle need more evidence.

### Reports

`report.py` produces:

- JSON for automation and archival.
- Markdown for build summaries and human review.

The report includes the policy, engine version, review time, change reference, and SHA-256
of the normalized evidence document. It is audit metadata, not a digital signature.

### Post-deployment canary comparison

`canary.py` is a separate evidence boundary after the pre-change gate. It strictly parses
an exact canary policy and aggregate observation, then cross-checks them against the
canonical reviewed change case and exact review-result bytes. An observation cannot
substitute another policy, review, case, component, or change reference.

The policy prospectively fixes evaluator reference, exact assignment unit/method,
sticky assignment, binary rate metrics, absolute degradation tolerances, minimum
window/sample sizes, family-wise confidence, and a maximum number of looks. Each look
contains distinct baseline/candidate deployment references and one full-denominator event
count for every declared metric.

The engine creates conservative Wilson intervals for each cohort proportion. Its
Bonferroni allocation covers both cohorts, all metrics, and all planned looks before it
forms each candidate-minus-baseline difference interval. Every metric must be noninferior
for `promote`; a conclusive regression yields `rollback`; an inconclusive non-final look
yields `continue`; and an invalid/insufficient design or inconclusive final look yields
`needs_evidence`.

The output is an exact-artifact-bound JSON receipt plus an optional Markdown report. This
module does not retrieve telemetry, verify that routing/evaluator declarations are true,
prove causality, or invoke deployment controls. The policy/evaluator and aggregate
evidence need independent source-control, attestation, authorization, and retention. See
the [canary outcome guide](canary-outcome-comparison.md).

### Azure DevOps review publication

`azure_devops.py` creates a closed publication record from the exact JSON result and
Markdown report bytes. It binds the review to the current Azure collection, project, build,
definition, requester, protected TFVC server path, and either a changeset or shelveset
target. Optional work-item IDs are sorted and deduplicated.

Changeset identity comes from `Build.SourceVersion`; gated and manually validated
shelvesets use the separate `Build.SourceTfvcShelveset` identity. The parser cross-checks
source branch, trigger reason, and target fields so a shelveset cannot be mislabeled as a
changeset.

Immediately before task completion, verification re-reads the publication, result, and
report. It compares exact SHA-256 and byte counts, reparses the result/report relationship,
matches the current build context, and enforces a freshness window. A successful receipt
feeds a Markdown-safe Azure build summary and downloadable build artifact.

These records detect mutation and context substitution but are not signatures. The
pipeline definition, agent environment, and artifact retention remain trusted controls.
See the
[Azure review-gate guide](azure-devops-review-gate.md).

### Trusted GitHub case generation

`trusted_case_generation.py` composes canonical project configuration, one selected GitHub
component, a separately trusted adapter directory, and a separate candidate root. It
accepts only a regular contained component file, hashes it before and after execution,
hashes the bounded protected adapter tree before and after execution, and requires a
new-only output directory and configured case path. The child resolves its exact entry
module only beneath that protected tree in Python isolated mode; the candidate root is not
placed on its import path.

Generated output must parse as one canonical `ChangeCase`, match the configured component,
stay within its byte budget, and use the exact repository/PR/head/path
`github://` reference. The module is rehashed after execution, the case is immediately
reviewed under the protected policy, and a minimized receipt records PR/component,
component/adapter/case hashes, execution limits, and output subjects without retaining the
absolute candidate root or component body.

`trusted_case_action_runner.py` adds the hosted composition. It confines two separate roots
beneath `GITHUB_WORKSPACE`, derives the exact PR identity, uses the same bounded read-only
filename discovery and component selection, verifies protected checkout `HEAD` against the
base SHA and candidate checkout `HEAD` against the head SHA, and then invokes generation.
No-match and committed-case mappings return without loading a generator. Generator-backed
forks fail before Git inspection or adapter execution. The companion composite Action and
bootstrap both run from a reviewed remote Action commit rather than candidate source.

This is not an OS sandbox: protected adapter code inherits the job's filesystem and network
permissions and can read the candidate root. The runner itself never imports or executes
candidate code; organizational adapter review must preserve data-only parsing. See the
[trusted case-generation guide](trusted-case-generation.md) and
[ADR 0029](decisions/0029-run-case-generators-only-from-a-protected-base.md).

### GitHub pull-request review publication

`github_review.py` creates a second closed delivery record from the exact change-case JSON,
review-result JSON, and Markdown report bytes. It treats `pull_request.head.sha` as the
candidate and separately records the base SHA and event-dependent `GITHUB_SHA`. Numeric
repository/owner IDs, base/head refs, fork/draft state, workflow ref/SHA, run attempt, job,
and the exact event-payload subject prevent name-only or merge-ref substitution.

Only the unprivileged `pull_request` event is accepted. The parser rejects
`pull_request_target`, requires the PR merge ref, requires a workflow under the base
repository's `.github/workflows/` directory, and cross-checks the event payload against the
GitHub environment. The raw event and PR content are not retained.

Verification re-reads and hashes the publication plus all three gate artifacts, reparses
their semantic relationship, matches the exact current PR/event/workflow identity, and
enforces a bounded freshness window. This offline module performs no GitHub API write.

`github_checks.py` consumes only that verified chain and creates a closed, token-free Check
Run plan. The plan fixes the PR head SHA, repository, run/attempt, verification digest,
stable check name, decision-derived conclusion, details URL, external ID, and at most 50
decision-affecting findings. Its HTTPS adapter can post only to the corresponding
GitHub.com Checks endpoint, disables redirects, bounds response size/time, validates the
201 response identity, and emits a minimized exact-request receipt. Tokens never enter the
plan, receipt, or summary.

`github_selection.py` adds a separate read-only boundary for automatic selection. It calls
only the validated base repository's PR and PR-files endpoints, disables redirects, bounds
each response and the total file count, validates pagination, and checks the exact event
base/head identities before and after discovery. It matches the normalized filenames and
rename origins against the closed project configuration, rejects candidate-modified config
or policy, and requires at most one configured component.

`github_action.py` composes review, publication, re-verification, Check Run planning, job
summary, and optional publication. `github_action_runner.py` accepts configured selection
or paired explicit overrides plus GitHub environment paths, confines a selectable logical
repository root and all file inputs/outputs to `GITHUB_WORKSPACE`, requires at least one
component mapping in automatic mode, and emits a successful `not_applicable` job when none
of those configured components changed. The nested root lets it consume a case generated in
the exact-head checkout without treating that checkout as Action code. The bootstrap runs
with Python isolated mode so the caller checkout cannot shadow the Action package. Default
`auto` mode publishes for ordinary same-repository PRs, skips the write for forks, and also
skips it for Dependabot when GitHub downgrades the workflow token; the deterministic workflow
job still carries the gate result. See the [GitHub Action guide](github-action.md) and
lower-level [GitHub review-publication guide](github-review-publication.md).

### Approval assertions

`approvals.py` keeps human actions outside the deterministic engine. A protected
organizational authority authenticates and authorizes a stable human identity, then signs
an `approve` confirmation or explicit `exception` against the exact Azure publication and
pre-approval verification bytes.

The trust store binds authority keys to permitted actions and validity windows. A
freshness-bounded revocation list handles compromise and retirement. Verification also
rechecks the exact result/report, reconstructs the Azure receipt at its recorded time, and
matches the current Azure TFVC build.

An exception must cover every finding with a decision-affecting consequence. It remains a
separate `record_only` artifact: the result's original decision and CLI gate status are not
rewritten. The issuer CLI is an adapter for an already authenticated organizational
service; it is not itself an identity provider. See
[authenticated approval assertions](approval-assertions.md).

### Team service foundation

`team_service.py` defines the domain boundary under the Team integration API. A
protected tenant policy maps stable identity-provider subjects to fixed investigator,
policy-administrator, and approver roles. The decision function selects roles from that
policy; it never accepts a caller-supplied role. Every decision binds the exact policy
bytes, revision, tenant, action, resource, and allow/deny reason.

Allowed, denied, and failed actions can be recorded as independent per-tenant audit
chains. Each event embeds its authorization decision, hashes rather than copies its acted-on
payload, records a policy-backed retention deadline, and links the canonical predecessor
hash. Complete exports must begin at sequence one, require a fresh policy-administrator
authorization for their export ID, end at a head digest supplied by the protected tenant
ledger, and preserve the longest contained retention deadline.

Hash chaining is tamper evidence, not storage immutability. The CLI does not authenticate
users or enforce immutable retention. `team_store.py` provides exact-byte SQLite
persistence, forward-only policy history, atomic per-tenant compare-and-swap heads,
full-chain export snapshots, immutable minimized case and investigation indexes,
ordinary-SQL mutation guards, and online backups for local or single-host pilots.

`team_cases.py` is the dashboard projection boundary. It consumes exact reviewed
change/Azure/approval/canary artifacts, cross-checks their identifiers and hashes, and
retains bounded operational summaries plus exact content subjects. Raw evidence
references, reports, justifications, and observations remain outside the projection.
Successor validation makes base evidence immutable and permits only additive delivery,
approval, and controlled canary progression.

`team_investigations.py` is the candidate-queue projection boundary. It reparses exact
investigation fixtures, selects an explicit cluster, and retains bounded operational
metadata plus exact fixture subjects without retaining trace/span references or fixture
bodies. Revisions either append one immutable observation or transition queue state.
Candidate-only/non-causal flags remain fixed, and terminal typed resolutions separate
change-case linkage, duplication, negative findings, no-change decisions, and abstention.

`team_application.py` composes that store with typed trusted identity, current-policy
membership, server IDs/timestamps, consistent read snapshots, and write-time
active-policy/head checks. `team_http.py` exposes a closed WSGI JSON/HTML boundary for
summary, event, action, export, evidence-console, change-case, and investigation
operations. It intentionally ignores raw authentication, tenant, and role headers; a
company host must validate credentials, select the tenant, inject the typed identity, and
attest request integrity for POSTs.

`team_dashboard.py` renders the low-level evidence console, joined case views, and
candidate investigation queue from bounded application models. Active policy, head, and
retained bytes come from one SQLite read transaction. The renderer receives no raw source
artifact, emits no JavaScript or forms, and labels candidate/receipt semantics rather
than presenting correlation as cause or a receipt as live authorization/deployment state.

`team_entra.py` is an optional resource-server adapter around that neutral boundary. It
parses a protected tenant/key snapshot, validates strict Microsoft Entra v2.0 bearer-token
profiles with tenant-partitioned RSA keys, and injects only the typed `(Team tenant,
Entra tenant, object ID)` identity. It neither assigns Team roles from token claims nor
performs discovery, token acquisition, or browser login on the request path.

`team_entra_refresh.py` is the separate network/control-plane boundary. A closed protected
configuration selects exact tenant-specific discovery and JWKS endpoints. The one-shot
refresher uses direct verified HTTPS without proxies or redirects, validates discovery and
per-key issuer scope, builds every tenant before atomically installing one newer same-store
snapshot, and never replaces last-known-good trust after a failed refresh. Request workers
can reload an atomically replaced file, but cannot extend the original expiration of a
missing, corrupt, stale, or rolled-back candidate.

The optional managed verifier is the single-process lifecycle layer around those
primitives. Startup refresh is synchronous with a fresh same-store fallback. One owned
worker schedules hourly refresh or five-minute failure retry. A strictly parsed unknown
key for an already trusted tenant can enqueue one globally rate-limited asynchronous
refresh, but the request is neither retried nor blocked on network I/O. Lifecycle status
contains stable codes rather than token/configuration details.

The coordinated verifier is the local-host multi-process lifecycle layer. Every process
keeps its own atomic reloader and supervision thread, but a protected local-volume OS file
lock permits exactly one process to create a managed network refresher. Followers never
fetch during ordinary startup or verification. A trusted-tenant unknown key creates one
bounded exclusive request marker; the owner polls it and schedules through the managed
five-minute cooldown before consuming it. OS process exit releases ownership, after which
one follower acquires the lock and performs the same guarded startup refresh. The manager
checks the lock-file identity before network work and again immediately before snapshot
installation. Objects inherited across a process fork fail closed.

This is not a distributed lease. Lock and marker paths must remain protected, unchanged,
and on the same supported local volume as the atomic snapshot. Multi-host ownership,
production jitter/HTTP abuse controls, and live deployment qualification remain hosting
responsibilities.

`team_admission.py` is the outer process-local WSGI backstop. A non-blocking semaphore
holds one slot through completion or close of the response iterable. A global token bucket
and bounded optional source buckets run before the Entra adapter. Default source
partitioning normalizes only `REMOTE_ADDR`, never forwarding headers; high-cardinality
state is capped and idle-pruned. Liveness bypasses admission, while readiness validates
the monotonic clock without consuming traffic capacity. Rejections expose generic stable
codes and bounded retry guidance.

`team_host.py` is the closed one-process composition boundary. A duplicate-rejecting host
policy binds three distinct absolute paths, the exact Entra refresh-config byte subject and
`store_id`, exact Waitress `3.0.2`, canonical loopback, and bounded server/admission
settings. Startup creates the SQLite/application stack, synchronously starts one managed
Entra verifier, then fixes middleware order as admission, Entra, and Team. Waitress asserts
the protected external `https` scheme but trusts no proxy or forwarded header. Server exit
or failure closes the refresh lifecycle.

`team_windows_service.py` is the optional Windows SCM management boundary. Exact pywin32
registers one fixed-name service under its passwordless virtual account and writes one
HKLM value binding the canonical host-config path, SHA-256, and byte count. The service
entry reparses that subject at every start and uses `TeamHostServer` so an SCM control
thread can close Waitress and managed refresh state. Configure/remove require stopped
state and removal leaves all operator data intact. SCM running is not readiness.

The launcher's counters and limits cover only its one process. A hosted deployment must
still supply a trusted same-host HTTPS edge, complete connection/body/request deadlines,
distributed edge rate limits/backpressure, public host policy, and credential-log
redaction, then place authoritative
logs/exports in append-only or WORM-capable storage. See the
[Team service foundation](team-service-foundation.md) and
[SQLite Team-store guide](team-sqlite-store.md), plus the
[trusted-identity Team HTTP API](team-http-api.md),
[Microsoft Entra bearer host](team-entra-bearer-host.md), and
[single-host Team service launcher](team-service-hosting.md), plus the
[read-only evidence console](team-evidence-console.md), plus the
[change-case dashboard](team-change-case-dashboard.md) and
[investigation queue](team-investigation-queue.md).

### CLI

`cli.py` provides these integration commands:

- `collect`: create a redacted OTLP trace manifest.
- `fixture`: create a draft-only candidate-cluster artifact from a validated manifest.
- `attest`: sign exact artifact bytes with an Ed25519 producer key.
- `public-key`: export a PEM key into the trust-store public-key representation.
- `verify-attestation`: verify bytes, signature, trust, time, retention, and revocation.
- `azure-publish`: bind exact result/report bytes to the current Azure TFVC build.
- `azure-verify`: recheck the artifacts, TFVC target, build identity, and publication age.
- `github-publish`: bind exact case/result/report bytes to the current GitHub PR head and
  unprivileged workflow run.
- `github-verify`: recheck those bytes, PR/event/workflow identity, and publication age.
- `issue-approval`: authority-side signing of an authenticated human action.
- `verify-approval`: verify the signed action, exact Azure chain, current build, and
  revocations while preserving the gate status.
- `team-authorize`: create an exact-policy tenant role decision and return a denial as
  machine-readable output.
- `team-audit-append`: create the next retention-bound event from a reproduced
  authorization decision and expected predecessor.
- `team-audit-export`: create a policy-authorized complete tenant event-chain export.
- `team-audit-verify`: recheck exact export bytes, the full chain, authorization, and
  retention floor.
- `team-store-init`: initialize or validate the versioned SQLite store.
- `team-store-policy-put` / `team-store-policy-get`: activate and retrieve exact policy
  snapshots.
- `team-store-head` / `team-store-append`: read and atomically compare-and-swap a tenant
  ledger head.
- `team-store-event-get`: retrieve exact authoritative predecessor bytes by sequence.
- `team-store-export`: create and persist a complete export at the protected head.
- `team-store-backup`: create a non-overwriting consistent online backup.
- `entra-trust-refresh`: retrieve protected tenant-specific Entra discovery/JWKS metadata
  and atomically install a complete trust snapshot.
- `team-serve`: run the closed single-process Team stack on canonical loopback behind a
  trusted same-host HTTPS edge.
- `validate`: structural validation only.
- `review`: full policy decision.
- `schema`: export the bundled schemas.

The separate `causure-windows-service` administrative entry point installs,
configures, starts, stops, inspects, and removes the fixed native Windows service. Those
commands mutate SCM/HKLM only when explicitly selected and require elevation; repository
tests replace those APIs with fakes.

Within the main CLI, `entra-trust-refresh`, `team-serve`, and `openai-quota-serve` are the
network-capable commands. `team-serve` performs the bounded Entra refresh lifecycle and
listens only on configured loopback. `openai-quota-serve` listens behind its required TLS
edges and can contact only its configured HTTPS provider endpoint after admitted worker
work. `openai-quota-pilot-prepare` reads local files and generates local state without
contacting the provider. The Windows `start` command asks SCM to launch the Team service
indirectly. All evidence/artifact commands remain offline and do not dereference evidence
references.

## Why the engine is deterministic

The gate should be independently reviewable. An LLM may help an upstream investigator form
hypotheses or run experiments, but the final decision is calculated from explicit evidence
and policy thresholds. The same normalized case, policy, and engine version yield the same
decision and finding set.

The timestamp is intentionally excluded from decision logic.

## Extension points

The next layer should create evidence, not weaken the gate:

- Live-provider quota/invoice reconciliation and production orchestrator, TLS, secret,
  network-mutation, crash-recovery, and hard-spend qualification beyond the one-host pilot.
- Multi-host Entra refresh ownership and live qualification, additional organizational SSO
  adapters, public HTTPS/signed-installer or orchestrator packaging and qualified
  distributed edge limits,
  shared service database, immutable object retention, hosted approval
  authority, and direct Azure approval ingestion.
- Azure Boards relation mutation when organizations require server-side work-item links.
- Managed KMS/HSM signing, authenticated trust distribution, and storage-enforced retention.

These systems should run outside the deterministic core and emit the same versioned bundle.
