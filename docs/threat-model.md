# Threat model

Causure sits on a sensitive approval boundary. Its output may decide whether an
agent change reaches production, so both false approval and denial-of-service matter.

## Assets

- Integrity of the decision and policy.
- Integrity and provenance of evidence.
- Confidentiality of production traces and customer data.
- Availability of the CI gate.
- Auditability of approvals, exceptions, and engine versions.
- Confidentiality of producer private keys and integrity of producer trust/revocation
  policy.
- Integrity of sandbox policy and provider quota enforcement.
- Confidentiality of provider credentials and scoped quota-lease tokens.
- Integrity of Azure build/TFVC identity and published gate artifacts.
- Auditability of the exact changeset or shelveset and associated work items.
- Integrity of authenticated approver identity, authority/action policy, and explicit
  exception scope.
- Confidentiality of approval-authority private keys.
- Isolation of tenant evidence, investigations, policies, approvals, and audit history.
- Integrity of Team access-policy history, authorization decisions, per-tenant ledger
  heads, retention deadlines, and audit exports.
- Integrity and confidentiality of minimized investigation revisions, exact fixture
  subjects, assignment, typed disposition, and tenant-local case/duplicate linkage.
- Confidentiality of bearer access tokens and integrity/freshness of Entra tenant,
  issuer, audience, client, grant, and signing-key trust snapshots.
- Integrity of predeclared canary policy, reviewed-change bindings, cohort aggregates, and
  post-deployment comparison receipts.

## Trust boundaries

The following inputs are untrusted:

- Change-case JSON.
- Policy override JSON.
- OTLP JSON trace exports.
- Redacted trace-manifest JSON.
- Canary policy and canary-observation JSON.
- Evidence-reference strings.
- Replay and evaluator adapter outcomes.
- Sandboxed worker output and the code inside a policy-selected worker image.
- Detached artifact-attestation JSON.
- Output paths supplied to the CLI.
- Any future trace, replay, evaluator, or source-control connector.
- Azure review-publication JSON supplied for later verification.
- Signed approval-assertion JSON and its claimed human identity/action.
- Team authorization, audit-event, audit-export, and verification JSON supplied for
  parsing or later verification.
- Investigation-fixture and Team investigation-record JSON supplied for queue ingestion or
  later verification.
- Raw `Authorization` values, JWT JOSE headers/claims/signatures, forwarding headers, and
  every client-supplied tenant, role, username, or identity-like header.

The local gate policy, sandbox policy, attestation trust store, revocation list, and
installed engine are trusted only to the extent that the CI environment and source-control
permissions protect them. The approval trust store and revocation list are separately
trusted only when protected from the authority, approver, evidence producer, and verifier
job. The Docker daemon and host kernel are trusted isolation
infrastructure. In connected mode, the quota controller, TLS proxy, provider accounting,
and exclusive control of the internal Docker network are also trusted. Azure agent
variables, the Classic Pipeline definition, configured TFVC server path, agent pool, and
artifact store are trusted orchestration inputs for Azure publication.
Team access-policy bytes, authenticated identity claims, server-side tenant resolution,
historical policy storage, and the authoritative per-tenant ledger head are trusted hosted
service inputs. For the single-host store, the SQLite library, local filesystem, database
file, process identity, and transaction boundary are trusted to serialize appends. An
immutable or WORM-capable retention store remains separately trusted to enforce recorded
deadlines. When the Entra adapter is used, the tenant-specific discovery/JWKS refresher,
its TLS validation, the closed trust snapshot, atomic installation/reload, local
owner-lock/request-marker directory, host clock, and trusted derivation of
`wsgi.url_scheme` are additional hosting trust boundaries. When local admission control is
used, the process monotonic clock, WSGI socket-derived `REMOTE_ADDR`, and any custom source
resolver are additional trusted host inputs.
When `team-serve` is used, its protected closed configuration, the exact pinned Waitress
installation, service identity, three path parents, loopback process boundary, and
same-host HTTPS edge are additional trusted inputs. The edge must ensure that only an
externally authenticated HTTPS request reaches a WSGI environment whose scheme is fixed to
`https`; the launcher deliberately does not trust forwarding headers to establish that
fact.
When the native Windows adapter is used, SCM/HKLM administrators, the service registry
ACL, exact pywin32/Python installation, `pythonservice.exe` import path, passwordless
virtual service account, filesystem ACLs, Windows service-control delivery, and
Application event log are additional trusted host boundaries.

For canary comparison, the protected prospective policy, evaluator implementation,
traffic assignment, deployment identities, aggregate producer, effective sample-size
choice, and retained cohort evidence are separate trusted deployment inputs.

A producer private key and provider credentials are secret inputs and are never evidence
documents. A scoped quota token is secret worker input; it is not accepted from an evidence
file. An approval-authority private key is secret authority input and must not be available
to the build/verifier job.

## Current mitigations

- JSON is limited to 5 MiB.
- Trace exports are limited to 16 MiB and 10,000 spans by default.
- Duplicate JSON keys are rejected.
- Duplicate span identities and attribute keys are rejected.
- Unknown properties and policy fields are rejected.
- IDs and hypothesis components must be unique.
- Numeric values, enums, timestamps, and schema versions are validated.
- The parser never executes input as code.
- Evidence references are not fetched or dereferenced.
- Report writes use a same-directory temporary file and atomic replacement.
- The normalized evidence bundle receives a SHA-256 audit digest.
- Canary observations bind the exact policy and review-result bytes plus the canonical
  reviewed change case, component, and change reference. Substitution and post-window
  policy declaration fail closed.
- Canary policy predeclares evaluator reference, exact assignment unit/method,
  sticky assignment, metric direction/tolerances, minimum window/sample sizes, and a
  maximum number of looks. Metric sets and denominators must match exactly.
- Canary binary rates use Wilson score bounds with a conservative family-wise allocation
  across both cohorts, all metrics, and all planned looks. Promotion requires every metric
  to be noninferior; conclusive regression, inconclusive evidence, and invalid design do
  not return promotion.
- A trace manifest is bound to the exact source bytes with SHA-256.
- Detached Ed25519 attestations bind exact artifact SHA-256 and byte count to a producer/key
  identity, validity window, retention requirement, and revocation-list identity.
- Producer identity is resolved from a protected trust-store binding rather than accepted
  from a self-asserted public key.
- Attestation, trust-store, and revocation-list inputs have strict closed parsers; all four
  attestation-related documents have committed schemas.
- Verification rejects signature mutation, artifact mutation, untrusted or out-of-window
  keys, future or expired attestations, stale revocation data, and applicable key
  revocations.
- Compromise revocations invalidate all signatures; retirement revocations preserve only
  signatures issued before the cutoff.
- PEM passwords are accepted through a named environment variable, never as CLI values.
- Downstream fixture generation reparses a strict, closed trace-manifest contract from the
  exact bytes hashed into the new artifact.
- Raw trace content, span names, resource/scope attributes, events, links, and status
  messages are excluded from manifests.
- Only constrained model/provider/kind and non-negative token/cost metadata are retained.
- Trace and trace-scoped span identifiers are domain-separated SHA-256 fingerprints.
- Investigation fixtures are structurally fixed as draft-only, non-gate-eligible, and free
  of inferred causal claims.
- Runtime fixture parsing is closed, duplicate-key rejecting, byte bounded, and rechecks
  exact trace/source subjects, references, counts, ordering, and observation times before a
  selected cluster can enter the Team queue.
- Company-owned adapters run in a spawned, killable child with a wall-clock deadline,
  bounded input/output counts, outcome validation, and reported-cost aggregation.
- Adapter stdout, stderr, and exception messages do not cross the runner boundary.
- The separate sandbox runner accepts only trusted, closed policy objects and
  digest-pinned Linux images; evidence cannot select an image, runtime command, or network.
- Image preflight verifies the exact local repository digest and rejects declared writable
  volumes.
- Each evidence reference runs in a separately named non-root, read-only container with no
  added capabilities or host mounts and bounded CPU, memory, swap, PIDs, temporary
  filesystem, file descriptors, output, and wall time.
- Parent scheduling independently caps simultaneous containers. Pending launches are
  suppressed after failure, and unconfirmed cleanup fails closed.
- Offline workers use Docker's `none` network.
- Connected workers require a provider hard-quota lease before Docker preflight or launch.
  The lease cannot exceed requested cost/concurrency and must authorize exactly the
  requested operation count.
- The connected network must be internal and contain only the named quota proxy before
  launch. Lease tokens are absent from command arguments, environment variables, results,
  representations, and Docker logs.
- Successful connected work uses authoritative settlement cost; all error paths attempt
  lease cancellation, and unconfirmed cancellation fails closed.
- The OpenAI-compatible reference accepts only non-streaming text Responses for exact
  configured models. It atomically holds full configured model-maximum input plus explicit
  output cost before forwarding, hashes lease tokens at rest, replaces worker credentials
  with the provider key, and makes ambiguous provider accounting un-settleable.
- The split-edge pilot gives only the core the provider/admin credentials and
  provider-egress network. Mutually exclusive TLS edges keep admin routes off the worker
  network and worker Responses off the loopback admin listener. Every container is
  non-root, read-only, capability-free, bounded, and denied the Docker socket.
- Pilot preparation binds exact quota bytes into closed host policy, imports the provider
  key from a file, generates an independent admin token, and retains no CA private key. Its
  self-cleaning local qualification tests route isolation, direct-provider denial, and
  restart-persistent leases without issuing a provider API request.
- Azure publication accepts only a TFVC repository provider on an Azure agent and records
  bounded collection, project, build, definition, requester, and source identity.
- Changeset builds cross-check the numeric source version and protected TFVC path.
  Shelveset builds cross-check the exact `name;owner` reference, source branch, and
  shelveset-specific build reason.
- Publication binds the exact JSON result and Markdown report SHA-256 and byte count to the
  parsed review identity and optional sorted work-item IDs.
- Pre-approval verification re-reads the publication and both artifacts, matches the
  current Azure/TFVC context, rejects future or stale publications, requires publication
  within five minutes of review, and emits a closed successful receipt.
- Azure build-summary fields are bounded and Markdown-escaped; collection URIs require
  canonical HTTPS without embedded credentials, query, or fragment.
- The Classic gate uploads the result, report, publication, verification receipt, and
  summary before returning a non-approval status.
- Approval assertions use detached Ed25519 signatures from a protected organizational
  authority; the signed payload includes stable approver identity, authentication method,
  source event ID/time, action, exact publication/receipt subjects, validity, and required
  revocation-list identity.
- Approval trust keys are bound to one authority, validity window, and explicit allowed
  actions. Verification rejects unauthorized actions, invalid signatures, out-of-window
  keys, expired assertions, stale revocations, and applicable compromise/retirement
  revocations.
- The approver event must follow the bound pre-approval verification; the authority must
  issue within 15 minutes; assertion lifetime and the full receipt-to-expiration window are
  capped at 24 hours.
- `approve` can confirm only an existing `approve`. `exception` can record only a
  non-approval and must exactly cover every finding with a non-`none` consequence.
- Approval verification rechecks exact result/report/publication/receipt bytes, rebuilds
  the Azure receipt at its recorded time, and matches the current TFVC build context.
- Both approval actions are `record_only`; the original review decision is retained and a
  verified exception still returns the original non-approval CLI status.
- Team roles are resolved from an exact protected tenant policy rather than accepted from
  a request. Stable principals include both identity-provider and subject IDs.
- Team actions and resource types use a closed compatibility map. Allow and deny decisions
  bind the exact policy SHA-256, byte count, ID, revision, tenant, roles, reason, and time.
- Team audit events embed the decision, bind only a content subject for the acted-on
  payload, enforce a 15-minute authorization window, and distinguish succeeded, failed,
  and denied outcomes.
- Each Team event has a policy-backed minimum retention deadline and a canonical SHA-256
  linking its predecessor. Genesis, cross-tenant, gap, reorder, duplicate event ID, and
  duplicate authorization-decision cases fail closed in a complete export.
- A complete export begins at sequence one, requires a fresh allowed `audit_export`
  decision for its exact export ID, must end at the protected tenant-head digest, and
  retains at least the longest event deadline and current default policy minimum.
- Team export verification rechecks exact export bytes, the full chain, export
  authorization, tenant, and retention floor before emitting a closed receipt.
- The SQLite Team store retains exact historical policy/event/export/case/investigation
  bytes, advances active policy revisions forward only, and requires `BEGIN IMMEDIATE`
  plus an expected tenant-head digest before an event insert and head update commit
  together.
- The store enforces tenant-local event, decision, digest, and export uniqueness. It
  rechecks every appended or exported event against the exact recorded historical policy.
- Minimized case records cross-bind exact change, review, Azure, approval, and canary
  subjects. A record and its authorized successful audit event commit in one transaction;
  failed successor validation leaves neither row nor head advance.
- Case successors preserve the exact base review/change, make recorded delivery/approval
  subjects immutable, and require a new exact canary subject when a look advances.
- Investigation records retain exact fixture subjects and bounded selected-cluster
  summaries without fixture bodies or trace/span references. Candidate-only,
  non-gate-eligible, and non-causal semantics are immutable.
- Investigation successors append exactly one immutable observation or make one material
  queue-state transition. Closure is terminal and requires a typed resolution; assignment
  and tenant-local case/duplicate targets are checked against current protected state.
- Each accepted investigation record and its exact authorized successful audit event
  commit atomically under both expected record revision and tenant-head checks. A denied
  mutation retains a digest-bound denial event rather than the supplied fixture or title.
- SQLite triggers reject ordinary record mutation/deletion, sequence skips, head rewind,
  and policy rollback. The online backup API creates a consistent non-overwriting snapshot.
- The Team HTTP boundary accepts identity only as an exact typed WSGI extension injected
  by trusted hosting middleware. It never treats raw authorization, remote-user, tenant,
  or role headers as authentication or authorization input.
- The closed single-host launcher accepts only canonical loopback, exact Waitress `3.0.2`,
  fixed external `https`, distinct absolute data/control paths, and internally consistent
  server/admission limits. It binds the Entra refresh configuration by exact byte count,
  SHA-256, and `store_id` before database initialization.
- The launcher trusts no proxy and no forwarded header; Waitress clears untrusted proxy
  headers. Admission wraps Entra, which wraps the Team application, so overload rejection
  occurs before bearer parsing. Server return or failure requests bounded managed-refresh
  shutdown.
- Native Windows registration uses a fixed name and virtual account rather than
  `LocalSystem`, enables the service SID, leaves install stopped, and stores one atomic
  registry JSON value containing only host-config schema/path/SHA-256/byte-count. Service
  start requires the exact file subject; configure/remove require SCM stopped.
- The Windows service control path closes the listener, bounds Waitress task drain and
  queued cancellation, closes remaining channels, and closes the managed verifier.
  Lifecycle errors sent to Event Log omit exception text, paths, tokens, and bodies.
- The optional Entra wrapper accepts only bounded canonical `JWT`/`RS256` v2.0 access
  tokens. It rejects duplicate JSON, noncanonical base64url, remote/embedded JOSE keys,
  critical extensions, algorithm substitution, and wrong token profiles before identity
  injection.
- Entra trust is selected by canonical directory `tid`; `kid` lookup and cached public
  keys remain inside that tenant partition. Exact issuer, scalar API audience, immutable
  `oid`, client `azp`, typed time claims, clock skew, and maximum lifetime are verified.
- Delegated access requires an accepted `scp`; app-only access requires `idtyp=app` and an
  accepted application role. Both require an allowed client ID. Mutable email, UPN, and
  display claims never select a Team tenant, subject, or role.
- Entra trust snapshots are closed, duplicate-rejecting, at most 24 hours long, and contain
  multiple validated tenant-specific rollover keys. Wrapped readiness checks snapshot
  freshness, optional dependencies, and every RSA public key.
- The one-shot Entra refresher selects exact tenant-specific discovery/JWKS URLs only from
  a closed protected configuration. It uses verified HTTPS without environment proxies or
  redirects, bounds response metadata/bodies, rejects ambiguous/private key material,
  checks discovery and per-key issuer scope, and constructs every tenant before install.
- Entra snapshot installation requires a valid newer same-store file and uses atomic
  replacement. Request workers retain a still-fresh last-known-good verifier after a
  missing, corrupt, stale, cross-store, or rolled-back candidate without extending its
  original expiration.
- The managed single-process lifecycle performs startup/hourly refresh through one worker,
  retries failure after five minutes, exposes stable status, and fails readiness when that
  lifecycle is absent or dead. Startup fallback requires fresh trust with the configured
  store ID.
- Only an unknown key reached after strict parsing and protected tenant selection can wake
  the worker. Concurrent events coalesce globally, attempts are at least five minutes
  apart, and the triggering request never waits on or retries after network I/O.
- For a same-host multi-process deployment, each coordinated verifier reloads the shared
  local snapshot while an exclusive OS file lock permits one managed writer. Process exit
  releases the lock; one follower can promote and run a guarded startup refresh.
  Follower unknown-key signals use one bounded exclusive-create marker, and ownership is
  rechecked before fetching and immediately before snapshot installation. Inherited
  pre-fork coordinator objects fail closed.
- The Entra wrapper requires trusted HTTPS scheme state, strips preexisting identity and
  integrity values, removes the bearer before invoking Team code, emits generic
  non-cacheable RFC 6750 errors, and does not use `X-Forwarded-Proto`.
- The optional outer admission wrapper rejects full concurrency slots and empty
  global/per-source token buckets before bearer parsing. It ignores forwarding headers,
  caps/idle-prunes source state, holds slots through WSGI iterable cleanup, fails closed
  on invalid/backward time or source integration, and exposes no source keys.
- The host must separately attest request integrity before a POST. Action bodies are
  closed, bounded, duplicate-key rejecting, and cannot supply tenant, role, server IDs, or
  timestamps. Reads verify current membership before revealing whether an event exists.
- Application event appends recheck both the expected head and still-active policy inside
  the write transaction. A concurrent policy advance or competing writer fails without a
  partial event/head update.
- Event-page reads bind active policy, current head, and at most 101 queried rows to one
  SQLite snapshot, return at most 100 contiguous newest-first summaries, and resolve
  current membership before revealing event existence.
- The HTML evidence console receives no payload body, escapes every displayed value, has
  no scripts/forms, and uses no-store, frame/referrer denial, and a CSP that permits only
  same-origin CSS.
- Case-page reads expose only the latest immutable revision per case. The HTML case views
  receive minimized summaries and exact subjects, never raw evidence references, report
  Markdown, approval justification, or canary observations.
- Investigation-page reads filter only after latest-revision selection. Queue HTML receives
  exact fixture subjects and bounded cluster metadata, never fixture bodies, trace
  references, or span evidence references.
- The gate is deterministic and has no network or runtime dependencies.
- The isolated packaging build pins its build backend version.
- CI exit codes fail closed for every decision except `approve` by default.

## Known limitations

- An unsigned SHA-256 digest still detects changes without proving who produced the
  evidence.
- Identifier fingerprints are pseudonymous, not encryption.
- An upstream producer could place sensitive data in an allowlisted metadata field.
- Trace-identity recurrence and queue grouping do not prove that an incident occurred, that
  observations share a cause, or that a harness change is justified. Queue closure and
  case linkage remain investigator claims, not automated causal proof.
- Redaction protects the manifest boundary; it does not remove sensitive data from the raw
  source artifact.
- Evidence references are not yet checked against signed or content-addressed artifacts.
- Attribution confidence is supplied by the upstream investigator.
- Trial independence and variable isolation cannot be proven from JSON alone.
- Retention metadata does not make the CLI store, preserve, delete, or authorize access to
  an artifact.
- Trust stores and revocation lists are protected local policy inputs but are not themselves
  signed against tampering or rollback.
- Local PEM signing does not provide KMS/HSM isolation, key-use authorization, or a
  transparency log.
- A verification receipt is audit metadata, not a signature.
- The CLI provides deterministic tenant authorization and audit contracts but does not
  authenticate identity claims, select a tenant independently, manage membership state, or
  provide hosted approval workflows.
- The WSGI boundary does not change that authentication trust boundary. A flawed OIDC/SSO
  adapter, proxy that forwards spoofable identity headers, or middleware that sets request
  integrity without validating bearer/session and CSRF requirements can fabricate trusted
  context.
- The action endpoint records a caller's claimed external outcome. It neither performs the
  external operation nor proves the operation occurred; the owning integration must
  define ordering, idempotency, and recovery across its side effect and audit append.
- The framework-neutral Team WSGI callable is not a production HTTP host. The bundled
  `team-serve` path adds one pinned loopback Waitress process, Entra bearer middleware,
  bounded server settings, and lifecycle ownership, but it still does not provide public
  TLS, service-manager policy, complete request deadlines, distributed rate limits, queue
  backpressure, or complete abuse controls. The bare Team callable still expects other
  trusted middleware.
- `team-serve` sets `wsgi.url_scheme` to protected configured `https` over a plain
  loopback hop. A malicious local caller that can reach the port may therefore enter the
  HTTPS-only bearer path. The same-host edge must be the sole intended caller, local
  process access is a trust boundary, and tokens must not be exposed to untrusted local
  processes.
- The Windows adapter is not a signed installer and repository tests do not register a
  real service or write HKLM. A per-user Python or inaccessible DLL/package path can make
  `pythonservice.exe` fail before application logging begins. Live SCM install, boot,
  service-account ACL, event-log, recovery, edge, and uninstall behavior require isolated
  host qualification.
- pywin32 reports SCM running before synchronous Entra startup and listener bind complete;
  only `/readyz` is the traffic signal. Stop during a long many-tenant startup sequence is
  not immediately cancellable, so the 45-second management wait can expire while bounded
  per-tenant network work continues toward cleanup.
- The first request carrying a legitimately rolled Entra key can fail once because
  unknown-key recovery is asynchronous. An attacker who knows a trusted tenant ID can
  still cause one bounded refresh attempt per five-minute window without possessing a
  valid signature.
- File coordination covers processes on one host and a supported local volume only. It is
  not a lease across hosts, containers with independent filesystems, network shares,
  synced folders, or distributed filesystems. Deleting/replacing a live lock file or
  allowing an untrusted process to write its protected directory can still deny service or
  undermine election. Multi-host deployments require an external scheduler with
  reload-only workers or a separately reviewed distributed coordinator.
- Admission limits and counters are independent per WSGI process, so total host capacity
  scales with worker count. Liveness/readiness bypass traffic capacity by design, source
  eviction weakens per-source continuity under key churn, and a trusted resolver that
  accepts spoofable forwarding data defeats source partitioning. A trusted edge remains
  responsible for aggregate connection, body, deadline, rate, and concurrency policy.
- The bundled launcher intentionally runs one process and trusts no forwarded client
  address, so the default socket source normally identifies the same-host edge. Enabling
  per-source admission in that topology groups all clients unless a separately reviewed
  protected source resolver is supplied; the global bucket remains the hard local limit.
- The custom refresh client has adversarial offline tests but has not been independently
  audited or qualified against every Entra cloud, enterprise proxy policy, DNS/TLS
  failure, rollover event, or platform scheduler.
- Bearer tokens can be stolen and replayed until expiry. This adapter does not implement
  proof-of-possession, token revocation lookup, Continuous Access Evaluation challenge
  handling, compromise detection, or identity-provider logout.
- Trust-snapshot authenticity and anti-rollback depend on hosting controls. A principal
  that can replace the snapshot can trust its own tenant, audience, client, and key.
- PyJWT/cryptography validation and offline unit tests do not qualify a real app
  registration, tenant issuer, sovereign cloud, proxy, WSGI host, key-roll event, or
  production identity policy.
- The evidence console exposes audit actors, resource IDs, action/outcome metadata,
  content hashes, and retention subjects to any current tenant member. Those identifiers
  must be opaque/minimized; HTML escaping is not anonymization.
- The consoles are mutable read views, not signed audit artifacts. Joined case views
  summarize rather than store complete cases or intervention evidence, while investigation
  views summarize rather than store fixture bodies. Azure, approval, and canary fields are
  point-in-time receipts rather than live checks.
- Case ingestion validates receipt structure and exact cross-bindings but does not contact
  Azure, refresh approval revocations, authenticate an issuer live, prove traffic routing,
  or invoke promotion/rollback. Those checks remain integration responsibilities.
- Minimized titles, proposed-change/review summaries, predictions, TFVC/build identifiers,
  actor IDs, and hashes may still disclose sensitive operational metadata. Escaping is not
  redaction or authorization partitioning within a tenant.
- Queue titles, assignees, model/provider identifiers, counts, timestamps, fixture/source
  hashes, and trace fingerprints may likewise be sensitive. Assignment checks current
  investigator membership when a revision is written; a later policy change does not
  rewrite historical assignment.
- Canary chronology, assignment, evaluator, contamination, deployment, and cohort
  evidence are asserted integration facts. Exact hashing does not prove those facts, and
  opaque evidence references are not fetched or authenticated. Exact review/policy
  digests also do not establish producer or authority identity without protected
  publication, attestation, or signing.
- Canary score bounds assume independent binomial observations. Correlated request samples,
  evaluator drift, sample-ratio mismatch, selection bias, interference, and hidden segment
  regressions can invalidate an aggregate comparison. This alpha does not analyze
  continuous latency/cost distributions or causal treatment effects.
- A canary result is an audit/decision artifact, not a deployment command. External safety,
  availability, latency, and cost controls must retain independent rollback authority.
- A user who can change both the evidence and policy can bypass organizational intent.
- Output paths are trusted operator input and can overwrite a file that process permissions
  allow.
- `ProcessAdapterRunner` remains a process boundary, not an OS security sandbox. Its
  adapter code inherits the invoking account's filesystem and network permissions.
- `ProcessAdapterRunner.max_concurrency` remains cooperative, and its cost check remains
  post-execution. Use the sandbox runner for independently scheduled workers and a
  provider-backed hard quota for connected work.
- The Docker daemon, host kernel, sandbox policy, and orchestration plane can defeat the
  container boundary if compromised. This code does not claim protection from a kernel or
  container-runtime escape.
- Internal-network inspection is a preflight check. A principal that can attach containers
  or alter the network after preflight can violate the dedicated-proxy assumption.
- Docker Desktop needs a non-internal admin-control bridge to publish the loopback admin
  port. The admin edge has no provider/admin credential, but the bridge can permit outbound
  traffic; production must replace it with explicit ingress and egress enforcement.
- Compose secret/config mounts on Docker Desktop are host bind mounts. Read-only container
  flags do not repair a permissive host ACL, and generated Python mode bits are not a
  substitute for reviewed Windows permissions.
- `quota_proxy` is hard only when the controller/proxy's protected model, maximum-token,
  flat-price, provider-usage, TLS, and exclusive-network assumptions match the live
  deployment. The shipped OpenAI-compatible reference is not evidence that those external
  facts hold.
- The reference preauthorizes the full configured maximum billable input to avoid relying
  on a local tokenizer estimate. It does not model threshold prices, cache-write premiums,
  service-tier credits, tool fees, multimodal units, streaming, background work, or remote
  state. Configuring any such surface collapses its cost model.
- SQLite records an ambiguous forwarded operation at its maximum authorized liability and
  blocks settlement, but it does not reconcile organization invoices or prove whether the
  provider ultimately charged the request.
- The worker image must validate the proxy's TLS chain. Pilot preparation emits a scoped CA
  certificate, but the HTTPS URL contract does not install it into a worker image and it
  should not be trusted machine-wide.
- A worker can create threads or subprocesses inside its one-container PID/CPU/memory
  envelope. Parent concurrency counts containers, not internal threads.
- Offline worker cost remains reported after execution. A reported value is not a provider
  quota.
- Container termination does not itself cancel remote work. Connected deployments rely on
  the quota proxy/controller to reject further work and revoke the lease.
- The default unit suite scripts Docker control responses and does not certify any
  particular Docker daemon, Linux kernel, image, proxy, or provider. The separate retained
  a17 local Docker receipt covers only its exact no-provider topology, route, restart, and
  cleanup assertions; it does not generalize to production or live accounting.
- Azure publication and verification receipts are unsigned integrity metadata. A principal
  that controls the pipeline, agent variables, and artifact store can fabricate a
  consistent record.
- `TF_BUILD=True` and other agent variables are not cryptographic authentication outside a
  protected Azure agent job.
- Work-item IDs are recorded and linked in the summary but no Azure Boards relations are
  created or validated in this release.
- `Build.RequestedForId` identifies the build requester, not an authenticated approver.
- The bundled issuer accepts claims only after an external authority has authenticated and
  authorized the human. It does not query Azure, perform SSO, evaluate organizational
  roles, or prove that a caller supplied truthful identity claims.
- An authority that signs arbitrary CLI-supplied claims, or exposes its private key to the
  pipeline/verifier, collapses the identity separation and can fabricate approvals.
- Approval trust stores and revocation lists are protected local policy inputs but are not
  themselves signed against tampering or rollback.
- Assertion IDs and authentication event IDs are structurally validated but global
  uniqueness/replay tracking requires an organizational audit store.
- `record_only` exceptions do not decide deployment authorization. A hosted policy layer
  must define whether and how a verified exception is acted upon without erasing the
  original decision.
- Team access policies are protected local inputs, not signed membership assertions. A
  principal that can replace a policy or roll back its revision can fabricate a consistent
  authorization history.
- A hash chain is tamper evidence, not immutability or producer authentication. A principal
  that controls both events and the authoritative head can rewrite a new internally
  consistent chain unless the head is independently anchored, signed, or held in protected
  immutable storage.
- The artifact-building CLI still computes an event outside shared state.
  `team-store-append` adds atomic compare-and-swap for processes sharing one local SQLite
  database. A shared multi-host service requires a qualified service database; SQLite WAL
  must not be placed on a network share or treated as synced-folder replication.
- Retention deadlines are verified metadata. The SQLite API preserves records and exposes
  no deletion operation, while triggers stop ordinary SQL deletion. A database owner can
  drop those triggers, replace or delete the file, or rewrite every anchor; this is not a
  filesystem retention lock or a WORM guarantee.
- The initial Team export is deliberately complete and capped at 10,000 events. Segmented
  exports, checkpoint proofs, rate limits, and backpressure are not yet implemented. The
  store can create consistent online backups, but off-host backup protection, restore
  drills, recovery objectives, and disaster-recovery qualification remain operational
  work.
- Team event, authorization-decision, digest, export, case-revision,
  investigation-revision, and export-decision uniqueness is enforced within one SQLite
  tenant store. Global uniqueness across independent databases still requires a hosted
  service. The hosted service must also supply decision and event timestamps from its
  trusted clock rather than accept them from an API client.
- Export verification reproduces the export action against its exact policy and verifies
  every event hash/link, but it does not fetch every historical policy needed to reproduce
  every embedded event authorization. Auditors must resolve those exact snapshots from
  protected policy history and verify the events against them.

## Production requirements

Before a hosted or regulated deployment:

1. Keep signing keys in a managed KMS/HSM; authenticate and version trust-store and
   revocation-list distribution.
2. Separate investigator, policy administrator, and approver permissions.
3. Store raw traces, investigation fixtures, and attested artifacts outside the Team
   projections with least-privilege access and enforced retention/deletion controls.
4. Redact secrets and personal data at instrumentation time as well as at collection.
5. Pin policies and engine versions in protected source control.
6. Run approval issuance in an independent identity/authorization service, use separate
   keys for ordinary approval and exception authority where practical, and retain
   assertion IDs in an immutable audit log.
7. Qualify the exact worker digest and Docker/Linux deployment with live filesystem,
   network, resource, timeout, cancellation, and container-escape tests.
8. Use the split-edge pilot only as an integration starting point. Independently qualify
   the provider-specific controller and production TLS/orchestrator boundary against exact
   live model/rate contracts. Prove operation/spend admission before forwarding, invoice
   reconciliation, restart ambiguity, TLS/secret rotation, proxy-bypass resistance,
   network-mutation prevention, and cancellation behavior; keep unsupported billing
   surfaces closed.
9. Restrict Docker/network administration so workers and producers cannot alter policies,
   attach a bypass container, or replace the quota proxy after preflight.
10. For Entra, protect the refresh configuration, snapshot, owner lock, request marker,
    and parent directory. On one local host, create coordinated verifier objects after
    worker fork and monitor the elected owner; across hosts, use a separately reviewed
    distributed owner. Rate-limit ahead of token parsing, and qualify real
    delegated/app-only tokens, issuer forms, key rollover, asynchronous first-request
    failure, proxy scheme handling, token redaction, authentication bypass, bearer replay,
    client/grant removal, and cross-tenant isolation. For another identity provider,
    supply an equivalently reviewed organizational adapter.
11. Put process-local admission outside authentication, derive source partitions only
    from protected connection metadata, size limits against worker count, and independently
    enforce aggregate connection/body/deadline/rate/concurrency policy at the trusted edge.
12. Preserve the store's compare-and-swap and exact-history invariants in any service
    database; add immutable or WORM-capable retention, independent head anchors, rate
    limits, protected off-host backups, and tested disaster recovery.
13. Protect Classic Pipeline definitions, TFVC mappings, agent pools, and build-artifact
    retention; require the real-case gate task on every protected path.
14. Fetch Azure approval identity/status directly in the protected authority where Azure
    is the identity source; never derive an approver from build requester variables or the
    build-service token.

Do not place personal access tokens, model API keys, raw customer conversations, or signed
download URLs in evidence files.
