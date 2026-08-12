# Changelog

All notable changes will be documented in this file.

## Unreleased

### Changed

- Rebranded the pre-public product as **Causure** (pronounced “cause-sure”) with the
  descriptor “Causal assurance for production AI-agent changes” and the principle “Change
  only what the evidence supports.”
- Renamed the Python distribution, import namespace, module launcher, and primary command
  from the former product name to `causure`; the Windows service command is now
  `causure-windows-service`.
- Renamed active configuration, environment, finding-code, media-type, schema, container,
  service, and GitHub Action identifiers to the `causure`, `CAUSURE_`, or `CAUSURE-`
  forms. This is an intentional pre-public breaking change with no legacy aliases.
- Advanced the alpha package and engine version to `0.4.0a18`. The existing Azure DevOps
  TFVC project path remains an administrative legacy mapping and completed qualification
  receipts remain immutable historical evidence.
- Invalidated the pre-rebrand Docker image IDs instead of relabeling their evidence. The
  Causure wheel input is hash-bound, while the Causure quota-pilot images now explicitly
  require a fresh offline qualification.
- Added a fresh-environment installed-wheel qualification for `causure` `0.4.0a18` that
  verifies the distribution/import versions, console entry point, absence of the legacy
  namespace, and both offline demo decisions without network access.

### Added

- A zero-credential `causure demo` that packages and deterministically reviews a
  justified minimal patch and an overbroad rejected change, then writes readable reports,
  canonical results, and a compact outcome index without overwriting existing output.
- New-only `causure init` project setup with a valid default policy, minimized
  configuration, trusted-adapter boundary, generated-state ignore rules, and disabled raw
  trace storage.
- A read-only `causure doctor` with text and stable JSON diagnostics for package,
  demo, configuration, policy, adapters, permissions, Git, and optional Docker readiness,
  plus a ten-minute getting-started guide.
- A guided `causure investigate` path that composes exact OTLP collection and
  candidate-only fixture generation, previews redaction before any write, supports numbered
  interactive or explicit automated selection, and creates deterministic hash-bound local
  workspaces without raw trace content or stored source paths.
- A nested `causure case create` wizard that strictly verifies the investigation
  selection and artifact subjects, gathers case facts and optional completed evidence in
  plain language, generates canonical change-case JSON internally, and immediately writes
  the human report, machine result, and exact source binding. Missing trials, hypotheses,
  controls, and measurements remain absent and produce explicit evidence requests.
- A committed `investigation-selection` JSON Schema and strict downstream loader covering
  fixed candidate-only flags, source minimization, artifact paths, digests, byte counts,
  selected cluster identity/order, and exact manifest/fixture consistency.
- A deterministic public-snapshot checker that rejects TFVC/Git metadata, generated or pilot
  state, credential and private-key signatures, unsafe GitHub workflow boundaries, missing
  community files, and mutable third-party action references without printing matched
  secret values.
- Least-privilege, commit-pinned GitHub CI, CodeQL, dependency-review, and Dependabot
  configuration, plus CODEOWNERS, structured issue forms, a pull-request template, and
  support guidance.
- A one-way TFVC-to-GitHub mirror decision and private-first publication runbook with
  separate approvals for repository creation, Git history, push, and public visibility.
- The unmodified Apache License 2.0 terms, matching SPDX Python package metadata, and ADR
  0027 recording the permissive public-distribution decision and contribution boundary.
- A productization roadmap that audits the original research and company-product promises,
  makes a no-manual-JSON local journey and GitHub-native review the next priorities, and
  records measurable exit criteria through enterprise deployment and PatchOrNotBench.
- A portfolio engineering case study with a user-flow architecture diagram, measured
  evidence, trust boundaries, explicit production limits, and a bounded public claim, plus
  a privacy-safe 90-second demo script and final-capture checklist.
- ADR 0031 and a gated clean-history runbook that preserve the current GitHub evidence in a
  private archive, handle public-fork and rename consequences explicitly, and require a fresh
  one-root-commit public snapshot and qualification.
- A machine-readable clean-public-history verifier requiring one parentless commit across all
  refs, the `main` branch, a clean tree, and the exact `Creation of Causure` subject.
- A minimized P0-A unfamiliar-user protocol with an exact-distribution binding, objective
  comprehension and timing criteria, zero-assistance requirement, and privacy-safe result
  template.
- A retained installed-wheel P0-A engineering audit binding the exact distribution and
  confirming the short help, explained demo decisions, and readable report while explicitly
  preserving the remaining unfamiliar-human criterion.
- A privacy-minimized P0-A unfamiliar-user qualification binding the exact wheel and verified
  demo artifacts: one unfamiliar participant finished in under five minutes with zero
  assistance, opened a Markdown report, and correctly explained both evidence-gated outcomes.
- A closed GitHub pull-request publication and verification contract, public Python API,
  committed JSON Schemas, and `github-publish` / `github-verify` commands binding exact
  case/result/report bytes to repository IDs, PR head/base SHAs, event payload subject,
  workflow definition/SHA, run attempt, fork state, and changed harness component.
- A root composite GitHub Action that performs deterministic review, PR/run publication,
  exact re-verification, Check Run planning, and job-summary generation in one step while
  loading its own source through Python isolated mode and confining caller paths to the
  workspace.
- A bounded GitHub Checks API publisher, `github-check-run` CLI, public Python API, and
  committed request/receipt schemas. The token-free request fixes the head SHA, stable check
  name, decision conclusion, workflow details, exact verification subject, and at most 50
  decision-affecting annotations; the minimized receipt rebinds GitHub's accepted identity
  to those exact bytes.
- A company-facing Action guide with a least-privilege caller workflow, full-commit action
  pins, caller-controlled evidence retention, explicit same-repository/fork modes, and a
  fork-compatible branch-protection target.
- Project-configuration schema 3.0 with backward-compatible 1.0/2.0 reads, closed GitHub
  component path/case mappings, artifact-retention behavior, validated trusted adapter
  registrations, and optional case-generator bindings. ADR 0028 records the
  one-canonical-config decision.
- `causure github-configure` for atomically adding one component mapping without
  manually editing JSON, plus read-only `doctor` validation of configured case presence and
  component type.
- `causure adapter-configure` for registering a reviewed replay, evaluator, or case
  generator entry point without importing it, including an atomic component binding for
  generators.
- A bounded GitHub PR-file discovery and deterministic selection layer with rename support,
  no-match success, ambiguous-match failure, paired explicit overrides, and Action outputs
  for the selected component/case/path and caller-controlled retention.
- A closed `CaseGenerationRequest`/adapter contract and `causure case generate`
  path that bind a canonical case to the exact GitHub repository, PR, base/head SHAs,
  component path/digest, expected change reference, and execution limits.
- A protected-base process runner and generation orchestrator with isolated trusted-module
  loading, candidate-as-data containment, component/adapter/module mutation checks,
  timeout/output limits, immediate deterministic review, new-only writes, and a minimized
  committed-schema provenance receipt.
- A companion `trusted-case-generator` composite Action that verifies separate exact-base
  and exact-head checkouts, reuses bounded PR-file selection, returns no-match or
  committed-case routing without loading an adapter, and rejects generator-backed forks
  before Git or adapter execution. ADR 0029 records this trust split.
- A credential-free GitHub-native example kit and local qualifier for approve, abstain, and
  needs-evidence stories, plus a full-SHA two-checkout workflow template retaining both
  generation and review evidence chains.

### Changed

- Classic CI now runs the strict public-release gate. The selected license makes the source
  candidate ready while repository creation and visibility remain separate owner actions.
- Git and TFVC ignore boundaries now cover TFVC local metadata, encrypted PAT handoffs,
  common key formats, generated databases, and prepared quota-pilot state.
- Documentation link validation now excludes ignored source-control, virtual-environment,
  build, distribution, coverage, and formatter-cache trees rather than inspecting bundled
  third-party notices as project documentation.
- Empty and short CLI help now lead with the one-command demo and three-command real-data
  path, while `--help-all` retains the complete automation and enterprise catalog. Demo and
  initialization summaries now explain decisions and print the next product action directly.
- The composite Action now defaults to canonical project configuration instead of requiring
  repeated case/component inputs. The caller workflow grants `pull-requests: read`, and its
  upload step can consume the configured `artifact-retention-days` output.
- The root composite Action now accepts a workspace-confined `repository-root` so it can
  review a separate exact-head checkout populated by protected generation. Dependabot's
  default automatic mode preserves the stable workflow gate while skipping only a custom
  Check Run write that its downgraded token cannot perform.

### Security

- Candidate workflows cannot use `pull_request_target`, repository secrets, blanket write
  permissions, or symbolic third-party action refs.
- GitHub review context accepts only unprivileged `pull_request` events, derives the
  candidate from `pull_request.head.sha`, cross-checks event and environment identity, and
  retains only the event hash/count rather than raw PR content. The offline contract makes
  no GitHub API write and grants no merge authorization.
- The network publisher is same-repository only, uses the job's short-lived token solely at
  the HTTPS boundary, accepts one fixed GitHub.com endpoint, disables redirects, bounds
  request/response/time, validates the returned Check Run identity, and never persists the
  token. Fork `auto` mode performs no write and never asks for a secret or write token.
- Automatic selection reads only fixed GitHub.com pull-request endpoints, caps discovery at
  500 files, validates pagination and JSON boundaries, and rechecks exact event base/head
  identities after discovery. It refuses candidate-modified project config or policy and
  never imports configured adapter entry points.
- Trusted case generation imports only from a bounded, mutation-checked protected adapter
  tree and never places the candidate root on Python's import path. It accepts one bounded
  regular component file, requires exact candidate identity in output, omits component data
  and absolute candidate paths from the receipt, and fails generator-backed forks before
  executing protected code. The trusted adapter remains privileged code rather than an OS
  sandbox and must treat the candidate as data.
- GitHub publication must start privately and pass scanning, required checks, ruleset, and
  private-reporting review before a separately authorized visibility change.
- Upgraded every optional cryptography, quota-pilot, Classic CI, and Windows service-bundle
  contract from `cryptography==49.0.0` to patched `50.0.0` for CVE-2026-69247. The prior
  bundle qualifications remain historical evidence for their old dependency set and do not
  qualify a newly built bundle.
- Qualified the TFVC-first cryptography remediation through a public protected pull request,
  made the successful dependency-review job required on `main`, retained green pre-merge and
  post-merge CI/CodeQL evidence, and recorded GitHub's fixed advisory and zero-open-alert
  state without rewriting the earlier public-fork receipt.
- Updated the verified GitHub-owned Action pins to checkout `v7.0.1`, setup-python `v7.0.0`,
  and the signed CodeQL `v4.37.6` release commit; documented their Node 24 runner boundary;
  and advanced the development formatter to Ruff `0.16.2` with its single deterministic
  documentation reformat.

## 0.4.0a17 — 2026-08-09

### Added

- A closed exact-Waitress `openai-quota-serve` host that binds exact quota bytes, SQLite,
  protected secret-file paths, listener resources, and a fixed HTTPS scheme while trusting
  no forwarding headers.
- `openai-quota-pilot-prepare` for new-only protected state: exact quota copy, provider-key
  file import, separate generated admin token, short-lived pilot CA/server certificate,
  secret-free manifest, and no retained CA private key.
- A split-edge Docker pilot with mutually exclusive worker/admin Caddy routes, an internal
  worker network, an internal core backend, provider egress confined to the core, and a
  loopback-published Docker Desktop admin-control bridge.
- Exact digest-locked Python/Caddy inputs, a hash-locked Waitress wheel, a
  content-bound/network-disabled local image builder, and a self-cleaning qualification
  harness that refuses mutable image tags.
- One retained Windows 11/Docker Desktop no-provider qualification covering verified TLS
  health/readiness, mutual route exclusion, direct-provider denial from the worker network,
  non-root/read-only/capability-free containers, lease persistence across a core restart,
  and complete disposable container/network/volume cleanup.
- The initial local observer attempt is also retained as failed evidence: its disposable
  cleanup passed, but a strict-mode empty network-diff property check stopped evidence
  capture. The observer was corrected and rerun rather than relabeling that receipt.
- A company pilot operator guide, host JSON Schema, example host policy, and ADR 0025.

### Changed

- Version advanced to `0.4.0a17`; the exact historical a15 Windows service bundle receipt
  and a16 quota-reference boundary remain unchanged.
- The provider-quota roadmap now separates the completed offline one-host pilot from live
  provider reconciliation and production TLS/secret/orchestrator qualification.
- Classic CI parse-checks the new PowerShell build and qualification harnesses, while live
  Docker execution remains an explicit operator action.

### Security

- Only the quota core receives provider/admin credentials and provider egress. Workers see
  a worker-only TLS edge and scoped lease token; the loopback admin edge has no provider or
  bearer credential and no worker/provider network.
- Pilot state must inherit protected host ACLs. Docker Desktop bind-mounted Compose secrets
  and Python mode bits do not repair permissive Windows permissions.
- The retained receipt makes no provider API request and performs no invoice
  reconciliation. Model identity, prices, live accounting, production TLS/secret rotation,
  registry admission, network mutation, and disaster recovery remain required external
  evidence before a hard-spend claim.

## 0.4.0a16 — 2026-08-09

### Added

- A first provider-specific `OpenAIQuotaController` and closed
  `OpenAIQuotaWSGIApplication` reference path for non-streaming, text-only
  OpenAI-compatible `/v1/responses` operations.
- `SQLiteOpenAIQuotaStore` with atomic lease admission, exact operation and concurrency
  limits, full configured model-maximum preauthorization, nanodollar ceiling arithmetic,
  hashed lease tokens at rest, authoritative usage settlement, cancellation, expiry, and
  worst-case accounting for ambiguous provider work.
- Direct verified HTTPS provider/admin clients with no redirects or environment proxy, a
  versioned secret-free pricing/configuration contract, JSON Schema, non-operational
  example, operator guide, and ADR 0024.
- Adversarial tests for concurrent admission, cost-before-forward ordering, credential
  separation, request-surface closure, expiry/revocation, missing or out-of-bound usage,
  provider non-success, and secret-free diagnostics.

### Changed

- Version advanced to `0.4.0a16`. The separately qualified offline Windows service bundle
  remains the exact historical `0.4.0a15` artifact; no a16 Windows bundle qualification is
  claimed.
- The provider-quota roadmap now distinguishes the shipped reference implementation from
  the still-open managed Docker/orchestrator and live-provider qualification gate.

### Security

- Workers receive only a high-entropy scoped lease credential and must identify its lease;
  the proxy replaces that credential with the provider key, which is never persisted in
  quota configuration, lease storage, receipts, or diagnostics.
- Only exact configured models and bounded text inputs are accepted. Streaming, background
  work, provider-hosted tools, files, images, conversations, and arbitrary endpoints remain
  closed because their spend cannot yet be bounded by this implementation before forwarding.
- Provider timeout, non-success, model mismatch, missing usage, or out-of-bound accounting
  revokes the lease, retains its maximum authorized liability, and prevents clean settlement.

## 0.4.0a15 — 2026-08-09

### Added

- A byte-for-byte reproducible, offline Windows service bundle builder that stages one
  private 64-bit CPython runtime from exact local wheels, removes target-dependent launchers
  and records, validates the staged service contract, rejects reparse points, and closes
  every managed file by byte count and SHA-256.
- Elevated machine install/remove workflows with fixed versioned Program Files layout,
  protected manifest/receipt state, exact host-policy binding, service-specific ACLs,
  ACL restoration, rollback-aware installation, interrupted-removal continuation, and deliberate
  preservation of operator config, identity state, SQLite data, backups, logs, and evidence.
- A live self-cleaning bundle qualification harness covering machine install, receipt and
  manifest integrity, real two-minute crash recovery, configuration-subject drift, loopback
  port collision, restored readiness, running-service removal, and operator-data survival.
- A separately authorized, restart-safe cold-boot harness that probes its exact verifier as
  64-bit `LocalSystem`, installs the exact a15 bundle in delayed-automatic mode, arms one
  hash-bound SYSTEM startup task, tests service-scoped network loss and the post-boot
  non-crash recovery sequence, restores readiness, and removes its task, firewall rule,
  bundle, and disposable state. Arming deliberately does not issue the reboot itself.
- A Windows bundle operator guide and ADR 0023.

### Changed

- Version advanced to `0.4.0a15`.
- Native service install now sets and reads back a closed SCM recovery policy: reset after
  900 seconds, restart once after 120 seconds, then no action, including non-crash failures.
- Native service removal now disables the stopped service before deletion and restores its
  prior start mode if SCM rejects deletion, preventing a queued recovery restart from racing
  removal.
- The administrative service CLI adds machine-readable `recovery-set` and
  `recovery-status` commands that do not expose recovery command or reboot-message values.
- The cold-boot completion task runs from its separate protected report directory and
  explicitly moves both the PowerShell and process-level current directories there before
  deleting the disposable qualification root; Windows cannot remove a process's current
  working directory.
- The first authorized cold-boot run is retained as failed-at-cleanup evidence rather than
  relabeled: every boot/recovery/readiness/removal assertion passed, but the task working
  directory prevented disposable-root deletion. The exact orphaned root was removed only
  after its protected report was archived and hash-verified.
- The second authorized run is also retained as failed evidence. It proved the corrected
  root cleanup, but exposed that the negative recovery case incorrectly used the ordinary
  administrative start command, whose contract waits for SCM `RUNNING`. SCM event 7031
  recorded the expected non-crash termination and scheduled 120,000 ms restart, while the
  command correctly returned failure because intentionally unavailable trust prevented
  `RUNNING`; the harness now sends a direct non-waiting SCM start request and immediately
  captures its process ID before observing the bounded recovery sequence.
- The third authorized run is retained as failed observer evidence. Its non-waiting start
  produced SCM event 7031 with failure count 1, restart action code 1, and 120,000 ms delay,
  followed 121.063 seconds later by event 7034 with failure count 2 and no loop; the
  250-millisecond CIM poll still missed that short recovered process. Recovery qualification
  now gates on those durable structured event properties and their bounded timestamps,
  treats a recovered PID as optional corroboration, and rejects a count-3 event.
- The fourth authorized run passed on Windows 11 Pro build 26200. It observed a new boot,
  delayed automatic startup, separately gated health/readiness 200, exact structured SCM
  events 7031/7034 across 121.197 seconds, one restart under service-scoped network loss,
  a bounded second failure with no count-3 event, exact trust/recovery restoration,
  readiness 200 after restoration, running-service removal, operator ACL restoration, and
  zero managed residue or cleanup errors. The canonical
  [cold-boot evidence](docs/qualifications/windows-service-cold-boot-2026-08-09.json) has
  SHA-256 `be019bac5afb0fb0cad0919aae92375eb89a7670f4e0f448ee0cb7cee133f351`.
- Team-host shutdown now treats only `EBADF`/`ENOTSOCK` (including Windows
  `WSAENOTSOCK 10038`) as an expected Waitress listener-close race, and only after an
  intentional shutdown has already begun; unrelated loop errors still propagate.
- The exact a15 bundle passed the self-cleaning Windows 11 build 26200 qualification:
  byte-identical rebuilds produced SHA-256
  `16ee1b521d70fa0670e1c2099843bc8a2ae22dd9520772748d6345ec1b6daf04`, real crash
  recovery completed in 121.69 seconds under a new PID, both adversarial failures stopped
  without loops, recovery was restored, and running-service removal preserved operator
  paths and ACLs. The sanitized result is committed as
  [bundle qualification evidence](docs/qualifications/windows-service-bundle-2026-08-09.json).

### Security

- Recovery configuration requires stopped state, reads both prior SCM values, writes both
  bounded values, verifies the exact result, and attempts complete rollback after a partial
  failure. Install treats recovery setup as part of its service-creation transaction.
- Bundle installation rejects unsafe/duplicate paths, unknown manifest fields, unmanifested
  files, integrity mismatches, reparse points, incompatible versions, and pre-existing fixed
  machine targets before service mutation.
- Runtime ACL hardening now protects only the versioned root, propagates its SYSTEM,
  Administrators, and service-SID rules through inheritance, and verifies every descendant;
  it rejects protected child ACLs instead of risking empty child DACLs.
- Removal advances its protected receipt with a supported atomic replacement and fixed
  protected backup, retains that marker across partial runtime/manifest deletion, removes
  the backup and receipt last, and rejects a stale backup during a new install.
- The bundle is hash-closed but intentionally described as unsigned: manifest integrity
  does not authenticate a publisher. Production distribution still requires an enterprise
  signature and authenticated delivery of the artifact hash.
- Cold boot is not implied by either a normal live run or a successfully armed startup
  task. Reboot remains separately authorized because Windows applies the non-crash failure
  flag after a system start; the cold-boot report must be inspected before recording a pass.

## 0.4.0a14 — 2026-08-03

### Added

- An idempotent `TeamHostServer` controller around exact Waitress `3.0.2`, with
  control-thread listener close, bounded task drain/cancellation, remaining-channel close,
  and managed Entra lifecycle cleanup.
- An optional native Windows SCM adapter pinned to pywin32 `312`, using the fixed
  `CausureTeam` service and passwordless `NT SERVICE\CausureTeam`
  virtual account instead of `LocalSystem`.
- A separate `causure-windows-service` command with explicit
  install/configure/start/stop/status/remove operations, a Windows operator guide, and ADR
  0022.
- An opt-in elevated `qualify_windows_service.ps1` harness with fixed-target preflight,
  isolated runtime staging, real SCM/HKLM/ACL and loopback-readiness checks, sanitized
  evidence output, and service-first cleanup.
- Offline fake-SCM/registry tests, a real ephemeral-loopback Waitress stop test, and safe
  service-entry Event Log tests that never register a real service during CI.

### Changed

- Version advanced to `0.4.0a14`.
- The `windows-service` optional extra adds exact pywin32 to the existing exact service
  dependencies; Windows development/Classic validation now verifies that version.
- The single-host guide now links the native Windows supervision path. The Team roadmap
  marks native single-host Windows supervision and one isolated live SCM lifecycle check
  complete while leaving signed packaging, production edge/host, live-identity, and
  multi-host qualification open.

### Security

- SCM stores one compact registry value binding the canonical absolute host-config path,
  SHA-256, and byte count. A config edit requires a stopped-service `configure` action or
  the next start fails closed.
- Host data/control paths and the Windows service host-config path now reject Windows
  UNC/device/network-share forms instead of relying on documentation alone.
- Install validates the host and Waitress contract before SCM mutation, enables the
  service SID, leaves the service stopped, and attempts rollback if SID/registry setup
  fails. Registry state contains no credential or config body.
- Configure and remove refuse to operate unless SCM reports stopped. Removal never stops
  implicitly or deletes configuration, Entra trust, SQLite data, backups, or logs.
- SCM running is explicitly not readiness; `/readyz` at the trusted edge remains the
  traffic gate. The exact a14 wheel passed a self-cleaning Windows 11 SCM lifecycle run,
  including its virtual account, unrestricted service SID, exact registry subject,
  health/readiness, graceful stop, and removal. Machine-wide Python accessibility,
  production ACLs/edge, recovery policy, boot/network behavior, real Entra identity, and
  target-host qualification remain operator responsibilities.

## 0.4.0a13 — 2026-08-03

### Added

- A closed `TeamHostConfiguration` contract and committed schema covering absolute
  database/trust paths, exact server identity/version, Entra refresh-policy subject,
  managed refresh lifecycle, and process-local admission limits.
- A `team-serve` command that initializes the single-host store, starts one managed Entra
  verifier, composes admission outside authentication outside the Team application, and
  serves it through pinned Waitress `3.0.2`.
- A `service` optional dependency extra, single-host operator guide, and ADR 0021, plus
  lifecycle, parser, CLI, dependency-version, and real Waitress-adjustment tests.

### Changed

- Version advanced to `0.4.0a13`.
- Classic validation now requires the exact Waitress runtime used by the supported
  launcher in addition to the existing exact cryptography dependency.
- The Team roadmap now distinguishes the completed closed one-process loopback launcher
  from outstanding public-edge, multi-host, live-Entra, and production qualification.

### Security

- The launcher accepts only canonical `127.0.0.1` or `::1`, asserts a protected external
  HTTPS scheme, trusts no proxy or forwarded header, clears untrusted proxy headers, and
  requires a trusted same-host HTTPS edge.
- Startup binds the exact Entra refresh configuration by byte count, SHA-256, and
  `store_id` before database initialization; relative/colliding paths, unknown fields,
  inconsistent limits, and dependency drift fail closed.
- Waitress threads, connections, backlog, channel timeout, headers, and the existing 24
  MiB Team request-body limit are bounded; tracebacks and request lookahead are disabled.
  Managed refresh is synchronously started and context-managed so server return or failure
  requests bounded worker shutdown.
- This remains one process on one host. Public TLS, aggregate edge controls, source-IP
  policy, multi-host storage/refresh, WORM retention, disaster recovery, and live Entra
  deployment qualification remain operator responsibilities.

## 0.4.0a12 — 2026-08-03

### Added

- A closed candidate-only `TeamInvestigationRecord` with exact fixture subjects, bounded
  cluster summaries, immutable observations, explicit ownership, typed priority/status,
  and terminal resolutions that do not imply causality.
- A version-3 SQLite investigation index with monotonic revisions, exact audit-event
  binding, latest-revision filtering, tenant-local case/duplicate links, atomic rollback,
  and transactional migration from valid version-1 and version-2 stores.
- Authorized open, observation-attachment, and queue-transition application operations;
  closed JSON routes; and script-free minimized overview/detail pages.
- Bundled schemas for the investigation record, three mutation requests, page, and detail;
  strict public investigation-fixture parsing; ADR 0020; and an operator guide.
- Adversarial candidate-boundary, source-substitution, successor, assignment, linkage,
  denial-minimization, CAS, XSS, filtering, migration, and rollback tests.

### Changed

- Version advanced to `0.4.0a12`.
- Investigation fixtures now have strict object/byte parsers in addition to deterministic
  generation and rendering.
- The Team roadmap now marks incident clustering and investigation queues complete.
- Existing Team stores are upgraded additively to schema version 3 when
  `SQLiteTeamStore.initialize` or `team-store-init` runs; operators should still back up
  and test restore first.

### Security

- Every queue revision is the exact payload subject of its authorized successful audit
  event, committed atomically with the tenant-head advance. A failed fixture, successor,
  linkage, policy, or head check leaves no partial record.
- Queue records never retain fixture bodies, trace references, or span evidence references;
  unauthorized attempts retain only a digest-bound denial event.
- Automated trace-identity clustering remains candidate-only, non-gate-eligible, and free
  of inferred causal claims. Closure requires an explicit typed investigator disposition.
- Minimized titles, actors, fingerprints, counts, timestamps, and allowlisted identifiers
  may still be sensitive, and SQLite remains single-host tamper evidence rather than WORM
  retention.

## 0.4.0a11 — 2026-08-03

### Added

- A closed, minimized `TeamCaseRecord` that cross-binds exact change-case, review,
  Azure publication/verification, approval-verification, and canary-result artifacts
  without retaining raw evidence references, report Markdown, approval justification, or
  canary observations.
- A version-2 SQLite case index with immutable rows, monotonic case revisions, exact
  event binding, consistent latest-case reads, cursor pages, atomic event/record commit,
  and transactional automatic migration from a valid version-1 store.
- Authorized `publish_case`, `list_cases`, and `get_case` application operations plus
  closed JSON routes and script-free server-rendered case overview/detail pages.
- Bundled schemas for the case record, exact-artifact publication request, page response,
  and detail response; public case/canary parser APIs; ADR 0019; and an operator guide.
- Adversarial source-substitution, chronology, minimization, XSS, authorization, CAS,
  rollback, pagination, immutability, and migration tests.

### Changed

- Version advanced to `0.4.0a11`.
- Canary comparison results now have strict public object/byte parsers in addition to the
  deterministic renderer.
- The Team roadmap now marks the full joined change-case dashboard complete.
- Existing version-1 Team stores are upgraded additively when `SQLiteTeamStore.initialize`
  or `team-store-init` runs; operators should still back up and test restore first.

### Security

- Every displayed stage retains an exact media type, digest, and byte count, and each case
  revision is the payload subject of its authorized successful audit event in the same
  transaction. Failed revision validation leaves no partial event or head advance.
- Recorded delivery/approval subjects cannot be swapped behind an unchanged summary;
  continuing canary looks must advance both their look and exact result subject.
- Stored summaries revalidate approval validity/revocation chronology, Azure publication
  order and TFVC path shape, and canary window/deployment invariants when read.
- Dashboard receipts are explicitly point-in-time evidence. Ingestion does not perform a
  live Azure/build/revocation/authentication/deployment check, and minimized narrative or
  stable-ID fields may still be sensitive.

## 0.4.0a10 — 2026-07-29

### Added

- Closed canary-policy, canary-observation, and canary-result contracts plus committed
  JSON Schemas and a synthetic prospective-policy example.
- `compare_canary_outcomes` with exact policy/review/case/change bindings, higher- and
  lower-is-better binary metrics, explicit noninferiority tolerances, and stable
  `promote`, `continue`, `rollback`, and `needs_evidence` outcomes.
- A `canary-compare` CLI that emits exact-artifact-bound JSON and Markdown and preserves
  non-promotion exit status unless `--allow-continue` is explicitly selected.
- ADR 0018, an operator guide, public APIs, and adversarial parsing, substitution,
  chronology, metric-set, sample/window, contamination, regression, and deterministic
  rendering tests.

### Changed

- Version advanced to `0.4.0a10`.
- The Team-service roadmap now marks bounded post-deployment canary comparison complete;
  rendering those results in the full change-case dashboard remains separate.
- The canary policy prospectively fixes evaluator reference, assignment unit/method,
  sticky-assignment requirement, metric thresholds, minimum evidence, and maximum planned
  looks.

### Security

- Observations cannot substitute another exact policy, review result, canonical change
  case, component, or change reference. Policy/review chronology must precede exposure.
- Wilson score intervals receive a conservative Bonferroni family-wise allocation across
  both cohorts, every declared metric, and every planned look. An inconclusive final look
  cannot be extended post hoc under the same policy.
- Opaque evidence references are never fetched, and raw prompts, messages, principal
  records, or per-request data are unnecessary at this boundary.
- Routing, evaluator, contamination, independence, and aggregate-evidence claims remain
  trusted integration facts; results never execute deployment promotion or rollback.

## 0.4.0a9 — 2026-07-29

### Added

- `TeamAdmissionControlMiddleware`, an outer WSGI backstop with a non-blocking bounded
  concurrency semaphore plus global and optional per-source token buckets.
- `TeamAdmissionStatus` with non-sensitive active/tracked counts, admitted/rejected totals,
  and a stable integration error code.
- Bounded source-state pruning/eviction, normalized socket-source defaults, probe-specific
  behavior, generic `429`/`503` responses, and safe slot release across WSGI streaming,
  close, and exception paths.
- ADR 0017 plus deterministic configuration, refill, backward-clock, source-spoofing,
  source-cardinality, concurrent-burst, saturation, liveness/readiness, cleanup, and
  pre-bearer-ordering tests.

### Changed

- Version advanced to `0.4.0a9`.
- The recommended Entra WSGI construction now places admission outside authentication so
  rejected traffic never reaches authorization-header parsing or signature verification.
- The roadmap now separates completed process-local admission from qualified production
  HTTP serving and distributed edge enforcement.

### Security

- Default source partitioning uses normalized `REMOTE_ADDR` only and never trusts
  `Forwarded`, `X-Forwarded-For`, or another HTTP header.
- Global capacity remains the hard local ceiling when bounded per-source state evicts old
  keys. Invalid/backward monotonic time and invalid custom source keys fail closed.
- Concurrency ownership lasts through response-iterable completion or close, preventing a
  streaming or exceptional application path from silently releasing or leaking a slot.
- Limits remain independent per process and do not replace trusted-edge connection, body,
  deadline, aggregate rate, or distributed concurrency controls.

## 0.4.0a8 — 2026-07-29

### Added

- `LocalFileEntraRefreshCoordinator`, a process-bound, cross-platform local-volume owner
  lock plus bounded exclusive-create refresh-request marker.
- `CoordinatedEntraAccessTokenVerifier`, which gives every local process an atomic
  last-known-good reloader while electing one managed network refresher, relaying follower
  unknown-key requests, and promoting a follower after owner exit.
- `EntraCoordinatedRefreshStatus` and stable coordination errors without configuration,
  path, token, or key disclosure.
- ADR 0016 plus deterministic election, request coalescing, subprocess crash recovery,
  guarded-install, follower-offline, rollover-relay, startup-deadline, and failover tests.

### Changed

- Version advanced to `0.4.0a8`.
- The recommended same-host multi-process Entra host construction now uses coordinated
  post-fork verifier instances against one protected local snapshot/lock/marker set.
- The roadmap now separates completed same-host process ownership from multi-host
  distributed ownership, production HTTP hardening, and live Entra qualification.

### Security

- Only the OS-lock owner may create a managed refresher or consume a rollover request.
  Followers never fetch during ordinary startup or request verification.
- Managed refresh checks ownership before retrieval and immediately before atomic
  installation. Missing/replaced ownership rejects the candidate; objects inherited across
  a process fork fail closed.
- Concurrent unknown-key requests coalesce in one bounded marker and still pass through the
  owner's five-minute cooldown. The triggering request is neither retried nor blocked.
- File election is explicitly limited to protected paths on one host and a qualified local
  volume. It is not a multi-host lease and does not support network shares, synced folders,
  or independent container filesystems.

## 0.4.0a7 — 2026-07-29

### Added

- `ManagedEntraAccessTokenVerifier`, an explicit lifecycle owner that performs startup
  refresh, runs one periodic background worker, retries refresh failures, delegates
  validation to the atomic reloader, and supports bounded asynchronous unknown-key
  recovery.
- `EntraManagedRefreshStatus` with non-sensitive running, in-progress, attempt-count,
  reason, stable-error, and last-success timestamp fields.
- A bounded protected-configuration file loader for host integrations.
- ADR 0015 plus deterministic lifecycle, fallback, periodic rollover, concurrent
  singleflight, cooldown, untrusted-tenant, and shutdown tests.

### Changed

- Version advanced to `0.4.0a7`.
- Successful refreshes schedule the next attempt after one hour by default; failures retry
  after five minutes while still-fresh last-known-good trust remains usable.
- Reloading verifiers now expose the installed store ID and snapshot refresh/expiry
  timestamps for protected lifecycle coordination.
- The roadmap now separates completed single-process managed refresh from multi-process
  coordination, production HTTP hardening, and live Entra qualification.

### Security

- Only `signing_key_unknown` after strict parsing and protected tenant selection can wake
  the worker. Concurrent triggers coalesce, and no unknown-key refresh can be scheduled
  more often than once per five minutes after any refresh attempt.
- The triggering request is never retried or blocked on network I/O; it fails with the
  ordinary invalid-token response. The worker can fetch only the same closed protected
  discovery/JWKS configuration used by explicit refresh.
- Startup fallback requires a fresh local snapshot with the configured `store_id`.
  Refreshed candidates pass full verifier readiness before installation; readiness fails
  when the manager is not running or its worker dies.
- The manager is a single-process, single-writer primitive. Multi-process deployments
  must elect one refresh owner rather than race managers against one snapshot.

## 0.4.0a6 — 2026-07-29

### Added

- A closed Entra refresh-configuration schema and parser binding each directory to exact
  tenant-specific discovery/JWKS endpoints, Team tenant, API audience, client/grant
  policy, token-lifetime limit, snapshot ID, and snapshot TTL.
- A one-shot `entra-trust-refresh` command that retrieves every configured tenant,
  validates one complete trust snapshot, and installs it atomically.
- `ReloadingEntraAccessTokenVerifier`, which adopts a newer valid same-store file before
  readiness/token checks and retains a still-fresh last-known-good verifier after a bad
  candidate without extending its expiry.
- A synthetic operator example, ADR 0014, expanded deployment/security guidance, public
  refresh APIs, and adversarial discovery, transport, JWK, atomic-install, rollback, and
  reload tests.

### Changed

- Version advanced to `0.4.0a6`.
- `EntraTeamIdentityMiddleware` now accepts the common `EntraTokenVerifier` interface so a
  file-reloading verifier can preserve the same typed-identity boundary.
- Entra trust-store rendering is public and deterministic for atomic snapshot
  installation.
- The roadmap now separates the completed one-shot refresh/reload primitive from managed
  scheduling, bounded unknown-key refresh, and live deployment qualification.

### Security

- Refresh uses direct HTTPS with platform certificate and hostname verification, no
  environment proxy, no redirects, exact final URLs, bounded time/body sizes, and strict
  response status, content type, encoding, and length handling.
- Discovery must return the protected exact issuer and JWKS URI. Remote JSON rejects
  duplicate members; JWK reduction rejects private material, admits only suitable public
  RSA `RS256` verification keys, and enforces each key's exact or
  `{tenantid}`-templated Microsoft issuer scope.
- All tenants succeed before a snapshot exists. Install refuses an invalid existing file,
  a changed `store_id`, or non-advancing `refreshed_at`, so refresh failure cannot clobber
  last-known-good trust.
- Network access remains outside the WSGI request path. The command is not a scheduler and
  this alpha does not refresh on unknown `kid`; deployments must schedule/monitor refresh
  and qualify real rollover behavior.

## 0.4.0a5 — 2026-07-29

### Added

- An optional Microsoft Entra v2.0 bearer-token verifier and WSGI identity middleware
  that maps verified `(tid, oid)` values into `AuthenticatedTeamIdentity` while keeping
  Team roles in protected Team access policy.
- A closed, committed Entra trust-store schema binding each directory to an exact Team
  tenant, issuer, API audience, client allowlist, delegated scopes/application roles,
  token-lifetime bound, freshness window, and tenant-scoped rollover keys.
- An Entra deployment/operator guide, ADR 0013, public APIs, schema CLI support, and
  adversarial parsing, cryptography, claim, tenant-partition, freshness, and HTTP tests.

### Changed

- Version advanced to `0.4.0a5`.
- The optional `entra` extra pins PyJWT 2.13.0 and cryptography 49.0.0; the development
  extra includes the same verifier dependencies.
- Entra-wrapped `/readyz` now checks trust freshness, dependency availability, and every
  configured RSA public key before the inner SQLite readiness check.
- The roadmap separates the concrete offline verifier from the still-required automatic
  tenant metadata/key refresher and production deployment qualification.

### Security

- Only canonical, duplicate-free, compact `JWT`/`RS256` Entra v2.0 access tokens are
  accepted. Remote or embedded JOSE keys, critical extensions, algorithm substitution,
  wrong issuer/audience/tenant, mutable display identity, invalid time profiles, and
  overlong tokens fail closed.
- Keys are selected by `kid` only after `tid` selects a protected tenant partition.
  Identical key IDs in two directories cannot cross-validate.
- Delegated tokens require an accepted `scp` and an allowed `azp`; app-only tokens require
  `idtyp=app`, an accepted `roles` value, and an allowed `azp`.
- Protected routes require trusted HTTPS scheme state. Middleware strips any preexisting
  identity/integrity context and the raw bearer value, emits generic RFC 6750 challenges,
  never trusts forwarding or tenant/role headers, and treats stale trust as unavailable.
- Metadata/JWKS retrieval remains outside this release. Production hosts must install
  tenant-specific snapshots through a protected atomic refresher and test real rollover.

## 0.4.0a4 — 2026-07-29

### Added

- A read-only, server-rendered Team evidence console at `/` and `/team`, with semantic
  HTML, a same-origin stylesheet, responsive/print layouts, no JavaScript, and no mutation
  controls.
- A bounded `GET /v1/team/events` summary API with strict newest-first
  `limit`/`before_sequence` cursor pagination and a committed response JSON Schema.
- `TeamEventPage`, `TeamEventSummary`, and consistent SQLite event-page snapshots, plus an
  operator guide, ADR 0012, public APIs, escaping/privacy tests, and browser visual QA.

### Changed

- Version advanced to `0.4.0a4`.
- Active policy, current head, and recent event bytes are read in one explicit SQLite
  transaction before current membership is resolved and a page is returned.
- The roadmap now distinguishes this initial ledger/evidence console from the future full
  change-case, causal-evidence, approval, and deployment-outcome dashboard.

### Security

- Event pages are capped at 100, reject unknown/duplicate/non-decimal query fields, never
  accept tenant selectors, and verify newest-first tenant/sequence/digest/cursor
  consistency.
- The browser model receives only audit metadata and payload content subjects; payload
  bodies are never loaded into the page model or rendered.
- Every displayed value is HTML escaped. Console responses deny framing/referrers/caching,
  permit only same-origin CSS under CSP, and expose no script or form surface.

## 0.4.0a3 — 2026-07-29

### Added

- A `TeamApplicationService` that accepts only typed trusted identity context, resolves
  roles from the current protected policy, generates decision/event/export IDs and
  timestamps server-side, and composes authorization with transactional SQLite writes.
- A framework-neutral `TeamWSGIApplication` with liveness/readiness, tenant summary,
  exact-event read, action-recording, and complete audit-export routes.
- A committed closed JSON Schema for action requests, a deployment and integration guide,
  ADR 0011, public API exports, and adversarial HTTP/identity tests.

### Changed

- Version advanced to `0.4.0a3`.
- SQLite tenant reads now use explicit consistent snapshots for active policy, protected
  head, and optional event bytes.
- Application event writes now require their exact authorization policy to remain active
  inside the append transaction, so a concurrent policy change returns a retryable
  conflict instead of committing stale authorization.

### Security

- The HTTP boundary never parses raw authorization, remote-user, tenant, or role headers.
  A company host must inject the exact trusted identity type after credential validation
  and server-side tenant selection.
- State-changing routes require a separate exact boolean request-integrity signal from
  trusted middleware, reject client-supplied tenant/role/ID/time fields, use closed JSON,
  bound request sizes, strict base64url, no-store responses, and generic internal errors.
- This is explicitly a single-host integration boundary, not bundled authentication, a
  production HTTP server, rate limiting, shared storage, a dashboard, WORM retention, or
  proof that a claimed external side effect occurred.

## 0.4.0a2 — 2026-07-29

### Added

- A standard-library `SQLiteTeamStore` with versioned initialization, WAL, full synchronous
  writes, foreign keys, bounded writer waits, and explicit `BEGIN IMMEDIATE` transactions.
- Exact historical policy, event, and export BLOB persistence with independently checked
  SHA-256 and byte counts.
- Forward-only active policy revisions and atomic per-tenant event/head
  compare-and-swap, including stable stale-writer and busy-writer errors.
- Ingress and export-time reproduction of every event against the exact historical policy
  subject embedded in its authorization decision.
- Tenant-local uniqueness for event IDs, authorization-decision IDs, event digests, export
  IDs, and export-authorization decisions.
- `team-store-init`, `team-store-policy-put`, `team-store-policy-get`,
  `team-store-head`, `team-store-append`, `team-store-event-get`, `team-store-export`,
  and `team-store-backup` commands.
- Non-overwriting consistent online backups, a store operator guide, ADR 0010, Classic
  Pipeline smoke coverage, and concurrency, rollback, cross-tenant, mutation, backup, and
  exact-byte tests.

### Changed

- Version advanced to `0.4.0a2`.
- The Team roadmap now separates the completed single-host transactional foundation from
  a future shared service database, immutable retention, independent head anchoring, and
  disaster-recovery qualification.
- Local database files and SQLite WAL/shared-memory sidecars are excluded from TFVC.

### Security

- An event insert and authoritative head advance now commit or roll back together after an
  expected-head comparison, preventing forks among writers sharing the same local store.
- Database triggers reject ordinary updates/deletes, policy rollback, head rewind, and
  skipped event sequences.
- These SQLite controls are explicitly not described as WORM retention. A database or
  filesystem owner can bypass them or replace the file; authenticated routing, multi-host
  storage, immutable retention, rate limits, protected off-host backups, and independent
  head anchoring remain deployment responsibilities.

## 0.4.0a1 — 2026-07-28

### Added

- Closed tenant access-policy snapshots mapping stable identity-provider subjects to fixed
  investigator, policy-administrator, and approver roles.
- Deterministic `team-authorize` decisions that bind exact policy bytes, revision, tenant,
  action/resource pairs, assigned roles, granting roles, and machine-readable allow or deny
  reasons.
- `team-audit-append` for retention-bound allowed, denied, and failed action events with
  payload content subjects and per-tenant canonical predecessor hashes.
- Policy-authorized complete event-chain exports and exact-byte verification receipts
  through `team-audit-export` and `team-audit-verify`, with an explicit protected
  tenant-head digest input to prevent accidental prefix export.
- Five committed Team JSON Schemas, public domain APIs, operator guidance, ADR 0009, and
  cross-role, cross-tenant, mutation, staleness, retention, chain, export, and CLI tests.

### Changed

- Version advanced to `0.4.0a1`.
- The Azure review-integration roadmap milestone is complete; the Team-service milestone is
  now in progress.

### Security

- Roles are resolved from protected tenant policy and cannot be supplied by the caller.
- Action/resource confusion, forged role decisions, stale authorization reuse, incorrect
  deny outcomes, shortened retention, predecessor substitution, chain gaps/reordering,
  duplicate event/decision IDs, partial exports, and unauthorized exports fail closed.
- Hash chains are explicitly treated as tamper evidence rather than storage immutability.
  Authentication, server-side tenant selection, policy rollback protection, atomic
  compare-and-swap, WORM retention, rate limits, and head anchoring remain hosted
  deployment responsibilities.

## 0.3.0a2 — 2026-07-28

### Added

- Separate signed approval-assertion and successful verification-receipt contracts that
  bind stable authority-authenticated approver identity to exact Azure publication and
  pre-approval receipt bytes.
- Protected approval authority/key/action trust stores with bounded key validity and
  freshness-checked compromise/retirement revocations.
- `issue-approval` for authority-side Ed25519 issuance and `verify-approval` for full
  signature, artifact, result/report, current Azure TFVC build, time, and revocation
  verification.
- A pinned `approval` dependency extra for the lazily loaded Ed25519 implementation.
- Explicit exception records with bounded justification and exact coverage of every
  decision-affecting finding.
- Four committed approval JSON Schemas, public models/APIs, operator guidance, ADR 0008,
  and adversarial signature, mutation, scope, event-order, current-build, revocation, and
  CLI tests.

### Changed

- Version advanced to `0.3.0a2`.
- Azure Markdown report binding now normalizes multiword recommended actions consistently,
  allowing non-approval reports such as `DO NOT PATCH` to enter the publication chain.

### Security

- Build requester variables and build-service tokens are explicitly excluded as human
  authentication sources.
- Approval authentication must follow the bound pre-approval verification, authority
  issuance must follow within 15 minutes, and neither assertion lifetime nor the complete
  receipt-to-expiration window can exceed 24 hours.
- Authority trust policy independently authorizes `approve` and `exception` actions.
- `approve` can confirm only an existing approval. An exception can record only a
  non-approval, must cover its full consequential finding set, is always `record_only`,
  and preserves the original non-approval CLI exit status.
- The bundled issuer remains an adapter for an independent organizational
  identity/authorization service; authority key custody, role checks, immutable uniqueness,
  and direct Azure approval ingestion remain deployment responsibilities.

## 0.3.0a1 — 2026-07-28

### Added

- Closed Azure review-publication and pre-approval verification-receipt contracts with
  strict parsers, stable renderers, CLI schema export, and committed JSON Schemas.
- `azure-publish` and `azure-verify` commands that bind exact review artifacts to the
  current Azure TFVC build and recheck them within a bounded freshness window.
- Changeset and gated-shelveset identity validation using Azure's distinct TFVC source
  variables, plus work-item associations and safe Markdown summary links.
- `scripts/azure_review_gate.ps1` for a real-case Classic Pipeline task that uploads the
  JSON result, Markdown report, publication, verification receipt, and verified build
  summary before returning the gate decision.
- Public Azure publication/verification models and APIs with deterministic changeset,
  shelveset, tamper, stale-record, wrong-build, schema, and CLI tests.

### Security

- Artifact SHA-256 and byte counts are recomputed immediately before gate completion.
- A publication must be created within five minutes of its bound review, preventing an old
  result from being repackaged with a fresh publication timestamp.
- Publications cannot be reused across build IDs, TFVC targets, server paths, projects, or
  source variables; inconsistent changeset/shelveset variables fail closed.
- Dynamic summary fields are bounded and Markdown-escaped. Collection URIs require
  canonical HTTPS without credentials, query, or fragment.
- Publication and verification records remain unsigned audit metadata. Protected pipeline
  definitions, trustworthy agents, artifact retention, approver authentication, and
  explicit exception authorization remain external requirements.

## 0.2.0a4 — 2026-07-28

### Added

- `SandboxedAdapterRunner` for one-reference-per-container replay and evaluation with
  parent-enforced worker concurrency and stable failure codes.
- `DockerCliSandboxRuntime` with digest-pinned Linux image preflight, deterministic
  hardening arguments, bounded standard input/output, global deadlines, and confirmed
  cancellation.
- Versioned sandbox-policy and worker request/response contracts with strict parsers,
  renderers, CLI schema export, and committed JSON Schemas.
- `ProviderQuotaController`, reservation, lease, settlement, and non-secret receipt
  contracts for provider-backed hard spend enforcement.
- Public sandbox APIs plus deterministic fake-runtime and scripted-Docker tests that do not
  require a daemon.

### Security

- Offline workers use Docker's `none` network. Worker images run non-root with a read-only
  root, bounded temporary filesystem, no added capabilities or host mounts,
  `no-new-privileges`, built-in seccomp, private cgroups, and CPU, memory, no-swap, PID,
  file, output, and wall-clock limits.
- Preflight requires the exact local repository digest, Linux image/server, no declared
  image volumes, and—when connected—an internal network containing only the named quota
  proxy before launch.
- Connected workers cannot launch until a hard cost/operation/concurrency lease is
  reserved. Scoped tokens travel only on bounded worker standard input; authoritative
  provider settlement supplies final cost.
- Pending launches are suppressed after a peer fails. Unconfirmed container cleanup or
  quota cancellation fails closed.
- Provider-specific controllers/proxies, Docker/Linux qualification, TLS trust, registry
  admission, and orchestration/network integrity remain explicit deployment
  responsibilities.

## 0.2.0a3 — 2026-07-28

### Added

- Detached Ed25519 attestations for exact evidence artifact bytes.
- Strict artifact-attestation, producer trust-store, key-revocation, and successful
  verification-receipt contracts with committed JSON Schemas.
- `attest`, `public-key`, and `verify-attestation` CLI commands.
- Producer/key validity, exclusive attestation expiration, retention coverage, and bounded
  revocation freshness checks.
- Separate compromise and planned-retirement revocation semantics.
- A pinned optional `attestation` dependency extra and public signing/verification API.

### Security

- Producer identity is resolved from a protected trust-store binding rather than a
  self-asserted key.
- Signature and exact-byte mutation, stale or mismatched revocation state, untrusted keys,
  invalid validity windows, expired attestations, and applicable revocations fail closed
  with stable non-sensitive codes.
- Private-key passwords are accepted only through a named environment variable.
- Trust/revocation policy integrity, managed KMS/HSM custody, and storage-enforced retention
  remain explicit deployment responsibilities.

## 0.2.0a2 — 2026-07-28

### Added

- Deterministic, trace-identity investigation fixtures generated from validated redacted
  manifests.
- A strict investigation-fixture schema and CLI export command.
- A spawned-process runner for company-owned replay and evaluator adapters.
- Wall-clock timeout, input/output count, unique-outcome, and reported-cost enforcement.
- Stable, non-sensitive adapter failure codes and runner integration documentation.

### Changed

- Evaluator outcomes now report latency and cost, matching replay outcomes and making
  aggregate runner budgets enforceable.
- Trace-manifest consumers reparse and validate the exact bytes bound to derived artifacts.
- Classic CI now smoke-tests the trace-to-draft-fixture boundary.

### Security

- Generated fixtures are permanently marked `draft_only: true`, `gate_eligible: false`, and
  `causal_claims_inferred: false`; they cannot masquerade as change cases.
- Adapter stdout, stderr, and exception messages are suppressed at the process boundary.
- The process runner is explicitly not represented as an OS/network sandbox; hard spend and
  resource isolation remain deployment responsibilities.

## 0.2.0a1 — 2026-07-28

### Added

- Deterministic OTLP JSON/OpenInference trace collector.
- Redacted trace-manifest model, CLI command, schema, and synthetic security fixture.
- Exact source hashing and content-addressed, trace-scoped span references.
- Replay and evaluator adapter protocols with explicit execution budgets.
- Collector architecture, privacy boundary, TFVC authentication, and usage documentation.

### Security

- Raw span names, content attributes, resource/scope metadata, events, links, and status
  messages are excluded from trace manifests.
- Trace input is bounded by bytes and span count, parsed with duplicate-key rejection, and
  cryptographically bound to the manifest source record.

## 0.1.0 — 2026-07-27

### Added

- Versioned evidence, policy, and result schemas.
- Deterministic evidence-gate engine with five decisions.
- Reproduction, attribution, null-hypothesis, minimality, control, cost, and latency checks.
- Markdown and JSON reports with stable finding codes and an audit digest.
- CLI validation, review, schema export, and CI exit-code contracts.
- Approved and intentionally rejected refund-policy examples.
- Strict production policy example.
- TFVC ignore rules and Azure Classic Pipeline build script.
- Security, architecture, evidence, roadmap, and source-control documentation.
