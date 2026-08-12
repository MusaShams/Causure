# Roadmap

This file tracks implemented technical capabilities. The prioritized remaining user and
enterprise journey is maintained in the
[productization roadmap](productization-roadmap.md). Its P0-A one-command experience is
complete; P0-B's final public decision examples are the immediate product milestone.

## 0.1 — Evidence gate foundation

- Versioned change-case, policy, and result contracts.
- Deterministic five-way decision engine.
- Positive, negative, and regression controls.
- CLI, Markdown report, JSON result, and CI exit codes.
- TFVC Classic Pipeline entry point.
- Security boundaries and automated test baseline.

## 0.2 — Evidence collection (in progress)

- [x] OpenTelemetry/OpenInference OTLP JSON trace importer.
- [x] Redacted trace manifest with exact content hashes.
- [x] Replay and evaluator adapter protocols.
- [x] Deterministic collection and explicit timeout, concurrency, case, and cost budget
  contracts.
- [x] Draft-only evidence-fixture generator from trace-identity incident candidates.
- [x] Process-bounded adapter runner enforcing wall-clock, case, outcome, and reported-cost
  budgets.
- [x] Digest-pinned Linux OCI worker boundary with an offline network mode, independently
  enforced parent worker concurrency, OS resource limits, and confirmed cancellation.
- [x] Fail-closed provider hard-quota lease/proxy integration contract with pre-launch
  reservation and authoritative settlement.
- [x] First provider-specific OpenAI-compatible quota controller/proxy reference with
  transactional operation/concurrency/spend admission and fail-closed usage settlement.
- [x] Split-edge, digest-pinned one-host Docker pilot with protected state preparation,
  separate worker/admin TLS routes, provider-only core egress, restart-persistent SQLite,
  and one retained self-cleaning local bypass/route/restart qualification that makes no
  provider request.
- [ ] Live-provider usage/invoice reconciliation plus production orchestrator TLS, secret
  delivery, registry admission, network-mutation resistance, ambiguous-operation recovery,
  disaster recovery, and hard-spend deployment qualification.
- [x] Detached Ed25519 producer attestations, protected producer/key bindings, retention
  windows, and freshness-bounded compromise/retirement revocations.

The gate will continue to consume the same evidence contract. Collectors must not gain the
ability to weaken policy thresholds.

## 0.3 — Azure DevOps review integration

- [x] Publish verified decision details into an Azure build summary.
- [x] Associate an evidence case with either a changeset or shelveset and with work-item
  IDs in a closed publication record.
- [x] Gated-check-in status with downloadable JSON and Markdown artifacts.
- [x] Separate signed, expiring approval assertions with authority-authenticated stable
  identity, protected action authorization, current revocations, and full
  decision-affecting finding scope for explicit exceptions.
- [x] Recheck referenced artifact hashes and current build identity immediately before the
  gate task completes.

## 0.3a — GitHub pull-request integration (in progress)

- [x] Closed offline publication and verification bound to exact PR head/base identity,
  repository IDs, event subject, workflow run/attempt, and case/result/report bytes.
- [x] Composite Action for one-step deterministic review, exact re-verification, stable job
  summary, workspace-confined files, and isolated loading of the Action's own source.
- [x] Bounded same-repository Checks API publisher with a stable name, decision-derived
  conclusion, at most 50 annotations, fixed endpoint, no redirects, and an exact-request
  receipt.
- [x] Secret-free fork behavior that skips the privileged API write in `auto` mode while
  preserving the workflow gate and local evidence chain.
- [x] Full-SHA-pinned caller recipe for downloadable evidence retention and fork-compatible
  branch protection.
- [x] One canonical project configuration, automatic component/case selection, and a
  protected-base case-generator Action with exact-head binding and no protected adapter
  execution for forks.
- [x] Credential-free approve/abstain/needs-evidence fixture sources, a two-checkout workflow
  template, and local deterministic qualification of all three decisions.
- [x] Private full-SHA Action qualification for same-repository approve, reject, and
  needs-evidence pull requests plus the Dependabot no-match path, with verified Check Run
  receipts and retained artifacts documented in the
  [2026-08-11 receipt](qualifications/github-native-private-2026-08-11.json).
- [x] Real public generator-backed fork qualification, retained in the
  [public 2026-08-11 receipt](qualifications/github-native-public-2026-08-11.json).
- [x] Public dependency-review qualification, required protected-main status, TFVC-first
  cryptography remediation, and zero-open-alert follow-up retained in the
  [remediation receipt](qualifications/github-native-public-remediation-2026-08-11.json).
- [ ] Fresh public approve/abstain/needs-evidence example pull requests.

## 0.4 — Team service (in progress)

- [x] Closed tenant access-policy snapshots with server-resolved investigator, policy
  administrator, and approver roles.
- [x] Exact-policy authorization decisions for bounded action/resource pairs, including
  machine-readable denials.
- [x] Per-tenant hash-chained audit events for allowed, denied, and failed actions with
  policy-backed retention deadlines.
- [x] Policy-authorized complete audit exports bound to a protected tenant-head digest,
  with exact-byte verification receipts.
- [x] Transactional single-host SQLite persistence with compare-and-swap ledger heads,
  exact historical policy/event/export bytes, normal-API mutation guards, and consistent
  online backups.
- [x] Trusted-identity application service and framework-neutral WSGI JSON boundary with
  server-selected tenant context, current-policy role resolution, and safe CAS writes.
- [x] Concrete Microsoft Entra v2.0 bearer host adapter with exact tenant/audience/actor
  validation and protected tenant-scoped offline signing-key snapshots.
- [x] Protected tenant-specific OIDC discovery/JWKS refresh command with strict HTTPS
  retrieval, all-tenant atomic snapshot installation, and last-known-good request-worker
  reload.
- [x] Single-process startup/periodic Entra refresh lifecycle with bounded failure retry,
  explicit status/shutdown, and rate-limited asynchronous unknown-key recovery.
- [x] Same-host cross-process Entra refresh ownership with crash-released local-volume
  locking, guarded snapshot writes, follower reload, coalesced rollover requests, and
  automatic owner promotion.
- [x] Process-local pre-authentication WSGI admission control with bounded concurrency,
  global/per-source token buckets, capped source state, safe streaming cleanup, and probe
  semantics.
- [x] Closed one-process Team launcher with exact-version Waitress, canonical loopback
  binding, protected refresh-policy subjects, fixed middleware/lifecycle composition,
  bounded HTTP resources, and no forwarded-header trust.
- [x] Native Windows single-host supervision with exact pywin32, a passwordless virtual
  service account, exact registry-bound host policy, controlled Waitress shutdown, and
  non-destructive stopped-state management commands; the exact a14 wheel also passed one
  self-cleaning isolated Windows 11 SCM/readiness/stop/removal qualification run. The exact
  reproducible a15 offline bundle then passed live bundle and separately authorized
  delayed-auto cold-boot/non-crash-recovery qualification on Windows 11 build 26200.
- [ ] Qualified shared service database, storage-enforced immutable/WORM retention,
  independently anchored heads, and tested disaster recovery.
- [ ] Multi-host refresh ownership, public HTTPS/signed installer or orchestrator
  packaging, qualified production target-image boot/recovery and distributed-edge controls,
  and live company Entra deployment qualification.
- [x] Initial read-only tenant ledger/evidence console with bounded event summaries and
  payload-free server rendering.
- [x] Full change-case dashboard joining causal evidence, review findings, approvals, and
  post-deployment outcomes.
- [x] Candidate-only incident clustering and immutable investigation queues with explicit
  assignment, typed abstention/closure, change-case linkage, and atomic audit binding.
- [x] Evidence-bound canary outcome comparison with predeclared evaluator/assignment,
  family-wise sequential-look control, explicit noninferiority tolerances, and
  promote/continue/rollback/needs-evidence outcomes.

## Public distribution (in progress)

- [x] Deterministic public-snapshot boundary for local metadata, secrets, generated state,
  required community files, and immutable GitHub Action references.
- [x] Least-privilege GitHub CI, CodeQL, dependency review, Dependabot, CODEOWNERS, and
  structured contribution templates.
- [x] Private-first publication and one-way TFVC mirror decision while TFVC remains the
  source of record.
- [x] Owner-selected Apache-2.0 license and matching SPDX package metadata.
- [x] Owner-approved private GitHub repository, reviewed initial history, and green hosted
  CI/package checks, including the portability repair merged through pull request 7.
- [x] Hosted private full-SHA qualification across same-repository approve, reject, and
  needs-evidence pull requests and a Dependabot no-match pull request, with complete retained
  evidence for each reviewed scenario.
- [x] Generator-backed public-fork qualification with exact hosted evidence.
- [x] Public dependency-review and post-merge CI/CodeQL qualification with the surfaced
  cryptography advisory fixed from a TFVC-first source change.
- [ ] Fresh public retained approve/abstain/needs-evidence examples.
- [x] Separately approved public visibility, secret scanning and push protection, private
  vulnerability reporting, pinned GitHub-owned Actions, active `main` ruleset, and successful
  public CodeQL qualification.
- [ ] Later source-of-record migration decision if GitHub becomes authoritative.

## Research track — PatchOrNotBench

- 40–60 controlled incidents across genuine and attractive false diagnoses.
- Change precision and recall.
- Attribution and abstention accuracy.
- Unnecessary modifications per 100 incidents.
- Harness growth, latency, cost, and negative transfer.
- Sequential evaluation across repeated optimization rounds.

The benchmark should be published separately from product telemetry so the reported research
results remain reproducible and inspectable.
