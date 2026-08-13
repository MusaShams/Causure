# Productization roadmap

- Status: active
- Updated: 2026-08-11
- Product stage: functional alpha and enterprise reference implementation

## Product judgment

Causure has implemented most of the original **assurance model**: failure
adjudication, causal-evidence requirements, a null hypothesis, minimal-intervention checks,
positive and negative controls, regression/cost/latency guardrails, deterministic decisions,
signed evidence, approvals, audit records, and post-deployment comparison.

It now implements the core **easy company workflow** locally and in a protected GitHub
composition: initialize, map a harness component, generate a candidate-bound case through
reviewed company code, and receive an evidence-backed pull-request decision. It is not yet a
finished self-serve company product. A new evaluator still has to supply company replay or
evaluation logic, review the two-checkout workflow, and understand security configuration
before seeing the simple product promised in the concept:

> Connect traces or a pull request, investigate a proposed agent change, and receive an
> understandable evidence-backed merge or canary decision.

The immediate product priority is therefore usability and integration, not another deep
control-plane feature. Until the golden path below works, new quota, service-hosting,
identity, and storage work should be limited to defects or requirements that directly block
that path.

## Original-promise coverage

| Original capability | Current state | What exists | Remaining product gap |
| --- | --- | --- | --- |
| Failure adjudication and abstention | Implemented guided local workflow | Deterministic five-way engine, reproducibility/oracle rules, null hypothesis, stable findings, and guided canonical case creation | Company replay and evaluation systems must still produce the underlying outcomes |
| Causal attribution | Partial | Typed hypotheses, isolated-intervention evidence, adapter contracts, bounded runners | No guided hypothesis workflow or end-to-end experiment orchestration |
| Counterfactual fix prediction | Implemented contract; partial execution | Predicted effects, expected unaffected behavior, regression and cost/latency bounds | Product does not generate or run the comparison automatically |
| Minimal intervention | Implemented gate | Scope and component consistency checks; explicit no-change alternative | No visual diff or guided comparison of candidate interventions |
| Positive, negative, and regression controls | Implemented gate | Required structured controls and deterministic review rules | Test generation and execution remain external/manual |
| Patch, abstain, request evidence, or escalate | Implemented semantics | `approve`, `conditional_pass`, `reject`, `needs_evidence`, and `human_review` | Outcomes need clearer product language and guided next actions |
| Canary validation | Partial | Evidence-bound, predeclared sequential comparison | No deployment/feature-flag connector or automatic observation import |
| OpenTelemetry/OpenInference trace importer | Implemented narrow connector | Redacted OTLP JSON collection, hashes, bounded draft fixture generation | File-based flow only; no polished live/platform import and selection UI |
| GitHub pull-request integration | Public alpha qualification complete | Canonical project config, protected-base case generation, automatic selection, closed PR/run/artifact receipts, composite gate, bounded Check Run publisher, decision annotations, fork/Dependabot modes, public approve/reject/needs-evidence stories, and public-fork boundary qualification | Each company must still qualify its own adapters, policies, and repository configuration |
| Incident investigation | Partial but locally usable | Candidate-only fixtures, guided redaction/selection workspace, immutable queue records, observations, assignment and closure | Hosted/self-serve collaboration and live connector selection remain open |
| Evidence dashboard | Partial technical implementation | Read-only evidence, investigation, and joined change-case dashboards | Operational setup is heavy; no self-serve creation/editing or local demo mode |
| Enterprise identity, policy, audit, and approvals | Strong pilot | Entra adapter, tenant policy, signed approval, hash-chained audit, SQLite CAS store | Single-host/reference boundaries; no supported shared production deployment |
| PatchOrNotBench research evaluation | Not implemented | Metrics and benchmark design are documented | Dataset, baselines, experiment runner, results, and paper remain open |

## Initial customer and product boundary

The first user should be an AI engineer or reliability lead who already has:

- an agent running in production or staging;
- GitHub pull requests for prompt, tool, router, retrieval, or reviewer changes;
- OpenTelemetry/OpenInference traces or an exportable trace platform; and
- a replay or evaluation function the company controls.

Causure should not initially replace the agent framework, observability platform,
evaluation system, Git host, or deployment controller. It should make one workflow excellent:

```text
Select incident traces or open a pull request
                    ↓
Create a redacted investigation draft
                    ↓
Confirm failure, hypotheses, and no-change alternative
                    ↓
Run or import bounded reproduction/intervention/control results
                    ↓
Review a generated change case and proposed component diff
                    ↓
Publish an understandable GitHub decision and evidence report
                    ↓
Import canary outcomes after an external deployment
```

## Definition of a usable first product

The first product-quality release is complete only when a new evaluator can:

- run a synthetic end-to-end demo with one command;
- create its first real project configuration without reading a schema;
- move from a trace export or pull request to a review with no manually authored JSON;
- complete the common path with at most three top-level commands;
- understand every finding and its required next action from the terminal or browser;
- attach a verified report to a GitHub pull request and enforce its result as a check;
- keep raw customer content and credentials outside review artifacts; and
- reproduce the same decision locally and in CI.

Target usability measures for the synthetic path are less than ten minutes to the first
decision, no prerequisite service deployment, and no cloud credentials. A real integration
should take less than thirty minutes after the user already has a trace export and replay
function.

## Milestone P0-A: one-command local experience

**Status: complete.** The exact installed wheel passed both the automated clean-environment
audit and the unassisted unfamiliar-user criterion.

Build this before another enterprise subsystem.

### Scope

- Add `causure demo` to run two coherent synthetic stories: one justified minimal
  patch and one attractive false diagnosis that ends in abstention or more evidence.
- Add `causure init` to create one small project configuration, policy preset,
  trusted adapter directory, and Git ignore entries.
- Add `causure doctor` to verify Python, configuration, adapter availability,
  permissions, and optional container runtime without changing state.
- Add a guided `causure investigate` flow that accepts an OTLP export, previews
  redaction, selects candidate traces, and creates an editable investigation draft.
- Add a guided `causure case create` flow that asks plain-language questions and
  generates canonical JSON internally. JSON remains an interchange format, not the user
  interface.
- Add concise terminal summaries with finding explanations and exact next commands.
- Publish a ten-minute quickstart built around the demo rather than the full CI harness.

### Exit criteria

- A clean machine can install the package, run `causure demo`, and open a readable
  report without editing any file.
- A usability test with someone unfamiliar with the schemas reaches both demo decisions
  without assistance.
- The generated artifacts remain byte-for-byte valid under the existing deterministic gate.

### Progress

- [x] Package and run two deterministic synthetic stories with `causure demo`.
- [x] Generate a new-only local configuration, default policy, trusted-adapter boundary, and
  ignore rules with `causure init`.
- [x] Inspect core and optional local readiness without writes or network access with
  `causure doctor`.
- [x] Make the one-command demo the public ten-minute quickstart.
- [x] Add guided trace redaction preview, numbered candidate selection, and a deterministic
  candidate-only local investigation workspace without raw content or stored source paths.
- [x] Add guided plain-language case creation backed by canonical JSON internally, with
  immediate review and honest empty evidence sections that resolve to `needs_evidence`.
- [x] Make the empty/help screen lead with the three-command product path while retaining the
  lower-level automation and enterprise catalog behind `--help-all`.
- [x] Publish a minimized, pass/fail unfamiliar-user protocol that binds the tested wheel and
  treats any facilitator command or interpretation hint as assistance.
- [x] Pass an isolated installed-wheel engineering audit for the short help, both demo
  decisions, explanations, and readable report; retain the exact
  [2026-08-10 receipt](qualifications/p0a-installed-wheel-2026-08-10.json) without treating it
  as human usability evidence.
- [x] Run that protocol with an unassisted person unfamiliar with the schemas. The participant
  completed the demo in under five minutes with zero assistance, opened a generated Markdown
  report, and correctly explained both outcomes; retain the minimized
  [2026-08-11 human receipt](qualifications/p0a-unfamiliar-user-2026-08-11.json).

## Milestone P0-B: GitHub-native review

GitHub should become the first polished company integration. Keep Azure TFVC support as a
working enterprise adapter, but do not make it the public onboarding path.

### Scope

- Add a GitHub review-publication contract that binds repository, full commit SHA, pull
  request, workflow run, case/result/report hashes, and changed harness component.
- Add verification that rechecks the exact GitHub candidate and report before completing the
  job.
- Ship a reusable or composite GitHub Action with least-privilege permissions and immutable
  dependency pins.
- Publish one stable Check Run summary with annotations for decision-affecting findings and
  downloadable evidence artifacts.
- Extend the generated canonical `.causure/config.json` for component paths, policy
  preset, adapter entry points, and artifact-retention behavior; avoid a competing YAML file
  and preserve the standard-library-only base package (ADR 0028).
- Handle fork pull requests without exposing secrets and fail closed when trusted adapters
  cannot run.
- Provide one public synthetic example repository whose pull requests demonstrate approve,
  abstain, and needs-evidence outcomes.

### Exit criteria

- A pull request changing a prompt or tool description receives a reproducible
  Causure status check.
- Branch protection can require the stable check without parsing console output.
- The check links to a useful report and identifies exactly what must change before merge.

### Progress

- [x] Add a closed offline publication contract bound to base/head repository IDs, exact PR
  head SHA, base SHA, event merge SHA/ref, workflow definition/SHA, run attempt, minimized
  event subject, changed component, and exact case/result/report bytes.
- [x] Add strict re-verification against the current event/run with freshness, context,
  semantic correspondence, and exact-byte checks plus committed JSON Schemas and CLI/API
  surfaces.
- [x] Handle same-repository and fork identities without tokens or secrets, accept only the
  unprivileged `pull_request` event, and deliberately reject `pull_request_target`.
- [x] Ship a least-privilege composite Action that isolates its own source, produces the full
  local evidence chain, accepts only workspace-confined inputs, and uses a short-lived token
  solely for an optional bounded publisher.
- [x] Publish a stable same-repository Check Run with at most 50 decision-affecting
  annotations; preserve a no-secret, read-only-token fork path and document the stable
  workflow job as the fork-compatible branch-protection target.
- [x] Document caller-controlled downloadable artifact retention using a full-SHA-pinned
  uploader that still runs for non-approval decisions.
- [x] Extend the generated canonical project configuration with closed component path/case
  mappings, the existing policy preset, strictly validated trusted-adapter registrations,
  and caller-consumable artifact retention; add `github-configure` so the common mapping
  path does not require editing JSON.
- [x] Add bounded read-only PR-file discovery and deterministic single-component selection,
  including rename matching, no-match success, ambiguous-match failure, event-SHA race
  checks, candidate-modified governance rejection, and explicit overrides.
- [x] Generate configured cases through a separate protected-base adapter workflow with
  exact base/head checkout verification, candidate-as-data containment, bounded child
  execution, component/adapter mutation checks, an exact candidate reference, immediate
  review, minimized provenance, and no adapter execution for forks.
- [x] Prepare credential-free approve, abstain, and needs-evidence source fixtures, a
  two-checkout full-SHA workflow template, and a local qualifier that verifies all three
  deterministic decisions without claiming hosted GitHub evidence.
- [x] Qualify the remote full-SHA Action, stable job, custom Check Run, and retained
  generation/review chains against private same-repository approve, reject, and
  needs-evidence pull requests; qualify the Dependabot no-match path without requiring a
  privileged custom Check Run. Retain the exact
  [2026-08-11 receipt](qualifications/github-native-private-2026-08-11.json).
- [x] Qualify a real generator-backed fork pull request that fails before protected adapter
  execution, retained in the
  [public 2026-08-11 receipt](qualifications/github-native-public-2026-08-11.json).
- [x] Qualify dependency review on a public TFVC-backed pull request, require it through the
  protected `main` ruleset, close the cryptography advisory, and retain the exact
  [remediation receipt](qualifications/github-native-public-remediation-2026-08-11.json).
- [x] Publish and exercise approve, reject/abstain, and needs-evidence synthetic pull-request
  stories against the final public repository, with the exact hosted outcomes retained in
  the [public-release qualification](qualifications/causure-public-release-2026-08-13.json).

## Milestone P0-C: trace-to-investigation onboarding

### Scope

- Turn the current OTLP JSON collector and candidate-only fixture generator into one
  discoverable ingestion command and UI path.
- Add trace search/filter/selection for local exports, with a redaction preview before any
  derived artifact is saved.
- Add a connector SDK with typed pagination, provenance, redaction, rate, and retry contracts.
- Polish OpenTelemetry/OpenInference as the default connector and add one platform export
  connector only after the generic contract is stable.
- Convert selected traces into reproducible test candidates, never automatic causal claims.
- Let an investigator confirm the claimed failure, requirement/oracle, reproduction status,
  competing hypotheses, and no-change alternative in plain language.

### Exit criteria

- A user can select a bad synthetic trace and open a bounded investigation without writing
  JSON or copying identifiers.
- Raw messages and secrets remain outside the stored investigation and report.
- Every generated claim clearly distinguishes observed, user-confirmed, and inferred data.

## Milestone P1-A: bounded evaluation and intervention orchestration

This milestone supplies the central product behavior that the original proposal described
but the current gate only consumes.

### Scope

- Publish an adapter SDK, templates, and a local test harness for company replay and
  evaluator functions.
- Register trusted adapters in project configuration rather than evidence files.
- Support first-class prompt, tool-description, model-routing, retrieval-configuration, and
  reviewer/verification components.
- Create an experiment plan containing reproduction, competing hypotheses, isolated
  interventions, a no-change baseline, positive controls, negative controls, and regression
  cases.
- Require human confirmation of the plan before trusted execution.
- Run the plan through the existing process/container budgets and provider quota boundary.
- Populate the change case from signed/attested results and show missing evidence rather than
  inventing it.
- Compare multiple candidate interventions and justify the smallest supported change.

### Exit criteria

- The synthetic refund scenario proceeds from selected traces through bounded experiments to
  the same deterministic decision without hand-entering outcome records.
- An environmental failure and a misleading trace both produce a correct non-patch outcome.
- Cancellation, cost ceilings, timeouts, and partial results are visible and fail closed.

## Milestone P1-B: usable investigation and evidence workspace

Reuse the existing Team application, store, queue, and read-only dashboards, but add a
purpose-built product surface instead of exposing infrastructure concepts.

### Scope

- Add `causure ui` for a local synthetic/demo mode with no Entra setup.
- Provide guided pages for project setup, trace import, investigation, experiment plan,
  evidence matrix, component diff, findings, decision, approval, and canary outcome.
- Preserve a read-only audit view while adding policy-authorized creation and transition
  forms with CSRF/request-integrity protection.
- Explain findings in user language and link each one to the missing evidence or failed
  control.
- Keep raw trace bodies in the connected source system; render only minimized references and
  confirmed summaries.
- Package a supported single-host evaluation deployment with one configuration and health
  check instead of a sequence of low-level service commands.

### Exit criteria

- An engineer can complete the common investigation without the CLI after installation.
- A manager can understand why a change was approved, rejected, or deferred without opening
  JSON.
- The UI and CLI produce and verify the same canonical artifacts.

## Milestone P1-C: post-deployment evidence loop

### Scope

- Import baseline and candidate observations from a generic webhook/file contract.
- Add adapters for deployment or feature-flag systems only after the generic contract is
  exercised.
- Guide users through prospective canary policy, assignment unit, planned looks, tolerances,
  and stopping behavior.
- Publish promote, continue, rollback, or needs-evidence recommendations back to GitHub and
  the evidence workspace.
- Keep deployment and rollback execution external until a separately reviewed control-plane
  design exists.

### Exit criteria

- A synthetic approved change can complete the full incident-to-canary audit story.
- The product never relabels an inconclusive canary as success and never deploys by itself.

## Milestone P2: enterprise deployment

Do this after at least one external team completes the P0/P1 workflow.

### Scope

- Replace the single-host SQLite authority with a qualified shared relational store and
  protected object/artifact storage.
- Add storage-enforced immutable retention, independent ledger anchoring, backup/restore,
  disaster-recovery tests, and migration tooling.
- Generalize SSO/OIDC onboarding while preserving stable server-derived tenant identity,
  exact policy snapshots, role separation, and signed approvals.
- Add multi-host coordination, edge rate/concurrency controls, TLS and secret-manager
  integration, observability, SLOs, and supported container/orchestrator packaging.
- Version the external API and publish small Python/TypeScript clients.
- Complete an independent security review and qualify at least one realistic enterprise
  deployment.

### Exit criteria

- Two separate organizations can operate isolated tenants on a supported deployment.
- Backup restoration, key rotation, revocation, retention, upgrade, and incident procedures
  are exercised rather than merely documented.

## Research track: PatchOrNotBench

Begin dataset construction after P1-A can execute the protocol; do not wait for the full
enterprise platform.

### Scope

- Build 40–60 controlled incidents containing genuine failures and attractive false
  diagnoses across prompt, tool, routing, retrieval, model, evaluator, environment, and
  requirement causes.
- Implement conventional observe–patch–regression baselines and ablations for adjudication,
  causal intervention, negative controls, and the no-change hypothesis.
- Measure change precision/recall, attribution, abstention, regressions, unnecessary changes
  per 100 incidents, harness growth, latency, cost, and sequential utility.
- Publish versioned incident definitions, evaluator code, complete result tables, and a paper
  separately from company telemetry.

### Exit criteria

- Every incident has a defensible ground-truth decision and causal component.
- Results are reproducible from a clean environment and include negative or inconclusive
  outcomes rather than only product wins.

## Portfolio-quality release gate

The project can appear publicly before enterprise P2, but the main portfolio launch should
follow P0-A and P0-B so visitors immediately see the product rather than internal machinery.

Required launch assets and current status:

- [x] Publish the final one-root-commit public repository and versioned `v0.4.0a18` release
  through the gated [clean-history runbook](clean-history-publication.md).
- [x] Retain the one-command demo. A hosted synthetic read-only demo remains optional when it
  can be published without adding an unnecessary service boundary.
- [x] Capture and publish the short video showing the incident, investigation, GitHub
  decision, and report using the [90-second script](portfolio-demo-script.md) and privacy
  checklist.
- [x] Capture final-repository screenshots of the evidence matrix and pull-request check.
- [x] Include one architecture diagram focused on the user flow in the
  [engineering case study](portfolio-case-study.md).
- [x] Publish and qualify approve, reject/abstain, needs-evidence, and credential-free fork
  cases against the final repository identity.
- [x] State the security/privacy boundary and explicit production limits in the case study.
- [x] Retain a concise case study covering the problem, design decisions, measured results,
  and remaining work.

The portfolio claim should be “functional evidence-gated agent change control,” not
“production-ready autonomous self-improvement” until the relevant product and research exit
criteria have actually passed.

## Product metrics

Track these from the first external pilot:

- time to first decision and integration completion;
- percentage of cases created without manual artifact editing;
- investigation completion and abandonment rate;
- unnecessary proposed changes rejected;
- genuine changes correctly approved;
- attribution and abstention accuracy;
- regressions caught before deployment;
- false-block and human-override rate;
- time from incident selection to an actionable decision; and
- post-canary change success, rollback, latency, and cost outcomes.

## Do not build next

P0-B and the portfolio release gate are complete. Until P0-C and P1-A produce a usable
trace-to-experiment path and at least one external pilot exercises it, do not prioritize:

- autonomous patch generation;
- another provider-specific quota system;
- another native service installer;
- a second enterprise identity provider;
- a broad marketplace of trace connectors;
- multi-region hosting; or
- a polished benchmark paper without the executable investigation path.

Those may become valuable later. Today they would increase the amount of impressive
infrastructure while leaving the first user with the same manual JSON workflow.
