# Causure

**Causal assurance for production AI-agent changes.**

> Change only what the evidence supports.

Causure (pronounced “cause-sure”) is the evidence and approval layer between an AI-agent
incident and the next production change.

Causure answers a deceptively important question before a team changes a prompt,
tool, router, retrieval policy, reviewer, retry rule, or other agent component:

> Is this change actually justified by reproducible and causally relevant evidence?

The current alpha has a zero-runtime-dependency deterministic gate plus optional Ed25519
producer and approval signing support. It collects a redacted manifest from
OTLP/OpenInference traces, creates a
deliberately incomplete investigation draft, bounds company-owned replay/evaluation
adapters in either a spawned process or digest-pinned Linux container, can require a
provider-backed hard-quota proxy before connected work, verifies producer provenance,
reviews a portable evidence bundle, and emits both human-readable and machine-readable
results. In GitHub Actions a protected companion step can load a reviewed case generator
only from the exact base checkout, treat the separate head checkout as bounded data, and
produce a case bound to the candidate component and PR head. Its ordinary composite gate
then discovers changed filenames, selects that configured component/case/policy, binds the
case and exact result/report bytes to the pull request's head commit and current unprivileged
workflow run, rechecks the closed publication, and publishes a minimized Check Run for
same-repository pull requests while preserving non-executing fork behavior. On Azure DevOps
it can bind those exact
artifacts to a TFVC changeset or gated
shelveset, recheck them against the current build, publish a downloadable audit record,
verify a separately signed organizational approval or policy exception, and place Team
actions behind exact-policy tenant roles with retention-bound, hash-chained audit exports
and a transactional single-host SQLite ledger, plus a trusted-identity application/WSGI
boundary that a company authentication host can call, a closed loopback-only single-host
launcher, and a read-only tenant evidence console, a candidate-only investigation queue,
and a minimized change-case dashboard
joining causal evidence, gate findings, TFVC delivery, approval, and canary outcomes.
After deployment it can compare exact
baseline/candidate canary aggregates
against a predeclared policy without relabeling inconclusive evidence as success.

## What works today

- A deterministic, zero-credential `demo` that produces one justified patch and one rejected
  overbroad change, with readable reports and canonical machine results.
- New-only `init` project setup and a read-only `doctor` readiness check, so first-time users
  do not need to author configuration JSON or deploy the Team service.
- A guided `investigate` command that previews OTLP/OpenInference redaction before any write,
  supports numbered candidate-trace selection, and creates an editable candidate-only local
  workspace without retaining raw trace content or the source path.
- A guided `case create` wizard that verifies the investigation's exact hashes, asks for
  incident, oracle, hypothesis, proposed-change, no-change, and control information in plain
  language, generates canonical JSON internally, and immediately produces the gate decision.
- Strict structural validation with bundled JSON Schemas.
- Independent-oracle and reproduction checks.
- Ranked causal hypotheses and isolated-intervention checks.
- An explicit null hypothesis: no harness change is necessary.
- Minimal-change enforcement.
- Positive, negative, and regression controls.
- Cost and p95-latency guardrails.
- An evidence-bound canary comparison with predeclared evaluator, assignment unit,
  tolerances, planned looks, and family-wise confidence control.
- Five outcomes: `approve`, `conditional_pass`, `reject`, `needs_evidence`, and
  `human_review`.
- Stable finding codes, policy overrides, CI exit codes, and a normalized evidence digest.
- A deterministic OTLP/OpenInference collector that omits raw trace content and emits exact
  source hashes plus content-addressed span references.
- A deterministic incident-cluster fixture generator whose output is explicitly draft-only,
  non-gate-eligible, and free of inferred causal claims.
- An immutable-revision Team investigation queue that binds selected fixture clusters to
  attributable observations, assignment, priority/status transitions, explicit abstention
  or closure, and optional change-case linkage without promoting correlation into cause.
- Typed replay and evaluator adapter protocols with mandatory execution budgets.
- A spawned-process runner that enforces wall-clock, case, outcome, protocol, and reported
  cost limits for company-owned adapters.
- A separate Docker CLI sandbox runner with digest-pinned Linux images, read-only/non-root
  containers, bounded CPU/memory/PIDs/output, one evidence reference per container,
  parent-enforced concurrency, and network denial by default.
- A fail-closed provider hard-quota lease/proxy contract that reserves before launch,
  carries its scoped token only over worker standard input, and settles authoritative cost
  after validated work.
- A first OpenAI-compatible reference controller/proxy for non-streaming text Responses,
  with atomic SQLite admission, separate worker/admin/provider credentials, full configured
  model-maximum cost holds, and fail-closed ambiguous accounting.
- A runnable split-edge Docker pilot for that reference, with a closed Waitress host,
  protected-file state preparation, separate worker/admin TLS routes, digest-pinned base
  images, network-disabled local builds, and a self-cleaning no-provider qualification.
- Detached Ed25519 attestations binding exact artifact bytes to a trusted producer/key,
  validity window, retention requirement, and freshness-bounded revocation list.
- Machine-readable verification receipts and stable failure codes for changed, expired,
  untrusted, revoked, or invalid-signature artifacts.
- Closed Azure review-publication and verification receipts that bind exact JSON/Markdown
  bytes to the current build, TFVC changeset or shelveset, and work-item IDs.
- Closed offline GitHub review-publication and verification receipts that bind the exact
  case/result/report bytes to repository IDs, PR head/base SHAs, event payload subject,
  workflow definition/SHA, run attempt, fork state, and changed harness component while
  rejecting `pull_request_target`.
- A generated canonical project configuration plus `github-configure` and
  `adapter-configure` commands for component path/case selection, the policy preset,
  trusted replay/evaluator/case-generator registration, generator binding, and evidence
  retention without manually authored JSON.
- A protected `case generate` command and companion composite Action that verify separate
  exact-base/exact-head roots, load generator code only from the protected adapter tree,
  treat one bounded candidate component as data, enforce timeout/output/mutation checks,
  require an exact PR-head change reference, immediately review the case, and emit minimized
  provenance without storing the candidate root or component body.
- A composite GitHub Action that discovers up to 500 event-bound PR filenames through a
  bounded read-only API client, deterministically selects one configured canonical case,
  reviews and verifies it, emits a stable job summary and token-free artifact chain,
  publishes a bounded same-repository Check Run with decision annotations, and skips that
  privileged write for forks or token-downgraded Dependabot runs by default.
- A credential-free GitHub-native qualification kit with protected/candidate checkouts,
  full-SHA workflow placeholders, and locally verified approve, abstain, and
  needs-evidence stories.
- A real-case Classic Pipeline gate that uploads a verified build summary and downloadable
  artifacts before returning the decision status.
- Signed, expiring approval assertions that bind an authority-authenticated stable human
  identity and exact Azure review artifacts.
- Explicit policy exceptions that must cover every decision-affecting finding while
  preserving the original gate decision and non-approval exit status.
- Protected tenant access-policy snapshots that resolve fixed investigator,
  policy-administrator, and approver roles without accepting client-supplied roles.
- Machine-readable allow and deny decisions bound to exact policy bytes, tenant, action,
  resource, assigned roles, and granting roles.
- Per-tenant hash-chained audit events for allowed, denied, and failed actions, with payload
  content subjects and policy-backed retention deadlines.
- Policy-authorized complete audit exports bound to a protected tenant-head digest, with
  full-chain and exact-byte verification receipts.
- A zero-dependency SQLite Team store with exact historical
  policy/event/export/case/investigation bytes, forward-only policy revisions, atomic
  per-tenant compare-and-swap heads, ordinary-SQL mutation guards, and consistent online
  backups.
- A framework-neutral Team application service and closed WSGI HTTP boundary that accepts
  only typed host identity, derives roles from active policy, creates IDs/timestamps
  server-side, and records actions with transactional policy/head race protection.
- A protected Entra discovery/JWKS refresher with atomic last-known-good reload, managed
  rollover recovery, and one crash-released refresh owner across local host processes.
- An outer WSGI admission backstop with bounded active-request slots, global/per-source
  token buckets, bounded source state, and rejection before bearer parsing.
- A closed single-process `team-serve` launcher that pins Waitress, binds only canonical
  loopback, composes admission/Entra/Team lifecycle in one order, binds exact refresh
  policy bytes, and trusts no forwarded headers.
- An optional native Windows service adapter with a passwordless virtual account, exact
  registry-bound host-config subject, explicit stopped-state management commands, and a
  controllable Waitress/Entra shutdown path, plus an opt-in self-cleaning live SCM
  qualification harness.
- A server-rendered, payload-free Team evidence console with consistent bounded event
  pages, newest-first cursor navigation, no JavaScript/forms, and restrictive browser
  response headers.
- An immutable-revision Team change-case index and script-free dashboard that joins
  minimized causal evidence, review findings, exact Azure delivery subjects,
  point-in-time approval receipts, canary outcomes, and their publishing audit events.
- A script-free investigation overview/detail dashboard with latest-revision status and
  priority filters, exact fixture subjects, bounded cluster summaries, and no raw trace or
  span references.
- A TFVC-friendly PowerShell CI entry point for Azure Classic Pipelines.

Causure deliberately does **not** execute arbitrary commands or select worker
images from evidence files, modify an agent, authenticate a Team user, make local files
immutable, enforce artifact deletion, or claim that a self-reported confidence score
proves causality. Worker images, sandbox policies, tenant access policies, and hosted
storage are trusted deployment inputs. Upstream replay and evaluation systems produce the
evidence; this gate makes provenance checks and approval decisions transparent and
reproducible.

## Public release status

The public GitHub mirror is available at
[`MusaShams/Causure`](https://github.com/MusaShams/Causure). TFVC remains the authoritative
source, and GitHub is a reviewed one-way mirror until a later migration decision.
The repository now contains commit-pinned GitHub CI/security workflows, structured community
files, an Apache-2.0 license, a deterministic candidate checker, the offline PR-head
publication/verification contract, a protected case-generator Action, and a configured
review Action with bounded PR-file discovery and Check Run publication. Private hosted
qualification invoked both Actions from exact commit
`9a57443e98b6c031bbadc48f863cdb25c92dc63e`: approve, reject, and needs-evidence pull
requests produced verified publications, GitHub Check Run receipts, and retained artifacts;
a rebased Dependabot no-match pull request preserved the stable job without a privileged
Check Run or artifact. Public cross-repository
[pull request 5](https://github.com/MusaShams/causure-examples/pull/5) then proved that a
generator-backed fork stops before protected adapter execution, ordinary review, custom
Check Run publication, or artifact creation. The
[private receipt](docs/qualifications/github-native-private-2026-08-11.json),
[public fork receipt](docs/qualifications/github-native-public-2026-08-11.json), and
[public remediation receipt](docs/qualifications/github-native-public-remediation-2026-08-11.json)
preserve the exact scope, commits, runs, controls, outcomes, and limitations. The public
repository also has secret scanning and push protection, private vulnerability reporting,
pinned GitHub-owned Actions, an active `main` ruleset requiring CI, CodeQL, and dependency
review, and zero open CodeQL, secret-scanning, or Dependabot alerts at the recorded
qualification. The strict checker must return `ready` before any later
repository-publication action:

```powershell
python .\scripts\check_public_release.py
```

Repository creation, initial Git history, public visibility, and the security baseline are
complete. Each later commit, merge, or repository-settings change remains a separate owner
action. See the
[GitHub public-release guide](docs/github-public-release.md) and
[ADR 0026](docs/decisions/0026-publish-a-reviewed-github-mirror.md). The
[productization roadmap](docs/productization-roadmap.md) records the completed P0-A human
usability gate and separates the implemented assurance core and protected GitHub workflow
from the remaining public decision-story qualification, experiment orchestration, and
enterprise deployment work. See the
[trusted case-generation guide](docs/trusted-case-generation.md) for the protected two-step
company workflow, the
[GitHub Action guide](docs/github-action.md) for the evidence gate and fork-safe
branch-protection model, and the
[GitHub review-publication guide](docs/github-review-publication.md) for the lower-level
offline boundary.

## Portfolio tour

The [engineering case study](docs/portfolio-case-study.md) explains the problem, user-flow
architecture, design decisions, measured evidence, security/privacy boundary, and explicit
production limits. The [90-second demo script](docs/portfolio-demo-script.md) provides the
exact synthetic story and capture checklist for the portfolio release. The
[clean-history publication runbook](docs/clean-history-publication.md) preserves private
provenance while requiring one audited public root commit and fresh hosted qualification.

## Quick start

Python 3.11 or newer is required.

```powershell
python -m pip install -e .
causure demo
```

Running `causure` by itself shows only this first-run path; use
`causure --help-all` for the lower-level automation and enterprise command catalog.
The `demo` command reviews two bundled synthetic stories without credentials, network
access, Docker, or a service deployment. It creates a new `causure-demo` directory
and prints:

```text
Causure demo completed (synthetic; no network was used):
  PATCH: APPROVE - Justified minimal patch
    Why: The failure reproduced, an isolated tool-description correction fixed it, and the controls passed.
  DO_NOT_PATCH: REJECT - Attractive but overbroad change
    Why: The evidence identified the tool description, but the proposal changed the global prompt, exceeded the minimal surface, and failed a negative control.
Open this local overview in your editor: ...\causure-demo\README.md
Machine result: ...\causure-demo\demo-result.json
Next: causure init my-agent-project
```

Open `causure-demo\README.md` for links to both human-readable evidence reports.
The first story approves a narrow tool-description fix; the second prevents a plausible but
overbroad global prompt change. Repeated output is deterministic because the stories and
their synthetic review time are fixed. The command refuses to overwrite an existing output
directory; use `causure demo --output another-demo` to create another copy.

To start a real local project, let the CLI create the small configuration:

```powershell
causure init my-agent-project
```

`init` prints the next command. `doctor` remains available as an optional read-only setup
diagnostic, keeping the common path to `init`, `investigate`, and `case create`.

Then enter that project and turn an OTLP/OpenInference JSON export into a redacted,
candidate-only investigation workspace:

```powershell
Set-Location my-agent-project
causure investigate `
  ..\examples\traces\refund-openinference-otlp.json
```

The command shows the source digest, redaction counts, and numbered trace clusters before it
writes anything. Select the candidates and confirm. In an initialized project, the output
goes under `.causure\artifacts` and is already ignored. For automation, make both
decisions explicit with `--select all --yes`; use `--preview-only` for a no-write inspection.

Copy the investigation path printed by that command into the guided case wizard:

```powershell
causure case create `
  .causure\artifacts\<investigation-id>
```

The wizard verifies the manifest, fixture, selection IDs, hashes, and byte counts before it
asks for any claim. Evidence sections accept zero completed items, so an early investigation
becomes an honest `NEEDS_EVIDENCE / COLLECT_EVIDENCE` result rather than invented trial or
control data. If complete evidence is entered, the same command can produce an approval or
rejection. The generated case, report, result, and source binding are stored under the
project's ignored `artifacts\cases` directory.

To make a committed canonical case selectable in pull requests without editing JSON:

```powershell
causure github-configure `
  --component-id refund-tool-description `
  --component tool_description `
  --path "agent/tools/**/*.py" `
  --case evidence/refund-tool-description.case.json
```

The [GitHub Action guide](docs/github-action.md) contains the minimal full-SHA-pinned caller
workflow. Automatic mode passes as `not_applicable` when no configured component changes and
fails closed for ambiguous matches or candidate-modified governance files.

See the [ten-minute getting-started guide](docs/getting-started.md) for the generated files,
the meaning of each outcome, and the current boundary between the easy synthetic path and
real evidence collection. The minimized
[P0-A unfamiliar-user usability protocol](docs/p0a-usability-test.md) passed with an
unassisted participant in under five minutes; the exact wheel, environment, outcomes, and
limitations are retained in the
[2026-08-11 receipt](docs/qualifications/p0a-unfamiliar-user-2026-08-11.json).

## Manual evidence pipeline

The lower-level collector, investigation fixture, and gate remain available when you want
to inspect each portable artifact directly:

```powershell
causure collect `
  examples\traces\refund-openinference-otlp.json `
  --source-id refund-openinference-fixture `
  --output causure-trace-manifest.json

causure fixture `
  causure-trace-manifest.json `
  --fixture-id refund-investigation `
  --output causure-investigation-fixture.json

causure validate `
  examples\change-cases\approve-refund-tool-description.json

causure review `
  examples\change-cases\approve-refund-tool-description.json `
  --output causure-report.md `
  --result-output causure-result.json
```

The collector reports two safely projected spans, the fixture generator creates one
candidate trace cluster, and the approved gate example produces:

```text
Collected 2 span(s) from 1 trace(s) to causure-trace-manifest.json
Generated 1 draft trace cluster(s) to causure-investigation-fixture.json
Causure: APPROVE (patch) - causure-report.md
```

The generated fixture is a queueing and triage artifact, not evidence that a failure
occurred or that a particular change caused an improvement. An investigator must still add
the requirement, oracle, reproduction, attribution, proposed change, and controls required
by the change-case contract.

The counterexample demonstrates the key product behavior:

```powershell
causure review `
  examples\change-cases\reject-overbroad-prompt.json `
  --format json
```

It returns `reject` because the proposed global prompt rule targets the wrong component,
changes too much surface area, and breaks a legitimate negative-control scenario. This
manual path exposes JSON because JSON remains the portable interchange and automation audit
format. The common local product path no longer requires authoring it by hand.

Producer attestations and approval assertions use the same pinned optional cryptographic
implementation through purpose-specific extras:

```powershell
python -m pip install -e ".[attestation]"
python -m pip install -e ".[approval]"
```

The single-host Team service launcher has a separate exact runtime extra:

```powershell
python -m pip install -e ".[service]"
python -m causure team-serve `
  C:\ProgramData\Causure\config\team-host.json
```

It requires a protected closed configuration and a trusted same-host HTTPS edge; see the
[single-host service guide](docs/team-service-hosting.md) before launching it.

The OpenAI-compatible quota core and split-edge company pilot use separate exact extras:

```powershell
python -m pip install -e ".[quota-service]"
python -m pip install -e ".[quota-pilot]"

python -m causure openai-quota-pilot-prepare `
  C:\Protected\openai-quota.json `
  C:\Protected\openai-provider-api-key `
  C:\ProgramData\Causure\quota-pilot\state-001
```

Preparation alone does not start a service or contact the provider. Follow the
[split-edge pilot guide](docs/openai-quota-pilot.md) for protected ACLs, exact offline image
construction, scoped CA trust, Compose startup, no-provider qualification, and teardown.

For native Windows Service Control Manager supervision, use a machine-wide elevated Python
installation and the separate exact extra/command:

```powershell
python -m pip install "causure[windows-service]==0.4.0a15"
python -m pywin32_postinstall -install
causure-windows-service install `
  C:\ProgramData\Causure\config\team-host.json
```

Installation leaves the service stopped. Follow the
[native Windows service guide](docs/team-windows-service.md) for account ACLs, trusted-edge
setup, readiness, start/stop, deliberate config updates, and removal.

## Decisions and CI behavior

| Decision | Meaning | Recommended action | Default exit |
| --- | --- | --- | ---: |
| `approve` | Evidence and controls meet policy | Patch | 0 |
| `conditional_pass` | Non-blocking conditions remain | Patch after acceptance | 1 |
| `reject` | Evidence contradicts the proposal or shows regression | Do not patch | 1 |
| `needs_evidence` | The case is not strong enough to decide | Collect evidence | 1 |
| `human_review` | Requirements are ambiguous or conflicting | Escalate | 1 |

Use `--allow-conditional` when a CI job should accept a conditional pass. Invalid JSON,
invalid schemas, and invalid policies return exit code 2.

## Evidence bundle

Each bundle records:

1. The claimed failure, expected behavior, observed behavior, and governing requirement.
2. An independent oracle and individual reproduction trials.
3. Competing causal hypotheses and isolated intervention trials.
4. A proposed minimal change with a prediction, unaffected behavior, and known risks.
5. The null hypothesis and evidence against doing nothing.
6. Positive, negative, and regression controls for baseline and candidate behavior.
7. Comparable cost, token, and latency measurements.

See [the evidence-bundle guide](docs/evidence-bundle.md) and the committed
[change-case schema](schemas/change-case.schema.json).

Trace collection has a separate trust boundary. See
[the trace-collection guide](docs/trace-collection.md), the committed
[trace-manifest schema](schemas/trace-manifest.schema.json), and the synthetic
[OTLP/OpenInference fixture](examples/traces/refund-openinference-otlp.json).

The next boundary turns a validated manifest into a constrained triage artifact. See
[investigation fixtures](docs/investigation-fixtures.md) and the committed
[investigation-fixture schema](schemas/investigation-fixture.schema.json).

Any of these artifacts can carry a detached producer signature without changing its native
schema. See [artifact attestations](docs/artifact-attestations.md), the committed
[attestation schema](schemas/artifact-attestation.schema.json), and the separate
[trust-store](schemas/attestation-trust-store.schema.json) and
[revocation-list](schemas/attestation-revocations.schema.json) contracts. Verification
checks exact bytes, trusted producer identity, key validity, expiration, retention
coverage, and current revocation state before emitting a
[verification receipt](schemas/attestation-verification.schema.json).

## Canary outcomes

The post-deployment comparison is a separate boundary from the pre-change gate. It accepts
an exact reviewed change case/result, a canary policy committed before exposure, and one
bounded baseline/candidate observation:

```powershell
python -m causure canary-compare `
  .\canary-observation.json `
  --policy .\canary-policy.json `
  --case .\change-case.json `
  --review-result .\review-result.json `
  --output .\canary-report.md `
  --result-output .\canary-result.json
```

The result is `promote`, `continue`, `rollback`, or `needs_evidence`. It uses conservative
Wilson bounds with a family-wise correction across every metric, cohort, and predeclared
look. It neither fetches telemetry nor changes a deployment. See the
[canary outcome guide](docs/canary-outcome-comparison.md), the committed
[policy](schemas/canary-policy.schema.json),
[observation](schemas/canary-observation.schema.json), and
[result](schemas/canary-result.schema.json) contracts.

## Policy overrides

The defaults are intentionally visible in `GatePolicy`. A team can supply a sparse JSON
override:

```powershell
python -m causure review evidence.json `
  --policy examples\policies\strict-production.json `
  --format json
```

The strict example requires more trials and controls, blocks metric regressions, and is
designed to return `needs_evidence` for the small demo dataset.

## Python API

```python
import json

from causure import parse_change_case, review_case

document = json.loads(open("evidence.json", encoding="utf-8").read())
case = parse_change_case(document)
result = review_case(case)

print(result.decision)
print(result.recommended_action)
```

Company-owned replay/evaluator implementations can be invoked through
`ProcessAdapterRunner`. See the [adapter-runner guide](docs/adapter-runner.md) for the
importability requirements, enforced limits, and security boundary.

`SandboxedAdapterRunner` is the separate deployment option for digest-pinned Linux worker
images. Its offline mode denies container networking; its connected mode requires a
hard-quota controller and dedicated TLS proxy before launch. The repository now includes
one deliberately narrow [OpenAI-compatible reference](docs/openai-compatible-quota-proxy.md)
and a runnable [split-edge one-host pilot](docs/openai-quota-pilot.md). The retained local
receipt covers route isolation, direct-provider denial, restart persistence, and cleanup
without making a provider request; it is not managed production qualification. See the
[sandboxed adapter-runner guide](docs/sandboxed-adapter-runner.md) and its committed
[policy](schemas/sandbox-policy.schema.json), [request](schemas/sandbox-worker-request.schema.json),
[response](schemas/sandbox-worker-response.schema.json), and
[quota configuration](schemas/openai-quota-config.schema.json) contracts.

The public API also exposes `create_artifact_attestation`,
`verify_artifact_attestation`, and strict parsers for attestation, trust-store, and
revocation-list documents. Cryptographic imports remain lazy, so collection and gate use do
not require the optional extra.

The separate approval API exposes `create_approval_assertion` and
`verify_approval_assertion`. An organizational authority must authenticate and authorize
the human before issuing; the bundled issuer command does not turn build variables into an
approver. See [authenticated approval assertions](docs/approval-assertions.md) and the
committed [assertion](schemas/approval-assertion.schema.json),
[trust-store](schemas/approval-trust-store.schema.json),
[revocation-list](schemas/approval-revocations.schema.json), and
[verification](schemas/approval-verification.schema.json) contracts.

The post-deployment API exposes `compare_canary_outcomes`, closed policy/observation
parsers, and JSON/Markdown rendering. It receives exact bytes so a result can bind the
prospective policy and review result without depending on filesystem paths.

The Team-service API exposes `create_team_authorization`,
`create_team_audit_event`, `create_team_audit_export`, and independent verification
functions. Its closed contracts bind stable principals and actions to one tenant and make
ledger mutation detectable. `SQLiteTeamStore` adds exact historical persistence and an
atomic tenant-head compare-and-swap boundary for local or single-host pilots.
`TeamApplicationService` and `TeamWSGIApplication` add a trusted-identity integration
boundary for a company-supplied authentication host; they do not parse bearer tokens or
trust client tenant/role fields. The same boundary serves a read-only evidence console at
`/` or `/team`, joined change-case views at `/team/cases`, candidate-only investigation
views at `/team/investigations`, and bounded event/case/investigation APIs.
Case publication atomically binds a minimized append-only record to a successful
investigation audit event while retaining source bodies outside the dashboard store.
Investigation mutations similarly bind each immutable queue revision to its successful
event while retaining fixture bodies outside the Team database. The optional
`EntraTeamIdentityMiddleware` now supplies one concrete host adapter: it validates a
strict Microsoft Entra v2.0 bearer profile against a protected tenant/key snapshot,
maps only verified directory/object IDs into the typed identity, and leaves Team roles in
the protected Team policy. The separate `entra-trust-refresh` command performs bounded
tenant-specific discovery/JWKS retrieval and atomic snapshot installation, while
`ReloadingEntraAccessTokenVerifier` adopts newer valid files without putting network access
on the request path. `ManagedEntraAccessTokenVerifier` adds one explicit single-process
startup/periodic worker, last-known-good fallback, and globally rate-limited asynchronous
unknown-key recovery. `CoordinatedEntraAccessTokenVerifier` layers a protected local-volume
OS lock, automatic owner failover, follower-only reload, and a coalesced unknown-key
request marker over those primitives for multi-process hosts.
`TeamAdmissionControlMiddleware` can sit outside the Entra adapter to reject excess local
concurrency or request rate before parsing or verifying a bearer token. The `team-serve`
command supplies one closed composition for a single process: exact Waitress `3.0.2`,
canonical loopback only, fixed trusted external HTTPS scheme, no trusted forwarding
headers, an exact refresh-configuration subject, and bounded managed-verifier shutdown.
`TeamHostServer` adds a controllable listener/task/channel lifecycle for service managers.
The optional `causure-windows-service` command binds the exact host-config path,
SHA-256, and byte count to one fixed-name SCM service under a passwordless virtual
account. Its lifecycle has an explicit
[isolated Windows qualification harness](scripts/qualify_windows_service.ps1), but a real
deployment still requires a trusted same-host HTTPS edge. See the
[Team service foundation](docs/team-service-foundation.md),
[SQLite store guide](docs/team-sqlite-store.md),
[Team HTTP API guide](docs/team-http-api.md),
[Microsoft Entra bearer-host guide](docs/team-entra-bearer-host.md),
[single-host service guide](docs/team-service-hosting.md),
[native Windows service guide](docs/team-windows-service.md),
[evidence-console guide](docs/team-evidence-console.md),
[change-case dashboard guide](docs/team-change-case-dashboard.md),
[investigation-queue guide](docs/team-investigation-queue.md), and the committed
[access policy](schemas/team-access-policy.schema.json),
[authorization](schemas/team-authorization.schema.json),
[audit event](schemas/team-audit-event.schema.json),
[audit export](schemas/team-audit-export.schema.json), and
[verification receipt](schemas/team-audit-verification.schema.json), plus the
[HTTP action request](schemas/team-http-action-request.schema.json) and
[event-page response](schemas/team-http-event-page.schema.json), the
[case record](schemas/team-case-record.schema.json),
[case publication request](schemas/team-http-case-publication-request.schema.json),
[case page](schemas/team-http-case-page.schema.json), and
[case detail](schemas/team-http-case-detail.schema.json), plus the
[investigation record](schemas/team-investigation-record.schema.json),
[open request](schemas/team-http-investigation-open-request.schema.json),
[observation request](schemas/team-http-investigation-attach-request.schema.json),
[transition request](schemas/team-http-investigation-transition-request.schema.json),
[investigation page](schemas/team-http-investigation-page.schema.json), and
[investigation detail](schemas/team-http-investigation-detail.schema.json), plus the protected
[Entra trust-store contract](schemas/entra-trust-store.schema.json) and protected
[refresh configuration](schemas/entra-refresh-config.schema.json), and the closed
[Team host configuration](schemas/team-host-config.schema.json).

## TFVC and Azure DevOps

This project currently uses TFVC for source control. Azure Pipelines supports TFVC through
the Classic pipeline editor. The reusable repository-validation entry point is:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\classic_ci.ps1
```

It verifies the pinned cryptography, Waitress, and Windows pywin32 runtimes, compiles the
package, runs all
tests (including deterministic sandbox command,
scheduling, and quota-controller tests), collects the redacted trace fixture, generates
and checks the draft investigation fixture, executes a tenant authorization/audit-export
smoke workflow, validates and reviews the approved example, runs Ruff when installed, and
builds a wheel. The default suite does not require or claim to qualify a live Docker
daemon, and its Windows-service tests never register a real service or write HKLM. The
quota pilot's live Docker checks remain an explicit, self-cleaning operator command.

Use the separate real-case gate after those checks:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\azure_review_gate.ps1 `
  -CasePath .\evidence\production-change.json `
  -TfvcServerPath '$/ProofBeforePatch' `
  -WorkItemId 17,93
```

It rejects non-TFVC agents, distinguishes changesets from gated shelvesets, hashes the exact
result and report, verifies the current build identity immediately before completion,
uploads a dedicated build summary, and publishes the files as a named Azure artifact. See
[the Azure review-gate guide](docs/azure-devops-review-gate.md) and
[TFVC and Classic Pipeline setup](docs/tfvc-and-classic-pipeline.md).

After an independent approval authority receives those artifacts, `issue-approval` creates
a signed confirmation or explicit exception. `verify-approval` rechecks the exact artifact
chain, authority/action policy, approver claim, expiration, revocations, and current Azure
TFVC identity. A verified exception remains `record_only` and returns the original
non-approval exit status.

## License

Causure is licensed under the [Apache License, Version 2.0](LICENSE). See
[ADR 0027](docs/decisions/0027-license-public-distribution-under-apache-2.0.md) for the
public-distribution decision.

## Project layout

```text
.github/               public CI, security automation, and contribution forms
src/causure/   gate, collection, runners, approvals, Azure, Team service/API, CLI
schemas/                versioned integration contracts
examples/               trace/canary fixtures, evidence cases, and policies
tests/                  deterministic unit and integration tests
scripts/                validation, release boundary, and TFVC/Azure pipeline entry points
docs/                   architecture, threat model, decisions, operations, and roadmap
```

## Status

Windows single-host pilots can now build a reproducible
[offline machine bundle](docs/windows-service-bundle.md) with a private runtime, exact
SCM recovery, protected install receipt, rollback-aware ACLs, and retry-safe removal. The
ZIP is hash-closed but unsigned; publisher signing and production target-image qualification
remain explicit production gates.

The exact a15 ZIP was rebuilt byte-for-byte and passed the 2026-08-09 self-cleaning
[Windows bundle qualification](docs/qualifications/windows-service-bundle-2026-08-09.json),
including real 121.69-second crash recovery, fail-closed configuration drift and port
collision, policy restoration, running-service removal, operator ACL restoration, and zero
remaining managed machine state. A separate restart-safe harness can now arm an exact,
hash-bound one-shot SYSTEM verifier for delayed-automatic startup, `/readyz`, service-only
network loss, post-boot non-crash recovery, and complete teardown. Arming never issues the
separately authorized reboot, and no cold-boot pass is claimed until its protected report
has been inspected and committed.

The fourth authorized run passed that pilot cold-boot gate on Windows 11 Pro build 26200.
The canonical [cold-boot evidence](docs/qualifications/windows-service-cold-boot-2026-08-09.json)
binds the exact a15 ZIP/manifest and SYSTEM task hashes, records delayed automatic readiness
200, proves the structured 121.197-second non-crash restart and bounded second failure,
restores readiness 200, removes the running bundle, restores operator ACLs, and records zero
cleanup errors or remaining managed machine state.

The first authorized cold-boot run proved the delayed-auto, readiness, post-boot non-crash
recovery, restoration, and managed-removal assertions but correctly recorded `failed`
because its task attempted to delete its own current working directory. The exact failed
[attempt-1 report](docs/qualifications/windows-service-cold-boot-2026-08-09-attempt-1.json)
is retained. A second run proved that cleanup correction and left no managed machine state,
but also correctly failed when the negative test used the ordinary start command that waits
for SCM `RUNNING`; its exact
[attempt-2 report](docs/qualifications/windows-service-cold-boot-2026-08-09-attempt-2.json)
is retained. A third run's non-waiting start produced the exact configured restart and
second bounded failure, but its transient recovered process fell between CIM polls; the
exact [attempt-3 report](docs/qualifications/windows-service-cold-boot-2026-08-09-attempt-3.json)
also remains failed. Those reports remain immutable engineering evidence rather than being
reclassified after the fourth run passed.

This is a `0.4.0a18` foundation, not yet a hosted platform. Trace collection, draft fixture
generation, process-bounded company adapters, detached producer attestations, and the
digest-pinned offline OCI boundary are usable locally. The protected GitHub composition can
discover an event-bound component, generate its case through a reviewed base-checkout
adapter, and select/review that exact canonical case. In the private hosted qualification,
the full-SHA-pinned approve, reject, and needs-evidence paths produced complete retained
evidence chains, and the Dependabot no-match path preserved the stable gate. A subsequent
public cross-fork run proved the generator-backed path fails before protected adapter
execution. Azure TFVC builds can publish and
recheck exact review artifacts and verify authority-signed, expiring approval/exception
records. The Team domain can resolve protected tenant roles, create verifiable audit
chains, serialize writers through a local SQLite store, and expose an integration-ready
trusted-identity WSGI boundary with a read-only audit/evidence console and minimized
joined change-case dashboard. The same boundary now provides an immutable candidate-only
investigation queue with explicit assignment, typed terminal outcomes, and optional
change-case linkage, while keeping exact fixture bodies outside the dashboard store. An
optional Microsoft Entra adapter validates v2.0 bearer tokens from an offline protected
tenant/key snapshot. Its explicit refresh command now fetches protected tenant-specific
metadata/keys, installs an all-tenant snapshot atomically, and supports last-known-good
request-worker reload. A managed single-process lifecycle now owns startup/hourly refresh,
five-minute failure retry, and asynchronous singleflight unknown-key recovery without
blocking the triggering request on network I/O. A coordinated lifecycle now elects one
crash-released writer across processes on the same host/local volume, relays unknown-key
requests from reload-only followers, and promotes a follower after owner exit. It is not a
distributed multi-host lease, and the first request carrying a legitimately new key can
fail once. A process-local admission wrapper now places bounded token buckets and
non-blocking concurrency ahead of bearer verification, while leaving aggregate
multi-worker/host enforcement to a trusted edge. A closed `team-serve` command now composes
those primitives into one exact-version, loopback-only Waitress process with protected
host policy, strict refresh-config binding, no trusted forwarding headers, and bounded
refresh-worker shutdown. It requires a trusted same-host HTTPS edge and remains a
single-host launcher rather than a production deployment qualification. An optional
native Windows adapter can supervise that one process through SCM, bind exact host policy
in HKLM, and stop it through the owned Waitress/Entra lifecycle. The exact a14 wheel passed
one self-cleaning Windows 11 live SCM/readiness/stop/removal run. A deployment still
requires a machine-wide service-accessible Python install, explicit ACL/edge setup, and
qualification on its exact production image. A separate canary comparator now binds
aggregate post-deployment binary outcomes to the exact reviewed change and a prospective
multi-look policy. It does not prove routing/evaluator claims or operate a deployment.
The dashboards deliberately do not retain complete source cases or fixtures, raw
intervention evidence, trace/span references, approval justification, or canary
observations. Queue clustering remains non-causal, and recorded receipts are point-in-time
evidence rather than live Azure, revocation, authorization, or deployment checks. The
project does not supply public TLS termination, signed installer packaging, a distributed
rate limiter, a shared multi-host database, or immutable retention. Causure does
not host the organizational authority or hold production signing keys.
Provider-connected execution now has one non-streaming, text-only OpenAI-compatible
controller/proxy reference plus a digest-pinned split-edge Docker pilot that passed one
retained local no-provider route/network/restart qualification. It does not support
unmodeled billing surfaces, and no live-provider accounting, invoice reconciliation, or
production orchestrator qualification is claimed.

The Apache-2.0 license and package metadata are selected. The public GitHub mirror and its
initial security controls are active; every later mirror publication, merge, or settings
change remains a separate owner-authorized action.
