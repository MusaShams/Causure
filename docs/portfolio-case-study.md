# Causure engineering case study

> Functional evidence-gated agent change control. Change only what the evidence supports.

## The problem

Agent failures often produce an attractive first diagnosis: rewrite the prompt, add another
reviewer, change routing, or patch a tool description. That diagnosis can be wrong even when
the proposed patch improves the visible example. A broad change can mask an environmental
failure, target the wrong harness component, break negative controls, or add cost and latency
without addressing the cause.

Causure treats the proposed change as a claim to be proved. It asks whether the failure
reproduces, whether an isolated intervention identifies the causal component, whether a
smaller change exists, and whether positive, negative, regression, cost, and latency controls
support the candidate. The output can approve a patch, reject it, request evidence, require
human review, or allow a narrowly qualified conditional pass.

## The user journey

```mermaid
flowchart LR
    A["Incident or harness pull request"] --> B["Import minimized trace references"]
    B --> C["Confirm failure, requirement, and competing hypotheses"]
    C --> D["Generate or select a candidate-bound change case"]
    D --> E["Run bounded company replay and evaluation adapters"]
    E --> F["Verify attribution, minimality, and controls"]
    F --> G{"Evidence-backed decision"}
    G -->|"Approve"| H["Patch recommendation"]
    G -->|"Reject"| I["Do-not-patch explanation"]
    G -->|"Incomplete"| J["Exact evidence request"]
    H --> K["GitHub Check Run and retained report"]
    I --> K
    J --> K
    K --> L["Human merge or external canary decision"]
```

The candidate repository remains data while trusted adapters come from a protected base.
Causure publishes evidence and recommendations; it does not merge, deploy, or roll back a
change by itself.

## What was built

- `causure demo` produces one supported narrow patch and one plausible wrong patch, entirely
  offline, with human-readable reports and canonical machine results.
- `causure init`, `causure doctor`, `causure investigate`, and `causure case create` provide
  a no-manual-JSON path from project setup through minimized trace selection and a bounded
  evidence case.
- A deterministic review engine checks reproduction, causal attribution, no-change evidence,
  minimality, positive/negative/regression controls, cost, and latency.
- A protected GitHub workflow discovers the changed harness component, generates or selects
  its exact case, re-verifies the publication subject, publishes one stable Check Run, and
  retains the evidence chain.
- TFVC integration, signed approvals, audit chains, tenant policy, a transactional Team
  service, Windows packaging, and an OpenAI-compatible quota pilot demonstrate deeper
  enterprise boundaries without making them the public onboarding path.

## Design decisions

1. **Gate evidence before generating another patch.** The product controls whether a proposed
   harness change is justified instead of becoming another autonomous patch generator.
2. **Keep one canonical project configuration.** GitHub selection and trusted adapters extend
   `.causure/config.json`; users do not maintain a second workflow-specific configuration.
3. **Execute trusted generators only from the protected base.** Candidate content never
   supplies executable adapter code, and generator-backed forks fail before adapter execution.
4. **Bind every hosted result to exact bytes and identities.** Repository IDs, base/head SHAs,
   run attempt, workflow SHA, case/result/report digests, and changed component are verified
   before publication.
5. **Make abstention a product outcome.** Missing or contradictory evidence remains visible as
   `needs_evidence`, `reject`, or `human_review`; it is not coerced into success.

The detailed rationale is retained in the
[architecture decisions](decisions/0001-evidence-gate-first.md), including the
[canonical configuration decision](decisions/0028-reuse-the-canonical-project-config-for-github-selection.md)
and [protected generator decision](decisions/0029-run-case-generators-only-from-a-protected-base.md).

## Measured engineering evidence

- The P0-A completion candidate Classic CI run passed 556 tests with one expected
  platform-specific skip, while Ruff `0.16.2` lint/format checks passed.
- The deterministic public-snapshot checker accepted 306 candidate files with no blocker or
  warning.
- The exact `0.4.0a18` session wheel installed offline into a fresh virtual environment,
  loaded only from that environment, produced both expected decisions, and created three
  Markdown reports.
- An unfamiliar terminal-capable participant used that exact wheel to finish the synthetic
  demo in under five minutes with zero assistance, opened a generated Markdown report, and
  correctly distinguished the causally supported narrow patch from the wrong-component,
  overbroad change that failed a negative control.
- Public Causure pull request 9 passed package build, six Python/OS matrix jobs, CodeQL, and
  dependency review before merging; the same CI and CodeQL gates passed on the merge commit.
- A public cross-repository fork run stopped before protected adapter execution, ordinary
  review, custom Check Run publication, or artifact upload.
- The recorded post-merge state had zero open Dependabot, CodeQL, or secret-scanning alerts.

The exact hosted claims and limitations are in the
[private Action receipt](qualifications/github-native-private-2026-08-11.json),
[public fork receipt](qualifications/github-native-public-2026-08-11.json), and
[public remediation receipt](qualifications/github-native-public-remediation-2026-08-11.json).

## Security and privacy boundary

- The guided importer previews redaction and stores candidate-only references rather than raw
  message bodies or source paths.
- Pull-request workflows accept the unprivileged `pull_request` event, use least-privilege
  permissions, pin third-party Actions to full commits, and do not expose secrets to forks.
- Trusted replay, evaluator, and generator adapters are privileged company code. Process and
  container budgets reduce impact but are not a complete hostile-code sandbox.
- Evidence files cannot choose arbitrary commands, worker images, credentials, tenant roles,
  or merge/deployment actions.
- Reports explain what was observed, user-confirmed, inferred, missing, or contradicted; a
  self-reported confidence score does not prove causality.

## Explicit production limits

Causure is a functional alpha, not a supported multi-tenant production control plane. The
current shared-service reference uses single-host SQLite and local storage; shared relational
authority, immutable object retention, independent ledger anchoring, disaster recovery,
multi-host coordination, generalized SSO, production TLS/secret management, and an
independent security review remain P2 work. Company replay/evaluator quality and deployment
policy remain trusted inputs.

The [P0-A human usability criterion](qualifications/p0a-unfamiliar-user-2026-08-11.json) is
complete for one participant and one Windows environment. The public approve, abstain, and
needs-evidence hosted examples will be requalified against the final clean public snapshot.

## Try the bounded product path

```powershell
causure demo
causure init my-agent-project
causure doctor --project my-agent-project
```

For real evidence, continue with `causure investigate` and `causure case create`. The public
claim is intentionally narrow: **functional evidence-gated agent change control**, not
production-ready autonomous self-improvement.
