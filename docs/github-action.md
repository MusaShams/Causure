# GitHub Action and Check Run

- Status: implemented protected case generation, configured selection, composite gate, and Check Run publisher
- Audience: repositories that configure committed cases or protected company case generators
- Supported host: GitHub.com
- Supported runner: GitHub-hosted, or self-hosted Actions Runner `v2.327.1` or newer for
  the pinned Node 24 `actions/checkout` and `actions/setup-python` dependencies

## What the Action does

The root [`action.yml`](../action.yml) turns the lower-level gate into one CI step. For one
pull-request run it:

1. reads the generated project configuration and discovers the event-bound pull request's
   changed filenames through a bounded, read-only GitHub API client;
2. selects exactly one configured harness component, its canonical change case, and its
   policy preset, while preserving explicit path overrides for advanced workflows;
3. runs the deterministic review and writes the exact JSON result and Markdown report;
4. binds those bytes to `pull_request.head.sha`, repository numeric IDs, the event payload,
   workflow definition/SHA, run ID, and run attempt;
5. re-verifies that closed publication against the current run;
6. creates a token-free, bounded Check Run request and a readable job summary;
7. publishes a completed Check Run for a same-repository pull request when permitted; and
8. writes a minimized receipt that binds GitHub's returned Check Run identity back to the
   exact request and verification bytes.

The root Action does not collect traces, run company replay/evaluator adapters, generate a
change case from source code, execute configured adapter entry points, upload artifacts,
configure branch protection, or merge a pull request. The separate
[`trusted-case-generator`](../trusted-case-generator/action.yml) Action can generate the
case first from a protected base checkout. Artifact retention, branch protection, and merge
authorization remain explicit surrounding workflow or product steps.

## Configure once without editing JSON

Initialize the repository and register each harness component through the CLI. The command
updates the canonical `.causure/config.json` safely; users do not need to author its
schema by hand.

```powershell
causure init .

causure github-configure `
  --component-id refund-tool-description `
  --component tool_description `
  --path "agent/tools/**/*.py" `
  --case evidence/refund-tool-description.case.json `
  --retention-days 30

causure doctor .
```

For a committed-case component, commit `.causure/config.json`,
`.causure/policy.json`, and the referenced case. The generated config also has a
closed `trusted_adapter_entry_points` registry. The root Action never imports or executes
those values. Register an already reviewed replay entry point without importing it:

```powershell
causure adapter-configure `
  --adapter-id company-replay `
  --kind replay `
  --entry-point company_agent.replay:run
```

For automatic case generation, place reviewed generator code beneath
`.causure/adapters` in the protected branch, then register and bind it to the
existing component:

```powershell
causure adapter-configure `
  --adapter-id company-case-generator `
  --kind case_generator `
  --entry-point company_agent.generator:generate `
  --component-id refund-tool-description

causure doctor .
```

Configuration schema `3.0` stores that binding while keeping `1.0` and `2.0` readable. A
missing configured case is then an expected `doctor` warning because it will be generated
at runtime. See the [trusted case-generation guide](trusted-case-generation.md) for the
adapter contract, provenance receipt, failure boundaries, and exact two-checkout workflow.

## Minimal caller workflow

Use the unprivileged `pull_request` event and pin every external action to a reviewed full
commit SHA. Replace `YOUR_ORG/Causure@REPLACE_WITH_REVIEWED_40_CHARACTER_COMMIT_SHA`
only after the reviewed GitHub mirror exists; never replace it with `uses: ./` after checking
out an untrusted pull-request head.

```yaml
name: Causure

on:
  pull_request:
    types: [opened, ready_for_review, reopened, synchronize]

permissions:
  contents: read
  pull-requests: read
  checks: write

jobs:
  causure:
    name: Causure gate
    runs-on: ubuntu-latest
    timeout-minutes: 10
    steps:
      - name: Check out the candidate
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
        with:
          persist-credentials: false

      - name: Review the proposed agent change
        id: gate
        uses: YOUR_ORG/Causure@REPLACE_WITH_REVIEWED_40_CHARACTER_COMMIT_SHA
        with:
          output-directory: causure-evidence
          github-token: ${{ github.token }}

      - name: Retain the exact evidence chain
        if: ${{ always() && steps.gate.outputs.selection-status != 'no_match' }}
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: causure-${{ github.run_id }}-${{ github.run_attempt }}
          path: causure-evidence
          if-no-files-found: error
          retention-days: ${{ steps.gate.outputs.artifact-retention-days }}
```

The caller grants `pull-requests: read` for filename discovery and `checks: write` for the
same-repository custom Check Run; a composite Action cannot elevate the caller's token
permissions. `github.token` is the repository-scoped GitHub App installation token created
for that job. Do not replace it with a long-lived personal access token.

The config, selected case, optional policy override, repository root, and output directory
must stay within `GITHUB_WORKSPACE`. `repository-root` defaults to `.`, and allows the root
Action to review a separate exact-head checkout such as `candidate` after protected case
generation. Output is new-only: the Action refuses to overwrite an existing artifact. The
selected changed path is where decision-affecting annotations are attached.
Each current annotation points to line 1 because the change-case contract identifies a
component, not an exact source-code diff hunk.

When no configured path matches, the step succeeds as `not_applicable`, writes an explanatory
job summary, and creates no evidence directory. When more than one configured component
matches, it fails closed rather than silently reviewing only part of the PR. Split that PR
or use a deliberate matrix/explicit workflow. Automatic mode also rejects a PR that changes
its own config or selected policy. A separately reviewed governance workflow can use both
explicit `case` and `component-path` inputs to bypass selection; supplying only one is an
error.

For a separately reviewed governance PR or a case produced earlier in the same trusted job,
set the pair explicitly:

```yaml
with:
  case: evidence/refund-tool-description.case.json
  component-path: agent/tools/refund.py
  policy: .causure/policy.json
  github-token: ${{ github.token }}
```

Paired explicit mode skips PR-file discovery and does not read the project configuration.

## Decisions and required checks

The workflow step returns success for `approve`. It returns success for
`conditional_pass` only when `allow-conditional: "true"` is explicit. `reject`,
`needs_evidence`, and `human_review` return a failing gate status while preserving their
distinct decision and recommended-action outputs.

Configured no-match runs return `decision=not_applicable` and
`recommended-action=no_review`. That is Action routing state, not a sixth deterministic
engine decision, and no review artifacts or custom Check Run are created.

Use the workflow job name **Causure gate** as the branch-protection required
status when the repository accepts fork contributions. Same-repository reviewed runs also
publish the richer custom Check Run named **Causure evidence gate**. A fork's token
is read-only: automatic selection uses it only to read the PR identity and filenames, then
the default `auto` mode deliberately skips the privileged Check Run write. Requiring only
the custom Check Run would otherwise leave fork pull requests waiting for a status they
cannot publish.

| `publish-check` | Same-repository pull request | Fork pull request |
| --- | --- | --- |
| `auto` (default) | Publish the explicit Check Run | Skip the write; preserve the workflow gate and local artifacts |
| `required` | Publish or fail closed | Fail closed because direct publication is unavailable |
| `disabled` | No API write | No API write |

Do not enable GitHub's setting that sends write tokens or secrets to fork pull-request
workflows. Do not change this workflow to `pull_request_target`. Fork runs remain useful:
the Action reviews public repository inputs, writes the job summary and token-free evidence
artifacts, and reports the deterministic job result using only the job's read-only
installation token for discovery. Dependabot behavior remains part of remote qualification
because GitHub can further restrict its same-repository workflow token. When the actor is
`dependabot[bot]`, default `auto` mode preserves the deterministic workflow gate but disables
the custom Check Run API write. `required` mode continues to fail closed if that write is
unavailable. The
[2026-08-11 private qualification](qualifications/github-native-private-2026-08-11.json)
confirmed the hosted no-match form of this path after a Dependabot rebase: the stable job
passed at the fixed Action SHA while no custom Check Run or empty artifact was created.

Generator-backed forks fail earlier in the companion trusted Action, before repository-head
verification or adapter execution. This prevents arbitrary fork content from reaching
protected company adapters or credentials. A component that uses a committed case can still
follow the root Action's ordinary secret-free fork path.

## Generated evidence

The output directory contains:

- `review-result.json` — the canonical deterministic decision;
- `review-report.md` — the human evidence report;
- `github-review-publication.json` — the exact PR/run binding;
- `github-review-verification.json` — the fresh re-verification receipt;
- `github-check-run-request.json` — the token-free API plan;
- `github-check-run-summary.md` — the minimized summary also appended to the job summary;
  and
- `github-check-run-receipt.json` — present only after GitHub accepts the explicit Check
  Run.

The Action exposes each path plus `decision`, `recommended-action`, `check-published`,
`check-publication-status`, selection metadata, and `artifact-retention-days`. The request
and receipt have committed schemas:

- [`github-check-run-request.schema.json`](../schemas/github-check-run-request.schema.json)
- [`github-check-run-receipt.schema.json`](../schemas/github-check-run-receipt.schema.json)

The optional artifact-upload step is intentionally outside the composite Action so each
company controls retention, encryption, region, and artifact permissions. Keep
`always()` plus the `no_match` exclusion so non-approval decisions retain their evidence
chain without treating an intentionally absent no-match directory as an upload error. An
Actions artifact is retention-controlled evidence, not an immutable or signed archive.

When the trusted generator precedes this Action, retain its separate directory as well. It
contains the generated canonical case, immediate result/report, and minimized
`trusted-case-generation.json` receipt. The full workflow template in
[`examples/github-native/causure.template.yml`](../examples/github-native/causure.template.yml)
uploads both chains.

## GitHub network boundaries

Automatic selection performs bounded `GET` requests only to the current base repository's
`/pulls/<number>` and `/pulls/<number>/files` endpoints. It accepts at most 500 changed
files, 100 per page; validates JSON media types and response sizes; disables redirects;
and checks the base/head repositories and exact event SHAs both before and after pagination.
If the PR moves during discovery, the run fails and can be retried. Explicit mode performs
none of these discovery requests.

The publisher sends one `POST` only to
`https://api.github.com/repos/<owner>/<repository>/check-runs`. Redirects are disabled, the
request and response are bounded, the API timeout is bounded, and the response must be a
201 JSON Check Run matching the planned name, head SHA, conclusion, external ID, and HTML
identity. At most 50 decision-affecting findings are annotated in the single request.
The token is read only from the Action input/environment boundary and is not written to any
artifact, exception text, or summary. The discovery and publication transports share the
same short-lived job token but have separate fixed methods and endpoints.

The receipt proves that the expected response was accepted for the exact request bytes. It
does not prove artifact immutability, authorize a merge, or turn a non-approval decision
into success. GitHub's runner, event/environment delivery, protected caller workflow,
remote Action commit, token issuance, and artifact retention remain trusted controls.

GitHub Enterprise Server is not supported by this publisher yet: context validation and
the API endpoint currently require `github.com`. A future GHES adapter needs an explicit
trusted-host configuration and separate qualification rather than accepting an arbitrary
server URL.

## Lower-level CLI

Custom workflows can run publication and verification separately, then use the bounded
publisher. Supply the short-lived token through an environment variable, never a command
argument:

```powershell
$env:CAUSURE_GITHUB_TOKEN = $env:GITHUB_TOKEN

causure github-check-run `
  github-publication.json `
  github-verification.json `
  case.json `
  result.json `
  report.md `
  --component-path agent/tools/refund.py `
  --request-output github-check-request.json `
  --summary-output github-check-summary.md `
  --output github-check-receipt.json
```

The command first writes the token-free request and summary, then reads the token and
performs the single API call. Its process exit still follows the underlying gate decision.

## Remaining P0-B work

The [2026-08-11 public qualification](qualifications/github-native-public-2026-08-11.json)
records the authorized public mirror controls, successful CodeQL run, and real
generator-backed fork pull request that failed before protected adapter execution. Remaining
work is to publish and exercise fresh approve, abstain, and needs-evidence synthetic
pull-request stories under the public repository configuration. The separate
[public remediation qualification](qualifications/github-native-public-remediation-2026-08-11.json)
records the first successful public dependency-review run, its addition to the protected
`main` ruleset, the cryptography advisory closure, and green post-merge CI and CodeQL.

The credential-free local source fixtures and qualifier are in
[`examples/github-native`](../examples/github-native/README.md). Their three passing local
stories remain engineering evidence rather than remote GitHub qualification. The separate
private qualification receipt supplies hosted evidence only for its stated same-repository
and Dependabot scope. The public receipt independently closes the generator-backed fork
gate; neither receipt substitutes for a company's own adapter and deployment qualification.

GitHub documents the
[`GITHUB_TOKEN` installation-token boundary](https://docs.github.com/en/actions/concepts/security/github_token),
[fork pull-request restrictions](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows),
and [Checks API permissions and annotation limit](https://docs.github.com/en/rest/checks/runs).
