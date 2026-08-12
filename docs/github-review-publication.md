# GitHub pull-request review publication

- Status: implemented offline contract; composite Action and Check Run publisher available
- Audience: maintainers integrating Causure into GitHub Actions
- Network behavior: none for the publication and verification commands on this page

## Purpose

The GitHub review-publication contract binds one exact Causure change case, review
result, and Markdown report to one exact pull-request candidate and one exact GitHub Actions
run. A second command rechecks all of those bytes and the current event/run immediately
before a later publisher is allowed to report the decision.

This is the tamper-evident foundation for the P0-B GitHub integration. These two offline
commands are usable inside a `pull_request` workflow, but this layer does **not** create a Check Run,
comment on a pull request, upload an artifact, or change branch protection. The
separately bounded publisher and one-step composite workflow are documented in the
[GitHub Action guide](github-action.md).

## Why the candidate is the head SHA

For a pull-request workflow, GitHub documents `GITHUB_REF` as
`refs/pull/<number>/merge`, while the meaning of `GITHUB_SHA` depends on the event. The
candidate under review is therefore read from `pull_request.head.sha`, not inferred from the
merge ref or `GITHUB_SHA`. See GitHub's
[default-variable reference](https://docs.github.com/en/actions/reference/workflows-and-actions/variables)
and
[pull-request event reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).

The publication keeps both values:

- `pull_request.head_sha` is the exact proposed candidate;
- `workflow.event_sha` records the event-dependent `GITHUB_SHA` supplied to that run; and
- `pull_request.base_sha` records the base commit observed in the signed-in runner event.

A later run, attempt, event file, head commit, base commit, repository identity, or workflow
identity cannot be substituted without verification failing.

## What is bound

The publication contains only minimized identities and content subjects:

- base and head repository numeric IDs, owner numeric IDs, and full names;
- pull-request number, base/head refs and SHAs, fork state, and draft state;
- server origin, event name/action, merge ref, workflow ref/SHA, run ID/number/attempt, and
  job name;
- SHA-256 and byte count of the exact GitHub event payload;
- review schema/engine/policy, case ID, component, input digest, time, decision, and
  recommended action; and
- media type, SHA-256, and byte count for the exact change-case JSON, review-result JSON,
  and Markdown report.

The raw GitHub event, pull-request title/body, actor profile, commit message, source code,
and report body are not copied into the publication. The exact event remains a workflow
input; only its digest and byte count are retained.

## Supported workflow boundary

The environment parser accepts only:

- `GITHUB_ACTIONS=true`;
- `GITHUB_EVENT_NAME=pull_request`;
- event actions `opened`, `ready_for_review`, `reopened`, or `synchronize`;
- `GITHUB_REF=refs/pull/<number>/merge`; and
- a `GITHUB_WORKFLOW_REF` under the base repository's `.github/workflows/` directory.

`pull_request_target` is deliberately unsupported. It runs in a more privileged base-repo
context and is unnecessary for this offline contract. GitHub also documents that fork
pull-request workflows normally receive a read-only token and no ordinary repository
secrets; this contract requires neither a token nor a secret. The composite Action preserves
this boundary by skipping its explicit Check Run write for forks in the default mode. Review GitHub's
[fork and pull-request behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
and
[Actions permission controls](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository)
before adding any future publisher.

Fork status is derived from the base and head repository IDs, not accepted from a string or
workflow option. A fork does not weaken artifact, repository, event, or workflow checks.
If a company evaluator needs a secret or privileged adapter that is unavailable to the
untrusted fork workflow, the surrounding workflow must report that evidence as unavailable
and fail closed; it must not switch to `pull_request_target` to execute fork code.

## Commands

Generate the result and report, then create the publication immediately in the same job:

```powershell
causure review case.json `
  --output report.md `
  --result-output result.json `
  --quiet

causure github-publish `
  case.json result.json report.md `
  --output github-publication.json
```

Recheck the exact files and current GitHub context immediately before any later publication
step:

```powershell
causure github-verify `
  github-publication.json case.json result.json report.md `
  --output github-verification.json
```

The default freshness limit is 3,600 seconds and the accepted configurable maximum is
86,400 seconds. Publication creation must be within five minutes of the review timestamp.
Output files are written atomically and cannot overwrite any input path.

The CLI obtains its identity only from the GitHub-provided event file and environment. It
cross-checks repository names and numeric IDs, owner ID, base/head refs, PR number, workflow
location, and merge ref rather than trusting a single variable. The required GitHub
variables are `GITHUB_ACTIONS`, `GITHUB_EVENT_NAME`, `GITHUB_EVENT_PATH`,
`GITHUB_REPOSITORY`, `GITHUB_REPOSITORY_ID`, `GITHUB_REPOSITORY_OWNER`,
`GITHUB_REPOSITORY_OWNER_ID`, `GITHUB_BASE_REF`, `GITHUB_HEAD_REF`, `GITHUB_SERVER_URL`,
`GITHUB_SHA`, `GITHUB_REF`, `GITHUB_WORKFLOW_REF`, `GITHUB_WORKFLOW_SHA`, `GITHUB_RUN_ID`,
`GITHUB_RUN_NUMBER`, `GITHUB_RUN_ATTEMPT`, and `GITHUB_JOB`.

## Outputs and interpretation

Committed schemas are available as:

- `causure schema github-review-publication`
- `causure schema github-review-verification`

The matching files are
[`github-review-publication.schema.json`](../schemas/github-review-publication.schema.json)
and
[`github-review-verification.schema.json`](../schemas/github-review-verification.schema.json).

A successful `github-verify` means the publication, artifacts, and current workflow context
match. It does not reinterpret the underlying review decision. In particular, verification
of a `reject`, `needs_evidence`, or `human_review` result is still a successful integrity
check, not permission to merge. The Check Run adapter maps the already verified decision to
a stable conclusion and bounded decision-affecting annotations without changing it.

## Failure and trust model

Parsing is closed: missing fields, unknown fields, malformed IDs/SHAs/timestamps, unsupported
events, oversized inputs, mismatched repository/ref data, non-corresponding case/result/report
content, and stale or future publications fail before a receipt is emitted. Verification
re-hashes all four documents, including the publication itself in the receipt.

These records detect mutation and context substitution; they are not digital signatures.
GitHub's runner, event/environment delivery, protected workflow definition, artifact
retention, and any future API publisher remain trusted controls. A verification receipt
must be consumed in the same protected job rather than treated as a transferable bearer
authorization.

## Remaining P0-B work

- generate a configured case through a separately trusted adapter workflow rather than
  requiring an existing canonical case;
- remotely qualify the configured composite Action from a full Git commit pin; and
- exercise approve, abstain, and needs-evidence pull requests in a public synthetic example.

The higher-level [GitHub Action guide](github-action.md) now covers the implemented canonical
project configuration, bounded PR-file discovery, deterministic case selection, fork-safe
read-only token behavior, and caller-selected artifact retention.
