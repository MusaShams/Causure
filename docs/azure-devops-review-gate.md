# Azure DevOps TFVC review gate

Causure can turn a real change case into a gated Azure build result with a human
summary and four exact-byte audit artifacts:

1. `causure-result.json`
2. `causure-report.md`
3. `causure-azure-publication.json`
4. `causure-azure-verification.json`

The pipeline also publishes `causure-azure-summary.md`.

## What the publication proves

The publication binds one review to:

- its case ID, decision, policy, engine version, component, evidence digest, and review time;
- the exact JSON result and Markdown report bytes;
- one TFVC target: either a changeset or a shelveset;
- the configured TFVC server path;
- the current Azure collection, project, build, definition, trigger, source, and requester;
  and
- any supplied work-item IDs.

The verification command re-reads the manifest and both artifacts, compares their hashes
and byte counts, confirms the current Azure build and TFVC identity still match, and rejects
a publication outside the configured age window. Publication creation must also occur
within five minutes of the bound review time, preventing an old result from being wrapped
in a newly fresh manifest.

Azure defines `Build.SourceVersion` as the changeset for a TFVC build and separately exposes
`Build.SourceTfvcShelveset` for gated or shelveset builds. Causure keeps those
cases distinct. See Microsoft's
[predefined-variable reference](https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops).

## Add the gate to a Classic Pipeline

TFVC uses the Classic build editor. After the dependency-install and
`scripts/classic_ci.ps1` validation tasks, add a PowerShell task that runs:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\azure_review_gate.ps1 `
  -CasePath .\evidence\production-change.json `
  -TfvcServerPath '$/ProofBeforePatch' `
  -WorkItemId 17,93
```

Use `-PolicyPath .\policy\production.json` when a protected override is required. The case,
policy, and TFVC path must be pipeline configuration or protected repository inputs; do not
accept them from untrusted evidence fields.

The script requires an Azure Pipelines agent (`TF_BUILD=True`) and a TFVC repository
provider. It writes under `$(Build.ArtifactStagingDirectory)\causure` by default.
On completion it:

- uploads the verified Markdown with `task.uploadsummary`;
- uploads all five files as the `Causure` build artifact;
- exposes result, report, publication, and verification paths as task variables; and
- returns the original gate exit status after the audit artifacts have been published.

Azure logging commands are interpreted from task standard output. The summary attachment
is presentation-only, while the named build artifact remains downloadable. See Microsoft's
[logging-command reference](https://learn.microsoft.com/en-us/azure/devops/pipelines/scripts/logging-commands?view=azure-devops)
and [artifact documentation](https://learn.microsoft.com/en-us/azure/devops/pipelines/artifacts/pipeline-artifacts?view=azure-devops).

An `approve` decision returns zero. Every other decision fails the task by default.
Configuration, parsing, build-identity, freshness, and integrity failures return a
configuration error and do not publish a successful verification receipt.

## Changeset and shelveset behavior

For an ordinary TFVC build:

- `Build.SourceVersion` must be a positive changeset ID.
- `Build.SourceBranch` must match `-TfvcServerPath`.
- `Build.SourceTfvcShelveset` must be absent.

For a gated or explicitly validated shelveset build:

- `Build.SourceTfvcShelveset` must contain `name;owner`.
- `Build.SourceBranch` must identify the same shelveset.
- `Build.Reason` must be `CheckInShelveset` or `ValidateShelveset`.

Azure's gated check-in flow shelves changes, runs the configured validation build, and
checks in only after a successful result. See
[Microsoft's gated-check-in guide](https://learn.microsoft.com/en-us/azure/devops/repos/tfvc/check-folder-controlled-by-gated-check-build-process?view=azure-devops).

## Direct CLI use

The PowerShell task is a thin orchestration layer. On an Azure TFVC agent, the underlying
commands are:

```powershell
causure azure-publish `
  .\dist\causure-result.json `
  .\dist\causure-report.md `
  --tfvc-server-path '$/ProofBeforePatch' `
  --work-item-id 17 `
  --output .\dist\causure-azure-publication.json

causure azure-verify `
  .\dist\causure-azure-publication.json `
  .\dist\causure-result.json `
  .\dist\causure-report.md `
  --tfvc-server-path '$/ProofBeforePatch' `
  --output .\dist\causure-azure-verification.json `
  --summary-output .\dist\causure-azure-summary.md
```

The committed contracts are
[`azure-review-publication.schema.json`](../schemas/azure-review-publication.schema.json)
and
[`azure-review-verification.schema.json`](../schemas/azure-review-verification.schema.json).

## Trust and approval boundary

Protect the Classic Pipeline definition, agent pool, source mapping, policy, and artifact
retention. Anyone who can change both the gate task and its output can fabricate internally
consistent unsigned records.

The requester ID comes from the build environment and identifies who queued the build. It
is not an authenticated approval. `System.AccessToken` authenticates the build service,
not the human. Work-item IDs are recorded and linked in the summary, but the command does
not mutate Azure Boards.

The verification receipt deliberately does not record an exception. The separate
`issue-approval` and `verify-approval` boundary binds an authority-authenticated human
action to the exact publication and receipt, caps validity, checks current authority-key
revocations, and keeps exceptions separate from the deterministic result. See
[authenticated approval assertions](approval-assertions.md).

Do not keep the approval-authority private key in this gate job. A protected authority can
query Azure's
[Approvals REST API](https://learn.microsoft.com/en-us/rest/api/azure/devops/approvalsandchecks/approvals/get?view=azure-devops-rest-7.1)
or another organizational identity service, authorize the returned stable subject, and
then issue the signed record. A verified exception is `record_only`; it retains the
original non-approval and `verify-approval` returns exit code 1 after writing the receipt.
