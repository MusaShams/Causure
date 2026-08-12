# ADR 0007: Bind Azure TFVC reviews to exact artifacts and build identity

- Status: Accepted
- Date: 2026-07-28

## Context

The deterministic gate already emits a JSON result and Markdown report, and the Classic
Pipeline script can upload the report as a build summary. That presentation alone does not
prove which exact bytes were reviewed, which TFVC changeset or shelveset triggered the
build, or whether the artifacts changed between review and a later approval step.

Azure Pipelines exposes different source identities for ordinary TFVC changeset builds and
gated or manually validated shelveset builds. Treating `Build.SourceVersion` as the target
in every case would lose the shelveset identity. A useful company control must also retain
work-item associations without requiring the deterministic gate to mutate Azure Boards.

## Decision

ProofBeforePatch will emit a closed `AzureReviewPublication` document after every configured
Azure TFVC gate run. It binds:

- the case, decision, component, policy, engine, input digest, and review time;
- either a positive TFVC changeset ID or an exact `name;owner` shelveset identity;
- the protected TFVC server path;
- the Azure collection, project, build, definition, trigger reason, requester ID, and source
  variables supplied by the agent;
- zero or more unique positive work-item IDs; and
- the exact SHA-256 and byte count of the JSON result and Markdown report.

Changeset builds require `Build.SourceVersion` and `Build.SourceBranch` to match the
configured TFVC target. Shelveset builds require `Build.SourceTfvcShelveset`,
`Build.SourceBranch`, and a shelveset-specific build reason to agree. The repository
provider must be `TfsVersionControl`.

A separate `AzureReviewVerification` receipt is produced immediately before the task
returns its gate status. Verification reparses the closed publication, compares it with the
current Azure build environment, re-reads both artifacts, checks their exact hashes and
byte counts, checks the result/report relationship, requires publication within five
minutes of review, and enforces a bounded publication-age window.

The verified data is rendered into an Azure build summary. The task uploads the JSON result,
Markdown report, publication, verification receipt, and summary as a named downloadable
build artifact.

## Consequences

An auditor can now determine which evidence decision and exact files were associated with a
specific TFVC changeset or shelveset build. Artifact mutation, publication reuse in another
build, stale publication, and inconsistent TFVC variables fail closed before the gate task
finishes.

The publication and receipt are integrity metadata, not digital signatures. Their
trustworthiness depends on a protected pipeline definition, trustworthy agent variables,
and artifact retention. A deployment can separately attest the publication bytes when
producer authentication is required.

Work-item IDs are recorded in the publication and linked in the summary; this release does
not create or modify Azure Boards relations. The Azure requester ID records who queued the
build, not who approved a policy exception.

Human approver authentication and explicit, expiring exception records remain a separate
control. The CLI and summary intentionally state that a verification receipt does not grant
an exception or authenticate an approver.
