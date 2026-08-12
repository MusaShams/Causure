# ADR 0002: Use TFVC for the initial project

- Status: accepted
- Date: 2026-07-27

## Context

The initial Azure DevOps project uses Team Foundation Version Control. The local folder also
contains Git metadata, but no Git commit was created for this implementation.

## Decision

Use TFVC as the source of record for now. Preserve the local `.git` directory without adding
it to TFVC. Package continuous integration as `scripts/classic_ci.ps1` because Azure
Pipelines does not support YAML pipelines for TFVC repositories.

## Consequences

- Workspace mapping and authentication are required before the first check-in.
- Classic Pipeline configuration lives partly in Azure DevOps rather than entirely as code.
- The portable CLI and tests remain source-control agnostic.
- A later migration to Azure Repos Git or another Git host is possible without changing the
  evidence contract.
