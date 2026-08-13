# Causure documentation

Start with the smallest path that matches what you want to do.

## Use Causure

- [Getting started](getting-started.md): install Causure, run the offline demo, initialize a
  project, investigate a trace export, and create a case.
- [Trace collection](trace-collection.md): supported OTLP/OpenInference input, redaction,
  source hashes, and minimized span references.
- [Investigation fixtures](investigation-fixtures.md): candidate clustering and the boundary
  between observed evidence and causal claims.
- [Evidence bundles](evidence-bundle.md): portable case, result, report, and verification
  artifacts.
- [Canary outcome comparison](canary-outcome-comparison.md): evaluate baseline and candidate
  outcomes under a predeclared policy.

## Integrate pull-request review

- [GitHub Action](github-action.md): configure component selection and a protected,
  full-SHA-pinned pull-request workflow.
- [Trusted case generation](trusted-case-generation.md): keep executable generators in the
  protected base while treating candidate code as data.
- [Azure DevOps review gate](azure-devops-review-gate.md): bind review evidence to a TFVC
  changeset or gated shelveset.
- [Approval assertions](approval-assertions.md): verify signed, expiring approvals and
  narrowly scoped policy exceptions.

## Run controlled adapters

- [Adapter runner](adapter-runner.md): company replay and evaluator contracts plus bounded
  process execution.
- [Sandboxed adapter runner](sandboxed-adapter-runner.md): digest-pinned OCI execution with
  resource and network controls.
- [OpenAI-compatible quota proxy](openai-compatible-quota-proxy.md): provider-backed
  reservation and settlement reference.

## Evaluate the Team reference

- [Deployment guide](deployment-guide.md): choose between the local, GitHub, single-host
  Team, Windows service, and quota-proxy evaluation paths.
- [Team service foundation](team-service-foundation.md): trust boundaries, tenant policy,
  and application-service composition.
- [Team HTTP API](team-http-api.md): integration endpoints and identity requirements.
- [Investigation queue](team-investigation-queue.md), [evidence console](team-evidence-console.md),
  and [change-case dashboard](team-change-case-dashboard.md): the reference investigation
  and review surfaces.
- [Single-host service](team-service-hosting.md) and
  [Windows service adapter](team-windows-service.md): controlled pilot deployment paths.

## Understand the design

- [Engineering case study](portfolio-case-study.md): problem, user journey, design choices,
  measured evidence, and current limits.
- [Architecture](architecture.md): component and trust-boundary details.
- [Threat model](threat-model.md): assets, actors, controls, and residual risks.
- [Architecture decisions](decisions/): individual design records.
- [Productization roadmap](productization-roadmap.md): completed milestones and the next
  product phases.

## Verify the release

- [Public-release qualification](qualifications/causure-public-release-2026-08-13.json):
  exact `v0.4.0a18` validation, artifact, hosted-flow, security, and limitation record.
- [Public-release boundary](github-public-release.md): checks used to keep generated state,
  secrets, and private provenance out of a public snapshot.
- [Security policy](../SECURITY.md): supported versions, vulnerability reporting, and safe
  deployment expectations.

Causure is an alpha. The reference service and deployment material demonstrate bounded
integration patterns; they do not constitute a supported multi-tenant production platform.
