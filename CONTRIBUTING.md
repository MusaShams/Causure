# Contributing

## Local checks

Python 3.11 or newer is required.

```powershell
python -m pip install -e ".[dev]"
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\classic_ci.ps1
```

The deterministic gate intentionally has no third-party dependencies. The development
extra includes the pinned package used by the optional Ed25519 attestation feature.

For a candidate public snapshot, also run:

```powershell
python .\scripts\check_public_release.py
```

The strict command must return `ready` before any Git commit or publication operation.

## License and contributions

Causure is licensed under the [Apache License 2.0](LICENSE). Unless explicitly
stated otherwise, contributions intentionally submitted for inclusion are provided under
the contribution terms in Section 5 of that license. Mark material that is not a
contribution clearly and do not submit code you are not authorized to license.

## Source of record and public mirror

TFVC remains the authoritative source under
[`ADR 0026`](docs/decisions/0026-publish-a-reviewed-github-mirror.md). GitHub is being
prepared as a reviewed public mirror; it is not yet an independent development branch.

- Start public snapshots only from a clean, checked-in TFVC workspace.
- Never publish `$tf`, generated reports, databases, prepared pilot state, PAT handoffs,
  credentials, or private signing material.
- Do not merge a GitHub-only change first. A maintainer must reproduce an accepted change in
  TFVC, validate and check it in there, then publish the reviewed result.
- Follow the [GitHub public-release guide](docs/github-public-release.md) for the current
  publication boundary.

## Change expectations

- Add or update tests for every decision-rule change.
- Keep structural validity separate from evidence sufficiency.
- Do not add network access or arbitrary command execution to the core gate.
- Treat evidence documents and policy overrides as untrusted input.
- Preserve stable finding codes; introduce a new code when semantics change.
- Update the architecture, threat model, and examples when behavior changes.

## Schema changes

Update `schema.py`, regenerate all affected schemas, and run the drift tests:

```powershell
$env:PYTHONPATH = "src"
python -m causure schema change-case --output schemas\change-case.schema.json
python -m causure schema policy --output schemas\policy.schema.json
python -m causure schema review-result --output schemas\review-result.schema.json
python -m causure schema artifact-attestation --output schemas\artifact-attestation.schema.json
python -m causure schema attestation-trust-store --output schemas\attestation-trust-store.schema.json
python -m causure schema attestation-revocations --output schemas\attestation-revocations.schema.json
python -m causure schema attestation-verification --output schemas\attestation-verification.schema.json
python -m causure schema azure-review-publication --output schemas\azure-review-publication.schema.json
python -m causure schema azure-review-verification --output schemas\azure-review-verification.schema.json
python -m causure schema sandbox-policy --output schemas\sandbox-policy.schema.json
python -m causure schema sandbox-worker-request --output schemas\sandbox-worker-request.schema.json
python -m causure schema sandbox-worker-response --output schemas\sandbox-worker-response.schema.json
python -m unittest discover -s tests -v
```

Breaking wire-format changes require a new schema version and a migration note.

## Sandbox changes

The default suite must remain deterministic and runnable without a Docker daemon. Use fake
runtimes for scheduling/quota behavior and scripted Docker inspection output for policy
tests. Do not weaken or remove a container flag merely to support an older deployment;
record a policy-version or compatibility decision.

Changes to runtime arguments, cleanup, network admission, image admission, lease ordering,
or secret transport require focused failure-path tests and updates to the sandbox guide,
threat model, and ADRs. A deployment may additionally run live Docker/provider tests, but
those tests must identify the exact engine, kernel, image digest, proxy, and quota backend
they qualify.

## Azure review integration changes

Keep Azure agent variables outside evidence documents. Changes to environment parsing,
TFVC target consistency, artifact hashing, publication freshness, or build-summary
rendering require both changeset and shelveset tests plus focused failure-path coverage.

`azure_review_gate.ps1` must publish the result, report, publication, and successful
verification receipt before it returns a non-approval decision. It must never convert a
non-approval into a passing task. Approver identity and exceptions belong in a separate
authenticated record, not in the build-requester field.

## GitHub contributions

Use the structured issue forms for synthetic, reproducible bug reports and bounded research
or feature proposals. Do not put vulnerabilities, customer content, production traces,
personal data, credentials, or signed artifact URLs in an issue or pull request. Follow
[`SECURITY.md`](SECURITY.md) for private vulnerability reporting.

Pull requests should identify the evidence for the change, the no-change alternative, the
smallest viable intervention, affected trust boundaries, and exact validation performed.
All remote GitHub Actions must remain pinned to full 40-character commit SHAs. Workflows must
not use `pull_request_target`, consume repository secrets for candidate validation, or grant
blanket write permissions.

## TFVC

Run `tf status /recursive` and review every pending change before check-in. Generated reports,
build artifacts, caches, virtual environments, and local Git metadata must remain unversioned.
