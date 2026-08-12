# ADR 0026: Publish a reviewed GitHub mirror while TFVC remains authoritative

- Status: accepted
- Date: 2026-08-09
- Release: unreleased

## Context

ADR 0002 made TFVC the initial source of record. The project now needs a public-facing GitHub
repository so companies and researchers can inspect, evaluate, and discuss the work. The
local Git repository has no commits or remote, and copying the workspace without a boundary
could expose TFVC metadata, generated reports, pilot state, credentials, or private signing
material.

Maintaining ordinary independent histories in TFVC and GitHub would also create split-brain
change control. A GitHub merge could appear public before it exists in the authoritative
TFVC changeset, while a TFVC-only fix could leave the public code stale.

## Decision

Prepare GitHub as a reviewed, one-way publication mirror while TFVC remains authoritative.

1. Build each GitHub snapshot only from a clean, checked-in TFVC workspace.
2. Exclude TFVC metadata, local Git internals, generated artifacts, pilot state, databases,
   credentials, and private-key formats from the candidate.
3. Run the deterministic public-release checker and full project validation before a Git
   commit or push. The checker reports finding types and paths without printing matched secret
   values. The strict checker must fail until an owner-approved license is present.
4. Create the GitHub repository privately first, push the reviewed snapshot, enable and
   verify the security controls and required checks, then treat public visibility as a
   separate owner-authorized operation.
5. Do not merge GitHub pull requests independently. Reproduce an accepted contribution in
   TFVC, validate and check it in there, and then publish the resulting reviewed snapshot.
6. Record a new ADR before changing the authoritative source of record from TFVC to GitHub.

No license, Git commit, remote, repository, or visibility change is selected by this ADR.
Those are explicit owner decisions at publication time.

ADR 0027 subsequently selected Apache-2.0. The Git and GitHub actions remain unselected by
this decision and separately authorized.

## Consequences

- GitHub can provide a clean public product and research surface without exposing local
  TFVC state.
- Pinned GitHub Actions, dependency review, CodeQL, structured contribution forms, and a
  release checker are versioned before the first push.
- Public contributions require maintainer coordination and may take longer while TFVC is
  authoritative.
- GitHub commit hashes identify mirror snapshots; the corresponding TFVC changeset remains
  the authoritative engineering record until a later migration decision.
- A missed synchronization is an operational risk. The publication guide therefore makes
  source changes, validation, snapshot creation, push, and visibility separate reviewable
  steps.

See the [GitHub public-release guide](../github-public-release.md) and
[ADR 0002](0002-use-tfvc-initially.md).
