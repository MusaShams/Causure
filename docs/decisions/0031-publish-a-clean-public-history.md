# ADR 0031: Retain private history and publish one clean public root commit

- Status: Accepted
- Date: 2026-08-11

## Context

TFVC remains the authoritative engineering record, while the current GitHub repositories
contain a temporary publication and qualification history. The portfolio release should show
the product as one coherent public snapshot rather than expose the long mirror-construction,
security-remediation, and qualification sequence as its default-branch history.

Changing a public GitHub repository to private does not retract bytes already cloned, and
GitHub leaves public forks public in a detached network. GitHub also warns that reusing a
renamed repository's former name removes its redirects, and Actions do not follow repository
rename redirects. The process therefore needs an explicit archive, fork inventory, exact
snapshot boundary, and fresh qualification against the final repository identity.

The 2026-08-11 preflight found no GitHub-hosted fork of `MusaShams/Causure`. The examples
repository has one public fork, `causure-project/causure-examples`, controlled by the owner.
Those observations must be repeated at execution time; they are not a permanent assumption.

## Decision

After P0-A and the final TFVC freeze:

1. Bring the temporary GitHub mirror through the final TFVC changeset and capture its refs,
   releases, issues, pull requests, reviews, checks, rulesets, alerts, and qualification
   metadata.
2. Preserve the current `MusaShams/Causure` repository itself as the private
   `MusaShams/Causure-history` archive so its GitHub pull-request and check history survives.
   Import the complete `causure-examples` Git object graph under namespaced archive refs and
   retain a hash manifest plus exported GitHub metadata.
3. Remove every owner-controlled public fork only after its refs and metadata are verified in
   the archive. Make the old examples repository private and delete it only after a separate
   exact authorization and a successful archive restore drill.
4. Create a new private `MusaShams/Causure` from a clean, exact TFVC export. Its `main` branch
   must contain one parentless commit with subject `Creation of Causure`; the strict public
   release checker and `verify_clean_public_history.py` must both return ready.
5. Treat public visibility as a separately authorized step. Recreate security controls and
   rulesets, then qualify CI, CodeQL, dependency review, fork fail-closed behavior, and the
   approve, abstain, and needs-evidence stories against the new repository ID and root SHA.
6. Capture portfolio screenshots and video only from that final identity, then publish the
   version tag and GitHub Release on the same root commit.

The [clean-history publication runbook](../clean-history-publication.md) defines the gates and
rollback points. Repository visibility, rename, transfer, deletion, creation, push, and public
release remain individually reviewable external actions even though this architecture is
accepted.

## Consequences

- The public default branch presents a single audited product snapshot while TFVC and the
  private archive retain provenance.
- Existing public clones cannot be recalled, and owner-uncontrolled forks would prevent a
  claim that all previously public GitHub copies became private.
- Old GitHub URLs intentionally stop redirecting when the original personal repository name
  is reused. Historical receipts must name the private archive identity or remain explicit
  offline audit evidence rather than promise a public URL.
- Every full-SHA Action reference and hosted qualification tied to the temporary repository
  becomes historical. The final release must use and prove the new root SHA.
- The temporary repositories are not deleted until both Git object restoration and GitHub
  metadata export have been verified.
