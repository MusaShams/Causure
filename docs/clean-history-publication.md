# Clean-history publication runbook

This runbook produces one private history archive and a one-root-commit public Causure
repository without pretending that previously public bytes can be revoked. Follow
[ADR 0031](decisions/0031-publish-a-clean-public-history.md) and stop at every authorization
gate.

> **Completed for `v0.4.0a18`.** The final outcome is recorded in the
> [public-release qualification](qualifications/causure-public-release-2026-08-13.json).
> The steps below remain as the reproducible publication and archive procedure, not as an
> outstanding launch checklist.

GitHub's current documentation says that public forks remain public and detach when an
upstream becomes private, that reusing a renamed repository's old name removes redirects,
and that an Action does not follow a repository rename. Review the current
[visibility consequences](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility),
[fork consequences](https://docs.github.com/en/pull-requests/collaborating-with-pull-requests/working-with-forks/what-happens-to-forks-when-a-repository-is-deleted-or-changes-visibility),
[rename behavior](https://docs.github.com/en/repositories/creating-and-managing-repositories/renaming-a-repository),
and [repository duplication procedure](https://docs.github.com/en/repositories/creating-and-managing-repositories/duplicating-a-repository)
again immediately before execution.

## Intended end state

- `MusaShams/Causure-history`: private, archived against ordinary development, preserving the
  former Causure repository and its GitHub metadata plus namespaced examples history.
- `MusaShams/Causure`: public, with one parentless `main` commit named
  `Creation of Causure`, one version tag pointing to it, and freshly qualified controls.
- No old owner-controlled public examples fork or legacy examples repository.
- TFVC remains authoritative until a later ADR explicitly changes source control.

This state does not erase local clones, cached objects, screenshots, or copies made while the
repositories were public.

## Gate 0: finish the product evidence

- Complete and retain the P0-A unassisted unfamiliar-user receipt.
- Check in every accepted change to TFVC and record the final changeset number.
- Mirror the final TFVC changesets into the temporary GitHub history through protected review.
- Require a clean TFVC status and a green full Classic CI run.

Do not move repository identities while a product change or qualification result is pending.

## Gate 1: capture and prove the history archive

1. Record repository IDs, visibility, default branch, fork network, refs, tags, releases,
   rulesets, environments, Actions runs, security alerts, issues, pull requests, reviews, and
   comments for both current repositories.
2. Create bare mirror clones and immutable Git bundles for `Causure` and
   `causure-examples`. Hash every bundle and metadata export with SHA-256.
3. Import all examples branches and tags into the Causure history repository under an
   `archive/causure-examples/` namespace. Never overwrite a Causure ref.
4. Run `git fsck --full`, compare the source and archive ref tips, restore both bundles into
   new temporary directories, and rerun `git fsck --full` there.
5. Store a minimized manifest binding repository IDs, ref names/tips, object counts, bundle
   hashes, export hashes, timestamps, and the final TFVC changeset. Do not store credentials,
   Actions tokens, raw webhook payload secrets, or local user paths.

**Authorization gate:** no visibility, rename, transfer, archive, or deletion operation occurs
until the owner reviews the manifest and restore drill.

## Gate 2: close the old public surface

Re-inventory forks immediately before this gate and stop if an uncontrolled public fork now
exists.

1. Delete the controlled public `causure-project/causure-examples` fork only after its exact
   head and objects are in the verified archive.
2. Make `MusaShams/causure-examples` private. GitHub must report no remaining public fork
   network before continuing.
3. Make `MusaShams/Causure` private, then rename it to `Causure-history` and disable ordinary
   Actions/development writes. Preserve its issues, pull requests, releases, and checks.
4. Reverify the private archive's repository ID and all imported ref tips. Deleting the
   separate private examples repository is a later, separate destructive authorization.

The brief name-reuse window must be automated and monitored. If GitHub refuses reuse of
`MusaShams/Causure`, stop and choose a new public owner/name rather than deleting more data.

## Gate 3: build the clean snapshot

1. Materialize the exact final TFVC changeset into a new temporary directory with no `.git`,
   `$tf`, build, distribution, database, credential, or generated state.
2. Run the full Classic CI validation and the strict checker against that filesystem source:

   ```powershell
   python .\scripts\check_public_release.py --candidate-source filesystem
   ```

3. Initialize a new `main` Git repository, add only the accepted snapshot, and create one
   commit:

   ```powershell
   git init -b main
   git add --all
   git commit -m "Creation of Causure"
   python .\scripts\verify_clean_public_history.py
   ```

4. Generate a canonical path, byte-count, and SHA-256 manifest from the committed tree and
   compare it with the accepted TFVC export. Run `git fsck --full`.
5. Create a new private `MusaShams/Causure`, push only `main`, and verify the remote tree and
   commit SHA against the local manifest.

No qualification branch or version tag is created until the one-root boundary is recorded.

## Gate 4: public controls and fresh qualification

Public visibility requires its own exact authorization. After the visibility change:

1. Enable secret scanning, push protection, dependency graph/Dependabot, private
   vulnerability reporting, and CodeQL; recreate the `main` ruleset with no bypass actors.
2. Require the exact CI, CodeQL, and dependency-review status checks after their first
   successful final-repository runs.
3. Replace every consumer placeholder with the new root SHA. A renamed repository does not
   preserve Action calls, and an old repository SHA does not qualify the new repository ID.
4. Run fresh approve, abstain, and needs-evidence pull requests without merging product
   changes. Run the generator-backed fork failure scenario from a newly inventoried,
   credential-free fork.
5. Record repository ID, root SHA, workflow SHAs, run attempts, Check Run IDs, artifacts,
   decisions, security controls, and zero-open-alert state in a new immutable receipt.
6. Delete qualification head branches only after the receipt and portfolio evidence are
   retained. Their existence does not change the one-commit `main` history.

## Gate 5: portfolio release

- Capture the evidence matrix, Check Run, required checks, and architecture image from the
  final repository only.
- Record the scripted demo with synthetic data and complete the privacy checklist.
- Tag the root commit with the selected alpha version and publish the GitHub Release without
  creating another commit.
- Run the clean-history verifier, public-release checker, security-control audit, and archive
  restore check once more. Record the final result in TFVC.

Only after all five gates pass may the old private examples repository be considered for
deletion under a final explicit authorization.
