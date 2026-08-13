# GitHub public-release guide

This guide prepares a clean public-facing GitHub repository without changing the current
source of record. Under [ADR 0026](decisions/0026-publish-a-reviewed-github-mirror.md), TFVC
remains authoritative until another accepted decision explicitly migrates it.

## Current publication state

- The owner-authorized public mirror,
  [`MusaShams/Causure`](https://github.com/MusaShams/Causure), is the canonical public product
  repository. Its `main` branch contains one parentless commit, `Creation of Causure`, at
  `8059c4b9d2e2aae5f6a4e2ab8a76b08b94f48eee`.
- [`v0.4.0a18`](https://github.com/MusaShams/Causure/releases/tag/v0.4.0a18) is the initial
  public alpha. Its wheel, normalized source archive, SBOM, architecture capture, portfolio
  video, evidence matrix, and checksum manifest were anonymously downloaded and verified.
- Approve, reject/abstain, needs-evidence, required-check, and credential-free fork behavior
  were exercised against the final repository identity. The
  [public-release qualification](qualifications/causure-public-release-2026-08-13.json)
  records the exact runs, checks, assets, security state, and limitations.
- The `Protect main` and exact-tag rulesets have no bypass actors. Secret scanning, push
  protection, vulnerability alerts, Dependabot security updates, private vulnerability
  reporting, read-only workflow defaults, and selected GitHub-owned Actions are enabled.
  The release audit recorded zero open CodeQL, secret-scanning, or Dependabot alerts.
- The earlier [public receipt](qualifications/github-native-public-2026-08-11.json) records
  the first public-fork boundary. The
  [remediation receipt](qualifications/github-native-public-remediation-2026-08-11.json)
  records the dependency repair; GitHub then marked the advisory fixed.
- Apache-2.0 is the public license, with matching Python package metadata.
- `MusaShams/Causure-history` is the private archived development-history repository, and
  `MusaShams/causure-examples` is preserved privately. The controlled public qualification
  fork is not the product repository.
- TFVC remains the source of record under ADR 0026. Each later mirror publication, release,
  or source-of-record change is a separate owner-authorized action.

## Release gate

Classic CI and publication both use the strict release check:

```powershell
python .\scripts\check_public_release.py
```

Exit code `0` means the candidate is ready for the separately authorized publication steps.
Exit code `1` means the candidate is incomplete or unsafe. Exit code `2` means the required
license has regressed or is absent. `--allow-missing-license` exists only for bootstrapping a
future unlicensed checkout; it is not permitted in CI or the publication procedure.

The checker enumerates tracked and non-ignored Git candidates when Git metadata is present.
On a TFVC build agent it performs a source-tree scan that excludes source-control metadata
and generated directories. It checks required community files, common credential and
private-key signatures, forbidden local state, Git ignore behavior, unsafe workflow
triggers or secret use, least-privilege workflow declarations, and full 40-character action
commit pins. It scans both composite Actions for isolated Python execution, explicit token
and checkout-root boundaries, and immutable third-party Action references. It never prints
a matched credential value.

Run the full project gate separately:

```powershell
python -m pip install -e ".[dev]"
.\scripts\classic_ci.ps1
```

## Owner decisions before any Git publication

1. Confirm the GitHub owner and repository name. The completed alpha uses
   `MusaShams/Causure`; any replacement publication must reconfirm its target identity.
2. Confirm that GitHub starts as a private repository and that TFVC remains authoritative
   for the mirror period.
3. Review every staged path and the full initial diff. Do not stage `$tf`, caches, reports,
   databases, prepared pilot state, encrypted PAT handoffs, or signing material.

## Create and verify the private repository

Create an empty private repository without a generated README, license, or `.gitignore` so
the reviewed snapshot has no unrelated root commit. Then, as separately authorized actions:

1. make the initial branch `main`;
2. stage only the reviewed candidate paths;
3. inspect the staged diff and rerun the strict release checker;
4. create one signed or otherwise owner-attributable initial commit;
5. add the confirmed GitHub remote; and
6. push `main` to the still-private repository.

Do not copy or rewrite TFVC's `$tf` directory into Git history. The first Git commit is a
reviewed source snapshot, not a synthetic reconstruction of TFVC changesets.

Wait for CI and package checks to pass in the private repository. CodeQL and dependency
review require repository security capabilities that may be unavailable before publication,
so both jobs use the fail-closed
`github.event.repository.visibility == 'public'` guard. They appear as skipped while the
repository is private and become eligible automatically for public-repository events.
Dependabot will propose pinned Python and GitHub Actions updates rather than changing them
silently.

## Qualify GitHub-native review while the mirror is private

After the first private push, replace both placeholders in
[`examples/github-native/causure.template.yml`](../examples/github-native/causure.template.yml)
with the reviewed 40-character mirror commit. Copy the synthetic template into a dedicated
private example repository or an owner-approved qualification branch. Do not use a branch,
tag, or `uses: ./` reference.

Open and retain evidence for:

1. a same-repository approve scenario with a published custom Check Run;
2. a same-repository abstain scenario whose stable workflow job fails with `reject`;
3. a same-repository incomplete scenario whose job fails with `needs_evidence`;
4. a generator-backed fork scenario that fails before protected adapter execution; and
5. a Dependabot pull request that preserves the stable workflow gate without requiring the
   unavailable custom Check Run write.

The retained 2026-08-11 private qualification completed items 1, 2, 3, and 5 at one exact
Action commit. The separate public qualification completed item 4 from an actual public
fork. The expected failing workflow conclusion is the passing boundary result: both exact
checkouts succeeded, the explicit fork guard stopped generation, and no protected adapter,
ordinary review, custom Check Run, or artifact ran.

Verify the exact base/head checkouts, generated case reference, generation receipt, review
publication/verification chain, decision annotations, and retained artifact contents and
duration. Record repository, PR, run/attempt, full Action SHA, artifact IDs, decisions, and
limitations in a committed qualification receipt. Local
[`qualify_github_native_examples.py`](../scripts/qualify_github_native_examples.py) results
are fixture engineering evidence only and cannot satisfy this hosted gate.

## Configure available GitHub controls before public visibility

Use GitHub repository settings to:

- enable private vulnerability reporting when it is available for the public repository;
- enable secret scanning and push protection;
- keep default workflow permissions read-only unless a reviewed job needs a narrower write
  permission;
- create a `main` ruleset that blocks force pushes and deletion, requires pull requests and
  resolved conversations, and initially requires the stable CI and package checks that have
  actually run; add CodeQL and dependency review only after their first successful public
  runs;
- require CODEOWNER review once more than one trusted maintainer is available; and
- review Dependabot and code-scanning alerts before changing visibility.

Repository-plan capabilities can constrain that ordering. On 2026-08-11, GitHub rejected
the private mirror's rulesets API with an instruction to upgrade the account or make the
repository public. Do not weaken the intended ruleset to work around that limitation. Verify
the response again during the final gate; configure every available private control first,
then treat the ruleset and any other public-only security control as immediate post-visibility
work in the same owner-attended release session.

GitHub documents the relevant controls in its guidance for
[private vulnerability reporting](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository),
[push protection](https://docs.github.com/en/code-security/concepts/secret-security/push-protection),
[repository rulesets](https://docs.github.com/en/repositories/configuring-branches-and-merges-in-your-repository/managing-rulesets/about-rulesets),
and
[dependency review](https://docs.github.com/en/code-security/how-tos/secure-your-supply-chain/manage-your-dependency-security/configure-dependency-review-action).

## Public-visibility gate

Changing visibility is a separate, consequential action. Immediately before it:

1. rerun the strict checker and full validation from the exact `main` commit;
2. verify every private-repository-capable required check is green and both capability-gated
   security jobs are skipped rather than failed;
3. verify the standard license text and package metadata agree;
4. inspect the GitHub file tree for local state or customer data;
5. confirm [`SECURITY.md`](../SECURITY.md) points to private vulnerability reporting; and
6. read GitHub's current
   [repository-visibility consequences](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/managing-repository-settings/setting-repository-visibility).

Only the owner should then authorize the private-to-public visibility change. A successful
push to a private repository is not authorization to make it public.

After an authorized visibility change, create the documented `main` ruleset immediately if
the current plan first enables it at public visibility. In the same owner-attended session,
manually dispatch CodeQL from the exact `main` commit, confirm dependency review on the next
pull request, review any resulting alerts, and only then make those security checks required
by the ruleset.

The 2026-08-11 owner-attended session completed visibility, the documented controls and
ruleset, CodeQL dispatch and alert review, the public fork qualification, and the TFVC-first
cryptography remediation. CodeQL and dependency review are now required. The follow-up
qualification recorded green pre-merge and post-merge checks and zero open Dependabot,
CodeQL, or secret-scanning alerts.

## Mirror updates while TFVC is authoritative

For each public update:

1. start from a clean TFVC workspace and identify the authoritative changeset;
2. run Classic CI and the strict public-release checker;
3. reproduce only that checked-in source change in the Git mirror;
4. review the candidate and commit message, including the TFVC changeset identifier;
5. push, wait for required GitHub checks, and verify the public tree; and
6. never merge a GitHub-only change first.

For a useful external pull request, review it publicly, reproduce the accepted minimal
change in TFVC, check it in there, and publish that resulting snapshot back to GitHub. This
is intentionally slower than ordinary GitHub development but prevents two authoritative
histories.

## Stop conditions

Stop before commit, push, or visibility change if the checker reports any error, the license
is absent or inconsistent, validation is not green, a credential may have entered the
candidate, the TFVC workspace is not clean, or the source-of-record mapping is ambiguous.
If a secret reaches the private remote, revoke or rotate it before rewriting the private
history; deletion from a later commit is not sufficient.
