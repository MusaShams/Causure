# ADR 0027: License public distribution under Apache-2.0

- Status: accepted
- Date: 2026-08-09
- Release: unreleased

## Context

The reviewed GitHub mirror in ADR 0026 needs explicit reuse terms before it can become a
useful public company and research project. Publishing source without a license would allow
inspection on the hosting platform but would not grant the broad use, modification, and
distribution rights expected from an open-source release.

ProofBeforePatch is intended to be usable inside commercial systems while retaining clear
provenance, warranty limitations, contribution terms, and an explicit patent grant.

## Decision

License the project under the Apache License, Version 2.0:

- include the unmodified standard terms in the root [`LICENSE`](../../LICENSE) file;
- declare the SPDX expression `Apache-2.0` and distribute `LICENSE` through the Python
  package metadata;
- treat contributions according to Section 5 of the license unless a contributor explicitly
  states otherwise or a separate agreement applies; and
- do not create a project `NOTICE` file until there is a reviewed attribution that belongs
  there.

Copyright ownership continues to follow authorship and applicable law. This decision does
not invent a separate company, foundation, trademark grant, or copyright owner.

## Consequences

- Companies and individuals may use, modify, and distribute the work, including
  commercially, subject to the license conditions.
- Contributors provide the copyright and patent grants defined by Apache-2.0.
- Redistributors must preserve the license and applicable notices and mark modified files.
- The license supplies no trademark permission, warranty, or project support commitment.
- The strict public-release gate can now become ready, but repository creation, Git history,
  push, security-setting verification, and public visibility remain separately authorized
  actions.

See [ADR 0026](0026-publish-a-reviewed-github-mirror.md) and the
[GitHub public-release guide](../github-public-release.md).
