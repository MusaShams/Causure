# ADR 0029: Run case generators only from a protected base

- Status: accepted
- Date: 2026-08-10
- Release: unreleased

## Context

ADR 0028 made `.proofbeforepatch/config.json` the one canonical source for GitHub component
selection and intentionally kept adapter entry points inert. That protected the ordinary
pull-request gate from importing candidate-controlled code, but left a practical gap: a
company still had to commit or create the canonical case before the Action could review a
prompt, tool, router, or policy change.

Running a configured generator from the candidate checkout would let the pull request
replace the very program judging it. Running `uses: ./` after a head checkout has the same
problem. `pull_request_target` or write credentials would add unnecessary privilege, and a
fork could send arbitrary content to protected company adapters or services.

The case must also be bound to the exact repository, pull request, head commit, component
path, and component bytes. A reusable case selected only by path is not enough to show that
the reviewed evidence describes the current candidate.

## Decision

- Advance the canonical project configuration to schema `3.0`, keep `1.0` and `2.0`
  readable, and add a closed `case_generator` adapter kind plus an optional component
  binding.
- Add `proofbeforepatch case generate` and a separate `trusted-case-generator` composite
  Action.
- Require separate protected-base and candidate-head roots. The GitHub Action verifies that
  they resolve to the event's exact full base and head SHAs.
- Discover and select components through the existing bounded GitHub.com read-only boundary.
- Resolve and import the configured generator only from the protected adapter directory in
  an isolated child process. Never add the candidate root to Python's import path.
- Treat the candidate component as one bounded regular data file, hash it and the complete
  bounded adapter tree before and after execution, and fail on mutation.
- Require the returned canonical case to match the configured component and exact
  `github://.../pull/.../head/.../...` candidate reference.
- Review the case immediately under the protected policy, write only new outputs, and emit
  a minimized receipt binding the exact component, adapter, case, limits, and PR identity.
- Fail generator-backed fork pull requests before adapter execution. Preserve the ordinary
  secret-free fork path for components that use already committed cases.
- Keep the ordinary root Action non-executing. It consumes the generated case from the
  candidate root through its explicit `repository-root` input.

## Consequences

- A same-repository pull request can move from a configured component change to a verified
  evidence decision without a person authoring JSON for that commit.
- Candidate code cannot shadow the Action package or configured adapter through normal
  Python imports, and the receipt exposes exact source subjects for audit.
- Protected configuration, policy, workflow, remote Action commit, adapter code, GitHub
  event delivery, and runner remain trusted controls.
- The adapter process is not an OS sandbox. Reviewed adapter code can access the candidate
  root and inherits job filesystem/network permissions, so it must treat candidate files as
  data and use a stronger sandbox/quota boundary when needed.
- Forks cannot invoke company generators in the first version. Supporting them would require
  a separately designed unprivileged service or sandbox with no protected credentials.
- Two checkouts and two composite steps make the caller workflow longer, but keep executable
  control code out of the candidate and make the trust split visible.
- Local synthetic qualification does not replace remote GitHub qualification. A private
  mirror and real same-repository, fork, and Dependabot pull requests are still required.

See the [trusted case-generation guide](../trusted-case-generation.md),
[GitHub Action guide](../github-action.md), and
[ADR 0028](0028-reuse-the-canonical-project-config-for-github-selection.md).
