# ADR 0028: Reuse the canonical project config for GitHub selection

- Status: accepted
- Date: 2026-08-10
- Release: unreleased

## Context

The P0-B roadmap proposed a small `.proofbeforepatch.yml` for GitHub component paths,
policy, trusted adapters, and artifact retention. P0-A subsequently shipped a generated,
closed `.proofbeforepatch/config.json` that already owns the project policy path, trusted
adapter directory, artifact directory, and raw-trace behavior.

Adding a second top-level configuration would force users and enterprise controls to decide
which file is authoritative. Adding a YAML parser would also end the base package's
zero-runtime-dependency property. Asking users to edit either format by hand would work
against the guided onboarding goal.

Automatic selection also consumes repository data from an untrusted pull-request checkout.
It must not silently accept a configuration or policy modified by the same candidate it is
judging.

## Decision

- Advance the generated project configuration to schema `2.0` and keep schema `1.0`
  readable.
- Extend that one canonical JSON document with closed GitHub component path/case mappings,
  artifact-retention days, and strictly validated trusted-adapter entry-point registrations.
- Add `proofbeforepatch github-configure` as the ordinary mutation path so a user can add a
  component mapping without writing JSON.
- Let automatic Action mode read that config, use a bounded read-only GitHub API client to
  discover the exact PR filenames, and select at most one mapping.
- Treat no configured match as `not_applicable`; reject ambiguous matches, identity races,
  excessive file counts, and candidate changes to the config or selected policy.
- Preserve paired explicit `case` and `component-path` inputs for separately reviewed
  governance changes and advanced workflows.
- Keep adapter entry points inert in the current Action. Candidate configuration can never
  cause this review step to import or execute code.

## Consequences

- Local onboarding and GitHub onboarding share one generated source of project truth.
- The base installation remains standard-library-only and no YAML dialect needs to be
  documented or secured.
- Existing initialized projects remain readable and are upgraded only when a configuration
  command writes a validated replacement.
- Normal pull-request workflows no longer repeat a case and annotation path on every run.
- Automatic discovery needs `pull-requests: read`; fork runs can use the job's read-only
  installation token but still cannot publish the privileged custom Check Run.
- A PR that intentionally changes policy or mappings needs a separately reviewed change or
  paired explicit inputs. This friction is deliberate because those files control the gate.
- The Action selects an existing canonical case; trusted adapter execution and case
  generation remain future orchestration work.

See the [GitHub Action guide](../github-action.md) and
[productization roadmap](../productization-roadmap.md).
