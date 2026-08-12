# Trusted GitHub case generation

- Status: implemented; private same-repository and Dependabot qualification complete;
  public generator-backed fork qualification complete
- Audience: teams that want a pull request to produce its own candidate-bound change case
- Supported host: GitHub.com

## Why this is a separate step

The ordinary Causure Action is deliberately non-executing: it selects and reviews
a canonical case but never imports code named by a pull-request checkout. A useful company
workflow, however, often needs reviewed replay or evaluation logic to inspect the proposed
prompt, tool, router, or policy and create that case automatically.

The trusted generator is the bridge between those requirements. It runs a company-owned
adapter from the protected pull-request base while treating the exact candidate head as
bounded input data. It then reviews the generated case immediately and hands the same
canonical bytes to the ordinary evidence gate.

## Trust boundary

Use two separate checkouts beneath `GITHUB_WORKSPACE`:

- **protected base** — exact `pull_request.base.sha`; owns
  `.causure/config.json`, the selected policy, and reviewed adapter source;
- **candidate head** — exact `pull_request.head.sha`; contains the proposed component and
  receives the generated case and evidence directories.

The generator Action verifies both checkout heads before execution. It discovers changed
filenames through the same bounded GitHub.com PR API boundary as the ordinary Action,
selects at most one configured component, and loads the configured entry point only from
the protected adapter directory. Python isolated mode and source-containment checks prevent
candidate modules from shadowing the Action or adapter package.

The selected candidate component must be one regular, non-symlink file of at most 2 MiB.
Causure hashes it before and after generation. The protected adapter tree is also
bounded and hashed before and after execution. The generated canonical case is capped at
5 MiB by default, must match the configured component, and must use this exact reference:

```text
github://OWNER/REPOSITORY/pull/NUMBER/head/FULL_HEAD_SHA/COMPONENT_PATH
```

The process runner enforces a wall-clock timeout, kills a timed-out child, suppresses its
standard output/error, validates the returned case, and reports stable non-sensitive
errors. The output and configured case paths are new-only; failures do not leave a partial
evidence chain.

This is an execution boundary, not an operating-system sandbox. The protected adapter is
trusted code and inherits the job's filesystem and network permissions. Causure
does not import or execute candidate code, but a poorly written trusted adapter could do so
itself. Review adapters to parse candidate files as data, give the job only required
credentials and network access, and use the digest-pinned container/quota boundary when the
adapter needs stronger execution or spend isolation.

## Configure a component once

Initialize a project and add the component mapping first:

```powershell
causure init .

causure github-configure `
  --component-id refund-tool-description `
  --component tool_description `
  --path "agent/tools/**/*.py" `
  --case evidence/refund-tool-description.case.json `
  --retention-days 30
```

Place the reviewed Python package beneath `.causure/adapters`, then register and
bind its callable atomically:

```powershell
causure adapter-configure `
  --adapter-id company-case-generator `
  --kind case_generator `
  --entry-point company_agent.generator:generate `
  --component-id refund-tool-description

causure doctor .
```

The callable receives a `CaseGenerationRequest` containing the project/component identity,
repository and pull-request identity, full base/head SHAs, contained component path,
absolute candidate root, exact component digest/size, execution budget, and
`expected_change_ref`. It returns either a `ChangeCase` or its canonical mapping. It should
not print secrets, mutate the selected component, reuse a case from another commit, or load
code from the candidate checkout.

Configuration schema `3.0` adds `case_generator` registrations and a nullable
`case_generator_adapter_id` on each GitHub component. Schema `1.0` and `2.0` projects remain
readable; a validated configuration write upgrades the document.

## GitHub workflow

Use the complete full-SHA-pinned recipe in
[`examples/github-native/causure.template.yml`](../examples/github-native/causure.template.yml).
Its order is security-significant:

1. check out the exact protected base to `trusted-control`;
2. check out the exact candidate head to `candidate`;
3. call `trusted-case-generator` from a reviewed remote Causure commit;
4. call the ordinary root Action against `repository-root: candidate`; and
5. retain both evidence directories even when the gate does not approve.

Never replace either remote Action reference with `uses: ./` after checking out the
candidate. The candidate must not supply executable Action code.

Selection has three successful routing states:

- `generated` — a bound generator ran and wrote a newly reviewed canonical case;
- `existing_case` — the selected component uses a committed case, so no generator ran;
- `no_match` — no configured component changed, so no case or evidence directory exists.

More than one matching component, a moved head, a candidate-modified governance file, a
checkout/SHA mismatch, mutation during generation, invalid output, or any containment
failure stops the job. Generator-backed fork pull requests fail before Git or adapter
execution because protected company credentials or code must not consume arbitrary fork
content. Components with committed cases can continue through the ordinary read-only fork
path. Dependabot keeps the stable workflow-job result; in automatic mode the ordinary
Action skips only the custom Check Run write when GitHub downgrades its token.

## Generated evidence

The configured case path receives the exact canonical bytes. The separate new-only
generation directory contains:

- `change-case.json` — the same canonical case bytes;
- `review-result.json` — immediate deterministic review under the protected policy;
- `report.md` — readable immediate review;
- `trusted-case-generation.json` — minimized provenance receipt; and
- `README.md` — artifact interpretation and limitations.

The receipt binds the repository/PR/base/head/component identity, component digest and byte
count, adapter-tree and exact entry-module digests, execution limits, case digest and byte
count, and output paths. It records that the adapter loaded from the trusted directory and
that the Causure runner did not execute candidate code. It deliberately omits the
absolute candidate root and component body. Its committed schema is
[`trusted-case-generation.schema.json`](../schemas/trusted-case-generation.schema.json).

## Local engineering qualification

The repository includes three credential-free synthetic stories:

```powershell
python scripts/qualify_github_native_examples.py
```

The qualifier builds separate temporary protected/candidate trees and verifies `approve`,
`reject` (the abstention story), and `needs_evidence`. It proves the local contract and
fixtures; by itself it is not evidence that GitHub permissions, hosted runners, artifact
retention, fork behavior, or a remote full-SHA pin work. The separate
[2026-08-11 private qualification](qualifications/github-native-private-2026-08-11.json)
confirmed the remote pin, hosted runner, complete retained chains, and published decisions
for all three same-repository outcomes, plus the Dependabot no-match path. The separate
[public qualification](qualifications/github-native-public-2026-08-11.json) records a real
cross-repository fork run: both exact checkouts succeeded, the explicit fork guard failed
the generation step, and review, custom Check Run publication, and artifact retention never
ran. That result qualifies the guard, not any company's adapter or deployment environment.

See [ADR 0029](decisions/0029-run-case-generators-only-from-a-protected-base.md), the
[GitHub Action guide](github-action.md), and the
[productization roadmap](productization-roadmap.md).
