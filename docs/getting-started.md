# Getting started in ten minutes

This path is for someone evaluating Causure for the first time. It does not require
customer data, cloud credentials, Docker, the Team service, or knowledge of the change-case
JSON schema.

## 1. Install the local command

From the repository root with Python 3.11 or newer:

```powershell
python -m pip install -e .
causure --version
causure
```

The last command prints only the first-run workflow. Use `causure --help-all` when
you need the lower-level automation and enterprise commands. The base package has no runtime
dependencies outside the Python standard library. Optional cryptography, service, and
container paths are not needed for this walkthrough.

## 2. Run the product story

```powershell
causure demo
```

The command creates `causure-demo` and reviews two fixed synthetic cases:

| Story | Decision | Product meaning |
| --- | --- | --- |
| Justified minimal patch | `approve` / `patch` | The failure reproduced, the proposed component matches the strongest causal evidence, the intervention worked, and the controls stayed healthy. |
| Attractive but overbroad change | `reject` / `do_not_patch` | The suggested global prompt guardrail targets the wrong component, changes too much surface, and breaks a legitimate negative control. |

Open `causure-demo\README.md`. It links to:

- `reports/`: readable evidence reports with findings and required resolutions;
- `results/`: canonical machine-readable gate results;
- `cases/`: the portable synthetic evidence bundles; and
- `demo-result.json`: a compact index of both outcomes.

No network request occurs. The packaged evidence and fixed synthetic review time make the
output deterministic across repeated runs. Causure refuses to overwrite the output
directory, so a later run should use a different destination:

```powershell
causure demo --output causure-demo-2
```

## 3. Create a local project safely

```powershell
causure init my-agent-project
```

`init` creates only a new `my-agent-project\.causure` directory. If that directory
already exists, it stops without changing anything. The generated boundary contains:

```text
.causure/
├── config.json          policy, trusted-adapter registry, and GitHub component mappings
├── policy.json          valid default evidence-gate preset
├── .gitignore           ignores generated artifacts, caches, and SQLite state
├── README.md            local next step
└── adapters/
    └── README.md        trusted-adapter boundary and warning
```

Raw trace storage is disabled. Evidence documents cannot choose or execute adapter code;
company-owned replay, evaluator, and case-generator adapters must be reviewed and placed in
the trusted adapter boundary separately. The generated GitHub mapping list starts empty and
evidence retention defaults to 30 days.

## 4. Optionally diagnose readiness without changing state

```powershell
causure doctor my-agent-project
```

The initialized project is already ready for the common path; `init`, `investigate`, and
`case create` are the three top-level commands. Use `doctor` when you want to diagnose setup
or adapter readiness. It checks the Python and package versions, bundled demo integrity,
project configuration, policy preset, configured GitHub case paths/types, adapter directory,
OS-reported permissions, and the presence of optional Git and Docker executables. It does
not write a probe file, contact the Docker daemon, access the network, or modify
configuration. A new project receives a GitHub-configuration warning until a component is
registered; this does not block the local investigation path.

For automation, use the stable JSON form:

```powershell
causure doctor my-agent-project --format json
```

A missing optional executable is a warning. A missing case is also an honest warning when
that component has a configured runtime generator; otherwise it is a failure. An invalid
configuration, missing configured policy, broken bundled story, or failed core permission
check is a failure and returns exit code 2.

## 5. Start from a real trace export

If you have an OTLP/OpenInference JSON export, enter the initialized project and run:

```powershell
Set-Location my-agent-project
causure investigate C:\path\to\agent-traces.json
```

Before creating a file, the command shows:

- the exact source byte count and SHA-256 digest;
- the trace and span counts;
- retained, redacted, and dropped attribute counts;
- an explicit `Raw content included: NO` statement; and
- numbered candidate clusters with only safe aggregate metadata.

Select candidate numbers, such as `1,3`, or press Enter for all candidates. After a separate
confirmation, the initialized project's ignored artifact directory receives:

```text
.causure/artifacts/<investigation-id>/
├── README.md
├── investigation.md              editable plain-language notebook
├── selection.json                selected IDs and exact artifact hashes
├── trace-manifest.json           content-minimized source projection
└── investigation-fixture.json    candidate-only cluster set
```

The original export is read and hash-bound but never copied into the workspace; its local
path is not stored. The generated fixture remains explicitly non-gate-eligible and makes no
failure or causal claim. To preview without writing, use `--preview-only`. A noninteractive
job must make selection and confirmation explicit:

```powershell
causure investigate C:\path\to\agent-traces.json --select all --yes
```

## 6. Create and review a canonical case without editing JSON

Copy the investigation directory printed by `investigate`, then run:

```powershell
causure case create `
  .causure\artifacts\<investigation-id>
```

The wizard first verifies the exact selection, manifest, and fixture bytes. It then asks
plain-language questions in these groups:

- the claimed failure, expected behavior, observation, severity, and requirement status;
- the independent oracle and its definition or result references;
- completed reproduction trials, if any;
- evidence-backed causal hypotheses and isolated interventions, if any;
- the smallest proposed harness change and behavior that must remain unaffected;
- the no-change alternative and any evidence against it;
- completed positive, negative, and regression cases, if any; and
- optional baseline and candidate cost, latency, and token measurements.

Enter `0` when a reproduction, attribution, or control section has not been completed. The
wizard leaves that evidence array empty; it never manufactures a passing result. After the
final confirmation it writes:

```text
.causure/artifacts/cases/<case-id>/
├── README.md
├── change-case.json       canonical portable case generated by the wizard
├── case-source.json       exact investigation-selection and case-byte binding
├── report.md              readable gate findings and required resolutions
└── review-result.json     machine decision and stable finding codes
```

An early case will normally return `NEEDS_EVIDENCE / COLLECT_EVIDENCE`. That is a successful
product outcome: the report says exactly what must be collected before changing the agent.
An evidence-complete case can instead approve a minimal change or reject a contradicted,
overbroad, or regressive proposal.

## 7. Optionally register pull-request review

Copy or generate the canonical case at a repository path you intend to commit, then register
the changed source pattern once:

```powershell
causure github-configure `
  --component-id refund-tool-description `
  --component tool_description `
  --path "agent/tools/**/*.py" `
  --case evidence/refund-tool-description.case.json

causure doctor .
```

The command updates the generated configuration atomically and refuses duplicate component
IDs or path patterns; any broader overlapping mappings fail as ambiguous during selection.
In a pull request, the composite Action can now fetch
the changed filename list with the job's read-only token, select this case and policy, run
the gate, and publish the result without repeating `case` or `component-path` in workflow
YAML. See the [GitHub Action guide](github-action.md) for the minimal pinned workflow and
fork behavior.

If the company can produce the case from reviewed replay/evaluation logic, keep that package
beneath `.causure/adapters` on the protected branch and bind it instead of
committing a case for every candidate:

```powershell
causure adapter-configure `
  --adapter-id company-case-generator `
  --kind case_generator `
  --entry-point company_agent.generator:generate `
  --component-id refund-tool-description

causure doctor .
```

The protected GitHub workflow then checks out the exact base and head separately, loads the
generator only from the base, treats the candidate component as bounded data, and writes a
canonical case bound to the exact pull-request head before running the ordinary gate. Start
with the full workflow in the
[trusted case-generation guide](trusted-case-generation.md), not `uses: ./` from a candidate
checkout.

## What this proves—and what comes next

This walkthrough proves the product's deterministic evidence-gate behavior and gives a new
project a safe configuration boundary. It does not pretend that the synthetic evidence was
collected from your agent.

Today, a real OTLP/OpenInference JSON export can reach a redacted investigation and canonical
gate decision without manually authored JSON. Replay, intervention, and control execution
still comes from company-owned systems; the wizard records their references and outcomes but
does not invent or autonomously execute them.

The installed-wheel usability test passed in under five minutes with an unfamiliar
participant and no assistance. The final public repository also exercised approve,
reject/abstain, needs-evidence, required-check, and credential-free fork behavior. The
[public-release qualification](qualifications/causure-public-release-2026-08-13.json) records
the exact release, tests, hosted runs, artifacts, security state, and limitations.

The next product milestone is a more discoverable trace-to-investigation experience,
followed by guided execution of company replay and evaluation adapters. See the
[productization roadmap](productization-roadmap.md) for that scope.
