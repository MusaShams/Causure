# P0-A unfamiliar-user usability test

This protocol closes the human usability criterion for the one-command local experience. A
maintainer, automated test, or coding agent may run an engineering audit, but that does not
count as the unfamiliar participant required by the productization roadmap.

## Participant and facilitator boundary

Use one participant who is comfortable running a developer command but has not read the
Causure schemas, source code, demo reports, or detailed documentation. Do not record
their name, email address, employer, customer data, credentials, or raw agent traces.

The facilitator may provide only:

- a machine with Python 3.11 or newer;
- the candidate wheel or the published installation command; and
- this starting instruction: "Use Causure to run its synthetic demonstration and
  explain which proposed change it would apply and which it would block."

After the timer starts, giving a command, path, interpretation, or recovery hint counts as
assistance. Record it rather than silently helping. Normal clarification of the task wording
is allowed only before the timer starts.

## Tasks

1. Install the candidate package in a fresh virtual environment.
2. Discover the first action from `causure` or `causure --help`.
3. Run the synthetic demonstration without editing a file.
4. Identify the decision and recommended action for both stories.
5. Explain, in the participant's own words, why the narrow change was accepted and why the
   attractive broad change was blocked.
6. Locate and open at least one generated human-readable report.

Stop the timer when the participant has completed task 6 or says they cannot continue.

## Passing criteria

The run passes only when all of the following are true:

- both observed outcomes are `approve/patch` and `reject/do_not_patch`;
- the participant correctly distinguishes causal support and passing controls from the wrong
  component, excessive surface, and failed negative control;
- a generated Markdown report is opened without schema or JSON editing;
- elapsed time from the end of installation is less than ten minutes;
- no cloud credentials, network request, Docker daemon, or service deployment is needed; and
- the assistance count is zero.

An installation failure is recorded separately from product-task time, but still blocks the
release when it is caused by the documented package or Python requirements.

## Result record

Store a minimized record at
`docs/qualifications/p0a-unfamiliar-user-YYYY-MM-DD.json`. Bind the exact tested distribution
by filename, byte count, and SHA-256. Paraphrase comprehension answers and friction; never
include personally identifying or customer information.

```json
{
  "schema_version": "1.0",
  "qualification": "p0a-unfamiliar-user",
  "performed_at": "YYYY-MM-DDTHH:MM:SSZ",
  "result": "passed-or-failed",
  "participant": {
    "anonymous_profile": "developer unfamiliar with Causure schemas",
    "prior_product_exposure": false
  },
  "environment": {
    "operating_system": "recorded without a user or machine name",
    "python_version": "3.11-or-newer",
    "installation_source": "wheel-or-published-package"
  },
  "distribution": {
    "filename": "causure-VERSION-py3-none-any.whl",
    "byte_count": 0,
    "sha256": "64-lowercase-hex-characters"
  },
  "observations": {
    "elapsed_seconds_after_install": 0,
    "assistance_count": 0,
    "outcomes": ["approve/patch", "reject/do_not_patch"],
    "opened_report": true,
    "comprehension": "minimized facilitator paraphrase",
    "friction": []
  },
  "limitations": []
}
```

## Triage after the run

Classify each observed problem as setup, discoverability, terminology, comprehension, report
navigation, or defect. Fix release-blocking problems and repeat with a different unfamiliar
participant; a coached retry by the same participant is useful regression feedback but is no
longer an unfamiliar first run.
