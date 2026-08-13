# Causure 90-second portfolio demo script

Use only synthetic Causure data and the final public repository. Do not show the TFVC PAT,
local user paths, browser notifications, private archive, or generated machine state.

The privacy-checked 94.83-second recording produced from this script is published with the
[`v0.4.0a18` release](https://github.com/MusaShams/Causure/releases/tag/v0.4.0a18). This file
is retained as the reproducible narration and capture checklist.

## Shot list and narration

### 0–12 seconds — the problem

Show the case-study title and user-flow diagram.

> An agent failure often produces a plausible patch before we know what actually failed.
> Causure asks whether the evidence supports changing that exact part of the harness.

### 12–30 seconds — one-command demo

Run `causure demo` from a clean directory. Show the two terminal outcome summaries, then open
the generated overview.

> The bundled demo is offline and deterministic. The same incident produces two proposals:
> a narrow tool-description correction and a broad global-prompt workaround.

### 30–48 seconds — evidence-backed outcomes

Show the overview table and briefly open both human reports.

> The narrow patch is approved because the failure reproduced, an isolated intervention
> identified the tool description, and every control passed. The broad change is rejected:
> it targets the wrong component, exceeds the minimal surface, and fails a negative control.

### 48–68 seconds — GitHub integration

Show the final public example pull request and its Causure Check Run, then the required CI,
CodeQL, and dependency-review checks.

> In GitHub, the result is bound to the exact pull request head, workflow run, component,
> case, result, and report. Teams get a stable status check and a retained explanation instead
> of parsing console output.

### 68–80 seconds — trust boundary

Return to the architecture diagram and emphasize the protected generator and human endpoint.

> Candidate code is treated as data. Trusted adapters run only from the protected base, forks
> receive no secrets, and Causure never merges or deploys the change by itself.

### 80–90 seconds — honest close

Show the repository README and production-limit section.

> Causure is a functional evidence-gated change-control alpha. The next work is final
> clean-public qualification, richer experiment orchestration, and qualified enterprise
> deployment.

End on: **Causure — Change only what the evidence supports.**

## Capture checklist

- Use the final one-commit public repository and its final full-SHA Action references.
- Use a new demo output directory so no overwrite error appears.
- Keep the terminal at a readable scale and crop local user/machine paths.
- Capture approve, reject, and needs-evidence public examples after final qualification.
- Show a green required-check summary without repository settings or notification content.
- Record at 1080p, 30 fps, with captions; keep the final export under two minutes.
- Verify the video contains no credentials, customer data, private archive URL, or personal
  notifications before publishing.
