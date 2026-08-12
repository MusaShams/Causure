## Summary

Describe the problem, the evidence for changing it, and the smallest implemented change.

## Evidence and alternatives

- What reproducible evidence supports this change?
- What null hypothesis or no-change option was considered?
- Which narrower alternatives were rejected, and why?

## Risk and trust boundaries

Describe security, privacy, compatibility, cost, latency, and operational consequences.
Do not include credentials, production traces, personal data, or signed artifact URLs.

## Validation

- [ ] I added or updated tests for changed behavior.
- [ ] I ran `./scripts/classic_ci.ps1 -SkipPackageBuild` or documented why I could not.
- [ ] I updated affected schemas, architecture, threat-model, and operator guidance.
- [ ] I preserved stable finding codes or documented a deliberate compatibility change.
- [ ] I kept network access, commands, images, and policy overrides outside untrusted evidence.

## Source-of-record coordination

Until ADR 0026 is superseded, TFVC remains authoritative. A maintainer must reproduce an
accepted public contribution in TFVC and publish the resulting reviewed snapshot; this
GitHub pull request must not become an independent source of truth.
