# ADR 0030: Rebrand as Causure before public release

- Status: Accepted
- Date: 2026-08-10

## Context

The original working name described one gate behavior literally, but it was long, clunky in
commands and identifiers, and narrower than the product that emerged. The product now spans
causal investigation, evidence qualification, approvals, bounded execution, change review,
publication, audit, and canary comparison for production AI-agent systems.

`Causure` combines the ideas of *cause* and *assurance*. It is short enough for a command and
package namespace while still pointing at the product's central claim: teams should change an
agent harness only when reproducible, causally relevant evidence supports that change.

An exact-name collision screen performed on 2026-08-10 found no active exact-name GitHub user,
organization, or repository; no package on PyPI, npm, crates.io, or NuGet; and no registered
`.com`, `.dev`, or `.io` domain through the queried RDAP services. Broader software-product and
indexed trademark searches found no obvious active product using the name. This is practical
preliminary screening, not formal legal or trademark clearance.

The project has not yet been published to GitHub or a package registry, so this is the least
costly point at which to make a clean, breaking rename.

## Decision

The product identity is:

- product name: **Causure**;
- pronunciation: **cause-sure**;
- descriptor: **Causal assurance for production AI-agent changes**;
- principle: **Change only what the evidence supports**;
- proposed public repository: `MusaShams/Causure`;
- Python distribution, import namespace, module launcher, and command: `causure`;
- Windows service command: `causure-windows-service`;
- project configuration directory: `.causure`;
- public environment-variable prefix: `CAUSURE_`;
- finding and diagnostic prefix: `CAUSURE-`;
- vendor media-type namespace and canonicalization identifier: `vnd.causure` and
  `causure-json-v1`;
- first rebranded alpha version: `0.4.0a18`.

Because no public compatibility contract exists yet, the implementation will not ship aliases
for the former package, import path, CLI, configuration directory, environment variables, or
wire identifiers. Generated cases, signatures, receipts, and deployment assets must be
regenerated under the Causure contracts.

The Azure DevOps TFVC project and mapped local workspace retain their existing administrative
name for now. Exact `$/ProofBeforePatch`, Azure project URL, and local mapping references remain
where they describe that real source-control location. Renaming the Azure project is a separate
administrative migration and is not required to publish `MusaShams/Causure`.

Prior ADRs and completed qualification receipts remain unchanged because they record historical
decisions and exact build evidence. This ADR supersedes their former-name assumptions for all
active product interfaces.

## Consequences

- The first public surface is coherent and does not expose mixed legacy branding.
- Existing unpublished alpha artifacts are intentionally incompatible and must be regenerated.
- Signatures and verifications using the former canonicalization identifier do not silently
  cross the rebrand boundary.
- A fresh installed-wheel and release qualification is required for `causure` `0.4.0a18`.
- Formal trademark review remains advisable before commercial launch or material brand spend.
