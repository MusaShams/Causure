# Authenticated approval assertions

Causure keeps human approval separate from its deterministic gate. An approval
authority can issue a short-lived Ed25519 assertion after it authenticates a human action.
The assertion signs the exact Azure review publication and exact pre-approval verification
receipt; it does not edit or relabel the review result.

There are two actions:

- `approve` confirms a review whose existing decision is already `approve`.
- `exception` records explicit acceptance of every finding that affected a non-approval
  decision.

Both actions have `gate_effect: record_only`. A verified exception preserves the original
`conditional_pass`, `reject`, `needs_evidence`, or `human_review` decision. The
`verify-approval` command writes its successful receipt and still returns the original
gate exit status, so a non-approval remains exit code 1.

Install the pinned optional signing implementation in the authority and verifier
environments:

```powershell
python -m pip install -e ".[approval]"
```

## Trust boundary

The assertion authenticates an approver only when the configured authority is trustworthy.
The authority must:

1. authenticate the human through an organizational control;
2. check that the human is authorized for the requested action;
3. obtain the stable identity-provider subject and source event ID;
4. show or otherwise bind the exact publication and verification receipt being approved;
5. issue the assertion within 15 minutes of that authenticated action; and
6. protect its signing key in a KMS/HSM or equivalent isolated service.

`issue-approval` is an authority-side integration command. Do not put the authority private
key in the build agent, verifier job, source tree, evidence bundle, or artifact store. A
pipeline that can choose both the identity claims and the signing key is not an independent
approval control.

Azure's `Build.RequestedForId` identifies who requested a build; it is not an approver.
`System.AccessToken` authenticates the build service to Azure DevOps; it does not
authenticate the human. Do not convert either value directly into `--approver-id`. See
Microsoft's
[predefined-variable reference](https://learn.microsoft.com/en-us/azure/devops/pipelines/build/variables?view=azure-devops)
for the two variables' documented roles.

For Azure approvals and checks, a protected authority can query the
[Approvals REST API](https://learn.microsoft.com/en-us/rest/api/azure/devops/approvalsandchecks/approvals/get?view=azure-devops-rest-7.1)
and use the approved step's `actualApprover.id`, approval ID, and last-modified time as its
authenticated subject, event ID, and event time after independently checking status and
authorization. The API response is input to the authority; it is not itself a signature.

## Protected policy

The verifier consumes a separate approval trust store:

```json
{
  "schema_version": "1.0",
  "store_id": "approval-trust-prod",
  "revocation_list_id": "approval-revocations-prod",
  "keys": [
    {
      "key_id": "approval-key-2026-q3",
      "authority_id": "corporate-approval-service",
      "algorithm": "ed25519",
      "public_key_base64url": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "valid_from": "2026-07-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z",
      "allowed_actions": [
        "approve",
        "exception"
      ]
    }
  ]
}
```

The all-`A` public-key value is illustrative and must be replaced with the authority's
actual exported Ed25519 public key.

`allowed_actions` is a protected authorization decision, not an assertion claim. An
organization can give ordinary approval and exception authority to different keys. Key IDs
must be unique. The complete revocation list is independently freshness-bounded:

```json
{
  "schema_version": "1.0",
  "list_id": "approval-revocations-prod",
  "updated_at": "2026-07-28T21:03:00Z",
  "revoked_keys": []
}
```

Compromise revocation invalidates every assertion from a key. Planned-retirement
revocation preserves only assertions issued before the cutoff. Protect both policy files
from the authority, evidence producer, and approver.

## Issuing a confirmation

After an organizational service authenticates the human action, it can invoke:

```powershell
causure issue-approval `
  .\causure-azure-publication.json `
  .\causure-azure-verification.json `
  .\causure-result.json `
  --assertion-id approval-event-2026-000417 `
  --authority-id corporate-approval-service `
  --key-id approval-key-2026-q3 `
  --approver-id 33333333-3333-4333-8333-333333333333 `
  --identity-provider azure-devops:example `
  --authentication-method azure_devops_approval `
  --authentication-event-id 44444444-4444-4444-8444-444444444444 `
  --authenticated-at 2026-07-28T21:02:00Z `
  --action approve `
  --issued-at 2026-07-28T21:03:00Z `
  --expires-at 2026-07-28T22:03:00Z `
  --revocation-list-id approval-revocations-prod `
  --private-key .\authority-private.pem `
  --output .\causure-approval.json
```

The identity provider, subject, authentication method, event ID, authentication time,
action, validity, authority, and exact artifact hashes are all signed.

The CLI accepts a PEM password only through the named
`--private-key-password-env` environment variable. Local PEM support is useful for
development and adapters; production issuance should perform the equivalent signing
operation inside the authority's managed key service.

## Issuing an exception

An exception is scoped to one exact publication, and therefore to one case, policy, result,
build, TFVC changeset or shelveset, and artifact set. It must also name every finding whose
consequence affected the non-approval:

```powershell
causure issue-approval `
  .\causure-azure-publication.json `
  .\causure-azure-verification.json `
  .\causure-result.json `
  --assertion-id exception-event-2026-000031 `
  --authority-id corporate-exception-service `
  --key-id exception-key-2026-q3 `
  --approver-id 33333333-3333-4333-8333-333333333333 `
  --identity-provider azure-devops:example `
  --authentication-method azure_devops_approval `
  --authentication-event-id 55555555-5555-4555-8555-555555555555 `
  --authenticated-at 2026-07-28T21:12:00Z `
  --action exception `
  --finding-code CAUSURE-ATT-003 `
  --finding-code CAUSURE-MET-001 `
  --finding-code CAUSURE-MET-002 `
  --finding-code CAUSURE-MIN-001 `
  --finding-code CAUSURE-VAL-002 `
  --justification "Time-bounded emergency risk acceptance under incident INC-417." `
  --issued-at 2026-07-28T21:13:00Z `
  --expires-at 2026-07-28T22:13:00Z `
  --revocation-list-id approval-revocations-prod `
  --private-key .\exception-authority-private.pem `
  --output .\causure-exception.json
```

Partial, extra, or duplicate exception finding sets fail issuance. The CLI sorts issuer
input before signing, while the wire parser rejects an unsorted record and requires a
canonical sorted set. Every assertion must expire within 24 hours of both issuance and the
bound pre-approval verification.

## Verifying in the Azure TFVC build

The verifier must run with the original result, report, publication, pre-approval receipt,
and current Azure TFVC context:

```powershell
causure verify-approval `
  .\causure-approval.json `
  .\causure-azure-publication.json `
  .\causure-azure-verification.json `
  .\causure-result.json `
  .\causure-report.md `
  --trust-store .\policy\approval-trust-store.json `
  --revocations .\policy\approval-revocations.json `
  --tfvc-server-path '$/ProofBeforePatch' `
  --output .\causure-approval-verification.json
```

Verification:

- checks the authority signature and protected authority/key/action binding;
- enforces key validity, assertion expiration, and current revocation freshness;
- binds the exact publication and pre-approval receipt bytes;
- rechecks the exact JSON result and Markdown report;
- reconstructs the pre-approval receipt at its recorded verification time;
- rechecks the current Azure build and TFVC identity;
- enforces receipt → authenticated action → assertion event ordering; and
- requires an exception to cover every decision-affecting finding.

The output is a closed successful receipt. Its original `review.decision`,
`action`, and `gate_effect` fields stay distinct.

## Contracts

The committed JSON Schemas are:

- [`approval-assertion.schema.json`](../schemas/approval-assertion.schema.json)
- [`approval-trust-store.schema.json`](../schemas/approval-trust-store.schema.json)
- [`approval-revocations.schema.json`](../schemas/approval-revocations.schema.json)
- [`approval-verification.schema.json`](../schemas/approval-verification.schema.json)

The trust store and revocation list are protected policy inputs. They are not made
trustworthy merely by matching their schemas.
