# Artifact attestations

Causure can bind exact artifact bytes to a producer identity with a detached
Ed25519 signature. Verification also applies a key-validity window, an organization-defined
retention deadline, and a freshness-bounded revocation list before returning a machine-
readable receipt.

This boundary is intended for change cases, trace manifests, investigation outputs, replay
results, and other evidence artifacts. It does not embed the artifact or a storage URL.

## Install

The deterministic evidence gate remains dependency-free. Ed25519 operations use an explicit
optional dependency:

```powershell
python -m pip install -e ".[attestation]"
```

The extra pins the audited cryptographic implementation used by this alpha. The package
does not implement signature mathematics itself.

## Documents

Four closed, versioned contracts are involved:

- `artifact-attestation`: detached signed metadata for exact artifact bytes.
- `attestation-trust-store`: protected producer-to-public-key bindings and key validity
  windows.
- `attestation-revocations`: the current key-revocation state.
- `attestation-verification`: a successful verification receipt.

Their canonical definitions are in [`schemas/`](../schemas/). The three input parsers reject
unknown fields, duplicate key IDs, non-canonical timestamps, malformed base64url, and
unsupported algorithms. Verification receipts are generated only after all checks pass.

The signed payload covers:

- Artifact ID, media type, byte count, and SHA-256 digest.
- Producer ID and key ID.
- Issue and exclusive expiration times.
- Retention class and minimum retention deadline.
- Required revocation-list ID.
- Signature algorithm and canonicalization identifier.

The signature value itself is the only excluded field. Canonicalization uses UTF-8 JSON
with sorted object keys, no insignificant whitespace, no non-finite numbers, and the
versioned `causure-json-v1` identifier.

## Establish producer trust

Generate and protect an Ed25519 key using the organization's approved key-management
process. For a local development key, OpenSSL can create a PEM pair:

```powershell
openssl genpkey -algorithm ED25519 -out producer-private.pem
openssl pkey -in producer-private.pem -pubout -out producer-public.pem
```

Do not check in the private key. Restrict its filesystem permissions and prefer a
short-lived CI secret or managed signing service for production.

Export the raw public-key value required by the trust-store contract:

```powershell
$publicKey = causure public-key .\producer-public.pem
```

Create a protected trust store such as:

```json
{
  "schema_version": "1.0",
  "store_id": "evidence-producers-prod",
  "revocation_list_id": "producer-keys-prod",
  "keys": [
    {
      "key_id": "replay-signing-2026-q3",
      "producer_id": "replay-service-prod",
      "algorithm": "ed25519",
      "public_key_base64url": "REPLACE_WITH_PUBLIC_KEY_OUTPUT",
      "valid_from": "2026-07-01T00:00:00Z",
      "valid_until": "2027-01-01T00:00:00Z"
    }
  ]
}
```

`key_id` values are unique within a trust store. An attestation's entire validity window
must fit inside the trusted key window.

Maintain the separately protected revocation list:

```json
{
  "schema_version": "1.0",
  "list_id": "producer-keys-prod",
  "updated_at": "2026-07-28T12:00:00Z",
  "revoked_keys": []
}
```

Refresh `updated_at` only when publishing a current, complete list. Verification rejects a
list more than 24 hours old by default and allows five minutes of clock skew.

## Sign an artifact

Every timestamp uses the canonical whole-second UTC form `YYYY-MM-DDTHH:MM:SSZ`. The
retention deadline must be at or after the attestation expiration.

```powershell
causure attest .\evidence.json `
  --artifact-id refund-case-001 `
  --media-type application/json `
  --producer-id replay-service-prod `
  --key-id replay-signing-2026-q3 `
  --private-key .\producer-private.pem `
  --expires-at 2026-07-30T12:00:00Z `
  --retention-class incident-evidence-90d `
  --retain-until 2026-10-26T12:00:00Z `
  --revocation-list-id producer-keys-prod `
  --output .\evidence.attestation.json
```

`--issued-at` defaults to the current UTC time. For an encrypted PEM, place the password in
a secret environment variable and pass only its name:

```powershell
causure attest .\evidence.json `
  ... `
  --private-key-password-env CAUSURE_SIGNING_PASSWORD
```

The password value is never accepted as a command-line argument.

## Verify before review

```powershell
causure verify-attestation .\evidence.json `
  .\evidence.attestation.json `
  --trust-store .\attestation-trust-store.json `
  --revocations .\attestation-revocations.json `
  --output .\attestation-verification.json

causure review .\evidence.json `
  --output .\causure-report.md
```

Run verification and review in the same protected pipeline stage. A successful verification
returns exit code 0 and a receipt whose `status` is `verified`. Invalid documents, failed
signatures, changed artifacts, stale revocations, and trust-policy failures return exit code
2. Failure messages contain a stable code without exposing key material.

Important failure codes include:

| Code | Meaning |
| --- | --- |
| `invalid_signature` | Signed metadata changed or the wrong public key was used. |
| `artifact_size_mismatch` | Exact artifact length differs from the signed subject. |
| `artifact_digest_mismatch` | Exact artifact bytes differ from the signed subject. |
| `untrusted_key` | The key ID is absent from the protected trust store. |
| `producer_mismatch` | The trusted key is bound to another producer identity. |
| `key_validity_exceeded` | The attestation falls outside the key validity window. |
| `attestation_expired` | The exclusive attestation deadline has passed. |
| `revocation_list_stale` | Current key status cannot be established. |
| `key_revoked` | The revocation policy invalidates this signature. |

The optional `--max-revocation-age-seconds` can tighten or relax the default up to 31 days.
Treat that pipeline setting as protected policy.

## Revocation semantics

Each revoked-key entry selects one mode:

- `all_signatures`: invalidate every signature from the key. Use this for suspected
  compromise or loss of control.
- `issued_at_or_after`: preserve signatures issued before `revoked_at` and reject later
  signatures. Use this for planned retirement or rotation.

The list requires a non-empty operational reason, but it should not contain incident
secrets.

## Security boundary

Verification proves that a holder of the trusted private key signed the metadata and that
the supplied artifact matches it. The producer identity comes from the protected
trust-store binding, not from a self-asserted field.

The feature does not:

- Upload, retain, delete, or authorize access to artifacts.
- Verify opaque evidence references inside a signed change case.
- Protect a private key stored with weak filesystem permissions.
- Detect rollback of a trust store or revocation list when their storage is compromised.
- Sign the verification receipt.
- Integrate directly with a cloud KMS, HSM, transparency log, or certificate authority.

Protect trust and revocation documents separately from producer credentials. A hosted
deployment should place signing keys in a managed KMS/HSM, distribute revocation state
through an authenticated channel, log trust-policy versions, and enforce retention in the
artifact store. The five-minute clock allowance and revocation freshness are verification
controls, not substitutes for reliable time synchronization.
