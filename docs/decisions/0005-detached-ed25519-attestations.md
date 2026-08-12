# ADR 0005: Use detached Ed25519 producer attestations

- Status: Accepted
- Date: 2026-07-28

## Context

SHA-256 binds an artifact reference to bytes but does not identify the producer. Embedding
signatures inside each existing evidence contract would couple provenance changes to the
gate, trace, fixture, and future adapter schemas. A self-asserted producer name or public
key would not establish organizational trust.

Retention and key revocation also have different owners from evidence contents. They need
to be evaluated against protected, current policy without rewriting an immutable artifact.

## Decision

ProofBeforePatch will use a versioned, detached attestation that signs the exact artifact
digest, byte count, producer/key identity, validity window, retention requirement, and
required revocation-list identity.

The only supported algorithm in this version is Ed25519. Signature operations use the
optional, pinned `cryptography` package; the project will not implement cryptographic
primitives. Producer identity is established by a separately protected trust store that
binds each key ID to one producer and a validity window.

Revocations remain separate and freshness-bounded. `all_signatures` handles compromise;
`issued_at_or_after` handles planned retirement while preserving earlier signatures.
Verification emits a machine-readable success receipt and otherwise fails closed with a
stable code.

## Consequences

One attestation contract can protect change cases, manifests, replay results, and future
artifact types without changing their schemas. Exact-byte mutation, signed-metadata
mutation, untrusted identity, expired validity, insufficient retention, stale revocation
state, and applicable revocation are independently detectable.

The core gate remains dependency-free, while signing users install the explicit
`attestation` extra. Local PEM signing is useful for development and conventional CI but
does not provide managed-key isolation. Trust stores and revocation lists are trusted local
policy inputs and are not yet signed against rollback. Artifact storage must still enforce
retention and access control, and production signers should move to a KMS/HSM integration.
