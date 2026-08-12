# ADR 0016: Use local file election for same-host Entra refresh

## Status

Accepted for the `0.4.0a8` single-host alpha.

## Context

`ManagedEntraAccessTokenVerifier` safely owns one refresh worker inside one process, but a
production WSGI server commonly runs several worker processes. Starting one manager in
every worker would create multiple discovery/JWKS clients and snapshot writers. Merely
documenting "start one" leaves startup ordering, process failure, and unknown-key rollover
signals to each host integration.

The Team SQLite pilot and atomic Entra snapshot already require one host and local storage.
That scope permits an OS file lock to provide crash-released mutual exclusion without
adding a runtime dependency or pretending to implement distributed consensus.

## Decision

Add `LocalFileEntraRefreshCoordinator` and
`CoordinatedEntraAccessTokenVerifier` for same-host processes sharing one protected local
control-plane directory.

- Each process creates the coordinated verifier after worker fork.
- A non-blocking exclusive OS lock admits one refresh owner. Windows locks one byte with
  `msvcrt.locking`; Unix uses `fcntl.flock`.
- The owner alone starts `ManagedEntraAccessTokenVerifier`. Every process validates
  requests through its own `ReloadingEntraAccessTokenVerifier`.
- A follower with no usable snapshot waits a bounded startup interval for the current
  owner; it never performs an unowned network refresh.
- An unknown key reached only after strict parsing and protected tenant selection creates
  one bounded marker with exclusive file creation. Concurrent follower signals coalesce.
- The owner polls that marker and schedules it through the existing singleflight,
  five-minute managed cooldown before consuming it. A transient marker-deletion failure
  retries consumption without scheduling the already satisfied marker again.
- Process exit releases the OS lock. A follower then acquires ownership, performs a guarded
  startup refresh, and becomes the sole writer.
- Managed refresh checks the lock-file identity before retrieval and immediately before
  snapshot installation. Replaced or missing ownership fails with a stable code and does
  not install the candidate.
- Coordinator objects are process-bound. Use after `fork()` fails closed so a child cannot
  treat an inherited descriptor or vanished parent thread as valid ownership.
- Status is bounded and non-sensitive: lifecycle state, owner role, acquisition count,
  request-pending state, stable coordination error, and optional managed-owner status.

## Consequences

Multi-process services on one host can share automatic startup, periodic rollover, bounded
unknown-key recovery, and owner failover without racing network clients or snapshot
writers. Followers remain request-path offline. The first request with a legitimate new
key can still fail once.

The lock and request marker become protected authentication control-plane files. Their
parent directory must prevent untrusted replacement, deletion, symlink insertion, or
marker flooding. Operators must never rotate or delete the live lock path.

This is not a distributed lease. Network shares, synced folders, distributed filesystems,
containers on different hosts, and filesystems whose lock semantics have not been
qualified are excluded. Multi-host services must use one external scheduler with
reload-only workers or supply a separately reviewed distributed coordinator. Production
HTTP rate limiting, jitter, and live Entra qualification remain future deployment work.
