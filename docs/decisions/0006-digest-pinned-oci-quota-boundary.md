# ADR 0006: Add a digest-pinned OCI worker and hard-quota proxy boundary

- Status: Accepted
- Date: 2026-07-28

## Context

The spawned-process adapter runner provides a useful deadline and accounting boundary, but
its child inherits the invoking account's filesystem and network authority. Its concurrency
limit is cooperative, and a returned cost can only detect overspend after provider work has
already occurred.

Calling that process a sandbox would create a dangerous deployment assumption. A practical
company boundary needs independently applied OS limits, network denial by default, parent
concurrency control, and a way to fail before launching networked work when hard spend
enforcement is unavailable.

## Decision

ProofBeforePatch will provide a separate `SandboxedAdapterRunner` with a versioned trusted
policy and a Docker CLI runtime.

Each evidence reference runs in its own digest-pinned Linux container. The parent, not the
worker, limits simultaneous containers. The runtime uses a read-only root, one bounded
temporary filesystem, a numeric non-root identity, no added capabilities or host mounts,
`no-new-privileges`, built-in seccomp, private cgroups, and explicit CPU, memory, swap, PID,
file, output, and wall-clock limits. Images that declare writable volumes are rejected.

Offline work uses `--network none`. Connected work is allowed only through an internal
Docker network that contains a named quota proxy and no other container before launch.
Before any connected preflight or worker launch, a trusted `ProviderQuotaController` must
reserve a provider-backed hard quota for the exact operation count, bounded cost,
concurrency, and deadline.

The scoped lease token travels only in the bounded standard-input worker request. It is not
placed in arguments, environment variables, result objects, or logs. Successful work is
settled against authoritative provider accounting; every failure path cancels the lease.
Unconfirmed container cleanup or quota cancellation replaces the original failure with a
stable fail-closed error.

The policy, worker request, and worker response remain closed JSON contracts with committed
schemas. Evidence files cannot choose images, networks, runtime commands, or quota
controllers.

## Consequences

Offline replay/evaluation can now run behind a genuine OS and network boundary when a
compatible Linux Docker engine is present. Connected deployments get a precise integration
contract for hard spend enforcement rather than treating worker-reported cost as a quota.

One reference per container makes parent concurrency observable and enforceable, but it
adds container startup overhead. A worker can still create threads inside its own CPU,
memory, and PID envelope.

Docker is an external deployment dependency, not a Python package dependency. The default
test suite validates the command and orchestration logic without requiring a daemon; each
production environment must qualify its actual engine, kernel, image, and cleanup behavior.

ProofBeforePatch does not ship provider credentials, a generic proxy that merely counts
self-reported costs, or provider-specific quota implementations. Companies must supply a
controller and TLS proxy whose limits are enforced before forwarding provider operations.
The Docker daemon, host kernel, policy distribution, proxy, controller, and orchestration
permissions remain trusted infrastructure.
