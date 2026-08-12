# ADR 0022: Bind a native Windows service to exact host policy

- Status: Accepted
- Date: 2026-08-03
- Release: 0.4.0a14

## Context

`team-serve` made the Team stack runnable as one loopback process, but an operator still
had to keep an interactive console alive and invent stop/restart behavior. On the initial
TFVC/Windows pilot platform, Windows Service Control Manager is the natural supervision
boundary. A generic script wrapper would not guarantee managed Entra cleanup, and storing
only a mutable config path in SCM would allow unnoticed policy drift.

## Decision

ProofBeforePatch will ship a separate optional native Windows service adapter.

1. The adapter pins pywin32 `312` and requires a machine-wide elevated installation in a
   Python location accessible to the service identity.
2. SCM registration uses one fixed name, `ProofBeforePatchTeam`, and the passwordless
   virtual account `NT SERVICE\ProofBeforePatchTeam`; `LocalSystem` is not the default.
3. Installation validates the closed host config and exact Waitress dependency before
   creating SCM state. It enables the service SID and stores one protected registry JSON
   value binding schema version, canonical absolute path, SHA-256, and byte count.
4. The service reparses that registry value and exact file subject at every start. A file
   edit without a stopped-service `configure` action fails closed.
5. The registry value contains no config body, credential, token, password, or private
   key. The protected file and HKLM administrator boundary remain trusted.
6. A new `TeamHostServer` controller owns Waitress listener close, a five-second task
   drain/cancel window, remaining channel close, and managed-verifier cleanup. It is
   idempotent and can be called from the SCM control thread while the server loop runs.
7. Install leaves the service stopped. Start/stop/status/configure/remove are explicit;
   configure and remove require SCM `stopped`, and remove never deletes operator data.
8. SCM running state is not application readiness. The trusted edge must gate on
   `/readyz` because synchronous Entra startup occurs after pywin32 reports running.

## Consequences

- A Windows pilot gains native boot/start/stop supervision without a third-party wrapper
  executable or a service password.
- The service account needs explicit read/execute access to machine-wide Python and
  least-privilege read/modify ACLs for the protected ProofBeforePatch paths.
- Virtual-account network access can use the computer account in a domain; outbound policy
  and remote authorization remain operator responsibilities.
- Waitress `3.0.2` is pinned partly because controlled shutdown uses its concrete server,
  task-dispatcher, and channel-map lifecycle. A dependency change must requalify that
  behavior rather than silently normalize it.
- A stop during a long multi-tenant startup fetch is not immediately cancellable. The SCM
  stop wait is bounded, but the process may finish its already-bounded tenant sequence
  afterward.
- Repository tests do not mutate real SCM or HKLM state. A separate opt-in, self-cleaning
  harness qualified install, virtual-account ACL/SID state, exact HKLM binding,
  health/readiness, stop, and uninstall for the exact a14 wheel on one isolated Windows 11
  host. Boot, recovery, event-log operations, real identity, edge, hardening, and each
  production image still require their own qualification.

## Alternatives considered

- **Use Task Scheduler or a startup script.** Rejected because stop, health, identity, and
  restart semantics are weaker and easier to misconfigure.
- **Require WinSW/NSSM.** Deferred to avoid another executable supply chain and because a
  native pywin32 adapter can call the owned host shutdown boundary directly.
- **Run as `LocalSystem`.** Rejected as an unnecessarily broad default.
- **Store only a config path in the registry.** Rejected because a protected but mutable
  file could change service policy without an explicit registration action.
- **Automatically delete data during uninstall.** Rejected because retention and recovery
  policy must remain separate from service registration.
