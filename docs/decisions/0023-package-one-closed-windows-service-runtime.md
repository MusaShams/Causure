# ADR 0023: Package one closed Windows service runtime with bounded recovery

- Status: Accepted
- Date: 2026-08-03
- Release: 0.4.0a15

## Context

ADR 0022 bound one exact Team host policy to a native Windows service, but installation
still depended on an administrator constructing a suitable machine-wide Python
environment. That left package resolution, runtime location, ACLs, recovery actions,
rollback, and uninstall behavior outside the product contract. A company pilot needs a
repeatable artifact and must not enter an unbounded restart loop when closed configuration
or a local dependency is invalid.

An MSI would improve integration, but an unsigned MSI does not solve publisher trust and
would add a second authoring toolchain before the runtime and failure contracts are stable.
The pilot first needs evidence that a closed runtime can install, recover, fail safely, and
remove cleanly.

## Decision

Ship a PowerShell-built ZIP for the Windows single-host pilot. The builder accepts one
standard 64-bit CPython runtime, one exact ProofBeforePatch wheel, and one local exact
wheelhouse. An exact pip wheel is a separate build input and runs under isolated Python;
dependency installation is offline and binary-only. The artifact contains a
private versioned runtime, administrative install/remove workflows, and a manifest with
the byte count and SHA-256 of every managed file. Sorted ZIP entries and normalized
timestamps make identical inputs byte-for-byte reproducible.

Install only at `C:\Program Files\ProofBeforePatch\Team\0.4.0a15`. Store an
administrator/SYSTEM-only receipt and manifest copy in `C:\ProgramData\ProofBeforePatch`.
Refuse unsafe paths, reparse points, unknown/unmanifested files, integrity drift, existing
fixed targets, or incompatible runtime/dependency contracts. Treat the operator's host
configuration, identity state, database, backups, and evidence as external data that
install/remove never owns.

Protect only the versioned runtime root, put inheritable full-control rules for SYSTEM and
Administrators plus read/execute for the virtual service SID on that root, and verify every
descendant retains inheritance and the expected effective rules. A protected descendant
ACL is an installation failure.

Install under the existing virtual service account and exact configuration subject. Apply
and verify an SCM policy that resets failures after 900 seconds, restarts once after
120 seconds, then takes no action, with non-crash failures enabled and no command or reboot
action. Require the service stopped for policy changes and restore both prior SCM values if
a partial write or verification fails.

Before service deletion, require stopped state and disable the service to prevent a queued
recovery restart. If SCM rejects deletion, restore the prior start mode. The bundle remover
may explicitly stop first, but the lower-level adapter must never hide that lifecycle
transition. Mark removal progress in the protected receipt so interrupted deletion can be
retried. Advance the marker with `File.Replace` and a non-null, fixed protected backup;
retain the backup until runtime and manifest deletion complete, then remove the backup and
advanced receipt last. A new installation refuses a leftover backup.

## Consequences

Pilot hosts get one reviewable artifact, fixed machine layout, exact dependency closure,
least-privilege service access, bounded recovery, rollback behavior, and non-destructive
removal. A live harness can exercise the same artifact rather than reconstructing the
runtime ad hoc.

The exact archive was independently rebuilt byte-for-byte and passed the 2026-08-09 live
Windows 11 build 26200 qualification, including real delayed crash restart, bounded
adversarial failures, policy restoration, running-service removal, ACL restoration, and
complete managed-state cleanup. The sanitized result is committed as
[`windows-service-bundle-2026-08-09.json`](../qualifications/windows-service-bundle-2026-08-09.json).

The ZIP remains unsigned and self-hashed; it cannot authenticate its publisher. CPython
and dependency wheels are part of the build trust boundary. The pilot supports one fixed
64-bit Windows service and one installed a15 runtime, not side-by-side services or an
in-place upgrade. Full MSI/MSIX authoring, Authenticode, enterprise distribution, upgrade
transactions, a real trusted edge/Entra identity, and target-image certification remain
future work.

Microsoft documents that the non-crash failure flag takes effect after a system start.
Crash restart can be qualified immediately, but cold boot remains a separately authorized,
disruptive qualification step.
