# Offline Windows service bundle

Causure `0.4.0a15` can be assembled as a repeatable, offline, machine-wide
Windows Team service bundle. The ZIP contains a private 64-bit CPython runtime, the exact
Causure wheel and service dependencies, administrative install/remove scripts,
and a closed per-file SHA-256 manifest.

The committed [manifest schema](../schemas/windows-service-bundle-manifest.schema.json) and
[installation-receipt schema](../schemas/windows-service-installation-receipt.schema.json)
document the on-disk contracts. The administrative scripts additionally enforce duplicate
JSON-key rejection, strict UTF-8, safe path resolution, reparse-point rejection, and exact
file-set closure.

This is pilot packaging, not a signed installer. The manifest detects accidental changes
and lets an operator bind an installation receipt to exact bytes, but it does not establish
publisher identity: anyone able to replace both payload and manifest can create a
self-consistent malicious bundle. Exchange the ZIP SHA-256 over an authenticated channel,
restrict who can write the extracted directory, and require Authenticode or an enterprise
package signature before production distribution.

## Build from exact offline inputs

The builder requires:

- a standard 64-bit CPython 3.11-or-newer installation on a fixed local drive;
- the exact `causure-0.4.0a15-py3-none-any.whl`;
- the exact `pip-26.1.2-py3-none-any.whl` build tool;
- a local wheelhouse containing binary-compatible wheels for exact cryptography `50.0.0`,
  CFFI `2.1.0`, pycparser `3.0`, PyJWT `2.13.0`, pywin32 `312`, and Waitress `3.0.2`; and
- a fixed-local-drive output parent.

Populate the wheelhouse during an explicitly networked build step, then build offline:

```powershell
python -m pip download `
  --only-binary=:all: `
  --dest .\build\windows-service-wheelhouse-a15 `
  cffi==2.1.0 `
  cryptography==50.0.0 `
  pycparser==3.0 `
  PyJWT==2.13.0 `
  pywin32==312 `
  waitress==3.0.2

python -m pip download `
  --no-deps `
  --dest .\build\windows-service-wheelhouse-a15 `
  pip==26.1.2

pwsh -File .\scripts\build_windows_service_bundle.ps1 `
  -SourcePythonRoot C:\Path\To\CPython `
  -WheelPath .\dist\causure-0.4.0a15-py3-none-any.whl `
  -WheelhousePath .\build\windows-service-wheelhouse-a15 `
  -PipWheelPath .\build\windows-service-wheelhouse-a15\pip-26.1.2-py3-none-any.whl `
  -OutputPath .\dist\causure-windows-service-0.4.0a15-win-amd64.zip
```

The actual assembly command executes the supplied pip wheel under isolated Python and uses
`--isolated --no-index --only-binary=:all:`. It copies
only the interpreter, standard library, runtime DLLs, and exact resolved packages. It
removes console launchers and wheel `RECORD` files whose generated contents contain the
random staging path, plus local-wheel `direct_url.json` records whose contents contain the
builder's input path; none is used by the service. It then validates package contracts
from the staged interpreter, rejects reparse points, hashes every managed file, and writes
ZIP entries in sorted order with a normalized timestamp.

Identical a15 inputs on the same source-runtime build produce identical ZIP bytes. Record
both the emitted bundle SHA-256 and manifest SHA-256. Reproducibility is an audit property,
not a substitute for signing or review of the source runtime and dependency wheels.

## Install on a pilot host

Before installation, create and review the protected host and Entra refresh configuration
described in the [single-host guide](team-service-hosting.md). Its database and trust-store
parent directories must already exist on fixed local storage. Extract the ZIP into an
administrator-controlled directory, compare its SHA-256 with the authenticated build
record, then use 64-bit elevated PowerShell:

```powershell
pwsh -File .\install.ps1 `
  -HostConfigurationPath C:\ProgramData\Causure\config\team-host.json
```

Use `-ManualStart` for a demand-start pilot. The default is delayed automatic start. Both
modes leave the service stopped so ACL, trusted-edge, egress, monitoring, backup, and
readiness checks can finish before traffic is enabled.

The installer accepts only the exact a15 manifest contract. It rejects unknown manifest
fields, duplicate/unsafe paths, unmanifested files, hash or byte-count mismatches, reparse
points, another fixed service, an existing receipt, or an existing versioned runtime. It
stages under `C:\Program Files\Causure\Team`, verifies the copied bytes, and moves
the stage to:

```text
C:\Program Files\Causure\Team\0.4.0a15
```

It then validates the exact host configuration with the private runtime, installs the
fixed `CausureTeam` service, applies the bounded recovery policy, and grants:

- full control of the runtime to `SYSTEM` and `BUILTIN\Administrators`;
- read/execute runtime access to `NT SERVICE\CausureTeam`;
- read access to the two exact protected configuration files; and
- modify access to only the configured trust-store and database parents.

The runtime root is the only protected ACL boundary. Its inheritable SYSTEM,
Administrators, and service-SID rules flow to every child; installation enumerates every
descendant and fails unless each child is inheritance-enabled and exposes the required
inherited rights. This prevents a recursive inheritance-removal command from leaving
runtime files with protected empty DACLs.

The protected installation receipt and a copy of the exact bundle manifest are stored at:

```text
C:\ProgramData\Causure\windows-service-installation.json
C:\ProgramData\Causure\windows-service-bundle-manifest.json
```

The receipt binds the package version, runtime path, service name, manifest SHA-256, and
host-configuration path/SHA-256/byte count. It contains no configuration body, token,
password, or private key. If any post-stage operation fails, installation attempts to stop
and remove a partial service, restore the captured access-control descriptors on external
operator paths, and then delete its exact runtime and receipt. If service rollback fails,
it preserves the runtime rather than orphaning a registered service whose image path no
longer exists.

## Recovery and readiness

Installation writes and reads back one closed SCM recovery policy while the service is
stopped:

```text
Failure-count reset:       900 seconds
First failure:             restart after 120,000 milliseconds
Second/later failure:      no action
Non-crash failure actions: enabled
Command/reboot action:     none
```

This avoids a tight restart loop when exact configuration, identity metadata, storage, or
the loopback port is invalid. Microsoft documents in
[`SERVICE_FAILURE_ACTIONS_FLAG`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_failure_actions_flag)
that changing the non-crash-failure flag takes effect after the next system start; crash
recovery is immediately testable, while a cold-boot qualification is still required before
relying on non-crash behavior.

Inspect the effective policy without exposing command or reboot-message values:

```powershell
& 'C:\Program Files\Causure\Team\0.4.0a15\python.exe' `
  -I -B -m causure.team_windows_service_cli recovery-status
```

SCM `running` remains distinct from application readiness. Gate traffic on `/readyz`
through the trusted same-host HTTPS edge, not on process state or `/healthz` alone.

## Retry-safe removal

Run the installed remover from 64-bit elevated PowerShell:

```powershell
pwsh -File `
  'C:\Program Files\Causure\Team\0.4.0a15\management\remove.ps1'
```

It verifies the protected receipt, manifest, exact managed path, every present runtime
file, and the absence of unmanifested files. It explicitly stops a running service, then
the adapter disables the stopped service before deletion so a queued recovery restart
cannot race removal, following Microsoft's
[`ChangeServiceConfig2`](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfig2w)
contract. After SCM confirms absence, it restores the access-control descriptors
captured for external operator paths, advances a protected `removal_started` receipt
marker, and deletes the versioned runtime and installed manifest. Marker advancement uses
an atomic same-directory replacement with the prior protected receipt retained temporarily
at the fixed
`C:\ProgramData\Causure\windows-service-installation.removal-backup.json`
path. The backup and advanced receipt are the final two managed files removed.

Before advancing the marker, removal verifies the complete manifest and runtime. If
deletion is interrupted after that point, a rerun may finish deleting a partial runtime or
an already-removed manifest because the protected advanced receipt fixes the only allowed
machine paths; reparse points remain forbidden. A new install rejects a stale removal
backup instead of treating an incomplete teardown as clean. Host/refresh configuration,
Entra trust state, SQLite data, backups, logs, and retention-controlled evidence are never
removal targets.

## Live qualification and cold boot

The elevated harness exercises the real bundle and fixed machine locations on an isolated
Windows pilot host:

```powershell
pwsh -File .\scripts\qualify_windows_service_bundle.ps1 `
  -BundlePath .\dist\causure-windows-service-0.4.0a15-win-amd64.zip `
  -ReportPath C:\SafeReports\causure-windows-bundle.json
```

It refuses pre-existing fixed targets, safely inspects the ZIP before extraction, creates
non-secret loopback-only policy, installs the bundle in manual mode, and verifies receipt,
manifest, service account, readiness, and the exact recovery policy. It force-terminates
the isolated service process and waits through the real two-minute SCM restart, then
requires health/readiness again. It also proves exact host-byte drift and loopback port
collision stop without a restart loop while recovery actions are temporarily set to
`none`, restores and verifies the shipping recovery policy, restores a healthy start,
removes the bundle while running, checks operator paths survived, and cleans only its fixed
qualification directory.

On 2026-08-09, the exact a15 archive and an independent rebuild were byte-identical at
SHA-256 `16ee1b521d70fa0670e1c2099843bc8a2ae22dd9520772748d6345ec1b6daf04`;
the closed 3,318-file manifest hash was
`2a625fb8af7e7b0ef1bed119fab055772c5870660c40234c29fe342747b41eab`.
The bundle passed on Windows 11 Pro build 26200. SCM restarted the deliberately crashed
service after 121.69 seconds under a different PID, health/readiness returned 200 before
and after recovery, configuration drift and port collision stopped without loops, the
shipping recovery policy was restored, and removal of the running service left no managed
machine state while preserving operator paths and ACLs. The committed
[machine-readable evidence](qualifications/windows-service-bundle-2026-08-09.json) has
SHA-256 `ef7c9fd919cf6fd9b0d16d2b4f0ec7f589f6215c7e9b6631c41c941bb7745dd5`.

The first harness intentionally records cold boot as not performed. Rebooting a workstation
is a separate disruptive action and requires explicit operator authorization.

After that authorization, prepare the exact a15 archive from elevated 64-bit PowerShell:

```powershell
pwsh -File .\scripts\prepare_windows_service_cold_boot_qualification.ps1 `
  -BundlePath .\dist\causure-windows-service-0.4.0a15-win-amd64.zip
```

Preparation does not reboot. It accepts only the independently reproduced a15 ZIP and
manifest hashes above, refuses any pre-existing fixed service/task/runtime/report target,
copies the completion script into an Administrator/SYSTEM-only ProgramData root, and first
runs that exact copy in a disposable `LocalSystem` task. Only after the probe proves a
64-bit PowerShell 7 SYSTEM execution path does preparation install the bundle without
`-ManualStart`, verify the stopped delayed-automatic service and exact recovery policy,
write hash-bound protected state, and register one SYSTEM startup task with a 30-second
delay. Inspect the returned `armed` record before issuing the separately authorized reboot:

```powershell
Restart-Computer
```

The startup task never treats SCM `running` as readiness. It waits for both `/healthz` and
`/readyz`, proves that the service process belongs to the new boot, and then exercises the
post-boot non-crash policy. For that bounded negative case it withholds the disposable
last-known-good trust file and adds one temporary outbound block scoped only to the exact
private `pythonservice.exe`; it does not disable a network adapter or change a global
firewall profile. It sends a direct non-waiting SCM start request and captures the resulting
first process ID because the ordinary administrative start command waits for `RUNNING`,
which an intentionally failed startup is not required to reach. Recovery itself is proved
from durable structured System-log events rather than a transient process poll: event 7031
must identify this service with failure count 1, action code 1, and delay 120000; event 7034
must then identify failure count 2 within the bounded interval, and no count-3 event may
follow. A recovered PID is optional corroboration. The exact policy must remain, and
removing the block/restoring trust must return `/readyz` to 200.

Success requires running-service bundle removal, exact operator-ACL restoration, absence
of every managed runtime/receipt/manifest, removal of the firewall rule and one-shot task,
and deletion of the disposable qualification root. The sanitized report survives in the
protected fixed path below for collection after sign-in:

```text
C:\ProgramData\CausureColdBootReport\windows-service-cold-boot.json
```

Until that report is inspected and committed, the cold-boot result remains pending rather
than implied by successful arming.

The first authorized cold-boot attempt on 2026-08-09 proved the new boot, delayed
automatic start, health/readiness 200, effective non-crash failure actions, a 121.517-second
first restart under service-only network loss, bounded second failure, exact trust/policy
restoration, restored readiness, running-service removal, operator ACL restoration, and
absence of every machine-managed service/runtime/receipt/firewall/task target. Its overall
result is still `failed`, not passed: the completion process tried to delete the disposable
qualification root while that root was its current working directory. The archived
[attempt-1 evidence](qualifications/windows-service-cold-boot-2026-08-09-attempt-1.json)
has SHA-256 `50c3aa593ddfe3d737443d9b23bd006ea3009172640d0918609c5b940b7c50bc`.

An administrator preserved that exact report and then removed the orphaned root, leaving
no service, runtime, receipt, receipt backup, installed manifest, firewall rule, startup
task, qualification root, or report root. The harness now runs the real startup task from
the separate report directory and explicitly changes there before qualification-root
deletion.

The second authorized attempt proved that cleanup correction: its report and an independent
fixed-path snapshot both show no service, runtime, receipt, receipt backup, installed
manifest, firewall rule, startup task, or qualification root. Its overall result also
remains `failed`, this time at `non_crash_recovery`. The negative case called the ordinary
administrative start command, which waits for SCM `RUNNING`; intentionally unavailable
trust caused the service to terminate during startup, so the command correctly returned 2
before the harness could observe recovery. Windows SCM event 7031 independently recorded
the non-crash termination and its scheduled 120,000 ms restart. The exact archived
[attempt-2 evidence](qualifications/windows-service-cold-boot-2026-08-09-attempt-2.json)
has SHA-256 `a84356ac65167cae985795351667ca2f1f6e70ee4d9ae996c8d296d58be3abe1`.

The harness now uses the direct non-waiting SCM start path described above for only that
negative case; restored healthy startup still uses the ordinary verified administrative
command.

The third authorized attempt proved that direct start and the actual SCM recovery sequence,
but remains `failed` because the observer required a recovered `RUNNING`/PID snapshot. SCM
record 127383 was event 7031 with service `Causure Team Service`, failure count 1,
120,000 ms delay, and restart action code 1. Record 127385 was event 7034 with failure count
2 exactly 121.063 seconds later; no third failure occurred. The recovered process failed too
quickly to appear between 250-millisecond CIM polls, so the harness timed out despite the
durable SCM proof. All cleanup assertions and the independent residue snapshot passed. The
exact archived
[attempt-3 evidence](qualifications/windows-service-cold-boot-2026-08-09-attempt-3.json)
has SHA-256 `c83f99e2cfc978fcfe783c5184d92d928215993d05d58cf36bf358a715eabc7a`.

The harness now gates on the structured event properties and timestamps described above,
while retaining a recovered PID only when observed.

The fourth authorized attempt passed on Windows 11 Pro build 26200. The hash-bound SYSTEM
task ran after a new boot, observed the delayed-automatic service at health/readiness 200,
and proved the negative sequence with first PID 11184, event 7031 record 127644, exact
restart delay/action properties, recovered PID 13056, and event 7034 record 127646 exactly
121.197 seconds later. No count-3 event or restart loop occurred. Exact trust and recovery
policy were restored, health/readiness returned to 200, running-service removal preserved
operator paths and ACLs, and both the report and an independent fixed-path snapshot found no
managed service, runtime, receipt, receipt backup, installed manifest, firewall rule,
startup task, or qualification root. Cleanup recorded no errors.

The canonical [passing evidence](qualifications/windows-service-cold-boot-2026-08-09.json)
has SHA-256 `be019bac5afb0fb0cad0919aae92375eb89a7670f4e0f448ee0cb7cee133f351`.
This closes the exact a15 pilot-host cold-boot gate; it does not sign the bundle or qualify
a separate production target image, public edge, or company Entra deployment.
