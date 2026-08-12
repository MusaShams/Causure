# Native Windows Team service

Causure `0.4.0a15` can register the closed single-host Team launcher with Windows
Service Control Manager (SCM). The adapter uses exact pywin32 `312`, one fixed service
name, a passwordless virtual service account, and an exact registry binding to the
protected host-configuration bytes.

This is a deployment aid for a Windows single-host pilot. The a15
[offline machine bundle](windows-service-bundle.md) closes the private runtime, install,
recovery, and removal workflows, but it is not an MSI, a signed installer, an
IIS/reverse-proxy setup, a multi-host service, or live production qualification. The
loopback-only and trusted same-host HTTPS-edge requirements in the
[single-host service guide](team-service-hosting.md) still apply.

## Machine-wide installation precondition

For a repeatable pilot deployment, prefer the
[closed offline bundle](windows-service-bundle.md). For direct adapter development, open
an elevated PowerShell session and use a machine-wide CPython installation in a path
the service account can read and execute, normally under `C:\Program Files`. Do not
register the service from a per-user Python under `%LOCALAPPDATA%`, `%APPDATA%`, or a user
profile. The package and its dependencies must be importable by `pythonservice.exe` when
SCM starts it outside your interactive profile.

Install the exact optional dependencies into that machine-wide interpreter:

```powershell
python -m pip install "causure[windows-service]==0.4.0a15"
python -m pywin32_postinstall -install
```

The pywin32 project specifically recommends a global elevated install for Windows service
hosting and requires Python and its DLLs to be accessible to the service identity. See the
[pywin32 service-install notes](https://github.com/mhammond/pywin32/blob/main/README.md#running-as-a-windows-service).

Do not run `pywin32_postinstall` inside a virtual environment. A company should package
and patch this interpreter like other privileged service runtimes rather than relying on a
developer workstation environment.

## Service identity and protected paths

The adapter installs exactly one service:

```text
Service name:    CausureTeam
Display name:    Causure Team Service
Logon identity:  NT SERVICE\CausureTeam
Default start:   Delayed automatic
```

Windows manages that virtual account without a password. The installer also enables its
service SID. Microsoft documents virtual accounts as locally managed, single-server
identities in the `NT SERVICE\<SERVICENAME>` form; network access uses the computer
account in a domain. See
[Windows service accounts](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-service-accounts)
and
[virtual-account service configuration](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-changeserviceconfiga).

Prepare the three distinct absolute paths described by the host guide under a protected
machine directory such as `C:\ProgramData\Causure`. The service identity needs:

- read access to `team-host.json` and `entra-refresh.json`;
- modify access to the Entra trust-snapshot parent;
- modify access to the SQLite database parent; and
- read/execute access to the machine-wide Python and installed package.

Grant those rights through the organization's normal ACL tooling and verify the effective
permissions before starting. A minimal local example is:

```powershell
$servicePrincipal = "NT SERVICE\CausureTeam"
icacls "C:\ProgramData\Causure\config" `
  /grant:r "${servicePrincipal}:(OI)(CI)(RX)"
icacls "C:\ProgramData\Causure\state" `
  /grant:r "${servicePrincipal}:(OI)(CI)(M)"
icacls "C:\ProgramData\Causure\data" `
  /grant:r "${servicePrincipal}:(OI)(CI)(M)"
```

Review inherited permissions rather than assuming these grants remove broader access.
Do not grant the service identity permission to rewrite its host or refresh configuration,
SCM registration, Python installation, or reverse-proxy configuration.

## Install without starting

Validate and install from the same elevated machine-wide interpreter:

```powershell
causure-windows-service install `
  C:\ProgramData\Causure\config\team-host.json
```

The command deliberately leaves the service stopped. It performs these steps:

1. requires a local-drive absolute, existing host-config path (not UNC/device storage);
2. strictly parses the host configuration and validates exact Waitress `3.0.2`;
3. computes the configuration's exact SHA-256 and byte count;
4. creates the fixed-name SCM service under its virtual account;
5. enables the service SID;
6. writes and verifies the bounded one-restart SCM recovery policy; and
7. writes one compact registry value containing schema version, canonical path, SHA-256,
   and byte count.

The one registry value is the complete service registration subject; it contains no token,
private key, password, or configuration body. If SID or registry setup fails after SCM
creation, installation attempts to remove the partial service. A failed rollback is
reported explicitly for administrator cleanup.

Use `--manual-start` when delayed automatic start is not desired:

```powershell
causure-windows-service install `
  C:\ProgramData\Causure\config\team-host.json `
  --manual-start
```

## Start, readiness, status, and stop

After provisioning Team access policy, ACLs, the reverse proxy, outbound Entra HTTPS, and
monitoring, start the service:

```powershell
causure-windows-service start
causure-windows-service status
```

SCM `running` is process state, not application readiness. The pywin32 host reports
running before synchronous Entra refresh and loopback binding finish so SCM does not apply
its short startup timeout to tenant discovery/JWKS work. Route traffic only after
`/readyz` succeeds through the trusted edge. Monitor `/readyz` continuously; `/healthz`
alone does not prove usable trust or storage.

Stop with:

```powershell
causure-windows-service stop
```

The control handler closes the loopback listener, waits up to five seconds for active
Waitress tasks while cancelling queued work, closes remaining channels, and requests up
to 30 seconds for managed Entra refresh-worker shutdown. The management command waits up
to 45 seconds for SCM `stopped`. Stop during a many-tenant synchronous startup refresh can
take longer because individual HTTPS operations are bounded but the whole tenant sequence
is not currently cancellable. If the command times out, inspect status and Event Viewer;
do not immediately force-kill a process that is still completing bounded cleanup.

Lifecycle messages go to the Windows Application event log through pywin32. Failure
messages include a bounded stable error code or exception class, never the exception text,
configuration path, token, or request body. The service suppresses original exception
context before propagating its sanitized non-zero failure to `pythonservice.exe`. The
trusted edge still owns access logging and must redact `Authorization` everywhere.

## Deliberate configuration updates

Editing `team-host.json` in place without updating SCM registration makes the next service
start fail closed, even if the new JSON is otherwise valid. Apply an intentional change as
one stopped-service workflow:

```powershell
causure-windows-service stop

# Replace and review the protected host configuration here.

causure-windows-service configure `
  C:\ProgramData\Causure\config\team-host.json
causure-windows-service start
```

`configure` refuses to run unless SCM reports the service stopped, revalidates the exact
host and Waitress contract, and atomically replaces the single registry subject value.
This prevents ordinary unnoticed config drift; an administrator able to rewrite both HKLM
service state and protected files remains trusted.

## Removal and recovery policy

Removal is explicit and non-destructive:

```powershell
causure-windows-service stop
causure-windows-service remove
```

`remove` never stops a running service implicitly and never deletes operator
configuration, the Entra trust snapshot, SQLite data, backups, or Event Log records. It
first disables the already stopped service so an SCM recovery action queued before removal
cannot restart it. If deletion fails, it restores the prior start mode or reports an
explicit rollback failure. SCM may retain a service marked for deletion until all handles
close or the host restarts. Archive or delete data only under a separate
retention-approved procedure.

Install applies an exact policy that resets the failure count after 900 seconds, restarts
once after 120 seconds, then takes no further action. Non-crash failures are enabled; no
command or reboot action is allowed. Inspect or reapply it while stopped:

```powershell
causure-windows-service recovery-status
causure-windows-service recovery-set
```

The commands return a closed JSON description without recovery command or reboot-message
values. Microsoft documents that a changed non-crash-failure flag takes effect after the
next system start, so cold boot remains required before production reliance. Continue to
test missing network, last-known-good trust, port collision, key rollover, stop during
refresh, service-account ACL denial, backup/restore, edge health gating, and uninstall on
the exact target Windows version.

## Live isolated qualification

The repository's unit suite does not register a service or mutate HKLM. It uses fake
SCM/registry modules plus an actual ephemeral-loopback Waitress stop test. The explicit
[Windows service qualification harness](../scripts/qualify_windows_service.ps1) is a
separate elevated operation for an isolated Windows host:

```powershell
pwsh -File .\scripts\qualify_windows_service.ps1 `
  -SourcePythonRoot C:\Path\To\CPython `
  -WheelPath .\dist\causure-0.4.0a15-py3-none-any.whl `
  -ReportPath C:\SafeReports\causure-windows-service.json
```

The harness refuses to run if the fixed service or
`C:\ProgramData\CausureQualification` already exists. It copies the supplied
runtime into that disposable machine path, installs the exact wheel there, derives and
checks the package's dependency contracts, generates non-secret loopback-only policy,
and uses public Microsoft tenant metadata solely to prove outbound discovery/key refresh.
It creates a manual-start service, applies least-privilege test ACLs, verifies the virtual
account, unrestricted service SID, image path, and exact HKLM subject, then requires SCM
running, `/healthz` 200, `/readyz` 200, graceful stop, and adapter removal. Its `finally`
path attempts service cleanup before deleting only the fixed directory it created. The
report is written outside that directory and contains no token or configuration body.

On 2026-08-03, wheel SHA-256
`905ec3c0ab439fcf232564b98a01c97f18a1bd84e38b374f6ad2d910762f3e42`
was qualified on Windows 11 Pro build 26200 with CPython `3.13.5`, pywin32 `312`, and
Waitress `3.0.2`. The fixed service reached SCM running and both loopback probes returned
200; controlled stop, adapter removal, service absence, and qualification-root removal
all passed. The sanitized machine-readable record is committed as
[Windows service qualification evidence](qualifications/windows-service-2026-08-03.json).

This establishes one development-host SCM lifecycle result, not signed provenance or
production certification. It does not qualify cold boot, recovery actions, a real company
Entra app/token, the trusted HTTPS edge, proxy/redaction behavior, domain egress policy,
target-host hardening, backup/restore, or a signed installer. Repeat the harness and the
broader failure matrix on every supported deployment image before production use.

The a15 [bundle qualification harness](../scripts/qualify_windows_service_bundle.ps1)
separately exercises the closed ZIP, versioned Program Files runtime, protected receipt,
exact recovery policy, real delayed crash restart, configuration drift, port collision,
readiness restoration, retry-safe removal, and operator-path preservation. See the
[bundle guide](windows-service-bundle.md) for its invocation and the still-separate
cold-boot authorization boundary.

The exact a15 bundle passed that self-cleaning harness on 2026-08-09. Its byte-identical
rebuilds, 121.69-second real crash recovery, bounded adversarial failures, recovery-policy
restoration, running-service removal, operator ACL restoration, and complete managed-state
cleanup are recorded in the committed
[bundle qualification evidence](qualifications/windows-service-bundle-2026-08-09.json).
