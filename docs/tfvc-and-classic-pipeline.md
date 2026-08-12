# TFVC and Azure Classic Pipeline setup

This guide uses the following public-safe placeholder for the authoritative project:

```text
https://dev.azure.com/YOUR_AZURE_DEVOPS_ORGANIZATION/ProofBeforePatch
```

Replace `YOUR_AZURE_DEVOPS_ORGANIZATION` locally with the organization that owns the TFVC
project. Do not commit a personal machine path or a private organization identifier merely
to make these examples copyable.

TFVC must be mapped through a local workspace before files can be added or checked in. Use
the Visual Studio 2026 Developer PowerShell or the installed `TF.exe`.

## One-time authentication

Sign into the intended organization through Visual Studio's Team Explorer / Manage
Connections flow. Opening the project in Source Control Explorer is a useful confirmation
that the IDE account can see TFVC. Do not put a personal access token in a command file,
environment file, evidence bundle, or chat transcript.

Discover the current `TF.exe` rather than pinning a Visual Studio edition path:

```powershell
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
$visualStudio = & $vswhere -latest -products * -property installationPath
$tf = Join-Path $visualStudio `
  "Common7\IDE\CommonExtensions\Microsoft\TeamFoundation\Team Explorer\TF.exe"

if (-not (Test-Path -LiteralPath $tf)) {
    throw "TF.exe was not found. Install the Azure DevOps/Team Explorer components."
}
```

For the first CLI authentication, allow the command to open its sign-in dialog:

```powershell
$collection = "https://dev.azure.com/YOUR_AZURE_DEVOPS_ORGANIZATION"

& $tf workspaces `
  /collection:$collection `
  /owner:* `
  /computer:* `
  /format:detailed
```

Do **not** add `/noprompt` to this first command. That switch suppresses the interactive
authentication flow and can make a valid Visual Studio sign-in look like a CLI credential
failure. After the command succeeds once and credentials are cached, use `/noprompt` for
automation:

```powershell
$collection = "https://dev.azure.com/YOUR_AZURE_DEVOPS_ORGANIZATION"

& $tf workspaces `
  /collection:$collection `
  /owner:* `
  /computer:* `
  /format:detailed `
  /noprompt
```

## Workspace mapping

First confirm the server path in Source Control Explorer. A new TFVC team project normally
uses `$/ProofBeforePatch`, but do not create a second root if the project already has a
different path.

Create one local workspace and map the existing project folder:

```powershell
$collection = "https://dev.azure.com/YOUR_AZURE_DEVOPS_ORGANIZATION"
$serverPath = "$/ProofBeforePatch"
$localPath = "C:\src\ProofBeforePatch"
$workspace = "Causure-$env:COMPUTERNAME"

& $tf workspace /new /location:local /collection:$collection $workspace
& $tf workfold /map $serverPath $localPath /workspace:$workspace /collection:$collection
& $tf get $localPath /recursive /noprompt
```

If the server already contains files, review `tf get` results before allowing it to merge
with local work.

## Add and inspect pending changes

The root `.tfignore` prevents local Git metadata, environments, caches, and build artifacts
from being added.

```powershell
& $tf add $localPath /recursive /noprompt
& $tf status $localPath /recursive /format:detailed /noprompt
```

Review the pending-change list before check-in. In particular, `.git`, `.venv`, caches,
reports, and `dist` must not appear.

## Check in

Run the full local validation first:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\classic_ci.ps1
```

Then check in the reviewed pending changes:

```powershell
& $tf checkin $localPath `
  /recursive `
  /comment:"Describe the reviewed Causure change" `
  /noprompt
```

If check-in policies require a gated build, use the Visual Studio Pending Changes window so
the required shelveset and policy flow remain visible.

## Azure Classic Pipeline

Azure Pipelines supports TFVC only through the Classic pipeline editor, not repository YAML.
Create an empty Classic build and configure:

1. **Source:** Azure Repos TFVC.
2. **Workspace mapping:** map only the Causure project root.
3. **Agent:** a hosted Windows agent with Python 3.11 or newer.
4. **PowerShell validation task:** run `.\scripts\classic_ci.ps1`.
5. **PowerShell gate task:** run `.\scripts\azure_review_gate.ps1` against the real change
   case and protected TFVC root.
6. **Publish Build Artifacts task:** optionally publish
   `$(Build.SourcesDirectory)\dist` for the validation wheel and smoke artifacts. The gate
   task publishes its own named `Causure` artifact.
7. **Trigger:** enable continuous integration; enable gated check-in when the project is
   ready to require it.

Install the development extra before the build script so the full suite covers the optional
attestation and approval-signature boundaries plus pinned lint configuration:

```powershell
python -m pip install -e ".[dev]"
```

The script still emits an explicit warning rather than silently claiming lint ran when Ruff
is unavailable. Attestation and approval tests require the pinned `cryptography`
dependency from the development extra; core collection and review installs remain
dependency-free. Sandbox
tests validate policy parsing, worker scheduling, generated Docker arguments, scripted
preflight responses, quota ordering, and cancellation through deterministic fakes. They do
not require or certify a live Docker daemon.

The PowerShell step exposes the result, report, trace manifest, and draft fixture paths as
`CausureResult`, `CausureReport`, `CausureTraceManifest`, and
`CausureInvestigationFixture` task variables. Publishing the entire `dist`
directory retains all four artifacts together with the wheel.

The validation script intentionally reviews a synthetic approved case as a smoke test. It
is not the production gate. Configure the next task with a real evidence case:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\azure_review_gate.ps1 `
  -CasePath .\evidence\production-change.json `
  -TfvcServerPath '$/ProofBeforePatch' `
  -WorkItemId 17,93
```

The gate publishes a verified summary and exact JSON/Markdown artifacts for either the
triggering changeset or gated shelveset, then returns the review exit status. A non-approval
therefore remains visible and downloadable while still failing the task. See the
[Azure DevOps TFVC review-gate guide](azure-devops-review-gate.md) for the source-variable
cross-checks, artifact contract, optional policy argument, and trust boundary.

## Optional independent approval stage

The real-case gate produces the publication and pre-approval receipt that an independent
organizational authority needs. Keep approval issuance outside the build agent. The
authority authenticates and authorizes the human, signs the exact artifact subjects, and
returns a short-lived assertion.

A later protected task can run `verify-approval` with the assertion, original result,
report, publication, receipt, protected approval trust store, current revocations, and the
same `-TfvcServerPath` value. The command rechecks the current Azure/TFVC identity. It emits
a successful receipt for a valid exception but returns the original non-approval status;
it does not make a rejected gated check-in pass.

Do not use `Build.RequestedForId` or `System.AccessToken` as an approver identity. The first
identifies the requester and the second authenticates the build service. See
[authenticated approval assertions](approval-assertions.md) for the authority-side and
verifier commands, Azure approval API mapping, key/action policy, and exception rules.

## Optional live sandbox qualification stage

Do not add an unqualified `docker run` smoke test to the general build and then treat its
success as production isolation proof. Create a separate protected agent pool and stage for
the intended Linux/Docker deployment.

Pin the exact worker repository digest and record the Docker server version, Linux kernel,
sandbox policy, proxy image digest, and quota backend in the test artifact. The stage should
prove at minimum:

1. The worker cannot write outside its bounded temporary filesystem or access a host mount.
2. Offline policy cannot reach the host, internet, provider, or another container.
3. Connected policy can reach only the TLS quota proxy and cannot bypass it.
4. CPU, memory, PID, output, and wall-clock overruns fail with the expected stable code.
5. Timeout and peer failure remove active containers and suppress queued launches.
6. The proxy rejects an invalid/revoked lease and enforces operation, concurrency, and cost
   limits before forwarding.
7. Authoritative settlement and cancellation remain correct when the worker crashes or the
   provider is unavailable.

Keep Docker administration, network mutation, quota policy, and provider credentials
outside the worker and producer identities. A live stage qualifies only the recorded
combination; rerun it after engine, kernel, image, proxy, or provider-policy changes.

## Optional attested-evidence stage

When a protected producer supplies a detached attestation, verify it before the `review`
command in the same job:

```powershell
causure verify-attestation .\evidence.json `
  .\evidence.attestation.json `
  --trust-store .\policy\attestation-trust-store.json `
  --revocations .\policy\attestation-revocations.json `
  --output .\dist\attestation-verification.json

causure review .\evidence.json `
  --output .\dist\causure-report.md `
  --result-output .\dist\causure-result.json
```

Protect the pipeline definition and both policy documents from producer modification. Keep
the producer's private key out of the verifier job. Refresh the complete revocation list
through an authenticated process; changing `updated_at` without refreshing key status
defeats the freshness control.
