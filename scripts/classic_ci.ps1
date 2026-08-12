[CmdletBinding()]
param(
    [string]$PythonCommand = "python",
    [switch]$SkipPackageBuild
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $projectRoot "src"
$approvedCase = Join-Path $projectRoot "examples\change-cases\approve-refund-tool-description.json"
$rejectedCase = Join-Path $projectRoot "examples\change-cases\reject-overbroad-prompt.json"
$traceSource = Join-Path $projectRoot "examples\traces\refund-openinference-otlp.json"
$teamPolicySource = Join-Path $projectRoot "examples\team\acme-access-policy.json"
$teamPayloadSource = Join-Path $projectRoot "examples\team\investigation-action.json"
$buildDirectory = Join-Path $projectRoot "build"
$bytecodeCache = Join-Path $buildDirectory "pycache"
$artifactDirectory = Join-Path $projectRoot "dist"
$resultPath = Join-Path $artifactDirectory "causure-result.json"
$reportPath = Join-Path $artifactDirectory "causure-report.md"
$rejectionResultPath = Join-Path $artifactDirectory "causure-rejection-example.json"
$traceManifestPath = Join-Path $artifactDirectory "causure-trace-manifest.json"
$investigationFixturePath = Join-Path $artifactDirectory "causure-investigation-fixture.json"
$teamAuthorizationPath = Join-Path $artifactDirectory "causure-team-authorization.json"
$teamAuditEventPath = Join-Path $artifactDirectory "causure-team-audit-event.json"
$teamExportAuthorizationPath = Join-Path $artifactDirectory "causure-team-export-authorization.json"
$teamAuditExportPath = Join-Path $artifactDirectory "causure-team-audit-export.json"
$teamAuditVerificationPath = Join-Path $artifactDirectory "causure-team-audit-verification.json"
$teamStorePath = Join-Path $buildDirectory "causure-team-store.sqlite3"
$teamStoreBackupPath = Join-Path $buildDirectory "causure-team-store-backup.sqlite3"
$teamStoreEmptyHeadPath = Join-Path $artifactDirectory "causure-team-store-empty-head.json"
$teamStoreHeadPath = Join-Path $artifactDirectory "causure-team-store-head.json"
$teamStoreBackupHeadPath = Join-Path $artifactDirectory "causure-team-store-backup-head.json"
$teamStoredPolicyPath = Join-Path $artifactDirectory "causure-team-stored-policy.json"
$teamStoredEventPath = Join-Path $artifactDirectory "causure-team-stored-event.json"
$teamStoredAuditExportPath = Join-Path $artifactDirectory "causure-team-stored-export.json"
$teamStoredAuditVerificationPath = Join-Path $artifactDirectory "causure-team-stored-verification.json"

function Invoke-Checked {
    param(
        [Parameter(Mandatory)]
        [string]$Executable,
        [Parameter(ValueFromRemainingArguments)]
        [string[]]$Arguments
    )

    & $Executable @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Command failed with exit code $LASTEXITCODE`: $Executable $Arguments"
    }
}

New-Item -ItemType Directory -Force -Path $bytecodeCache | Out-Null
foreach ($generatedStorePath in @(
    $teamStorePath,
    "${teamStorePath}-wal",
    "${teamStorePath}-shm",
    $teamStoreBackupPath,
    "${teamStoreBackupPath}-wal",
    "${teamStoreBackupPath}-shm"
)) {
    Remove-Item -LiteralPath $generatedStorePath -Force -ErrorAction SilentlyContinue
}
$env:PYTHONPATH = $sourcePath
$env:PYTHONPYCACHEPREFIX = $bytecodeCache

Invoke-Checked $PythonCommand -c "import cryptography; assert cryptography.__version__ == '50.0.0', cryptography.__version__"
Invoke-Checked $PythonCommand -c "import importlib.metadata; assert importlib.metadata.version('waitress') == '3.0.2'"
if ($env:OS -eq "Windows_NT") {
    Invoke-Checked $PythonCommand -c "import importlib.metadata; assert importlib.metadata.version('pywin32') == '312'"

    $checkedPowerShellScripts = @(
        "qualify_windows_service.ps1",
        "build_openai_quota_pilot.ps1",
        "qualify_openai_quota_pilot.ps1"
    )
    foreach ($checkedPowerShellScript in $checkedPowerShellScripts) {
        $scriptPath = Join-Path $PSScriptRoot $checkedPowerShellScript
        $scriptTokens = $null
        $scriptErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile(
            $scriptPath,
            [ref]$scriptTokens,
            [ref]$scriptErrors
        )
        if ($scriptErrors.Count -ne 0) {
            throw "$checkedPowerShellScript has PowerShell parse errors."
        }
    }
}
Invoke-Checked $PythonCommand -m compileall -q $sourcePath
Invoke-Checked $PythonCommand -m unittest discover -s (Join-Path $projectRoot "tests") -v
Invoke-Checked $PythonCommand (Join-Path $PSScriptRoot "check_public_release.py")
Invoke-Checked $PythonCommand -m causure validate $approvedCase

New-Item -ItemType Directory -Force -Path $artifactDirectory | Out-Null
Invoke-Checked $PythonCommand -m causure collect $traceSource --source-id refund-openinference-fixture --output $traceManifestPath --quiet
$traceManifest = Get-Content -LiteralPath $traceManifestPath -Raw | ConvertFrom-Json
if ($traceManifest.source.span_count -ne 2 -or $traceManifest.redaction.raw_content_included) {
    throw "The trace collector smoke test produced an unsafe or unexpected manifest."
}

Invoke-Checked $PythonCommand -m causure fixture $traceManifestPath --fixture-id refund-investigation-fixture --output $investigationFixturePath --quiet
$investigationFixture = Get-Content -LiteralPath $investigationFixturePath -Raw | ConvertFrom-Json
if (
    -not $investigationFixture.draft_only `
    -or $investigationFixture.gate_eligible `
    -or $investigationFixture.causal_claims_inferred `
    -or $investigationFixture.candidate_clusters.Count -ne 1
) {
    throw "The investigation fixture smoke test produced an unsafe or unexpected draft."
}

$teamBaseTime = [DateTime]::UtcNow.AddMinutes(-4)
$teamDecisionTime = $teamBaseTime.ToString("yyyy-MM-ddTHH:mm:ssZ")
$teamEventTime = $teamBaseTime.AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ssZ")
$teamExportDecisionTime = $teamBaseTime.AddMinutes(2).ToString("yyyy-MM-ddTHH:mm:ssZ")
$teamExportTime = $teamBaseTime.AddMinutes(3).ToString("yyyy-MM-ddTHH:mm:ssZ")

Invoke-Checked $PythonCommand -m causure team-authorize $teamPolicySource --decision-id team-ci-action-1 --identity-provider entra:example --subject-id investigator-demo --action investigation_write --resource-type investigation --resource-id investigation-demo-1 --decided-at $teamDecisionTime --output $teamAuthorizationPath --quiet
Invoke-Checked $PythonCommand -m causure team-audit-append $teamPolicySource $teamAuthorizationPath $teamPayloadSource --payload-media-type application/json --event-id team-ci-event-1 --outcome succeeded --occurred-at $teamEventTime --output $teamAuditEventPath --quiet
$teamAuditHead = (Get-Content -LiteralPath $teamAuditEventPath -Raw | ConvertFrom-Json).event_sha256
Invoke-Checked $PythonCommand -m causure team-authorize $teamPolicySource --decision-id team-ci-export-1 --identity-provider entra:example --subject-id policy-admin-demo --action audit_export --resource-type audit_export --resource-id team-ci-export-1 --decided-at $teamExportDecisionTime --output $teamExportAuthorizationPath --quiet
Invoke-Checked $PythonCommand -m causure team-audit-export $teamPolicySource $teamExportAuthorizationPath $teamAuditEventPath --export-id team-ci-export-1 --authoritative-head-sha256 $teamAuditHead --created-at $teamExportTime --output $teamAuditExportPath --quiet
Invoke-Checked $PythonCommand -m causure team-audit-verify $teamPolicySource $teamAuditExportPath --output $teamAuditVerificationPath --quiet
$teamAuditVerification = Get-Content -LiteralPath $teamAuditVerificationPath -Raw | ConvertFrom-Json
if (
    $teamAuditVerification.status -ne "verified" `
    -or $teamAuditVerification.tenant_id -ne "tenant-acme-demo" `
    -or $teamAuditVerification.audit_range.event_count -ne 1
) {
    throw "The Team authorization/audit smoke test produced an invalid verification."
}

Invoke-Checked $PythonCommand -m causure team-store-init $teamStorePath
Invoke-Checked $PythonCommand -m causure team-store-policy-put $teamStorePath $teamPolicySource
Invoke-Checked $PythonCommand -m causure team-store-head $teamStorePath --tenant-id tenant-acme-demo --output $teamStoreEmptyHeadPath --quiet
$teamStoreEmptyHead = Get-Content -LiteralPath $teamStoreEmptyHeadPath -Raw | ConvertFrom-Json
if ($teamStoreEmptyHead.sequence -ne 0 -or $null -ne $teamStoreEmptyHead.event_sha256) {
    throw "The initialized Team store did not return an empty tenant head."
}
Invoke-Checked $PythonCommand -m causure team-store-append $teamStorePath $teamAuditEventPath --expect-empty --output $teamStoreHeadPath --quiet
$teamStoreHead = Get-Content -LiteralPath $teamStoreHeadPath -Raw | ConvertFrom-Json
if ($teamStoreHead.sequence -ne 1 -or $teamStoreHead.event_sha256 -ne $teamAuditHead) {
    throw "The Team store append did not atomically advance to the expected event."
}
Invoke-Checked $PythonCommand -m causure team-store-event-get $teamStorePath --tenant-id tenant-acme-demo --sequence 1 --output $teamStoredEventPath --quiet
if (
    (Get-FileHash -LiteralPath $teamAuditEventPath -Algorithm SHA256).Hash `
    -ne (Get-FileHash -LiteralPath $teamStoredEventPath -Algorithm SHA256).Hash
) {
    throw "The Team store did not return the exact audit-event bytes."
}
$teamPolicySubject = (Get-Content -LiteralPath $teamAuthorizationPath -Raw | ConvertFrom-Json).policy
Invoke-Checked $PythonCommand -m causure team-store-policy-get $teamStorePath --tenant-id tenant-acme-demo --policy-id $teamPolicySubject.policy_id --revision $teamPolicySubject.revision --sha256 $teamPolicySubject.sha256 --byte-count $teamPolicySubject.byte_count --output $teamStoredPolicyPath --quiet
if (
    (Get-FileHash -LiteralPath $teamPolicySource -Algorithm SHA256).Hash `
    -ne (Get-FileHash -LiteralPath $teamStoredPolicyPath -Algorithm SHA256).Hash
) {
    throw "The Team store did not return the exact access-policy bytes."
}
Invoke-Checked $PythonCommand -m causure team-store-export $teamStorePath $teamExportAuthorizationPath --export-id team-ci-export-1 --created-at $teamExportTime --output $teamStoredAuditExportPath --quiet
Invoke-Checked $PythonCommand -m causure team-audit-verify $teamPolicySource $teamStoredAuditExportPath --output $teamStoredAuditVerificationPath --quiet
Invoke-Checked $PythonCommand -m causure team-store-backup $teamStorePath $teamStoreBackupPath
Invoke-Checked $PythonCommand -m causure team-store-head $teamStoreBackupPath --tenant-id tenant-acme-demo --output $teamStoreBackupHeadPath --quiet
$teamStoreBackupHead = Get-Content -LiteralPath $teamStoreBackupHeadPath -Raw | ConvertFrom-Json
if (
    $teamStoreBackupHead.sequence -ne $teamStoreHead.sequence `
    -or $teamStoreBackupHead.event_sha256 -ne $teamStoreHead.event_sha256
) {
    throw "The Team store online backup did not preserve the authoritative tenant head."
}

Invoke-Checked $PythonCommand -m causure review $approvedCase --format markdown --output $reportPath --result-output $resultPath

& $PythonCommand -m causure review $rejectedCase --format json --output $rejectionResultPath --quiet
if ($LASTEXITCODE -ne 1) {
    throw "The rejection example returned unexpected exit code $LASTEXITCODE; expected 1."
}
$rejectionDecision = (Get-Content -LiteralPath $rejectionResultPath -Raw | ConvertFrom-Json).decision
if ($rejectionDecision -ne "reject") {
    throw "The rejection example returned unexpected decision '$rejectionDecision'."
}

$ruff = Get-Command ruff -ErrorAction SilentlyContinue
if ($null -ne $ruff) {
    Invoke-Checked $ruff.Source check $projectRoot
    Invoke-Checked $ruff.Source format --check $projectRoot
}
else {
    Write-Warning "ruff is unavailable; install the pinned dev extra to run static linting."
}

if (-not $SkipPackageBuild) {
    $setuptoolsLibrary = Join-Path $buildDirectory "lib"
    $packageWheel = Join-Path $artifactDirectory "causure-0.4.0a18-py3-none-any.whl"
    Remove-Item -LiteralPath $setuptoolsLibrary -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $packageWheel -Force -ErrorAction SilentlyContinue
    Invoke-Checked $PythonCommand -m pip wheel $projectRoot --no-deps --wheel-dir $artifactDirectory
    if (-not (Test-Path -LiteralPath $packageWheel -PathType Leaf)) {
        throw "The expected Causure wheel was not created at $packageWheel."
    }
    Invoke-Checked $PythonCommand -c "import sys,zipfile; names=zipfile.ZipFile(sys.argv[1]).namelist(); legacy=''.join(('proof','before','patch')); assert 'causure/__init__.py' in names; assert not any(legacy in name.lower() for name in names)" $packageWheel
}

Write-Host "##vso[task.setvariable variable=CausureResult]$resultPath"
Write-Host "##vso[task.setvariable variable=CausureReport]$reportPath"
Write-Host "##vso[task.setvariable variable=CausureTraceManifest]$traceManifestPath"
Write-Host "##vso[task.setvariable variable=CausureInvestigationFixture]$investigationFixturePath"
Write-Host "##vso[task.setvariable variable=CausureTeamAuditExport]$teamAuditExportPath"
Write-Host "##vso[task.setvariable variable=CausureTeamAuditVerification]$teamAuditVerificationPath"
Write-Host "##vso[task.setvariable variable=CausureTeamStoredAuditExport]$teamStoredAuditExportPath"
Write-Host "##vso[task.setvariable variable=CausureTeamStoreBackup]$teamStoreBackupPath"
Write-Host "##vso[task.uploadsummary]$reportPath"
Write-Host "Causure CI checks passed."
