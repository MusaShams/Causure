[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$CasePath,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$TfvcServerPath,

    [string]$PolicyPath,

    [int[]]$WorkItemId = @(),

    [string]$PythonCommand = "python",

    [string]$OutputDirectory,

    [ValidateRange(1, 86400)]
    [int]$MaximumPublicationAgeSeconds = 3600
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$sourcePath = Join-Path $projectRoot "src"

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

if ($env:TF_BUILD -ne "True") {
    throw "azure_review_gate.ps1 must run on an Azure Pipelines agent (TF_BUILD=True)."
}

if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    if ([string]::IsNullOrWhiteSpace($env:BUILD_ARTIFACTSTAGINGDIRECTORY)) {
        throw "BUILD_ARTIFACTSTAGINGDIRECTORY is required when -OutputDirectory is omitted."
    }
    $OutputDirectory = Join-Path $env:BUILD_ARTIFACTSTAGINGDIRECTORY "causure"
}

$resolvedCasePath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
    $CasePath
)
if (-not (Test-Path -LiteralPath $resolvedCasePath -PathType Leaf)) {
    throw "The change case does not exist: $resolvedCasePath"
}

$resolvedPolicyPath = $null
if (-not [string]::IsNullOrWhiteSpace($PolicyPath)) {
    $resolvedPolicyPath = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath(
        $PolicyPath
    )
    if (-not (Test-Path -LiteralPath $resolvedPolicyPath -PathType Leaf)) {
        throw "The policy override does not exist: $resolvedPolicyPath"
    }
}

$resolvedOutputDirectory = (
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDirectory)
)
New-Item -ItemType Directory -Force -Path $resolvedOutputDirectory | Out-Null

$resultPath = Join-Path $resolvedOutputDirectory "causure-result.json"
$reportPath = Join-Path $resolvedOutputDirectory "causure-report.md"
$publicationPath = Join-Path $resolvedOutputDirectory "causure-azure-publication.json"
$verificationPath = Join-Path $resolvedOutputDirectory "causure-azure-verification.json"
$summaryPath = Join-Path $resolvedOutputDirectory "causure-azure-summary.md"

$inputPaths = @($resolvedCasePath)
if ($null -ne $resolvedPolicyPath) {
    $inputPaths += $resolvedPolicyPath
}
foreach ($outputPath in @(
    $resultPath,
    $reportPath,
    $publicationPath,
    $verificationPath,
    $summaryPath
)) {
    foreach ($inputPath in $inputPaths) {
        if ($outputPath.Equals($inputPath, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Gate output paths must not overwrite the change case or policy."
        }
    }
}

$env:PYTHONPATH = $sourcePath

$reviewArguments = [System.Collections.Generic.List[string]]::new()
$reviewArguments.Add("-m")
$reviewArguments.Add("causure")
$reviewArguments.Add("review")
$reviewArguments.Add($resolvedCasePath)
if ($null -ne $resolvedPolicyPath) {
    $reviewArguments.Add("--policy")
    $reviewArguments.Add($resolvedPolicyPath)
}
$reviewArguments.Add("--output")
$reviewArguments.Add($reportPath)
$reviewArguments.Add("--result-output")
$reviewArguments.Add($resultPath)
$reviewArguments.Add("--quiet")

& $PythonCommand @reviewArguments
$reviewExitCode = $LASTEXITCODE
if ($reviewExitCode -notin @(0, 1)) {
    throw "Causure review failed with configuration exit code $reviewExitCode."
}

$publicationArguments = [System.Collections.Generic.List[string]]::new()
$publicationArguments.Add("-m")
$publicationArguments.Add("causure")
$publicationArguments.Add("azure-publish")
$publicationArguments.Add($resultPath)
$publicationArguments.Add($reportPath)
$publicationArguments.Add("--tfvc-server-path")
$publicationArguments.Add($TfvcServerPath)
foreach ($id in ($WorkItemId | Sort-Object -Unique)) {
    $publicationArguments.Add("--work-item-id")
    $publicationArguments.Add($id.ToString([Globalization.CultureInfo]::InvariantCulture))
}
$publicationArguments.Add("--output")
$publicationArguments.Add($publicationPath)
$publicationArguments.Add("--quiet")
Invoke-Checked $PythonCommand @publicationArguments

Invoke-Checked $PythonCommand -m causure azure-verify `
    $publicationPath `
    $resultPath `
    $reportPath `
    --tfvc-server-path $TfvcServerPath `
    --maximum-age-seconds $MaximumPublicationAgeSeconds `
    --output $verificationPath `
    --summary-output $summaryPath `
    --quiet

$decision = (Get-Content -LiteralPath $resultPath -Raw | ConvertFrom-Json).decision

Write-Host "##vso[task.setvariable variable=CausureResult]$resultPath"
Write-Host "##vso[task.setvariable variable=CausureReport]$reportPath"
Write-Host "##vso[task.setvariable variable=CausureAzurePublication]$publicationPath"
Write-Host "##vso[task.setvariable variable=CausureAzureVerification]$verificationPath"
Write-Host "##vso[task.uploadsummary]$summaryPath"

foreach ($artifactPath in @(
    $resultPath,
    $reportPath,
    $publicationPath,
    $verificationPath,
    $summaryPath
)) {
    Write-Host (
        "##vso[artifact.upload containerfolder=causure;" +
        "artifactname=Causure]$artifactPath"
    )
}

if ($reviewExitCode -ne 0) {
    Write-Host (
        "##vso[task.logissue type=error;code=CAUSURE_GATE_DECISION;]" +
        "Causure returned decision '$decision'."
    )
    exit $reviewExitCode
}

Write-Host "Causure Azure TFVC gate passed with decision '$decision'."
