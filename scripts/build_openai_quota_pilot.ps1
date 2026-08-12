[CmdletBinding()]
param(
    [ValidateNotNullOrEmpty()]
    [string]$PythonCommand = "python",

    [ValidateNotNullOrEmpty()]
    [string]$DockerCommand = "docker",

    [string]$WaitressWheelPath,

    [ValidatePattern("^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+$")]
    [string]$CoreImageTag = "causure/openai-quota-pilot:0.4.0a18-local",

    [ValidatePattern("^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9._-]+$")]
    [string]$EdgeImageTag = "causure/openai-quota-edge:2.11.4-causure1-local"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$PSNativeCommandUseErrorActionPreference = $false

$packageVersion = "0.4.0a18"
$waitressVersion = "3.0.2"
$waitressByteCount = 56232
$waitressSha256 = "c56d67fd6e87c2ee598b76abdd4e96cfad1f24cacdea5078d382b1f9d7b5ed2e"
$projectRoot = Split-Path -Parent $PSScriptRoot
$buildRoot = Join-Path $projectRoot "build"
$wheelRoot = Join-Path $buildRoot "quota-pilot\wheels"
$distRoot = Join-Path $projectRoot "dist"
$expectedWaitressWheel = Join-Path $wheelRoot "waitress-3.0.2-py3-none-any.whl"
$packageWheel = Join-Path $distRoot "causure-0.4.0a18-py3-none-any.whl"
$coreDockerfile = Join-Path $projectRoot "deploy\openai-quota-pilot\Dockerfile"
$edgeDockerfile = Join-Path $projectRoot "deploy\openai-quota-pilot\Dockerfile.edge"
$temporaryWheelRoot = Join-Path $buildRoot ("quota-pilot-wheel-" + [Guid]::NewGuid().ToString("N"))

function Invoke-CheckedNative {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Executable,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments,

        [Parameter(Mandatory = $true)]
        [string]$Operation
    )

    $output = @(& $Executable @Arguments 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw [InvalidOperationException]::new(
            "$Operation failed with exit code $LASTEXITCODE"
        )
    }
    return ($output -join "`n")
}

function Assert-ExactFile {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [long]$ByteCount,

        [Parameter(Mandatory = $true)]
        [string]$Sha256,

        [Parameter(Mandatory = $true)]
        [string]$Description
    )

    $item = Get-Item -LiteralPath $Path -ErrorAction Stop
    if (-not $item.PSIsContainer -and $item.Length -eq $ByteCount) {
        $actualHash = (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actualHash -eq $Sha256) {
            return
        }
    }
    throw [InvalidOperationException]::new("$Description does not match its exact lock")
}

try {
    if ([string]::IsNullOrWhiteSpace($WaitressWheelPath)) {
        $WaitressWheelPath = $expectedWaitressWheel
    }
    $resolvedWaitressWheel = (Resolve-Path -LiteralPath $WaitressWheelPath).Path
    Assert-ExactFile `
        -Path $resolvedWaitressWheel `
        -ByteCount $waitressByteCount `
        -Sha256 $waitressSha256 `
        -Description "Waitress wheel"

    New-Item -ItemType Directory -Force -Path $buildRoot, $wheelRoot, $distRoot | Out-Null
    New-Item -ItemType Directory -Path $temporaryWheelRoot | Out-Null

    $setuptoolsVersion = Invoke-CheckedNative `
        -Executable $PythonCommand `
        -Arguments @(
            "-c",
            "import importlib.metadata as m; print(m.version('setuptools'))"
        ) `
        -Operation "setuptools version check"
    if ($setuptoolsVersion.Trim() -ne "83.0.0") {
        throw [InvalidOperationException]::new(
            "offline pilot build requires exact setuptools 83.0.0"
        )
    }

    $null = Invoke-CheckedNative `
        -Executable $PythonCommand `
        -Arguments @(
            "-m",
            "pip",
            "wheel",
            $projectRoot,
            "--no-deps",
            "--no-build-isolation",
            "--no-cache-dir",
            "--no-index",
            "--wheel-dir",
            $temporaryWheelRoot
        ) `
        -Operation "offline Causure wheel build"
    $builtWheel = Join-Path $temporaryWheelRoot "causure-$packageVersion-py3-none-any.whl"
    if (-not (Test-Path -LiteralPath $builtWheel -PathType Leaf)) {
        throw [InvalidOperationException]::new("offline build did not produce the exact package wheel")
    }
    Copy-Item -LiteralPath $builtWheel -Destination $packageWheel -Force

    if (
        -not [IO.Path]::GetFullPath($resolvedWaitressWheel).Equals(
            [IO.Path]::GetFullPath($expectedWaitressWheel),
            [StringComparison]::OrdinalIgnoreCase
        )
    ) {
        Copy-Item -LiteralPath $resolvedWaitressWheel -Destination $expectedWaitressWheel -Force
    }
    Assert-ExactFile `
        -Path $expectedWaitressWheel `
        -ByteCount $waitressByteCount `
        -Sha256 $waitressSha256 `
        -Description "staged Waitress wheel"

    $packageWheelSha256 = (
        Get-FileHash -LiteralPath $packageWheel -Algorithm SHA256
    ).Hash.ToLowerInvariant()

    $null = Invoke-CheckedNative `
        -Executable $DockerCommand `
        -Arguments @("version", "--format", "{{.Server.Version}}") `
        -Operation "Docker engine preflight"
    $null = Invoke-CheckedNative `
        -Executable $DockerCommand `
        -Arguments @(
            "build",
            "--network",
            "none",
            "--provenance=false",
            "--build-arg",
            "CAUSURE_WHEEL_SHA256=$packageWheelSha256",
            "--file",
            $coreDockerfile,
            "--tag",
            $CoreImageTag,
            $projectRoot
        ) `
        -Operation "network-disabled quota-core image build"
    $null = Invoke-CheckedNative `
        -Executable $DockerCommand `
        -Arguments @(
            "build",
            "--network",
            "none",
            "--provenance=false",
            "--file",
            $edgeDockerfile,
            "--tag",
            $EdgeImageTag,
            $projectRoot
        ) `
        -Operation "network-disabled quota-edge image build"

    $coreImageId = (
        Invoke-CheckedNative `
            -Executable $DockerCommand `
            -Arguments @("image", "inspect", "--format", "{{.Id}}", $CoreImageTag) `
            -Operation "quota-core image inspection"
    ).Trim()
    $edgeImageId = (
        Invoke-CheckedNative `
            -Executable $DockerCommand `
            -Arguments @("image", "inspect", "--format", "{{.Id}}", $EdgeImageTag) `
            -Operation "quota-edge image inspection"
    ).Trim()
    foreach ($imageId in @($coreImageId, $edgeImageId)) {
        if ($imageId -notmatch '^sha256:[a-f0-9]{64}$') {
            throw [InvalidOperationException]::new("Docker returned a non-content-addressed image ID")
        }
    }

    [ordered]@{
        schema_version = "1.0"
        package_version = $packageVersion
        package_wheel = [ordered]@{
            path = $packageWheel
            sha256 = $packageWheelSha256
        }
        waitress_wheel = [ordered]@{
            version = $waitressVersion
            byte_count = $waitressByteCount
            sha256 = $waitressSha256
        }
        images = [ordered]@{
            quota_core = [ordered]@{
                tag = $CoreImageTag
                id = $coreImageId
            }
            quota_edge = [ordered]@{
                tag = $EdgeImageTag
                id = $edgeImageId
            }
        }
        compose_environment = [ordered]@{
            CAUSURE_QUOTA_CORE_IMAGE = $coreImageId
            CAUSURE_QUOTA_EDGE_IMAGE = $edgeImageId
        }
        build_network = "none"
        provenance_attestation = $false
    } | ConvertTo-Json -Depth 6
}
finally {
    if (Test-Path -LiteralPath $temporaryWheelRoot) {
        $resolvedBuildRoot = [IO.Path]::GetFullPath($buildRoot).TrimEnd(
            [IO.Path]::DirectorySeparatorChar
        ) + [IO.Path]::DirectorySeparatorChar
        $resolvedTemporaryRoot = [IO.Path]::GetFullPath($temporaryWheelRoot)
        if (-not $resolvedTemporaryRoot.StartsWith(
            $resolvedBuildRoot,
            [StringComparison]::OrdinalIgnoreCase
        )) {
            throw [InvalidOperationException]::new("temporary wheel path escaped the build root")
        }
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
