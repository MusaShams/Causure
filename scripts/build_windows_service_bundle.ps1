[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$SourcePythonRoot,

    [Parameter(Mandatory = $true)]
    [string]$WheelPath,

    [Parameter(Mandatory = $true)]
    [string]$WheelhousePath,

    [Parameter(Mandatory = $true)]
    [string]$PipWheelPath,

    [Parameter(Mandatory = $true)]
    [string]$OutputPath,

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$manifestSchemaVersion = "1.0"
$productName = "Causure Windows Team Service Bundle"
$supportedPipVersion = "26.1.2"
$fixedInstallBase = "C:\Program Files\Causure\Team"
$fixedReceiptPath = "C:\ProgramData\Causure\windows-service-installation.json"
$fixedServiceName = "CausureTeam"
$normalizedTimestamp = [DateTimeOffset]::new(2000, 1, 1, 0, 0, 0, [TimeSpan]::Zero)
$projectRoot = Split-Path -Parent $PSScriptRoot
$installerSource = Join-Path $PSScriptRoot "install_windows_service_bundle.ps1"
$removerSource = Join-Path $PSScriptRoot "remove_windows_service_bundle.ps1"

function Resolve-FixedLocalPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Leaf", "Container")]
        [string]$PathType
    )

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if (-not (Test-Path -LiteralPath $resolved -PathType $PathType)) {
        throw [IO.IOException]::new("required input path has the wrong type")
    }
    if ($resolved.StartsWith("\\", [StringComparison]::Ordinal)) {
        throw [IO.IOException]::new("bundle inputs must be on a local fixed drive")
    }
    $root = [IO.Path]::GetPathRoot($resolved)
    if ([string]::IsNullOrWhiteSpace($root)) {
        throw [IO.IOException]::new("bundle input has no local drive root")
    }
    $drive = [IO.DriveInfo]::new($root)
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw [IO.IOException]::new("bundle inputs must be on a local fixed drive")
    }
    return [IO.Path]::GetFullPath($resolved)
}

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
        throw [InvalidOperationException]::new("$Operation failed with exit code $LASTEXITCODE")
    }
    return ($output -join "`n")
}

function Copy-RuntimeDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Source,

        [Parameter(Mandatory = $true)]
        [string]$Destination
    )

    if (-not (Test-Path -LiteralPath $Source -PathType Container)) {
        return
    }
    $null = New-Item -ItemType Directory -Path $Destination
    $arguments = @(
        $Source,
        $Destination,
        "/E",
        "/COPY:DAT",
        "/DCOPY:DAT",
        "/R:1",
        "/W:1",
        "/NFL",
        "/NDL",
        "/NJH",
        "/NJS",
        "/NP",
        "/XD",
        "site-packages",
        "__pycache__",
        "/XF",
        "*.pyc",
        "*.pyo"
    )
    $null = & "$env:SystemRoot\System32\robocopy.exe" @arguments
    if ($LASTEXITCODE -gt 7) {
        throw [InvalidOperationException]::new(
            "runtime directory copy failed with exit code $LASTEXITCODE"
        )
    }
}

function Get-RelativeBundlePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $relative = [IO.Path]::GetRelativePath($Root, $Path).Replace("\", "/")
    if (
        [string]::IsNullOrWhiteSpace($relative) -or
        $relative.StartsWith("../", [StringComparison]::Ordinal) -or
        $relative.Contains(":") -or
        $relative.Contains("\")
    ) {
        throw [IO.IOException]::new("staged file escaped the bundle root")
    }
    return $relative
}

if (-not [Environment]::Is64BitOperatingSystem) {
    throw [PlatformNotSupportedException]::new("the pilot bundle supports 64-bit Windows only")
}
if (-not (Test-Path -LiteralPath $installerSource -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new("bundle installer source is missing")
}
if (-not (Test-Path -LiteralPath $removerSource -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new("bundle remover source is missing")
}

$sourceRoot = Resolve-FixedLocalPath -Path $SourcePythonRoot -PathType Container
$sourcePython = Join-Path $sourceRoot "python.exe"
if (-not (Test-Path -LiteralPath $sourcePython -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new("source Python root does not contain python.exe")
}
if (Get-ChildItem -LiteralPath $sourceRoot -Filter "python*._pth" -File) {
    throw [InvalidOperationException]::new(
        "an embeddable _pth runtime is not supported by this pilot bundle"
    )
}
$resolvedWheel = Resolve-FixedLocalPath -Path $WheelPath -PathType Leaf
if ([IO.Path]::GetExtension($resolvedWheel) -ne ".whl") {
    throw [IO.IOException]::new("Causure package input must be a wheel")
}
$resolvedWheelhouse = Resolve-FixedLocalPath -Path $WheelhousePath -PathType Container
$resolvedPipWheel = Resolve-FixedLocalPath -Path $PipWheelPath -PathType Leaf
if ([IO.Path]::GetExtension($resolvedPipWheel) -ne ".whl") {
    throw [IO.IOException]::new("pip build-tool input must be a wheel")
}

$resolvedOutput = [IO.Path]::GetFullPath($OutputPath)
if ([IO.Path]::GetExtension($resolvedOutput) -ne ".zip") {
    throw [IO.IOException]::new("bundle output must use the .zip extension")
}
$outputParent = Split-Path -Parent $resolvedOutput
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    throw [IO.DirectoryNotFoundException]::new("bundle output parent does not exist")
}
$null = Resolve-FixedLocalPath -Path $outputParent -PathType Container
if (Test-Path -LiteralPath $resolvedOutput) {
    if (-not $Force) {
        throw [IO.IOException]::new("bundle output already exists; use -Force to replace it")
    }
    Remove-Item -LiteralPath $resolvedOutput -Force
}

$runtimeText = Invoke-CheckedNative `
    -Executable $sourcePython `
    -Arguments @(
        "-I",
        "-B",
        "-c",
        ("import json,platform,sys; " +
            "print(json.dumps({'version':platform.python_version()," +
            "'major':sys.version_info.major,'minor':sys.version_info.minor," +
            "'architecture':platform.architecture()[0]}))")
    ) `
    -Operation "source Python inspection"
$runtime = $runtimeText | ConvertFrom-Json
if ($runtime.major -ne 3 -or $runtime.minor -lt 11 -or $runtime.architecture -ne "64bit") {
    throw [PlatformNotSupportedException]::new(
        "the pilot bundle requires 64-bit CPython 3.11 or newer"
    )
}
$pipRunner = (
    "import runpy,sys; sys.path.insert(0,sys.argv[1]); " +
    "sys.argv=['pip']+sys.argv[2:]; runpy.run_module('pip',run_name='__main__')"
)
$pipVersionText = Invoke-CheckedNative `
    -Executable $sourcePython `
    -Arguments @("-I", "-B", "-c", $pipRunner, $resolvedPipWheel, "--version") `
    -Operation "isolated pip build-tool inspection"
if ($pipVersionText -notmatch "^pip $([regex]::Escape($supportedPipVersion)) ") {
    throw [InvalidOperationException]::new("pip build-tool version is not exact")
}

$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryRoot = Join-Path $temporaryBase ("CausureBundle-" + [Guid]::NewGuid().ToString("N"))
$stageRoot = Join-Path $temporaryRoot "bundle"
$runtimeRoot = Join-Path $stageRoot "runtime"

try {
    $null = New-Item -ItemType Directory -Path $runtimeRoot

    foreach ($directoryName in @("DLLs", "Lib")) {
        Copy-RuntimeDirectory `
            -Source (Join-Path $sourceRoot $directoryName) `
            -Destination (Join-Path $runtimeRoot $directoryName)
    }

    $requiredRootFiles = @(
        "LICENSE.txt",
        "python.exe",
        "pythonw.exe",
        "python3.dll",
        ("python{0}{1}.dll" -f $runtime.major, $runtime.minor)
    )
    foreach ($fileName in $requiredRootFiles) {
        $sourceFile = Join-Path $sourceRoot $fileName
        if (Test-Path -LiteralPath $sourceFile -PathType Leaf) {
            Copy-Item -LiteralPath $sourceFile -Destination (Join-Path $runtimeRoot $fileName)
        }
    }
    foreach ($runtimeDll in Get-ChildItem -LiteralPath $sourceRoot -File) {
        if ($runtimeDll.Name -like "vcruntime*.dll" -or $runtimeDll.Name -eq "ucrtbase.dll") {
            Copy-Item -LiteralPath $runtimeDll.FullName -Destination $runtimeRoot
        }
    }
    $stagedPython = Join-Path $runtimeRoot "python.exe"
    if (-not (Test-Path -LiteralPath $stagedPython -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new("source runtime did not yield python.exe")
    }

    $sitePackages = Join-Path $runtimeRoot "Lib\site-packages"
    $null = New-Item -ItemType Directory -Path $sitePackages
    $wheelRequirement = "$resolvedWheel[windows-service]"
    $null = Invoke-CheckedNative `
        -Executable $sourcePython `
        -Arguments @(
            "-I",
            "-B",
            "-c",
            $pipRunner,
            $resolvedPipWheel,
            "install",
            "--isolated",
            "--disable-pip-version-check",
            "--no-index",
            "--only-binary=:all:",
            "--no-compile",
            "--no-warn-script-location",
            "--find-links",
            $resolvedWheelhouse,
            "--target",
            $sitePackages,
            $wheelRequirement
        ) `
        -Operation "offline dependency installation"

    $generatedLauncherRoot = Join-Path $sitePackages "bin"
    if (Test-Path -LiteralPath $generatedLauncherRoot) {
        Remove-Item -LiteralPath $generatedLauncherRoot -Recurse -Force
    }
    foreach ($recordFile in Get-ChildItem -LiteralPath $sitePackages -Recurse -Filter "RECORD" -File) {
        if ($recordFile.Directory.Name.EndsWith(".dist-info", [StringComparison]::Ordinal)) {
            Remove-Item -LiteralPath $recordFile.FullName -Force
        }
    }
    foreach ($directUrlFile in Get-ChildItem `
            -LiteralPath $sitePackages `
            -Recurse `
            -Filter "direct_url.json" `
            -File) {
        if ($directUrlFile.Directory.Name.EndsWith(".dist-info", [StringComparison]::Ordinal)) {
            Remove-Item -LiteralPath $directUrlFile.FullName -Force
        }
    }

    $serviceExecutableSource = Join-Path $sitePackages "win32\pythonservice.exe"
    if (-not (Test-Path -LiteralPath $serviceExecutableSource -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new("pywin32 wheel did not provide pythonservice.exe")
    }
    Copy-Item `
        -LiteralPath $serviceExecutableSource `
        -Destination (Join-Path $runtimeRoot "pythonservice.exe")
    $pywin32System32 = Join-Path $sitePackages "pywin32_system32"
    $systemDlls = @(Get-ChildItem -LiteralPath $pywin32System32 -Filter "*.dll" -File)
    if ($systemDlls.Count -lt 2) {
        throw [IO.FileNotFoundException]::new("pywin32 wheel did not provide its runtime DLLs")
    }
    foreach ($systemDll in $systemDlls) {
        Copy-Item -LiteralPath $systemDll.FullName -Destination $runtimeRoot
    }

    $previousBytecodeSetting = $env:PYTHONDONTWRITEBYTECODE
    $env:PYTHONDONTWRITEBYTECODE = "1"
    try {
        $contractText = Invoke-CheckedNative `
            -Executable $stagedPython `
            -Arguments @(
                "-I",
                "-B",
                "-c",
                ("import contextlib,importlib.metadata as m,io,json,os,platform," +
                    "win32serviceutil; " +
                    "from causure.constants import PACKAGE_VERSION; " +
                    "from causure.team_host import TEAM_HOST_WAITRESS_VERSION; " +
                    "from causure.team_windows_service import " +
                    "TEAM_WINDOWS_SERVICE_DEPENDENCY_VERSION; " +
                    "sink=io.StringIO(); " +
                    "redirect=contextlib.redirect_stdout(sink); redirect.__enter__(); " +
                    "service_executable=win32serviceutil.LocatePythonServiceExe(); " +
                    "redirect.__exit__(None,None,None); " +
                    "print(json.dumps({'causure':m.version('causure')," +
                    "'package_contract':PACKAGE_VERSION,'cryptography':m.version('cryptography')," +
                    "'cffi':m.version('cffi'),'pycparser':m.version('pycparser')," +
                    "'pyjwt':m.version('PyJWT'),'pywin32':m.version('pywin32')," +
                    "'pywin32_contract':TEAM_WINDOWS_SERVICE_DEPENDENCY_VERSION," +
                    "'waitress':m.version('waitress'),'waitress_contract':" +
                    "TEAM_HOST_WAITRESS_VERSION,'python':platform.python_version()," +
                    "'service_executable':os.path.realpath(service_executable)}))")
            ) `
            -Operation "staged runtime validation"
    }
    finally {
        $env:PYTHONDONTWRITEBYTECODE = $previousBytecodeSetting
    }
    $contract = $contractText | ConvertFrom-Json
    if ($contract.causure -ne $contract.package_contract) {
        throw [InvalidOperationException]::new("staged Causure contract mismatch")
    }
    if ($contract.pywin32 -ne $contract.pywin32_contract) {
        throw [InvalidOperationException]::new("staged pywin32 contract mismatch")
    }
    if ($contract.waitress -ne $contract.waitress_contract) {
        throw [InvalidOperationException]::new("staged Waitress contract mismatch")
    }
    if ($contract.cffi -ne "2.1.0" -or $contract.pycparser -ne "3.0") {
        throw [InvalidOperationException]::new("staged transitive dependency lock mismatch")
    }
    $expectedServiceExecutable = Join-Path $runtimeRoot "pythonservice.exe"
    if (-not [string]::Equals(
            [IO.Path]::GetFullPath($contract.service_executable),
            [IO.Path]::GetFullPath($expectedServiceExecutable),
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw [InvalidOperationException]::new("staged service executable escaped its runtime")
    }

    $compiledFiles = @(Get-ChildItem -LiteralPath $runtimeRoot -Recurse -File -Force |
        Where-Object { $_.Extension -in @(".pyc", ".pyo") })
    foreach ($compiledFile in $compiledFiles) {
        Remove-Item -LiteralPath $compiledFile.FullName -Force
    }
    $cacheDirectories = @(Get-ChildItem -LiteralPath $runtimeRoot -Recurse -Directory -Force |
        Where-Object { $_.Name -eq "__pycache__" } |
        Sort-Object { $_.FullName.Length } -Descending)
    foreach ($cacheDirectory in $cacheDirectories) {
        Remove-Item -LiteralPath $cacheDirectory.FullName -Recurse -Force
    }

    Copy-Item -LiteralPath $installerSource -Destination (Join-Path $stageRoot "install.ps1")
    $managementRoot = Join-Path $runtimeRoot "management"
    $null = New-Item -ItemType Directory -Path $managementRoot
    Copy-Item `
        -LiteralPath $removerSource `
        -Destination (Join-Path $managementRoot "remove.ps1")

    $reparsePoints = @(Get-ChildItem -LiteralPath $stageRoot -Recurse -Force |
        Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
    if ($reparsePoints.Count -ne 0) {
        throw [IO.IOException]::new("bundle staging contains a reparse point")
    }

    $manifestFiles = @()
    $stagedFiles = @(Get-ChildItem -LiteralPath $stageRoot -Recurse -File -Force |
        Sort-Object FullName)
    foreach ($stagedFile in $stagedFiles) {
        $relativePath = Get-RelativeBundlePath -Root $stageRoot -Path $stagedFile.FullName
        $manifestFiles += [ordered]@{
            path = $relativePath
            byte_count = [int64]$stagedFile.Length
            sha256 = (Get-FileHash -LiteralPath $stagedFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    $manifest = [ordered]@{
        schema_version = $manifestSchemaVersion
        product = $productName
        package_version = $contract.causure
        service_name = $fixedServiceName
        build = [ordered]@{
            pip_version = $supportedPipVersion
            pip_wheel_sha256 = (Get-FileHash `
                -LiteralPath $resolvedPipWheel `
                -Algorithm SHA256).Hash.ToLowerInvariant()
            causure_wheel_sha256 = (Get-FileHash `
                -LiteralPath $resolvedWheel `
                -Algorithm SHA256).Hash.ToLowerInvariant()
        }
        runtime = [ordered]@{
            python_version = $contract.python
            architecture = $runtime.architecture
            dependencies = [ordered]@{
                cffi = $contract.cffi
                cryptography = $contract.cryptography
                pycparser = $contract.pycparser
                pyjwt = $contract.pyjwt
                pywin32 = $contract.pywin32
                waitress = $contract.waitress
            }
        }
        install = [ordered]@{
            base_path = $fixedInstallBase
            receipt_path = $fixedReceiptPath
            runtime_relative_path = "runtime"
        }
        files = $manifestFiles
    }
    $manifestPath = Join-Path $stageRoot "bundle-manifest.json"
    [IO.File]::WriteAllText(
        $manifestPath,
        ($manifest | ConvertTo-Json -Depth 10),
        [Text.UTF8Encoding]::new($false)
    )

    Add-Type -AssemblyName System.IO.Compression
    $archiveStream = [IO.FileStream]::new(
        $resolvedOutput,
        [IO.FileMode]::CreateNew,
        [IO.FileAccess]::Write,
        [IO.FileShare]::None
    )
    try {
        $archive = [IO.Compression.ZipArchive]::new(
            $archiveStream,
            [IO.Compression.ZipArchiveMode]::Create,
            $true
        )
        try {
            $archiveFiles = @(Get-ChildItem -LiteralPath $stageRoot -Recurse -File -Force |
                Sort-Object { Get-RelativeBundlePath -Root $stageRoot -Path $_.FullName })
            foreach ($archiveFile in $archiveFiles) {
                $relativePath = Get-RelativeBundlePath `
                    -Root $stageRoot `
                    -Path $archiveFile.FullName
                $entry = $archive.CreateEntry(
                    $relativePath,
                    [IO.Compression.CompressionLevel]::Optimal
                )
                $entry.LastWriteTime = $normalizedTimestamp
                $entryStream = $entry.Open()
                $inputStream = [IO.File]::OpenRead($archiveFile.FullName)
                try {
                    $inputStream.CopyTo($entryStream)
                }
                finally {
                    $inputStream.Dispose()
                    $entryStream.Dispose()
                }
            }
        }
        finally {
            $archive.Dispose()
        }
    }
    finally {
        $archiveStream.Dispose()
    }

    $result = [ordered]@{
        schema_version = "1.0"
        bundle_path = $resolvedOutput
        bundle_sha256 = (Get-FileHash -LiteralPath $resolvedOutput -Algorithm SHA256).Hash.ToLowerInvariant()
        manifest_sha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
        package_version = $contract.causure
        python_version = $contract.python
        file_count = $manifestFiles.Count
    }
    $result | ConvertTo-Json -Depth 5
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        $resolvedTemporaryRoot = (Resolve-Path -LiteralPath $temporaryRoot).Path
        if (
            -not $resolvedTemporaryRoot.StartsWith(
                $temporaryBase,
                [StringComparison]::OrdinalIgnoreCase
            ) -or
            -not (Split-Path -Leaf $resolvedTemporaryRoot).StartsWith(
                "CausureBundle-",
                [StringComparison]::Ordinal
            )
        ) {
            throw [InvalidOperationException]::new(
                "refusing to remove an unexpected temporary path"
            )
        }
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}
