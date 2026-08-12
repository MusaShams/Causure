[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$HostConfigurationPath,

    [switch]$ManualStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$supportedSchemaVersion = "1.0"
$supportedProduct = "Causure Windows Team Service Bundle"
$supportedPackageVersion = "0.4.0a15"
$fixedInstallBase = "C:\Program Files\Causure\Team"
$fixedReceiptPath = "C:\ProgramData\Causure\windows-service-installation.json"
$fixedRemovalReceiptBackupPath = (
    "C:\ProgramData\Causure\windows-service-installation.removal-backup.json"
)
$fixedInstalledManifestPath = "C:\ProgramData\Causure\windows-service-bundle-manifest.json"
$fixedServiceName = "CausureTeam"
$servicePrincipal = "NT SERVICE\CausureTeam"
$bundleRoot = [IO.Path]::GetFullPath($PSScriptRoot)
$manifestPath = Join-Path $bundleRoot "bundle-manifest.json"
$stagingPath = Join-Path $fixedInstallBase (".staging-" + [Guid]::NewGuid().ToString("N"))
$finalRuntimePath = Join-Path $fixedInstallBase $supportedPackageVersion
$installationSucceeded = $false

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory = $true)]
        [object]$Value,

        [Parameter(Mandatory = $true)]
        [string[]]$Names,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    if ($null -eq $Value) {
        throw [InvalidDataException]::new("$Label is missing")
    }
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    if (@(Compare-Object -ReferenceObject $expected -DifferenceObject $actual).Count -ne 0) {
        throw [InvalidDataException]::new("$Label has unknown or missing fields")
    }
}

function Assert-UniqueJsonProperties {
    param(
        [Parameter(Mandatory = $true)]
        [Text.Json.JsonElement]$Element
    )

    if ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Object) {
        $names = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($property in $Element.EnumerateObject()) {
            if (-not $names.Add($property.Name)) {
                throw [InvalidDataException]::new("JSON contains a duplicate object field")
            }
            Assert-UniqueJsonProperties -Element $property.Value
        }
    }
    elseif ($Element.ValueKind -eq [Text.Json.JsonValueKind]::Array) {
        foreach ($item in $Element.EnumerateArray()) {
            Assert-UniqueJsonProperties -Element $item
        }
    }
}

function ConvertFrom-ClosedJsonBytes {
    param(
        [Parameter(Mandatory = $true)]
        [byte[]]$Bytes,

        [Parameter(Mandatory = $true)]
        [string]$Label
    )

    try {
        $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes)
        $options = [Text.Json.JsonDocumentOptions]::new()
        $options.AllowTrailingCommas = $false
        $options.CommentHandling = [Text.Json.JsonCommentHandling]::Disallow
        $options.MaxDepth = 32
        $document = [Text.Json.JsonDocument]::Parse($text, $options)
        try {
            Assert-UniqueJsonProperties -Element $document.RootElement
        }
        finally {
            $document.Dispose()
        }
        return $text | ConvertFrom-Json -Depth 32
    }
    catch {
        throw [InvalidDataException]::new("$Label is not closed UTF-8 JSON")
    }
}

function Assert-LocalFixedPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Leaf", "Container")]
        [string]$PathType
    )

    $resolved = (Resolve-Path -LiteralPath $Path).Path
    if (-not (Test-Path -LiteralPath $resolved -PathType $PathType)) {
        throw [IO.IOException]::new("required path has the wrong type")
    }
    if ($resolved.StartsWith("\\", [StringComparison]::Ordinal)) {
        throw [IO.IOException]::new("installation inputs must be on a local fixed drive")
    }
    $root = [IO.Path]::GetPathRoot($resolved)
    $drive = [IO.DriveInfo]::new($root)
    if ($drive.DriveType -ne [IO.DriveType]::Fixed) {
        throw [IO.IOException]::new("installation inputs must be on a local fixed drive")
    }
    $item = Get-Item -LiteralPath $resolved -Force
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw [IO.IOException]::new("installation inputs cannot be reparse points")
    }
    return [IO.Path]::GetFullPath($resolved)
}

function Resolve-ClosedRelativePath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$RelativePath
    )

    if (
        [string]::IsNullOrWhiteSpace($RelativePath) -or
        $RelativePath.Length -gt 512 -or
        $RelativePath.Contains("\") -or
        $RelativePath.Contains(":") -or
        $RelativePath.StartsWith("/", [StringComparison]::Ordinal) -or
        $RelativePath.EndsWith("/", [StringComparison]::Ordinal) -or
        @($RelativePath.Split("/") | Where-Object { $_ -in @("", ".", "..") }).Count -ne 0 -or
        @($RelativePath.ToCharArray() | Where-Object { [char]::IsControl($_) }).Count -ne 0
    ) {
        throw [InvalidDataException]::new("bundle manifest contains an unsafe relative path")
    }
    $fullPath = [IO.Path]::GetFullPath((Join-Path $Root $RelativePath.Replace("/", "\")))
    $rootPrefix = $Root.TrimEnd("\") + "\"
    if (-not $fullPath.StartsWith($rootPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw [InvalidDataException]::new("bundle manifest path escaped the bundle root")
    }
    return $fullPath
}

function Test-IsSameOrDescendantPath {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string]$Parent
    )

    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd("\")
    $fullParent = [IO.Path]::GetFullPath($Parent).TrimEnd("\")
    return (
        [string]::Equals($fullPath, $fullParent, [StringComparison]::OrdinalIgnoreCase) -or
        $fullPath.StartsWith(
            $fullParent + "\",
            [StringComparison]::OrdinalIgnoreCase
        )
    )
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

function Grant-CheckedAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    $null = Invoke-CheckedNative `
        -Executable "$env:SystemRoot\System32\icacls.exe" `
        -Arguments (@($Path) + $Arguments + @("/Q")) `
        -Operation "ACL update"
}

function Assert-RequiredRuntimeAclRule {
    param(
        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemSecurity]$Acl,

        [Parameter(Mandatory = $true)]
        [Security.Principal.SecurityIdentifier]$Identity,

        [Parameter(Mandatory = $true)]
        [Security.AccessControl.FileSystemRights]$RequiredRights,

        [switch]$RequireInherited,
        [switch]$RequireChildInheritance
    )

    $rules = @($Acl.GetAccessRules(
        $true,
        $true,
        [Security.Principal.SecurityIdentifier]
    ) | Where-Object { $_.IdentityReference.Value -eq $Identity.Value })
    foreach ($rule in $rules) {
        if (
            $rule.AccessControlType -eq [Security.AccessControl.AccessControlType]::Deny -and
            ($rule.FileSystemRights -band $RequiredRights) -ne 0
        ) {
            throw [UnauthorizedAccessException]::new(
                "machine runtime ACL contains a conflicting deny rule"
            )
        }
    }
    $matchingAllow = @($rules | Where-Object {
        $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
        ($_.FileSystemRights -band $RequiredRights) -eq $RequiredRights -and
        (-not $RequireInherited -or $_.IsInherited) -and
        (
            -not $RequireChildInheritance -or
            (
                ($_.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ContainerInherit) -ne 0 -and
                ($_.InheritanceFlags -band [Security.AccessControl.InheritanceFlags]::ObjectInherit) -ne 0
            )
        )
    })
    if ($matchingAllow.Count -lt 1) {
        throw [UnauthorizedAccessException]::new(
            "machine runtime ACL is missing a required allow rule"
        )
    }
}

function Assert-ClosedRuntimeAcl {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Root,

        [Parameter(Mandatory = $true)]
        [string]$ServicePrincipal
    )

    $systemSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-18")
    $administratorsSid = [Security.Principal.SecurityIdentifier]::new("S-1-5-32-544")
    $serviceSid = ([Security.Principal.NTAccount]::new($ServicePrincipal)).Translate(
        [Security.Principal.SecurityIdentifier]
    )
    $rootAcl = Get-Acl -LiteralPath $Root
    if (-not $rootAcl.AreAccessRulesProtected) {
        throw [UnauthorizedAccessException]::new(
            "machine runtime root must use a protected ACL"
        )
    }
    Assert-RequiredRuntimeAclRule `
        -Acl $rootAcl `
        -Identity $systemSid `
        -RequiredRights ([Security.AccessControl.FileSystemRights]::FullControl) `
        -RequireChildInheritance
    Assert-RequiredRuntimeAclRule `
        -Acl $rootAcl `
        -Identity $administratorsSid `
        -RequiredRights ([Security.AccessControl.FileSystemRights]::FullControl) `
        -RequireChildInheritance
    Assert-RequiredRuntimeAclRule `
        -Acl $rootAcl `
        -Identity $serviceSid `
        -RequiredRights ([Security.AccessControl.FileSystemRights]::ReadAndExecute) `
        -RequireChildInheritance

    foreach ($item in Get-ChildItem -LiteralPath $Root -Recurse -Force) {
        $itemAcl = Get-Acl -LiteralPath $item.FullName
        if ($itemAcl.AreAccessRulesProtected) {
            throw [UnauthorizedAccessException]::new(
                "machine runtime descendant ACL must inherit from the protected root"
            )
        }
        Assert-RequiredRuntimeAclRule `
            -Acl $itemAcl `
            -Identity $systemSid `
            -RequiredRights ([Security.AccessControl.FileSystemRights]::FullControl) `
            -RequireInherited
        Assert-RequiredRuntimeAclRule `
            -Acl $itemAcl `
            -Identity $administratorsSid `
            -RequiredRights ([Security.AccessControl.FileSystemRights]::FullControl) `
            -RequireInherited
        Assert-RequiredRuntimeAclRule `
            -Acl $itemAcl `
            -Identity $serviceSid `
            -RequiredRights ([Security.AccessControl.FileSystemRights]::ReadAndExecute) `
            -RequireInherited
    }
}

function Invoke-ServiceCli {
    param(
        [Parameter(Mandatory = $true)]
        [string]$PythonExecutable,

        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    return Invoke-CheckedNative `
        -Executable $PythonExecutable `
        -Arguments (@("-I", "-B", "-m", "causure.team_windows_service_cli") + $Arguments) `
        -Operation "Causure Windows service command"
}

function Wait-ServiceAbsent {
    param([ValidateRange(1, 60)][int]$Seconds = 20)

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($Seconds)
    do {
        if ($null -eq (Get-Service -Name $fixedServiceName -ErrorAction SilentlyContinue)) {
            return $true
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return $false
}

if (-not (Test-IsAdministrator)) {
    throw [UnauthorizedAccessException]::new("machine-wide bundle installation requires elevation")
}
if (-not [Environment]::Is64BitProcess) {
    throw [PlatformNotSupportedException]::new("run the installer from 64-bit PowerShell")
}
$null = Assert-LocalFixedPath -Path $bundleRoot -PathType Container
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new("bundle manifest is missing")
}

$manifestBytes = [IO.File]::ReadAllBytes($manifestPath)
if ($manifestBytes.Length -lt 2 -or $manifestBytes.Length -gt 16MB) {
    throw [InvalidDataException]::new("bundle manifest size is outside the supported limit")
}
$manifest = ConvertFrom-ClosedJsonBytes -Bytes $manifestBytes -Label "bundle manifest"
Assert-ExactProperties `
    -Value $manifest `
    -Names @(
        "schema_version",
        "product",
        "package_version",
        "service_name",
        "build",
        "runtime",
        "install",
        "files"
    ) `
    -Label "bundle manifest"
Assert-ExactProperties `
    -Value $manifest.build `
    -Names @("pip_version", "pip_wheel_sha256", "causure_wheel_sha256") `
    -Label "bundle build contract"
Assert-ExactProperties `
    -Value $manifest.runtime `
    -Names @("python_version", "architecture", "dependencies") `
    -Label "bundle runtime"
Assert-ExactProperties `
    -Value $manifest.runtime.dependencies `
    -Names @("cffi", "cryptography", "pycparser", "pyjwt", "pywin32", "waitress") `
    -Label "bundle dependencies"
Assert-ExactProperties `
    -Value $manifest.install `
    -Names @("base_path", "receipt_path", "runtime_relative_path") `
    -Label "bundle install contract"
if (
    $manifest.schema_version -ne $supportedSchemaVersion -or
    $manifest.product -ne $supportedProduct -or
    $manifest.package_version -ne $supportedPackageVersion -or
    $manifest.service_name -ne $fixedServiceName -or
    $manifest.build.pip_version -ne "26.1.2" -or
    $manifest.build.pip_wheel_sha256 -notmatch "^[a-f0-9]{64}$" -or
    $manifest.build.causure_wheel_sha256 -notmatch "^[a-f0-9]{64}$" -or
    $manifest.runtime.architecture -ne "64bit" -or
    $manifest.runtime.dependencies.cffi -ne "2.1.0" -or
    $manifest.runtime.dependencies.cryptography -ne "50.0.0" -or
    $manifest.runtime.dependencies.pycparser -ne "3.0" -or
    $manifest.runtime.dependencies.pyjwt -ne "2.13.0" -or
    $manifest.runtime.dependencies.pywin32 -ne "312" -or
    $manifest.runtime.dependencies.waitress -ne "3.0.2" -or
    $manifest.install.base_path -ne $fixedInstallBase -or
    $manifest.install.receipt_path -ne $fixedReceiptPath -or
    $manifest.install.runtime_relative_path -ne "runtime"
) {
    throw [InvalidDataException]::new("bundle manifest does not match this installer contract")
}

$expectedBundleFiles = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
$runtimeEntries = @()
foreach ($entry in @($manifest.files)) {
    Assert-ExactProperties `
        -Value $entry `
        -Names @("path", "byte_count", "sha256") `
        -Label "bundle file entry"
    if ($entry.path -isnot [string] -or $entry.sha256 -isnot [string]) {
        throw [InvalidDataException]::new("bundle file entry has an invalid type")
    }
    if (
        $entry.byte_count -isnot [int] -and
        $entry.byte_count -isnot [long]
    ) {
        throw [InvalidDataException]::new("bundle file byte count is not an integer")
    }
    if ($entry.byte_count -lt 0 -or $entry.sha256 -notmatch "^[a-f0-9]{64}$") {
        throw [InvalidDataException]::new("bundle file integrity value is invalid")
    }
    $fullPath = Resolve-ClosedRelativePath -Root $bundleRoot -RelativePath $entry.path
    if (-not $expectedBundleFiles.Add($entry.path)) {
        throw [InvalidDataException]::new("bundle manifest contains a duplicate file path")
    }
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new("bundle manifest file is missing")
    }
    $file = Get-Item -LiteralPath $fullPath -Force
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw [IO.IOException]::new("bundle file cannot be a reparse point")
    }
    if (
        $file.Length -ne [int64]$entry.byte_count -or
        (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
            $entry.sha256
    ) {
        throw [InvalidDataException]::new("bundle file integrity verification failed")
    }
    if ($entry.path.StartsWith("runtime/", [StringComparison]::Ordinal)) {
        $runtimeEntries += $entry
    }
    elseif ($entry.path -ne "install.ps1") {
        throw [InvalidDataException]::new("bundle contains an unsupported top-level payload")
    }
}
foreach ($requiredPath in @(
        "install.ps1",
        "runtime/python.exe",
        "runtime/pythonservice.exe",
        "runtime/management/remove.ps1"
    )) {
    if (-not $expectedBundleFiles.Contains($requiredPath)) {
        throw [InvalidDataException]::new("bundle is missing a required managed file")
    }
}
$actualBundleFiles = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
$reparsePoints = @(Get-ChildItem -LiteralPath $bundleRoot -Recurse -Force |
    Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
if ($reparsePoints.Count -ne 0) {
    throw [IO.IOException]::new("bundle contains a reparse point")
}
foreach ($actualFile in Get-ChildItem -LiteralPath $bundleRoot -Recurse -File -Force) {
    $relative = [IO.Path]::GetRelativePath($bundleRoot, $actualFile.FullName).Replace("\", "/")
    $null = $actualBundleFiles.Add($relative)
}
$null = $expectedBundleFiles.Add("bundle-manifest.json")
if (
    $actualBundleFiles.Count -ne $expectedBundleFiles.Count -or
    @($actualBundleFiles | Where-Object { -not $expectedBundleFiles.Contains($_) }).Count -ne 0
) {
    throw [InvalidDataException]::new("bundle contains an unmanifested file")
}
$manifestSha256 = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Warning "This pilot bundle is hash-closed but not Authenticode-signed. Verify its separately supplied SHA-256 before installation."

$resolvedHostConfiguration = Assert-LocalFixedPath `
    -Path $HostConfigurationPath `
    -PathType Leaf
if ($null -ne (Get-Service -Name $fixedServiceName -ErrorAction SilentlyContinue)) {
    throw [InvalidOperationException]::new("the fixed Windows service is already installed")
}
if (Test-Path -LiteralPath $fixedReceiptPath) {
    throw [InvalidOperationException]::new("a machine-wide installation receipt already exists")
}
if (Test-Path -LiteralPath $fixedRemovalReceiptBackupPath) {
    throw [InvalidOperationException]::new("an incomplete bundle removal backup already exists")
}
if (Test-Path -LiteralPath $fixedInstalledManifestPath) {
    throw [InvalidOperationException]::new("an installed bundle manifest already exists")
}
if (Test-Path -LiteralPath $finalRuntimePath) {
    throw [InvalidOperationException]::new("the versioned machine runtime already exists")
}
if (Test-Path -LiteralPath $stagingPath) {
    throw [InvalidOperationException]::new("the unique staging path already exists")
}

$finalCreated = $false
$receiptCreated = $false
$installedManifestCreated = $false
$operatorAclBackups = @{}
$runtimePython = Join-Path $finalRuntimePath "python.exe"
try {
    $null = New-Item -ItemType Directory -Path $fixedInstallBase -Force
    $null = New-Item -ItemType Directory -Path $stagingPath
    $copyArguments = @(
        (Join-Path $bundleRoot "runtime"),
        $stagingPath,
        "/E",
        "/COPY:DAT",
        "/DCOPY:DAT",
        "/R:1",
        "/W:1",
        "/NFL",
        "/NDL",
        "/NJH",
        "/NJS",
        "/NP"
    )
    $null = & "$env:SystemRoot\System32\robocopy.exe" @copyArguments
    if ($LASTEXITCODE -gt 7) {
        throw [InvalidOperationException]::new(
            "runtime staging failed with exit code $LASTEXITCODE"
        )
    }
    foreach ($entry in $runtimeEntries) {
        $relativeRuntimePath = $entry.path.Substring("runtime/".Length)
        $stagedPath = Resolve-ClosedRelativePath `
            -Root $stagingPath `
            -RelativePath $relativeRuntimePath
        $stagedFile = Get-Item -LiteralPath $stagedPath -Force
        if (
            $stagedFile.Length -ne [int64]$entry.byte_count -or
            (Get-FileHash -LiteralPath $stagedPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
                $entry.sha256
        ) {
            throw [InvalidDataException]::new("staged runtime integrity verification failed")
        }
    }
    Move-Item -LiteralPath $stagingPath -Destination $finalRuntimePath
    $finalCreated = $true

    $runtimePython = Join-Path $finalRuntimePath "python.exe"
    $previousBytecodeSetting = $env:PYTHONDONTWRITEBYTECODE
    $env:PYTHONDONTWRITEBYTECODE = "1"
    try {
        $configurationText = Invoke-CheckedNative `
            -Executable $runtimePython `
            -Arguments @(
                "-I",
                "-B",
                "-c",
                ("import json,sys; from causure.team_host import " +
                    "load_team_host_configuration_subject,validate_team_host_dependencies; " +
                    "s=load_team_host_configuration_subject(sys.argv[1]); " +
                    "validate_team_host_dependencies(s.configuration); c=s.configuration; " +
                    "print(json.dumps({'host_path':s.path,'host_sha256':s.sha256," +
                    "'host_byte_count':s.byte_count," +
                    "'refresh_path':c.identity.refresh_configuration_path," +
                    "'trust_path':c.identity.trust_store_path," +
                    "'database_path':c.database.path}))"),
                $resolvedHostConfiguration
            ) `
            -Operation "machine runtime and host-configuration validation"
    }
    finally {
        $env:PYTHONDONTWRITEBYTECODE = $previousBytecodeSetting
    }
    $configuration = $configurationText | ConvertFrom-Json
    Assert-ExactProperties `
        -Value $configuration `
        -Names @(
            "host_path",
            "host_sha256",
            "host_byte_count",
            "refresh_path",
            "trust_path",
            "database_path"
        ) `
        -Label "validated host configuration"
    $refreshPath = Assert-LocalFixedPath -Path $configuration.refresh_path -PathType Leaf
    $trustParent = Split-Path -Parent ([IO.Path]::GetFullPath($configuration.trust_path))
    $databaseParent = Split-Path -Parent ([IO.Path]::GetFullPath($configuration.database_path))
    $null = Assert-LocalFixedPath -Path $trustParent -PathType Container
    $null = Assert-LocalFixedPath -Path $databaseParent -PathType Container
    foreach ($readPath in @($resolvedHostConfiguration, $refreshPath)) {
        if (
            (Test-IsSameOrDescendantPath -Path $readPath -Parent $finalRuntimePath) -or
            (Test-IsSameOrDescendantPath -Path $readPath -Parent $bundleRoot)
        ) {
            throw [InvalidDataException]::new(
                "operator configuration cannot be stored in bundle-managed paths"
            )
        }
    }
    foreach ($modifyPath in @($trustParent, $databaseParent) | Select-Object -Unique) {
        if ([string]::Equals(
                $modifyPath.TrimEnd("\"),
                [IO.Path]::GetPathRoot($modifyPath).TrimEnd("\"),
                [StringComparison]::OrdinalIgnoreCase
            )) {
            throw [InvalidDataException]::new(
                "a writable service directory cannot be a drive root"
            )
        }
        foreach ($readPath in @($resolvedHostConfiguration, $refreshPath)) {
            if (Test-IsSameOrDescendantPath -Path $readPath -Parent $modifyPath) {
                throw [InvalidDataException]::new(
                    "a writable service directory cannot contain protected configuration"
                )
            }
        }
        foreach ($protectedPath in @(
                $env:SystemRoot,
                $env:ProgramFiles,
                ${env:ProgramFiles(x86)},
                $finalRuntimePath,
                $bundleRoot
            )) {
            if (
                -not [string]::IsNullOrWhiteSpace($protectedPath) -and
                (Test-IsSameOrDescendantPath -Path $modifyPath -Parent $protectedPath)
            ) {
                throw [InvalidDataException]::new(
                    "a writable service directory overlaps protected machine files"
                )
            }
        }
    }

    $operatorAclPaths = @(
        $resolvedHostConfiguration,
        (Split-Path -Parent $resolvedHostConfiguration),
        $refreshPath,
        (Split-Path -Parent $refreshPath),
        $trustParent,
        $databaseParent
    ) | Select-Object -Unique
    foreach ($operatorAclPath in $operatorAclPaths) {
        $operatorAcl = Get-Acl -LiteralPath $operatorAclPath
        $operatorAclBackups[$operatorAclPath] = $operatorAcl.GetSecurityDescriptorSddlForm(
            [Security.AccessControl.AccessControlSections]::Access
        )
    }

    $installArguments = @("install", $resolvedHostConfiguration)
    if ($ManualStart) {
        $installArguments += "--manual-start"
    }
    $null = Invoke-ServiceCli -PythonExecutable $runtimePython -Arguments $installArguments

    Grant-CheckedAcl `
        -Path $finalRuntimePath `
        -Arguments @(
            "/inheritance:r",
            "/grant:r",
            "NT AUTHORITY\SYSTEM:(OI)(CI)(F)",
            "BUILTIN\Administrators:(OI)(CI)(F)",
            "${servicePrincipal}:(OI)(CI)(RX)"
        )
    Assert-ClosedRuntimeAcl -Root $finalRuntimePath -ServicePrincipal $servicePrincipal
    foreach ($readPath in @($resolvedHostConfiguration, $refreshPath)) {
        Grant-CheckedAcl -Path (Split-Path -Parent $readPath) -Arguments @(
            "/grant:r",
            "${servicePrincipal}:(RX)"
        )
        Grant-CheckedAcl -Path $readPath -Arguments @(
            "/grant:r",
            "${servicePrincipal}:(R)"
        )
    }
    foreach ($modifyPath in @($trustParent, $databaseParent) | Select-Object -Unique) {
        Grant-CheckedAcl -Path $modifyPath -Arguments @(
            "/grant:r",
            "${servicePrincipal}:(OI)(CI)(M)"
        )
    }

    $recoveryText = Invoke-ServiceCli `
        -PythonExecutable $runtimePython `
        -Arguments @("recovery-status")
    $recovery = $recoveryText | ConvertFrom-Json
    if (
        $recovery.reset_period_seconds -ne 900 -or
        $recovery.apply_on_non_crash_failures -ne $true -or
        @($recovery.actions).Count -ne 2 -or
        $recovery.actions[0].action -ne "restart" -or
        $recovery.actions[0].delay_milliseconds -ne 120000 -or
        $recovery.actions[1].action -ne "none" -or
        $recovery.actions[1].delay_milliseconds -ne 0 -or
        $recovery.reboot_message_configured -ne $false -or
        $recovery.command_configured -ne $false
    ) {
        throw [InvalidOperationException]::new("installed recovery policy is not exact")
    }

    $operatorAclBackupDocuments = @()
    foreach ($operatorAclPath in @($operatorAclBackups.Keys | Sort-Object)) {
        $operatorAclBackupDocuments += [ordered]@{
            path = $operatorAclPath
            access_sddl = $operatorAclBackups[$operatorAclPath]
        }
    }
    $receipt = [ordered]@{
        schema_version = "1.0"
        package_version = $supportedPackageVersion
        service_name = $fixedServiceName
        runtime_path = $finalRuntimePath
        manifest_path = $fixedInstalledManifestPath
        manifest_sha256 = $manifestSha256
        host_configuration_path = $resolvedHostConfiguration
        host_configuration_sha256 = $configuration.host_sha256
        host_configuration_byte_count = [int64]$configuration.host_byte_count
        automatic_start = (-not $ManualStart.IsPresent)
        removal_started = $false
        operator_acl_backups = $operatorAclBackupDocuments
    }
    $receiptParent = Split-Path -Parent $fixedReceiptPath
    $null = New-Item -ItemType Directory -Path $receiptParent -Force
    Copy-Item -LiteralPath $manifestPath -Destination $fixedInstalledManifestPath
    $installedManifestCreated = $true
    $temporaryReceipt = "$fixedReceiptPath.$([Guid]::NewGuid().ToString('N')).tmp"
    [IO.File]::WriteAllText(
        $temporaryReceipt,
        ($receipt | ConvertTo-Json -Depth 5),
        [Text.UTF8Encoding]::new($false)
    )
    Move-Item -LiteralPath $temporaryReceipt -Destination $fixedReceiptPath
    $receiptCreated = $true
    Grant-CheckedAcl -Path $fixedReceiptPath -Arguments @(
        "/inheritance:r",
        "/grant:r",
        "NT AUTHORITY\SYSTEM:(F)",
        "BUILTIN\Administrators:(F)"
    )
    Grant-CheckedAcl -Path $fixedInstalledManifestPath -Arguments @(
        "/inheritance:r",
        "/grant:r",
        "NT AUTHORITY\SYSTEM:(F)",
        "BUILTIN\Administrators:(F)"
    )

    $installationSucceeded = $true
    [ordered]@{
        schema_version = "1.0"
        result = "installed"
        package_version = $supportedPackageVersion
        service_name = $fixedServiceName
        runtime_path = $finalRuntimePath
        receipt_path = $fixedReceiptPath
        start_mode = $(if ($ManualStart) { "manual" } else { "delayed_automatic" })
        service_state = "stopped"
        manifest_sha256 = $manifestSha256
    } | ConvertTo-Json -Depth 5
}
catch {
    $originalError = $_
    $rollbackFailures = [Collections.Generic.List[string]]::new()
    $existingService = Get-Service -Name $fixedServiceName -ErrorAction SilentlyContinue
    if ($null -ne $existingService -and (Test-Path -LiteralPath $runtimePython -PathType Leaf)) {
        if ($existingService.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            try {
                $null = Invoke-ServiceCli -PythonExecutable $runtimePython -Arguments @("stop")
            }
            catch {
                $rollbackFailures.Add("service_stop")
            }
        }
        $existingService = Get-Service -Name $fixedServiceName -ErrorAction SilentlyContinue
        if ($null -ne $existingService -and $existingService.Status -eq "Stopped") {
            try {
                $null = Invoke-ServiceCli -PythonExecutable $runtimePython -Arguments @("remove")
                $null = Wait-ServiceAbsent -Seconds 20
            }
            catch {
                $rollbackFailures.Add("service_remove")
            }
        }
    }
    $serviceAbsent = $null -eq (Get-Service -Name $fixedServiceName -ErrorAction SilentlyContinue)
    if ($serviceAbsent) {
        foreach ($operatorAclPath in $operatorAclBackups.Keys) {
            try {
                $operatorAcl = Get-Acl -LiteralPath $operatorAclPath
                $operatorAcl.SetSecurityDescriptorSddlForm(
                    $operatorAclBackups[$operatorAclPath],
                    [Security.AccessControl.AccessControlSections]::Access
                )
                Set-Acl -LiteralPath $operatorAclPath -AclObject $operatorAcl
            }
            catch {
                $rollbackFailures.Add("operator_acl_restore")
            }
        }
        if ($receiptCreated -and (Test-Path -LiteralPath $fixedReceiptPath)) {
            try {
                Remove-Item -LiteralPath $fixedReceiptPath -Force
            }
            catch {
                $rollbackFailures.Add("receipt_remove")
            }
        }
        if ($installedManifestCreated -and (Test-Path -LiteralPath $fixedInstalledManifestPath)) {
            try {
                Remove-Item -LiteralPath $fixedInstalledManifestPath -Force
            }
            catch {
                $rollbackFailures.Add("manifest_remove")
            }
        }
        if ($finalCreated -and (Test-Path -LiteralPath $finalRuntimePath)) {
            try {
                Remove-Item -LiteralPath $finalRuntimePath -Recurse -Force
            }
            catch {
                $rollbackFailures.Add("runtime_remove")
            }
        }
    }
    else {
        $rollbackFailures.Add("service_still_registered")
    }
    if ($rollbackFailures.Count -ne 0) {
        throw [InvalidOperationException]::new(
            "machine installation failed and rollback was incomplete: " +
            ($rollbackFailures -join ",")
        )
    }
    throw $originalError
}
finally {
    if (Test-Path -LiteralPath $stagingPath) {
        $resolvedStaging = (Resolve-Path -LiteralPath $stagingPath).Path
        $fixedPrefix = $fixedInstallBase.TrimEnd("\") + "\.staging-"
        if (-not $resolvedStaging.StartsWith($fixedPrefix, [StringComparison]::OrdinalIgnoreCase)) {
            throw [InvalidOperationException]::new("refusing to remove an unexpected staging path")
        }
        Remove-Item -LiteralPath $resolvedStaging -Recurse -Force
    }
}

if (-not $installationSucceeded) {
    exit 1
}
