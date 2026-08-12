[CmdletBinding()]
param()

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
$expectedRuntimePath = Join-Path $fixedInstallBase $supportedPackageVersion

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
        throw [InvalidDataException]::new("bundle manifest path escaped the runtime root")
    }
    return $fullPath
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

function Protect-Receipt {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path
    )

    $output = @(& "$env:SystemRoot\System32\icacls.exe" `
        $Path `
        "/inheritance:r" `
        "/grant:r" `
        "NT AUTHORITY\SYSTEM:(F)" `
        "BUILTIN\Administrators:(F)" `
        "/Q" 2>&1)
    if ($LASTEXITCODE -ne 0) {
        throw [InvalidOperationException]::new("receipt ACL update failed")
    }
}

if (-not (Test-IsAdministrator)) {
    throw [UnauthorizedAccessException]::new("machine-wide bundle removal requires elevation")
}
if (-not [Environment]::Is64BitProcess) {
    throw [PlatformNotSupportedException]::new("run the remover from 64-bit PowerShell")
}
if (-not (Test-Path -LiteralPath $fixedReceiptPath -PathType Leaf)) {
    throw [IO.FileNotFoundException]::new("machine-wide installation receipt is missing")
}
$receiptBytes = [IO.File]::ReadAllBytes($fixedReceiptPath)
if ($receiptBytes.Length -lt 2 -or $receiptBytes.Length -gt 64KB) {
    throw [InvalidDataException]::new("installation receipt size is outside the supported limit")
}
$receipt = ConvertFrom-ClosedJsonBytes -Bytes $receiptBytes -Label "installation receipt"
Assert-ExactProperties `
    -Value $receipt `
    -Names @(
        "schema_version",
        "package_version",
        "service_name",
        "runtime_path",
        "manifest_path",
        "manifest_sha256",
        "host_configuration_path",
        "host_configuration_sha256",
        "host_configuration_byte_count",
        "automatic_start",
        "removal_started",
        "operator_acl_backups"
    ) `
    -Label "installation receipt"
if (
    $receipt.schema_version -ne $supportedSchemaVersion -or
    $receipt.package_version -ne $supportedPackageVersion -or
    $receipt.service_name -ne $fixedServiceName -or
    -not [string]::Equals(
        [IO.Path]::GetFullPath($receipt.runtime_path),
        $expectedRuntimePath,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    -not [string]::Equals(
        [IO.Path]::GetFullPath($receipt.manifest_path),
        $fixedInstalledManifestPath,
        [StringComparison]::OrdinalIgnoreCase
    ) -or
    $receipt.manifest_sha256 -notmatch "^[a-f0-9]{64}$" -or
    $receipt.host_configuration_sha256 -notmatch "^[a-f0-9]{64}$" -or
    $receipt.automatic_start -isnot [bool] -or
    $receipt.removal_started -isnot [bool]
) {
    throw [InvalidDataException]::new("installation receipt does not match the fixed contract")
}
$operatorAclBackups = @($receipt.operator_acl_backups)
if ($operatorAclBackups.Count -lt 1 -or $operatorAclBackups.Count -gt 16) {
    throw [InvalidDataException]::new("installation receipt ACL backup count is unsupported")
}
$operatorAclBackupPaths = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
foreach ($backup in $operatorAclBackups) {
    Assert-ExactProperties `
        -Value $backup `
        -Names @("path", "access_sddl") `
        -Label "operator ACL backup"
    if (
        $backup.path -isnot [string] -or
        $backup.access_sddl -isnot [string] -or
        -not [IO.Path]::IsPathFullyQualified($backup.path) -or
        $backup.path.StartsWith("\\", [StringComparison]::Ordinal) -or
        $backup.path.Length -gt 512 -or
        $backup.access_sddl.Length -lt 1 -or
        $backup.access_sddl.Length -gt 8192 -or
        -not $operatorAclBackupPaths.Add([IO.Path]::GetFullPath($backup.path))
    ) {
        throw [InvalidDataException]::new("installation receipt ACL backup is invalid")
    }
    $null = [Security.AccessControl.RawSecurityDescriptor]::new($backup.access_sddl)
    if (Test-Path -LiteralPath $backup.path) {
        $backupItem = Get-Item -LiteralPath $backup.path -Force
        if ($backupItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw [IO.IOException]::new("operator ACL backup target cannot be a reparse point")
        }
    }
}
if (Test-Path -LiteralPath $fixedRemovalReceiptBackupPath) {
    $removalBackupItem = Get-Item -LiteralPath $fixedRemovalReceiptBackupPath -Force
    if (
        $removalBackupItem.PSIsContainer -or
        $removalBackupItem.Attributes -band [IO.FileAttributes]::ReparsePoint -or
        -not $receipt.removal_started
    ) {
        throw [InvalidDataException]::new("removal receipt backup state is invalid")
    }
}
$expectedRuntimeFiles = [Collections.Generic.Dictionary[string, object]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
if (-not $receipt.removal_started) {
    if (-not (Test-Path -LiteralPath $fixedInstalledManifestPath -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new("installed bundle manifest is missing")
    }
    if (
        (Get-FileHash -LiteralPath $fixedInstalledManifestPath -Algorithm SHA256).Hash.ToLowerInvariant() -ne
            $receipt.manifest_sha256
    ) {
        throw [InvalidDataException]::new("installed bundle manifest hash does not match receipt")
    }
    $manifestBytes = [IO.File]::ReadAllBytes($fixedInstalledManifestPath)
    if ($manifestBytes.Length -lt 2 -or $manifestBytes.Length -gt 16MB) {
        throw [InvalidDataException]::new("installed bundle manifest size is unsupported")
    }
    $manifest = ConvertFrom-ClosedJsonBytes `
        -Bytes $manifestBytes `
        -Label "installed bundle manifest"
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
        -Label "installed bundle manifest"
    if (
        $manifest.schema_version -ne $supportedSchemaVersion -or
        $manifest.product -ne $supportedProduct -or
        $manifest.package_version -ne $supportedPackageVersion -or
        $manifest.service_name -ne $fixedServiceName
    ) {
        throw [InvalidDataException]::new("installed bundle manifest contract is unsupported")
    }

    foreach ($entry in @($manifest.files)) {
        Assert-ExactProperties `
            -Value $entry `
            -Names @("path", "byte_count", "sha256") `
            -Label "bundle file entry"
        if (-not $entry.path.StartsWith("runtime/", [StringComparison]::Ordinal)) {
            continue
        }
        $relativeRuntimePath = $entry.path.Substring("runtime/".Length)
        $null = Resolve-ClosedRelativePath `
            -Root $expectedRuntimePath `
            -RelativePath $relativeRuntimePath
        if ($expectedRuntimeFiles.ContainsKey($relativeRuntimePath)) {
            throw [InvalidDataException]::new("runtime manifest contains a duplicate path")
        }
        if (
            $entry.byte_count -isnot [int] -and
            $entry.byte_count -isnot [long]
        ) {
            throw [InvalidDataException]::new("runtime file byte count is not an integer")
        }
        if ($entry.byte_count -lt 0 -or $entry.sha256 -notmatch "^[a-f0-9]{64}$") {
            throw [InvalidDataException]::new("runtime file integrity value is invalid")
        }
        $expectedRuntimeFiles.Add($relativeRuntimePath, $entry)
    }
    foreach ($requiredPath in @("python.exe", "pythonservice.exe", "management/remove.ps1")) {
        if (-not $expectedRuntimeFiles.ContainsKey($requiredPath)) {
            throw [InvalidDataException]::new("runtime manifest is missing a management file")
        }
    }
}

if (Test-Path -LiteralPath $expectedRuntimePath) {
    $runtimeItem = Get-Item -LiteralPath $expectedRuntimePath -Force
    if ($runtimeItem.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw [IO.IOException]::new("managed runtime cannot be a reparse point")
    }
    $reparsePoints = @(Get-ChildItem -LiteralPath $expectedRuntimePath -Recurse -Force |
        Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint })
    if ($reparsePoints.Count -ne 0) {
        throw [IO.IOException]::new("managed runtime contains a reparse point")
    }
    if (-not $receipt.removal_started) {
        $actualRuntimeFiles = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::OrdinalIgnoreCase
        )
        foreach ($actualFile in Get-ChildItem -LiteralPath $expectedRuntimePath -Recurse -File -Force) {
            $relativePath = [IO.Path]::GetRelativePath(
                $expectedRuntimePath,
                $actualFile.FullName
            ).Replace("\", "/")
            if (-not $expectedRuntimeFiles.ContainsKey($relativePath)) {
                throw [InvalidDataException]::new("managed runtime contains an unmanifested file")
            }
            $entry = $expectedRuntimeFiles[$relativePath]
            if (
                $actualFile.Length -ne [int64]$entry.byte_count -or
                (Get-FileHash -LiteralPath $actualFile.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ne
                    $entry.sha256
            ) {
                throw [InvalidDataException]::new("managed runtime integrity verification failed")
            }
            $null = $actualRuntimeFiles.Add($relativePath)
        }
        if (
            $actualRuntimeFiles.Count -ne $expectedRuntimeFiles.Count
        ) {
            throw [InvalidDataException]::new("managed runtime is incomplete before removal")
        }
    }
}

$runtimePython = Join-Path $expectedRuntimePath "python.exe"
$existingService = Get-Service -Name $fixedServiceName -ErrorAction SilentlyContinue
if ($null -ne $existingService) {
    if ($receipt.removal_started) {
        throw [InvalidOperationException]::new(
            "removal receipt is advanced but the Windows service is still registered"
        )
    }
    if (-not (Test-Path -LiteralPath $runtimePython -PathType Leaf)) {
        throw [IO.FileNotFoundException]::new("managed runtime cannot remove its service")
    }
    if ($existingService.Status -eq [ServiceProcess.ServiceControllerStatus]::Running) {
        $null = Invoke-ServiceCli -PythonExecutable $runtimePython -Arguments @("stop")
    }
    elseif ($existingService.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
        throw [InvalidOperationException]::new(
            "Windows service is in a transitional state; retry after it settles"
        )
    }
    $null = Invoke-ServiceCli -PythonExecutable $runtimePython -Arguments @("remove")
    if (-not (Wait-ServiceAbsent -Seconds 20)) {
        throw [TimeoutException]::new("Windows service remained registered after removal")
    }
}

$restoredOperatorAcls = 0
$missingOperatorAclTargets = 0
foreach ($backup in $operatorAclBackups) {
    if (-not (Test-Path -LiteralPath $backup.path)) {
        $missingOperatorAclTargets += 1
        continue
    }
    $operatorAcl = Get-Acl -LiteralPath $backup.path
    $operatorAcl.SetSecurityDescriptorSddlForm(
        $backup.access_sddl,
        [Security.AccessControl.AccessControlSections]::Access
    )
    Set-Acl -LiteralPath $backup.path -AclObject $operatorAcl
    $restoredOperatorAcls += 1
}

if (-not $receipt.removal_started) {
    $receipt.removal_started = $true
    $temporaryReceipt = "$fixedReceiptPath.$([Guid]::NewGuid().ToString('N')).tmp"
    try {
        [IO.File]::WriteAllText(
            $temporaryReceipt,
            ($receipt | ConvertTo-Json -Depth 5),
            [Text.UTF8Encoding]::new($false)
        )
        Protect-Receipt -Path $temporaryReceipt
        [IO.File]::Replace(
            $temporaryReceipt,
            $fixedReceiptPath,
            $fixedRemovalReceiptBackupPath,
            $true
        )
        Protect-Receipt -Path $fixedReceiptPath
    }
    finally {
        if (Test-Path -LiteralPath $temporaryReceipt -PathType Leaf) {
            Remove-Item -LiteralPath $temporaryReceipt -Force -ErrorAction SilentlyContinue
        }
    }
}

if (Test-Path -LiteralPath $expectedRuntimePath) {
    $resolvedRuntime = (Resolve-Path -LiteralPath $expectedRuntimePath).Path
    if (-not [string]::Equals(
            $resolvedRuntime,
            $expectedRuntimePath,
            [StringComparison]::OrdinalIgnoreCase
        )) {
        throw [InvalidOperationException]::new("refusing to remove an unexpected runtime path")
    }
    Remove-Item -LiteralPath $resolvedRuntime -Recurse -Force -ErrorAction Stop
    if (Test-Path -LiteralPath $expectedRuntimePath) {
        throw [IO.IOException]::new("managed runtime remained after removal")
    }
}
if (Test-Path -LiteralPath $fixedInstalledManifestPath -PathType Leaf) {
    Remove-Item -LiteralPath $fixedInstalledManifestPath -Force -ErrorAction Stop
}
if (Test-Path -LiteralPath $fixedRemovalReceiptBackupPath -PathType Leaf) {
    Remove-Item -LiteralPath $fixedRemovalReceiptBackupPath -Force -ErrorAction Stop
}
Remove-Item -LiteralPath $fixedReceiptPath -Force -ErrorAction Stop

[ordered]@{
    schema_version = "1.0"
    result = "removed"
    package_version = $supportedPackageVersion
    service_name = $fixedServiceName
    runtime_removed = (-not (Test-Path -LiteralPath $expectedRuntimePath))
    receipt_removed = (-not (Test-Path -LiteralPath $fixedReceiptPath))
    operator_configuration_preserved = $true
    operator_state_and_data_preserved = $true
    operator_acls_restored = $restoredOperatorAcls
    missing_operator_acl_targets = $missingOperatorAclTargets
} | ConvertTo-Json -Depth 5
